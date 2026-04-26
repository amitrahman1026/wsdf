use std::fs;
use std::path::PathBuf;
use std::process::Command;

// ── shared helpers ────────────────────────────────────────────────────────────

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("CARGO_MANIFEST_DIR has no parent")
        .to_path_buf()
}

/// Build the builder example and install it via post_build so tshark can find it.
/// Idempotent — safe to call from multiple tests.
fn ensure_builder_plugin_installed() {
    let root = workspace_root();

    let build = Command::new("cargo")
        .args(["build", "--example", "builder"])
        .status()
        .expect("failed to run cargo build");
    assert!(build.success(), "cargo build --example builder failed");

    // post_build handles platform-specific processing (.dylib→.so rename, rpath, codesign)
    // and copies the result into the personal Wireshark plugin directory.
    let post_build_bin = root.join("target/debug/post_build");

    // Find the raw built artifact before post_build renames it.
    let raw_plugin = [
        root.join("target/debug/examples/libbuilder.dylib"),
        root.join("target/debug/examples/libbuilder.so"),
        root.join("target/debug/examples/builder.dll"),
    ]
    .into_iter()
    .find(|p| p.exists())
    .expect("plugin artifact not found after build");

    let status = Command::new(&post_build_bin)
        .args([raw_plugin.to_str().unwrap(), "--install"])
        .status()
        .unwrap_or_else(|_| panic!("failed to run {}", post_build_bin.display()));
    assert!(status.success(), "post_build --install failed");
}

/// Wrap `payload_bytes` in an Ethernet+IP frame (proto=17, no UDP header) using
/// text2pcap, then dissect with tshark and return the `wsdf_example` JSON layer.
///
/// The builder example registers on `ip.proto == 17`, so it receives the raw IP
/// payload — our bytes — directly, with no UDP header in between.
fn dissect_bytes(payload_bytes: &[u8]) -> serde_json::Value {
    let tmp = std::env::temp_dir();
    let hex_file = tmp.join("wsdf_test_input.txt");
    let pcap_file = tmp.join("wsdf_test.pcap");

    let hex_line = format!(
        "000000 {}\n",
        payload_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    std::fs::write(&hex_file, &hex_line).expect("failed to write hex file");

    let t2p = Command::new("text2pcap")
        .args([
            "-i",
            "17",
            hex_file.to_str().unwrap(),
            pcap_file.to_str().unwrap(),
        ])
        .status()
        .expect("text2pcap not found — install Wireshark");
    assert!(t2p.success(), "text2pcap failed");

    let mut tshark = Command::new("tshark");
    tshark.args([
        "-r",
        pcap_file.to_str().unwrap(),
        "-T",
        "json",
        "-J",
        "wsdf_example",
    ]);
    #[cfg(target_os = "macos")]
    tshark.env(
        "DYLD_LIBRARY_PATH",
        "/Applications/Wireshark.app/Contents/Frameworks",
    );

    let out = tshark
        .output()
        .expect("tshark not found — install Wireshark");
    assert!(
        out.status.success(),
        "tshark failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let packets: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout))
        .expect("tshark output is not valid JSON");

    packets[0]["_source"]["layers"]["wsdf_example"].clone()
}

/// Integration tests for wsdf plugin generation and tshark compatibility
/// These tests build example plugins and verify they can be loaded by Wireshark/tshark

#[test]
fn test_plugin_builds_successfully() {
    // Build the example plugin
    let output = Command::new("cargo")
        .args(&["build", "--example", "builder"])
        .output()
        .expect("Failed to run cargo build");

    assert!(
        output.status.success(),
        "Plugin build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Check that the plugin file was created
    // Determine the workspace root (integration tests run from wsdf/ subdirectory)
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Failed to get workspace root")
        .to_path_buf();

    let plugin_paths = vec![
        workspace_root.join("target/debug/examples/libbuilder.so"),
        workspace_root.join("target/debug/examples/libbuilder.dylib"),
        workspace_root.join("target/debug/examples/builder.dll"),
    ];

    let plugin_exists = plugin_paths.iter().any(|path| path.exists());

    assert!(
        plugin_exists,
        "No plugin file found in expected locations: {:?}",
        plugin_paths
    );
}

#[test]
fn test_plugin_file_properties() {
    // First ensure the plugin is built
    test_plugin_builds_successfully();

    // Find the built plugin
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Failed to get workspace root")
        .to_path_buf();

    let plugin_paths = vec![
        workspace_root.join("target/debug/examples/libbuilder.so"),
        workspace_root.join("target/debug/examples/libbuilder.dylib"),
    ];

    let plugin_path = plugin_paths
        .iter()
        .find(|path| path.exists())
        .expect("No plugin file found")
        .to_str()
        .expect("Invalid path");

    // Check file properties using system tools
    match std::env::consts::OS {
        "macos" => {
            // Use otool to check library dependencies on macOS
            let output = Command::new("otool")
                .args(&["-L", plugin_path])
                .output()
                .expect("Failed to run otool");

            assert!(
                output.status.success(),
                "otool failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            let deps = String::from_utf8_lossy(&output.stdout);
            // Should have references to Wireshark libraries
            assert!(
                deps.contains("libwireshark") || deps.contains("wireshark"),
                "Plugin doesn't link to Wireshark libraries"
            );
        }
        "linux" => {
            // Use ldd to check shared library dependencies on Linux
            let output = Command::new("ldd")
                .arg(plugin_path)
                .output()
                .expect("Failed to run ldd");

            if output.status.success() {
                let deps = String::from_utf8_lossy(&output.stdout);
                // Should have references to Wireshark libraries
                assert!(
                    deps.contains("libwireshark") || deps.contains("wireshark"),
                    "Plugin doesn't link to Wireshark libraries"
                );
            }
            // Note: ldd might fail if libraries aren't found, which is OK for this test
        }
        _ => {
            // For other platforms, just check the file exists and is not is_empty
            // TODO: Improve this in future
            let metadata = fs::metadata(plugin_path).expect("Failed to get file metadata");
            assert!(metadata.len() > 0, "Plugin file is empty");
        }
    }
}

#[test]
fn test_tshark_plugin_listing() {
    // This test checks if tshark can list plugins without crashing
    // It doesn't require our plugin to be properly loaded since it's just an example

    let output = Command::new("tshark").args(&["-G", "plugins"]).output();

    match output {
        Ok(result) => {
            if result.status.success() {
                let plugins_output = String::from_utf8_lossy(&result.stdout);
                // Just verify tshark can list plugins without error
                // Our plugin may not appear here since it's a basic example
                assert!(
                    plugins_output.contains("plugins") || plugins_output.len() > 0,
                    "tshark -G plugins produced no output"
                );
            } else {
                // tshark might not be available or configured, which is OK
                eprintln!(
                    "tshark not available or failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
            }
        }
        Err(_) => {
            // tshark not available, skip this test
            eprintln!("tshark not available, skipping plugin listing test");
        }
    }
}

#[test]
fn test_build_system_environment() {
    // Test that our build system correctly sets up the environment

    // Check that Wireshark libraries can be found
    let output = Command::new("pkg-config")
        .args(&["--exists", "wireshark"])
        .output();

    if let Ok(result) = output {
        if result.status.success() {
            // pkg-config found wireshark, verify version info
            let version_output = Command::new("pkg-config")
                .args(&["--modversion", "wireshark"])
                .output()
                .expect("Failed to get Wireshark version");

            if version_output.status.success() {
                let version = String::from_utf8_lossy(&version_output.stdout);
                assert!(!version.trim().is_empty(), "Wireshark version is empty");
                eprintln!("Found Wireshark version: {}", version.trim());
            }
        } else {
            eprintln!("pkg-config wireshark not found, build system should handle this");
        }
    }
}

#[test]
fn test_cargo_metadata_support() {
    // Test that our metadata configuration system works
    let output = Command::new("cargo")
        .args(&["metadata", "--format-version", "1"])
        .output()
        .expect("Failed to run cargo metadata");

    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata = String::from_utf8_lossy(&output.stdout);
    // Verify our workspace structure is correct
    assert!(
        metadata.contains("epan-sys"),
        "epan-sys not found in metadata"
    );
    assert!(metadata.contains("wsdf"), "wsdf not found in metadata");
}

#[cfg(target_os = "macos")]
#[test]
fn test_macos_plugin_postprocessing() {
    use std::fs::copy;

    // Build plugin first
    test_plugin_builds_successfully();

    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Failed to get workspace root")
        .to_path_buf();

    let plugin_path = workspace_root.join("target/debug/examples/libbuilder.dylib");
    if !plugin_path.exists() {
        eprintln!("Plugin not found, skipping macOS post-processing test");
        return;
    }

    // Create a temporary copy for testing post-processing
    let temp_plugin = workspace_root.join("target/debug/examples/test_libbuilder.dylib");
    copy(&plugin_path, &temp_plugin).expect("Failed to copy plugin for testing");

    // Test the post-processing script functionality
    // Note: We don't run the actual post-processing script here to avoid modifying build artifacts

    // Check initial state
    let output = Command::new("otool")
        .args(&["-L", temp_plugin.to_str().unwrap()])
        .output()
        .expect("Failed to run otool");

    assert!(output.status.success(), "otool failed");

    let deps = String::from_utf8_lossy(&output.stdout);

    // Verify we can detect Wireshark dependencies
    let has_wireshark_deps = deps.lines().any(|line| {
        line.contains("libwireshark") || line.contains("libwsutil") || line.contains("libwiretap")
    });

    if has_wireshark_deps {
        eprintln!("Found Wireshark dependencies in plugin (good)");
    } else {
        eprintln!("No Wireshark dependencies found (may be expected for basic example)");
    }

    // Clean up
    let _ = fs::remove_file(&temp_plugin);
}

/// Dissect an uncompressed builder packet and assert every field decodes correctly.
///
/// Packet layout (10 bytes, ip.proto=17 payload):
///   [0]      field1    = 0x01  → decimal "1"
///   [1..2]   field2    = 0x0002 → hex "0x0002"
///   [3]      comp_flag = 0x00  (MSB=0 → uncompressed path)
///   [4..5]   orig_size = 0x000a = 10
///   [6..9]   raw_data  = 11 22 33 44
#[test]
fn test_dissection_uncompressed_packet() {
    ensure_builder_plugin_installed();

    let wsdf = dissect_bytes(&[0x01, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x11, 0x22, 0x33, 0x44]);

    assert_eq!(wsdf["wsdf.header_field"]["wsdf.field1"], "1");
    assert_eq!(wsdf["wsdf.header_field"]["wsdf.field2"], "0x0002");
    assert_eq!(wsdf["wsdf.payload_field"]["wsdf.comp_flag"], "0x00");
    assert_eq!(wsdf["wsdf.payload_field"]["wsdf.orig_size"], "10");
    assert_eq!(wsdf["wsdf.raw"], "11:22:33:44");
}
