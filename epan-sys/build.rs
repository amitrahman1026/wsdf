#[cfg(feature = "bindgen")]
extern crate bindgen;

use cargo_metadata::MetadataCommand;
use std::env;
use std::path::{Path, PathBuf};
#[cfg(any(feature = "source-build", feature = "bindgen"))]
use std::process::Command;

#[derive(Debug)]
struct WiresharkConfig {
    lib_dir: PathBuf,
    include_dir: PathBuf,
    version: String,
    lib_name: String, // libwireshark vs libwireshark.18
    major_version: Option<u32>,
    #[allow(dead_code)] // Reserved for future version checking
    minor_version: Option<u32>,
}

#[derive(Debug, Default)]
struct MetadataConfig {
    verbose_build: bool,
    generate_soname: bool,
    fix_rpaths: bool,
    wireshark_lib_dir: Option<PathBuf>,
    wireshark_include_dir: Option<PathBuf>,
    fix_app_bundle_rpaths: bool,
    preferred_version: Option<String>,
}

#[allow(dead_code)] // Error types reserved for future enhanced error handling
#[derive(Debug)]
enum BuildError {
    LibraryNotFound,
    IncompatibleVersion { found: String, required: String },
    UnsupportedPlatform(String),
    MissingDevelopmentHeaders,
    ConfigurationError(String),
    SmokeTestFailed(String),
    MetadataError(String),
}

fn main() {
    // If we are in docs.rs, there is no need to actually link.
    if std::env::var("DOCS_RS").is_ok() {
        return;
    }

    // Load metadata configuration
    let metadata_config = load_metadata_config().unwrap_or_else(|e| {
        if env::var("CARGO_FEATURE_VERBOSE").is_ok() {
            println!("cargo:warning=Failed to load metadata config: {:?}", e);
        }
        MetadataConfig::default()
    });

    if metadata_config.verbose_build {
        println!("cargo:warning=Using metadata config: {:?}", metadata_config);
    }

    // Regenerate version-specific bindings when the bindgen feature is enabled.
    // In normal builds the committed bindings_44.rs / bindings_46.rs are used directly.
    #[cfg(feature = "bindgen")]
    generate_bindings();

    let config = find_wireshark_config(&metadata_config).unwrap_or_else(|e| handle_build_error(e));

    configure_linking(&config, &metadata_config);
    configure_soname_if_cdylib(&metadata_config);
}

fn load_metadata_config() -> Result<MetadataConfig, BuildError> {
    let metadata = MetadataCommand::new()
        .exec()
        .map_err(|e| BuildError::MetadataError(format!("Failed to get cargo metadata: {}", e)))?;

    let package = metadata
        .root_package()
        .ok_or_else(|| BuildError::MetadataError("No root package found".to_string()))?;

    let mut config = MetadataConfig::default();

    if let Some(wsdf_metadata) = package.metadata.get("wsdf") {
        if let Some(verbose) = wsdf_metadata.get("verbose_build") {
            config.verbose_build = verbose.as_bool().unwrap_or(false);
        }
        if let Some(soname) = wsdf_metadata.get("generate_soname") {
            config.generate_soname = soname.as_bool().unwrap_or(false);
        }
        if let Some(rpaths) = wsdf_metadata.get("fix_rpaths") {
            config.fix_rpaths = rpaths.as_bool().unwrap_or(false);
        }
        if let Some(lib_dir) = wsdf_metadata.get("wireshark_lib_dir") {
            if let Some(path_str) = lib_dir.as_str() {
                config.wireshark_lib_dir = Some(PathBuf::from(path_str));
            }
        }
        if let Some(inc_dir) = wsdf_metadata.get("wireshark_include_dir") {
            if let Some(path_str) = inc_dir.as_str() {
                config.wireshark_include_dir = Some(PathBuf::from(path_str));
            }
        }
        if let Some(fix_app) = wsdf_metadata.get("fix_app_bundle_rpaths") {
            config.fix_app_bundle_rpaths = fix_app.as_bool().unwrap_or(false);
        }
        if let Some(version) = wsdf_metadata.get("preferred_version") {
            config.preferred_version = version.as_str().map(String::from);
        }

        // Check for target-specific configuration
        let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
        if let Some(target_config) = wsdf_metadata.get(format!("target.{}", target)) {
            if let Some(lib_dir) = target_config.get("wireshark_lib_dir") {
                if let Some(path_str) = lib_dir.as_str() {
                    config.wireshark_lib_dir = Some(PathBuf::from(path_str));
                }
            }
            if let Some(version) = target_config.get("preferred_version") {
                config.preferred_version = version.as_str().map(String::from);
            }
        }
    }

    Ok(config)
}

fn find_wireshark_config(metadata_config: &MetadataConfig) -> Result<WiresharkConfig, BuildError> {
    let result = try_metadata_config(metadata_config)
        .or_else(|_| try_environment_config())
        .or_else(|_| try_pkg_config())
        .or_else(|_| try_platform_detection(metadata_config))
        .or_else(|_| try_smoke_test());

    // Source build clones ~200 MB and takes several minutes. Opt-in only.
    #[cfg(feature = "source-build")]
    let result = result.or_else(|_| fallback_source_build());

    result
}

fn try_metadata_config(metadata_config: &MetadataConfig) -> Result<WiresharkConfig, BuildError> {
    if let (Some(lib_dir), Some(inc_dir)) = (
        &metadata_config.wireshark_lib_dir,
        &metadata_config.wireshark_include_dir,
    ) {
        if let Some(mut config) = probe_wireshark_installation(lib_dir, inc_dir) {
            // Apply preferred version if specified
            if let Some(preferred_version) = &metadata_config.preferred_version {
                config.version = preferred_version.clone();
                config.lib_name = format!("wireshark.{}", preferred_version);
                if let Ok(version) = preferred_version.parse::<u32>() {
                    config.major_version = Some(version);
                }
            }
            return Ok(config);
        }
    } else if let Some(lib_dir) = &metadata_config.wireshark_lib_dir {
        // Try to infer include dir from lib dir
        let possible_inc_dirs = vec![
            lib_dir.parent().unwrap_or(lib_dir).join("include"),
            lib_dir
                .parent()
                .unwrap_or(lib_dir)
                .join("include/wireshark"),
            PathBuf::from("/usr/include/wireshark"),
            PathBuf::from("/usr/local/include/wireshark"),
        ];

        for inc_dir in possible_inc_dirs {
            if let Some(mut config) = probe_wireshark_installation(lib_dir, &inc_dir) {
                if let Some(preferred_version) = &metadata_config.preferred_version {
                    config.version = preferred_version.clone();
                    config.lib_name = format!("wireshark.{}", preferred_version);
                    if let Ok(version) = preferred_version.parse::<u32>() {
                        config.major_version = Some(version);
                    }
                }
                return Ok(config);
            }
        }
    }

    Err(BuildError::LibraryNotFound)
}

fn try_environment_config() -> Result<WiresharkConfig, BuildError> {
    if let (Ok(lib_dir), Ok(include_dir)) = (
        env::var("WIRESHARK_LIB_DIR"),
        env::var("WIRESHARK_INCLUDE_DIR"),
    ) {
        let lib_path = PathBuf::from(&lib_dir);
        let inc_path = PathBuf::from(&include_dir);

        if let Some(config) = probe_wireshark_installation(&lib_path, &inc_path) {
            return Ok(config);
        }
    }

    Err(BuildError::LibraryNotFound)
}

fn try_pkg_config() -> Result<WiresharkConfig, BuildError> {
    if let Ok(lib) = pkg_config::probe_library("wireshark") {
        let lib_dir = lib
            .link_paths
            .first()
            .ok_or(BuildError::ConfigurationError(
                "No lib paths from pkg-config".to_string(),
            ))?;
        let include_dir = lib
            .include_paths
            .first()
            .ok_or(BuildError::ConfigurationError(
                "No include paths from pkg-config".to_string(),
            ))?;

        println!(
            "cargo:warning=Found Wireshark via pkg-config at {}",
            lib_dir.display()
        );
        return Ok(WiresharkConfig {
            lib_dir: lib_dir.clone(),
            include_dir: include_dir.clone(),
            version: "unknown".to_string(),
            lib_name: "wireshark".to_string(),
            major_version: None,
            minor_version: None,
        });
    }

    Err(BuildError::LibraryNotFound)
}

fn try_platform_detection(metadata_config: &MetadataConfig) -> Result<WiresharkConfig, BuildError> {
    match std::env::consts::OS {
        "macos" => detect_macos_wireshark(metadata_config),
        "linux" => detect_linux_wireshark(metadata_config),
        "windows" => detect_windows_wireshark(metadata_config),
        os => Err(BuildError::UnsupportedPlatform(os.to_string())),
    }
}

fn try_smoke_test() -> Result<WiresharkConfig, BuildError> {
    // Compile src/smoke.c against standard include paths using the cc crate.
    // try_compile produces an object file only — no linking, no binary execution.
    // This makes it safe for cross-compilation and avoids needing libwireshark
    // in the linker search path at this stage.
    let compiled = cc::Build::new()
        .file("src/smoke.c")
        .try_compile("smoke_wireshark")
        .is_ok();

    if compiled {
        infer_from_system_paths()
    } else {
        Err(BuildError::SmokeTestFailed(
            "Wireshark headers not found in standard include paths".to_string(),
        ))
    }
}

fn infer_from_system_paths() -> Result<WiresharkConfig, BuildError> {
    let system_lib_paths = vec!["/usr/lib", "/usr/local/lib", "/opt/local/lib"];

    let system_inc_paths = vec!["/usr/include", "/usr/local/include", "/opt/local/include"];

    for lib_path in system_lib_paths {
        for inc_path in &system_inc_paths {
            let lib_dir = PathBuf::from(lib_path);
            let inc_dir = PathBuf::from(inc_path);

            if let Some(config) = probe_wireshark_installation(&lib_dir, &inc_dir) {
                return Ok(config);
            }
        }
    }

    Err(BuildError::LibraryNotFound)
}

fn detect_macos_wireshark(
    _metadata_config: &MetadataConfig,
) -> Result<WiresharkConfig, BuildError> {
    let search_configs = vec![
        (
            "/Applications/Wireshark.app/Contents/Frameworks",
            "/Applications/Wireshark.app/Contents/Resources/include",
        ),
        ("/opt/homebrew/lib", "/opt/homebrew/include"),
        ("/usr/local/lib", "/usr/local/include"),
        ("/opt/local/lib", "/opt/local/include"),
    ];

    for (lib_path, inc_path) in search_configs {
        let lib_dir = PathBuf::from(lib_path);
        let inc_dir = PathBuf::from(inc_path);

        if let Some(config) = probe_wireshark_installation(&lib_dir, &inc_dir) {
            println!(
                "cargo:warning=Found Wireshark {} at {} (lib: {})",
                config.version,
                config.lib_dir.display(),
                config.lib_name
            );
            return Ok(config);
        }
    }

    Err(BuildError::LibraryNotFound)
}

fn detect_linux_wireshark(
    _metadata_config: &MetadataConfig,
) -> Result<WiresharkConfig, BuildError> {
    // TODO: Potentially look into CSP standard/ pkg-config standards & paramaterise
    let arch = std::env::consts::ARCH;
    let search_configs = vec![
        (
            format!("/usr/lib/{}-linux-gnu", arch),
            "/usr/include".to_string(),
        ),
        ("/usr/lib64".to_string(), "/usr/include".to_string()),
        ("/usr/lib".to_string(), "/usr/include".to_string()),
        (
            "/usr/local/lib".to_string(),
            "/usr/local/include".to_string(),
        ),
    ];

    for (lib_path, inc_path) in search_configs {
        let lib_dir = PathBuf::from(&lib_path);
        let inc_dir = PathBuf::from(&inc_path);

        if let Some(config) = probe_wireshark_installation(&lib_dir, &inc_dir) {
            println!(
                "cargo:warning=Found Wireshark {} at {} (lib: {})",
                config.version,
                config.lib_dir.display(),
                config.lib_name
            );
            return Ok(config);
        }
    }

    Err(BuildError::LibraryNotFound)
}

fn detect_windows_wireshark(
    _metadata_config: &MetadataConfig,
) -> Result<WiresharkConfig, BuildError> {
    // TODO: Should test this in CI, currently just going off what Google says
    let search_configs = vec![(
        "C:\\Program Files\\Wireshark",
        "C:\\Program Files\\Wireshark\\include",
    )];

    for (lib_path, inc_path) in search_configs {
        let lib_dir = PathBuf::from(lib_path);
        let inc_dir = PathBuf::from(inc_path);

        if let Some(config) = probe_wireshark_installation(&lib_dir, &inc_dir) {
            println!(
                "cargo:warning=Found Wireshark {} at {} (lib: {})",
                config.version,
                config.lib_dir.display(),
                config.lib_name
            );
            return Ok(config);
        }
    }

    Err(BuildError::LibraryNotFound)
}

fn probe_wireshark_installation(lib_dir: &PathBuf, inc_dir: &Path) -> Option<WiresharkConfig> {
    if let Some(versioned) = find_versioned_library(lib_dir) {
        return Some(versioned);
    }

    let extensions = match std::env::consts::OS {
        "macos" => vec!["dylib"],
        "windows" => vec!["lib", "dll"],
        _ => vec!["so"],
    };

    for ext in extensions {
        let lib_file = lib_dir.join(format!("libwireshark.{}", ext));
        if lib_file.exists() {
            return Some(WiresharkConfig {
                lib_dir: lib_dir.clone(),
                include_dir: inc_dir.to_path_buf(),
                version: "unknown".to_string(),
                lib_name: "wireshark".to_string(),
                major_version: None,
                minor_version: None,
            });
        }
    }

    None
}

fn find_versioned_library(lib_dir: &PathBuf) -> Option<WiresharkConfig> {
    // Look for versioned libraries like libwireshark.18.dylib
    if let Ok(entries) = std::fs::read_dir(lib_dir) {
        for entry in entries.flatten() {
            let filename = entry.file_name();
            let name = filename.to_string_lossy();

            // Match patterns like libwireshark.18.dylib or libwireshark.so.18
            if name.starts_with("libwireshark.")
                && (name.contains(".dylib") || name.contains(".so"))
            {
                // Extract version number
                if let Some(version) = extract_version_from_filename(&name) {
                    let lib_name = if name.contains(".dylib") {
                        format!("wireshark.{}", version)
                    } else {
                        "wireshark".to_string() // Linux uses soname differently
                    };

                    let major_version = version.parse::<u32>().ok();
                    let minor_version = None; // Could be enhanced to parse minor versions

                    return Some(WiresharkConfig {
                        lib_dir: lib_dir.clone(),
                        include_dir: lib_dir.clone(), // May need adjustment
                        version: version.clone(),
                        lib_name,
                        major_version,
                        minor_version,
                    });
                }
            }
        }
    }
    None
}

fn extract_version_from_filename(filename: &str) -> Option<String> {
    // Extract version from libwireshark.18.dylib or similar
    if let Some(after_wireshark) = filename.strip_prefix("libwireshark.") {
        if let Some(before_ext) = after_wireshark.split('.').next() {
            if before_ext.chars().all(|c| c.is_ascii_digit()) {
                return Some(before_ext.to_string());
            }
        }
    }
    None
}

#[cfg(feature = "source-build")]
fn fallback_source_build() -> Result<WiresharkConfig, BuildError> {
    println!("cargo:warning=libwireshark was not found, will be built from source");

    clone_wireshark_or_die();
    let dst = build_wireshark();

    let lib_dir = dst.join("lib");
    let include_dir = dst.join("include").join("wireshark");

    Ok(WiresharkConfig {
        lib_dir,
        include_dir,
        version: "source".to_string(),
        lib_name: "wireshark".to_string(),
        major_version: None,
        minor_version: None,
    })
}

fn configure_linking(config: &WiresharkConfig, metadata_config: &MetadataConfig) {
    if metadata_config.verbose_build {
        println!(
            "cargo:warning=Linking with Wireshark library: {}",
            config.lib_name
        );
        println!(
            "cargo:warning=Library directory: {}",
            config.lib_dir.display()
        );
        println!(
            "cargo:warning=Include directory: {}",
            config.include_dir.display()
        );
        println!("cargo:warning=Version: {}", config.version);
    }

    println!("cargo:rustc-link-lib=dylib={}", config.lib_name);
    println!(
        "cargo:rustc-link-search=native={}",
        config.lib_dir.display()
    );

    // Discover wsutil/wiretap by scanning the library directory for versioned
    // filenames (e.g. libwsutil.16.dylib on macOS). Simpler than Mach-O parsing
    // and works on all platforms.
    let deps = scan_wireshark_dependencies(&config.lib_dir);
    if deps.is_empty() {
        fallback_dependency_linking(config);
    } else {
        for dep in &deps {
            println!("cargo:warning=Linking dependency: {}", dep);
            println!("cargo:rustc-link-lib=dylib={}", dep);
        }
    }

    // For macOS, set rpath
    if std::env::consts::OS == "macos" && metadata_config.fix_rpaths {
        println!(
            "cargo:rustc-link-arg=-Wl,-rpath,{}",
            config.lib_dir.display()
        );
        if metadata_config.verbose_build {
            println!(
                "cargo:warning=Added rpath for macOS: {}",
                config.lib_dir.display()
            );
        }
    } else if std::env::consts::OS == "macos"
        && config.lib_dir.to_string_lossy().contains("Wireshark.app")
    {
        // Default behavior for Wireshark.app bundles
        println!(
            "cargo:rustc-link-arg=-Wl,-rpath,{}",
            config.lib_dir.display()
        );
    }

    // Emit version cfg flags so dependent crates (and epan-sys/lib.rs itself) can
    // select the right bindings file.  The flags are additive: a 4.6 build emits
    // both wireshark4 and wireshark46.  Pattern mirrors openssl-sys.
    emit_version_cfg(&config.include_dir);

    // Set metadata for potential post-build processing
    println!("cargo:rustc-env=WSDF_WIRESHARK_VERSION={}", config.version);
    println!("cargo:rustc-env=WSDF_LIB_DIR={}", config.lib_dir.display());
}

fn emit_version_cfg(include_dir: &Path) {
    // Tell rustc these are valid cfg names so it doesn't warn downstream.
    println!("cargo::rustc-check-cfg=cfg(wireshark4)");
    println!("cargo::rustc-check-cfg=cfg(wireshark44)");
    println!("cargo::rustc-check-cfg=cfg(wireshark46)");

    let (major, minor) = read_ws_version(include_dir).unwrap_or((4, 4));

    // wireshark4  — true for any 4.x build
    println!("cargo:rustc-cfg=wireshark{}", major);
    // wireshark44 / wireshark46 — exact minor match used for bindings selection
    println!("cargo:rustc-cfg=wireshark{}{}", major, minor);

    println!(
        "cargo:warning=Wireshark version cfg: wireshark{} + wireshark{}{}",
        major, major, minor
    );
}

fn read_ws_version(include_dir: &Path) -> Option<(u32, u32)> {
    // ws_version.h may live directly in include_dir or in a wireshark/ subdirectory.
    let candidates = [
        include_dir.join("ws_version.h"),
        include_dir.join("wireshark/ws_version.h"),
    ];
    let content = candidates
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())?;

    let mut major: Option<u32> = None;
    let mut minor: Option<u32> = None;
    for line in content.lines() {
        if major.is_none() {
            if let Some(rest) = line.strip_prefix("#define WIRESHARK_VERSION_MAJOR ") {
                major = rest.trim().parse().ok();
            }
        }
        if minor.is_none() {
            if let Some(rest) = line.strip_prefix("#define WIRESHARK_VERSION_MINOR ") {
                minor = rest.trim().parse().ok();
            }
        }
        if major.is_some() && minor.is_some() {
            break;
        }
    }
    Some((major?, minor?))
}

fn scan_wireshark_dependencies(lib_dir: &PathBuf) -> Vec<String> {
    ["wsutil", "wiretap"]
        .iter()
        .filter_map(|base| find_dep_lib_name(lib_dir, base))
        .collect()
}

fn find_dep_lib_name(lib_dir: &PathBuf, base: &str) -> Option<String> {
    let prefix = format!("lib{}.", base);
    let entries = std::fs::read_dir(lib_dir).ok()?;
    for entry in entries.flatten() {
        let filename = entry.file_name();
        let name = filename.to_string_lossy();
        if !name.starts_with(&prefix) {
            continue;
        }
        // macOS: libwsutil.16.dylib → "wsutil.16"
        if let Some(inner) = name
            .strip_prefix(&prefix)
            .and_then(|s| s.strip_suffix(".dylib"))
        {
            if inner.chars().all(|c| c.is_ascii_digit()) {
                return Some(format!("{}.{}", base, inner));
            }
        }
        // Linux: libwsutil.so or libwsutil.so.N → "wsutil"
        if name.contains(".so") {
            return Some(base.to_string());
        }
    }
    None
}

fn fallback_dependency_linking(config: &WiresharkConfig) {
    if config.lib_dir.to_string_lossy().contains("Wireshark.app") {
        // Known versions for Wireshark.app bundle
        println!("cargo:rustc-link-lib=dylib=wsutil.16");
        println!("cargo:rustc-link-lib=dylib=wiretap.15");
    } else {
        // Generic names for system installations
        println!("cargo:rustc-link-lib=dylib=wsutil");
        println!("cargo:rustc-link-lib=dylib=wiretap");
    }
}

fn configure_soname_if_cdylib(metadata_config: &MetadataConfig) {
    // epan-sys's build script cannot detect whether the downstream plugin crate
    // is a cdylib — Cargo does not expose the consumer's crate type to a
    // dependency's build script. Soname generation is therefore opt-in: set
    // `generate_soname = true` in `[package.metadata.wsdf]` of the plugin's
    // own Cargo.toml to enable it.
    if !metadata_config.generate_soname {
        return;
    }
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_default();
    if let Ok(semver_version) = semver::Version::parse(&version) {
        generate_soname_args(&semver_version);
        if metadata_config.verbose_build {
            println!("cargo:warning=Generated soname for version {}", version);
        }
    }
}

fn generate_soname_args(version: &semver::Version) {
    let pkg_name = env::var("CARGO_PKG_NAME").unwrap_or_default();

    match std::env::consts::OS {
        "linux" | "freebsd" | "dragonfly" | "netbsd" => {
            if version.major >= 1 {
                println!(
                    "cargo:rustc-cdylib-link-arg=-Wl,-soname,lib{}.so.{}",
                    pkg_name, version.major
                );
            } else {
                println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,lib{}.so", pkg_name);
            }
        }
        "macos" | "ios" => {
            println!(
                "cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/lib{}.dylib",
                pkg_name
            );
        }
        _ => {}
    }
}

fn handle_build_error(error: BuildError) -> ! {
    match error {
        BuildError::LibraryNotFound => {
            eprintln!("ERROR: Wireshark library not found");
            eprintln!("SOLUTIONS:");
            print_platform_specific_install_instructions();
            eprintln!("MANUAL CONFIGURATION:");
            eprintln!("  export WIRESHARK_LIB_DIR=/path/to/wireshark/lib");
            eprintln!("  export WIRESHARK_INCLUDE_DIR=/path/to/wireshark/include");
        }
        BuildError::UnsupportedPlatform(platform) => {
            eprintln!("ERROR: Unsupported platform: {}", platform);
            eprintln!("SUPPORTED: macOS, Linux, Windows");
            eprintln!("WORKAROUND: Set manual library paths via environment variables");
        }
        _ => eprintln!("BUILD ERROR: {:?}", error),
    }

    std::process::exit(1);
}

// TODO: Research on common platform specific help messages
fn print_platform_specific_install_instructions() {
    match std::env::consts::OS {
        "macos" => {
            eprintln!("  macOS:");
            eprintln!("    brew install wireshark");
            eprintln!("    # OR download from https://www.wireshark.org/download.html");
        }
        "linux" => {
            eprintln!("  Ubuntu/Debian:");
            eprintln!("    sudo apt install wireshark-dev");
            eprintln!("  Fedora/RHEL:");
            eprintln!("    sudo dnf install wireshark-devel");
            eprintln!("  Arch:");
            eprintln!("    sudo pacman -S wireshark-cli");
        }
        _ => {}
    }
}

#[cfg(not(feature = "bindgen"))]
#[allow(dead_code)]
fn generate_bindings() {
    panic!("Regenerating bindings requires --features bindgen: cargo build --features bindgen");
}

#[cfg(feature = "bindgen")]
fn generate_bindings() {
    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .generate_comments(false);

    match pkg_config::probe_library("wireshark") {
        Ok(libws) => {
            for path in libws.include_paths {
                builder = builder.clang_arg(format!("-I{}", path.to_string_lossy()));
            }
        }
        Err(_) => {
            let glib = pkg_config::Config::new()
                .probe("glib-2.0")
                .expect("glib-2.0 must be installed");

            for path in glib.include_paths {
                builder = builder.clang_arg(format!("-I{}", path.to_string_lossy()));
            }

            clone_wireshark_or_die();
            let dst = build_wireshark();

            let mut ws_headers_path = dst;
            ws_headers_path.push("include");
            ws_headers_path.push("wireshark");

            builder = builder.clang_arg(format!("-I{}", ws_headers_path.to_string_lossy()));
        }
    }

    let bindings = builder
        .generate()
        .expect("should be able to generate bindings from wrapper.h");

    // Detect the version from the generated bindings to name the output file.
    // Fall back to "44" if the constants aren't findable (safe default).
    let bindings_str = bindings.to_string();
    let minor = bindings_str
        .lines()
        .find(|l| l.contains("WIRESHARK_VERSION_MINOR"))
        .and_then(|l| l.split('=').nth(1))
        .and_then(|s| s.trim().trim_end_matches(';').parse::<u32>().ok())
        .unwrap_or(4);
    let filename = format!("bindings_4{}.rs", minor);

    let out_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    bindings
        .write_to_file(out_path.join(&filename))
        .unwrap_or_else(|e| panic!("failed to write {}: {}", filename, e));
    println!("cargo:warning=Wrote {}", filename);
}

#[cfg(any(feature = "source-build", feature = "bindgen"))]
fn clone_wireshark_or_die() {
    Command::new("git")
        .args(["submodule", "update", "--init", "--recursive", "wireshark"])
        .output()
        .expect("wireshark should be obtained as a git submodule");
}

#[cfg(any(feature = "source-build", feature = "bindgen"))]
fn build_wireshark() -> PathBuf {
    let result = std::panic::catch_unwind(|| {
        let dst = cmake::Config::new("wireshark")
            .define("BUILD_androiddump", "OFF")
            .define("BUILD_capinfos", "OFF")
            .define("BUILD_captype", "OFF")
            .define("BUILD_ciscodump", "OFF")
            .define("BUILD_corbaidl2wrs", "OFF")
            .define("BUILD_dcerpcidl2wrs", "OFF")
            .define("BUILD_dftest", "OFF")
            .define("BUILD_dpauxmon", "OFF")
            .define("BUILD_dumpcap", "OFF")
            .define("BUILD_editcap", "OFF")
            .define("BUILD_etwdump", "OFF")
            .define("BUILD_logray", "OFF")
            .define("BUILD_mergecap", "OFF")
            .define("BUILD_randpkt", "OFF")
            .define("BUILD_randpktdump", "OFF")
            .define("BUILD_rawshark", "OFF")
            .define("BUILD_reordercap", "OFF")
            .define("BUILD_sshdump", "OFF")
            .define("BUILD_text2pcap", "OFF")
            .define("BUILD_tfshark", "OFF")
            .define("BUILD_tshark", "OFF")
            .define("BUILD_wifidump", "OFF")
            .define("BUILD_wireshark", "OFF")
            .define("BUILD_xxx2deb", "OFF")
            .build();
        assert!(
            Command::new("cmake")
                .arg("-DCOMPONENT=Development")
                .arg("-P")
                .arg("cmake_install.cmake")
                .current_dir(dst.join("build"))
                .status()
                .unwrap()
                .success(),
            "should generate header files"
        );

        dst
    });
    match result {
        Ok(path) => path,
        Err(_err) => {
            println!("cargo:warning=Failed to build wireshark from source possibly due to missing dependancies.\nPlease check https://www.wireshark.org/docs/wsdg_html_chunked/ChapterSetup.html for details on how to setup build environmen
t to build Wireshark");
            std::process::exit(1)
        }
    }
}
