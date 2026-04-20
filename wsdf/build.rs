use std::env;
use std::path::PathBuf;

fn main() {
    // Only propagate rpath for macOS where Wireshark.app bundles need it
    if std::env::consts::OS == "macos" {
        // Try to get the Wireshark library directory from epan-sys metadata
        // or use default locations
        if let Ok(wireshark_lib_dir) = env::var("WIRESHARK_LIB_DIR") {
            add_rpath(&wireshark_lib_dir);
        } else if let Ok(ws_lib_dir) = env::var("WSDF_LIB_DIR") {
            add_rpath(&ws_lib_dir);
        } else {
            // Default locations for Wireshark on macOS
            let default_locations = vec![
                "/Applications/Wireshark.app/Contents/Frameworks",
                "/opt/homebrew/lib",
                "/usr/local/lib",
            ];

            for location in default_locations {
                let path = PathBuf::from(location);
                if path.exists() &&
                   (path.join("libwireshark.dylib").exists() ||
                    path.read_dir().ok().and_then(|entries| {
                        entries.filter_map(Result::ok).find(|e| {
                            e.file_name().to_string_lossy().starts_with("libwireshark.")
                        })
                    }).is_some())
                {
                    add_rpath(location);
                    break;
                }
            }
        }
    }
}

fn add_rpath(path: &str) {
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", path);
    println!("cargo:warning=Added rpath for Wireshark libraries: {}", path);
}
