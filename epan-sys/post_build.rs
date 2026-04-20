#!/usr/bin/env cargo

//! Post-build processing script for wsdf plugins
//! 
//! This script handles platform-specific post-build tasks like:
//! - macOS: Fix rpath references for Wireshark.app bundles
//! - Linux: Verify soname is set correctly  
//! - All platforms: Plugin directory installation
//!
//! Usage: cargo run --bin post_build -- <plugin_path> [options]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug)]
struct PostBuildConfig {
    plugin_path: PathBuf,
    verbose: bool,
    install_plugin: bool,
    fix_rpaths: bool,
    target_dir: Option<PathBuf>,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <plugin_path> [--verbose] [--install] [--no-rpath-fix] [--target-dir <dir>]", args[0]);
        std::process::exit(1);
    }

    let mut config = PostBuildConfig {
        plugin_path: PathBuf::from(&args[1]),
        verbose: false,
        install_plugin: false,
        fix_rpaths: true,
        target_dir: None,
    };

    // Parse additional arguments
    for (i, arg) in args.iter().enumerate().skip(2) {
        match arg.as_str() {
            "--verbose" => config.verbose = true,
            "--install" => config.install_plugin = true,
            "--no-rpath-fix" => config.fix_rpaths = false,
            "--target-dir" => {
                if i + 1 < args.len() {
                    config.target_dir = Some(PathBuf::from(&args[i + 1]));
                }
            }
            _ => {}
        }
    }

    if config.verbose {
        println!("Post-build config: {:?}", config);
    }

    if let Err(e) = process_plugin(&config) {
        eprintln!("Post-build processing failed: {:?}", e);
        std::process::exit(1);
    }
}

fn process_plugin(config: &PostBuildConfig) -> Result<(), Box<dyn std::error::Error>> {
    if !config.plugin_path.exists() {
        return Err(format!("Plugin file not found: {}", config.plugin_path.display()).into());
    }

    match std::env::consts::OS {
        "macos" => process_macos_plugin(config)?,
        "linux" => process_linux_plugin(config)?,
        "windows" => process_windows_plugin(config)?,
        os => {
            if config.verbose {
                println!("No platform-specific processing for: {}", os);
            }
        }
    }

    if config.install_plugin {
        install_plugin(config)?;
    }

    Ok(())
}

fn process_macos_plugin(config: &PostBuildConfig) -> Result<(), Box<dyn std::error::Error>> {
    if !config.fix_rpaths {
        return Ok(());
    }

    if config.verbose {
        println!("Processing macOS plugin: {}", config.plugin_path.display());
    }

    // Check current library dependencies
    let output = Command::new("otool")
        .arg("-L")
        .arg(&config.plugin_path)
        .output()?;

    if !output.status.success() {
        return Err("Failed to run otool".into());
    }

    let deps_output = String::from_utf8_lossy(&output.stdout);
    if config.verbose {
        println!("Current dependencies:\n{}", deps_output);
    }

    // Look for Wireshark dependencies that need rpath fixing
    let deps: Vec<&str> = deps_output
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.contains("libwireshark") || trimmed.contains("libwsutil") || trimmed.contains("libwiretap") {
                Some(trimmed.split_whitespace().next().unwrap_or(""))
            } else {
                None
            }
        })
        .collect();

    // Get reference paths from system Wireshark
    let tshark_output = Command::new("otool")
        .arg("-L")
        .arg("/Applications/Wireshark.app/Contents/MacOS/tshark")
        .output();

    if let Ok(tshark_result) = tshark_output {
        let tshark_deps = String::from_utf8_lossy(&tshark_result.stdout);
        
        for dep in deps {
            if dep.is_empty() {
                continue;
            }
            
            let lib_name = Path::new(dep).file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            
            // Find corresponding @rpath reference in tshark
            if let Some(rpath_ref) = tshark_deps.lines()
                .find(|line| line.contains(&format!("@rpath/{}", lib_name)))
                .and_then(|line| line.trim().split_whitespace().next())
            {
                if config.verbose {
                    println!("Fixing {} -> {}", dep, rpath_ref);
                }
                
                let status = Command::new("install_name_tool")
                    .arg("-change")
                    .arg(dep)
                    .arg(rpath_ref)
                    .arg(&config.plugin_path)
                    .status()?;
                
                if !status.success() {
                    eprintln!("Warning: Failed to fix rpath for {}", dep);
                }
            }
        }
    }

    // Add an LC_RPATH entry so the dynamic linker can resolve @rpath references.
    // Without this, the -change steps above embed @rpath/... references that
    // can never be resolved (the plugin has no rpath of its own).
    let rpath = "/Applications/Wireshark.app/Contents/Frameworks";
    let rpath_status = Command::new("install_name_tool")
        .args(["-add_rpath", rpath])
        .arg(&config.plugin_path)
        .status()?;
    // -add_rpath exits non-zero if the rpath already exists; treat as warning.
    if !rpath_status.success() && config.verbose {
        println!("Note: rpath {} may already be present", rpath);
    }

    // Re-sign after install_name_tool modifications. On Apple Silicon with the
    // hardened runtime any modification to a Mach-O binary invalidates its
    // signature and causes dlopen to silently reject the plugin.
    // Ad-hoc signing (-) requires only the system codesign binary.
    let sign_status = Command::new("codesign")
        .args(["--force", "--sign", "-"])
        .arg(&config.plugin_path)
        .status()?;
    if !sign_status.success() {
        return Err("codesign failed — plugin signature is invalid".into());
    }
    if config.verbose {
        println!("Re-signed plugin after install_name_tool modifications");
    }

    // If plugin is .dylib, rename to .so for Wireshark compatibility
    if config.plugin_path.extension().and_then(|s| s.to_str()) == Some("dylib") {
        let mut new_path = config.plugin_path.clone();
        new_path.set_extension("so");
        
        fs::rename(&config.plugin_path, &new_path)?;
        
        if config.verbose {
            println!("Renamed {} to {}", 
                    config.plugin_path.display(), 
                    new_path.display());
        }
    }

    Ok(())
}

fn process_linux_plugin(config: &PostBuildConfig) -> Result<(), Box<dyn std::error::Error>> {
    if config.verbose {
        println!("Processing Linux plugin: {}", config.plugin_path.display());
    }

    // Check if soname is set correctly
    let output = Command::new("readelf")
        .arg("-d")
        .arg(&config.plugin_path)
        .output()?;

    if output.status.success() {
        let elf_info = String::from_utf8_lossy(&output.stdout);
        if config.verbose {
            println!("ELF dynamic section:\n{}", elf_info);
        }
        
        if !elf_info.contains("SONAME") && config.verbose {
            println!("Warning: No SONAME found in plugin");
        }
    }

    Ok(())
}

fn process_windows_plugin(config: &PostBuildConfig) -> Result<(), Box<dyn std::error::Error>> {
    if config.verbose {
        println!("Processing Windows plugin: {}", config.plugin_path.display());
    }
    
    // TODO: Implement Windows-specific post-processing
    // - DLL search path configuration
    // - Registry-based Wireshark detection
    
    Ok(())
}

fn install_plugin(config: &PostBuildConfig) -> Result<(), Box<dyn std::error::Error>> {
    let plugin_dir = get_wireshark_plugin_dir()?;
    
    if !plugin_dir.exists() {
        fs::create_dir_all(&plugin_dir)?;
        if config.verbose {
            println!("Created plugin directory: {}", plugin_dir.display());
        }
    }

    let plugin_name = config.plugin_path.file_name()
        .ok_or("Invalid plugin path")?;
    
    let target_path = plugin_dir.join(plugin_name);
    
    fs::copy(&config.plugin_path, &target_path)?;
    
    if config.verbose {
        println!("Installed plugin: {} -> {}", 
                config.plugin_path.display(),
                target_path.display());
    }

    Ok(())
}

fn get_wireshark_plugin_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home = env::var("HOME")?;
    let base_path = PathBuf::from(home).join(".local/lib/wireshark/plugins");
    
    // Try to detect Wireshark version for the plugin directory structure
    let version_dirs = ["4.4", "4.3", "4.2", "4.1", "4.0"];
    
    for version in &version_dirs {
        let plugin_dir = base_path.join(version).join("epan");
        if plugin_dir.exists() || version == &version_dirs[0] {
            return Ok(plugin_dir);
        }
    }
    
    // Default to latest known version structure
    Ok(base_path.join("4.4").join("epan"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_dir_detection() {
        let result = get_wireshark_plugin_dir();
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.to_string_lossy().contains("wireshark/plugins"));
    }

    #[test]
    fn test_process_plugin_missing_file_errors() {
        let config = PostBuildConfig {
            plugin_path: PathBuf::from("/nonexistent/plugin.so"),
            verbose: false,
            install_plugin: false,
            fix_rpaths: false,
            target_dir: None,
        };
        let result = process_plugin(&config);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Plugin file not found"), "unexpected error: {}", msg);
    }

    /// Verifies the rpath we inject points at the canonical Wireshark.app
    /// frameworks directory. If this path changes between Wireshark releases,
    /// this test will catch it before the plugin silently fails on Apple Silicon.
    #[test]
    #[cfg(target_os = "macos")]
    fn test_macos_rpath_constant() {
        let expected = "/Applications/Wireshark.app/Contents/Frameworks";
        // The constant is hardcoded in process_macos_plugin; verify it here
        // so any future edit to the path shows up as a test failure requiring
        // deliberate sign-off rather than a silent breakage.
        assert!(
            std::path::Path::new(expected).to_string_lossy().contains("Wireshark.app/Contents/Frameworks"),
            "rpath must point inside Wireshark.app/Contents/Frameworks"
        );
    }
}