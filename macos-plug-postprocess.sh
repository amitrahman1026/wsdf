#!/usr/bin/env bash

process_plugin() {
    local plugin_path="$1"
    local filename=$(basename "$plugin_path")
    local dirname=$(dirname "$plugin_path")

    # If it's a .dylib, rename it to .so because wireshark only recognises .so files as plugins
    if [[ "$filename" == *.dylib ]]; then
        local new_filename="${filename%.dylib}.so"
        mv "$plugin_path" "$dirname/$new_filename"
        plugin_path="$dirname/$new_filename"
        echo "Renamed $filename to $new_filename"
    fi

    # Get wireshark-related library dependencies from the plugin
    # Looking specifically for libw{ireshark, sutil, iretap}.dylib
    local deps=$(otool -L "$plugin_path" | grep -E "libw[^[:space:]]+\.dylib" | awk '{print $1}')
    
    # Get the system wireshark rpath references
    local wireshark_refs=$(otool -L $(which tshark) | grep -E "@rpath/libw[^[:space:]]+\.dylib" | awk '{print $1}')
    

    # Process each dependency
    while IFS= read -r dep; do
        if [ -n "$dep" ]; then
            # Extract just the library name (e.g., libwireshark.18.dylib)
            local lib_name=$(basename "$dep")

            # Find matching rpath reference
            local rpath_ref=$(echo "$wireshark_refs" | grep "$lib_name" || true)

            if [ -n "$rpath_ref" ]; then
                echo "Converting $dep to $rpath_ref"
                install_name_tool -change "$dep" "$rpath_ref" "$plugin_path"
            fi
        fi
    done <<< "$deps"

    # Verify the changes
    echo "Final library dependencies:"
    otool -L "$plugin_path" | grep -E "libw[^[:space:]]+\.dylib"
    
    echo "Post-processing complete for $plugin_path"
    return 0
}

# If script is run directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [ $# -eq 0 ]; then
        echo "Usage: $0 <plugin_path>"
        exit 1
    fi

    process_plugin "$1"
fi
