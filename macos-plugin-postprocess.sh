#!/usr/bin/env bash
# macos-plugin-postprocess.sh

print_usage() {
    cat << EOF

wsdf plugin post-processor for macOS
----------------------------------------

PURPOSE:
    This script fixes library path issues in Wireshark plugins on macOS. When plugins
    are built, they often contain absolute paths to Wireshark libraries. However,
    Wireshark on macOS expects relative paths using @rpath. This script converts the
    paths and ensures the plugin will load correctly.

PROBLEM:
    - Wireshark does not recognise macOS dynamic libraries as of now and only expects .so or
      .dll shared objects
    - Built plugins reference absolute paths (e.g., /opt/homebrew/opt/wireshark/lib/libwireshark.18.dylib)
    - macOS Wireshark expects @rpath references (e.g., @rpath/libwireshark.18.dylib)
    - Without conversion, plugins may fail to load or find required libraries. You will be 
      able to find your plug in under About Wireshark > Plugsins, but be unable to find them in
      you search filter, not use it in any meaningful way.

PREREQUISITES:
    - This post processor is meant for plugins to be compatible to compatible with the 
      version of libwireshark and other supporting libraries that the plugin was compiled for.
      Wireshark does not guarantee binary compatibility between versions and neither do we.
    - Tshark of said wireshark install.
    
USAGE:
    $0 <path_to_plugin>

EXAMPLES:
    $0 ./libudp.dylib     # Process a .dylib file
    $0 ./libudp.so        # Process an already renamed .so file for whatever reason

The script will:
1. Rename .dylib to .so (Wireshark expects .so extension)
2. Convert absolute library paths to @rpath
3. Verify the changes were applied correctly

You can verify the changes yourself using:
    otool -L <plugin_path>

EOF
}

process_plugin() {
    local plugin_path="$1"

    echo "Starting plugin post-processing..."
    echo "Input plugin: $plugin_path"
    echo

    if [ ! -f "$plugin_path" ]; then
        echo "Error: Plugin file not found: $plugin_path"
        return 1
    fi  

    local filename=$(basename "$plugin_path")
    local dirname=$(dirname "$plugin_path")

    # Show initial state
    echo "Initial library dependencies:"
    otool -L "$plugin_path" | grep -E "libw[^[:space:]]+\.dylib"
    echo

    # If it's a .dylib, rename it to .so
    if [[ "$filename" == *.dylib ]]; then
        local new_filename="${filename%.dylib}.so"
        mv "$plugin_path" "$dirname/$new_filename"
        plugin_path="$dirname/$new_filename"
        echo "Renamed $filename to $new_filename"
        echo
    fi

    # Wireshark-related library dependencies from the plugin
    local deps=$(otool -L "$plugin_path" | grep -E "libw[^[:space:]]+\.dylib" | awk '{print $1}')

    # System wireshark rpath references
    echo "Getting reference paths from system Wireshark..."
    local wireshark_refs=$(otool -L $(which tshark) | grep -E "@rpath/libw[^[:space:]]+\.dylib" | awk '{print $1}')

    while IFS= read -r dep; do
        if [ -n "$dep" ]; then
            local lib_name=$(basename "$dep")
            local rpath_ref=$(echo "$wireshark_refs" | grep "$lib_name" || true)

            if [ -n "$rpath_ref" ]; then
                echo "Converting $dep"
                echo "      to $rpath_ref"
                install_name_tool -change "$dep" "$rpath_ref" "$plugin_path"
            else
                echo "Warning: No matching rpath reference found for $lib_name"
            fi
        fi
    done <<< "$deps"

    echo
    echo "Final library dependencies:"
    otool -L "$plugin_path" | grep -E "libw[^[:space:]]+\.dylib"

    echo
    echo "Post-processing complete for $plugin_path"
    return 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [ $# -eq 0 ] || [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
        print_usage
        exit 1
    fi

    process_plugin "$1"
fi
