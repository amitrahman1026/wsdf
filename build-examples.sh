#!/usr/bin/env bash

#
# Helper script to build all our example plugins, and copies them to where Wireshark will search
#

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cargo build --examples

case "$OSTYPE" in
  darwin*)
    epan_dir="$HOME/.local/lib/wireshark/plugins/4-4/epan"
    lib_ext="dylib"
    
    # Check if post-processing script exists
    if [ ! -f "$SCRIPT_DIR/macos-plugin-postprocess.sh" ]; then
        echo "Error: macos-plugin-postprocess.sh not found in $SCRIPT_DIR"
        echo "Please ensure macos-plugin-postprocess.sh is in the same directory as this script"
        exit 1
    fi
    
    # Source the macos post-processing script
    source "$SCRIPT_DIR/macos-plugin-postprocess.sh"
    ;;
  linux*)
    epan_dir="$HOME/.local/lib/wireshark/plugins/4.4/epan"
    lib_ext="so"
    ;;
  *)
    echo "Unsupported OS: $OSTYPE for this script."
    exit 1
    ;;
esac

mkdir -p "$epan_dir"

for file in wsdf/examples/*; do
    filename=$(basename -- "$file")
    example="${filename%.*}"
    shared_obj="target/debug/examples/lib${example}.${lib_ext}"

    if [ -f "$shared_obj" ]; then
        if [[ "$OSTYPE" == darwin* ]]; then
            echo "Processing plugin: $shared_obj"

            process_plugin "$shared_obj"

            shared_obj="${shared_obj%.dylib}.so"
            
            if [ ! -f "$shared_obj" ]; then
                echo "Warning: Processing failed for $shared_obj"
                continue
            fi
        fi

        cp "$shared_obj" "${epan_dir}/lib${example}.so"
        echo "Copied ${shared_obj} to ${epan_dir}/lib${example}.so"
    else
        echo "Warning: ${shared_obj} not found, skipping."
    fi
done
