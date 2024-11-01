#!/usr/bin/env sh

#
# Helper script to build all our example dissectors, and copies them to where Wireshark will search
# Currently this 
#

cargo build --examples

case "$OSTYPE" in
  darwin*) 
    epan_dir="/Applications/Wireshark.app/Contents/PlugIns/wireshark/4-4/epan"
    lib_ext="dylib"
    ;;
  linux*)  
    epan_dir="$HOME/.local/lib/wireshark/plugins/4.4/epan"
    lib_ext="so";;
	*)
    echo "Unsupported OS: $OSTYPE for this script."
    exit 1
    ;;
esac

mkdir -p "$epan_dir"

for file in wsdf/examples/*;
do
    filename=$(basename -- "$file")
    example="${filename%.*}"
    shared_obj="target/debug/examples/lib${example}.${lib_ext}"

    if [ -f "$shared_obj" ]; then
        cp "$shared_obj" "${epan_dir}/lib${example}.so"
        echo "Copied ${shared_obj} to ${epan_dir}/lib${example}.so"
    else
        echo "Warning: ${shared_obj} not found, skipping."
    fi
done
