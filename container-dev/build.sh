#!/bin/bash

# Compile the plugin with corrected include paths
clang -shared hello.c -o hello.so \
    $(pkg-config --cflags wireshark)\
    $(pkg-config --libs wireshark)\
    -Wall \
    -fPIC

# Copy to Wireshark plugins directory
cp hello.so /root/.local/lib/wireshark/plugins/4.4/epan/

# Test the plugin
tshark -Y "hello_ws" -V
