Rust FFI bindings to the epan module of libwireshark.

This module is used to write Wireshark dissectors plugins. To the best of this
crate's ability, it will attempt to look for a system-installed `libwireshark.so`
via pkg-config and link against it at compile time. If the library is not found,
it will attempt to build a dynamic library from source.

In case pkg-config cannot tell us where to find `libwireshark.so`, a path to the
directory containing the dynamic library can be set via the `WIRESHARK_LIB_DIR`
environment variable.

The caveat of building from source is that the user must have the necessary build
dependencies installed on their system. The source of this crate uses Wireshark source
code in a git submodule. To provide relvant devel files headers and libraries. In
the event that there are missing dependancies, the user is would have to obtain
the necessary dependencies with help from the official [Wireshark documentation.](https://www.wireshark.org/docs/wsdg_html_chunked/ChapterSetup.html)

By default, pre-generated bindings are used, which was generated on a Linux machine.

To produce fresh bindings at build time via bindgen, build this crate with the
`bindgen` feature. You may run the following command to generate a new
`bindings.rs` file:

```bash
cargo build --features "bindgen"
```
