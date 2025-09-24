API Improvements - Lua API Parity Focus

    The overarching goal is to provide a Lua-like API with Rust ergonomics and
    native C performance. After benchmarking it may turn out that they
    performance gain is minimal, however, it might be more important for
    usability of this crate to at least reach parity with Lua API.

    Generating Wireshark's Lua API documentation by running make-wsluarm.py, the
    we are currently missing the following for implementation for decent-ish
    parity:

    -- 1. Core Missing Features --

    Packet Info Enhancement: Add getters for packet metadata (timestamp,
    addresses, ports, frame numbers, protocol context). Currently only supports
    column setting and memory allocation.

    Preferences System: Complete Pref class implementation with Pref.bool(),
    Pref.uint(), Pref.enum(), Pref.range(), Pref.string() builders and runtime
    preference access via proto.prefs table equivalent.

    Field Builders Enhancement: Add convenience constructors matching Lua's
    ProtoField class - FieldBuilder::ipv4(), ::timestamp(), ::string(),
    ::guid() etc. for ergonomic field creation.

    DissectorTable Runtime Access: Allow dynamic dissector table manipulation
    with add(), remove(), try(), get_dissector() equivalent to Lua's DissectorTable
    class methods.

    -- 2. Advanced Protocol Features --

    Heuristic Dissector Support: Implement proto:register_heuristic() equivalent
    and DissectorTable.try_heuristics() for protocol auto-detection.

    Field Access System: Add Field and FieldInfo classes for accessing fields
    from other dissectors, enabling cross-protocol field references.

    Enhanced String Encoding: Full charset support beyond current UTF8/ASCII
    basic implementation to match Lua's encoding options.

    Address Manipulation: Implement Address class with ip(), ipv6(), ether()
    constructors and comparison operations for network address handling.

    -- 3. Extended Functionality --

    Int64/UInt64 Classes: Large integer manipulation with arithmetic, bitwise
    operations, and conversions for protocols requiring 64-bit precision.

    Listener/Tap System: Packet statistics and analysis framework with
    Listener.new() equivalent and tap registration.

    ByteArray Utilities: Data manipulation helpers for protocol processing
    beyond current TvbRange byte extraction.

    Tree API: Implement RAII-style tree management to eliminate
    end_subtree calls

Developer Experience
    Build System: Improve platform detection and Wireshark version compatibility

    Installation Tools: Automated plugin installation and management

Be aware of possible incoming changes to the plugin API

    There is [discussion](https://lists.wireshark.org/archives/wireshark-dev/202312/msg00000.html)
    on the wireshark-dev mailing list about changes to the plugin API. This has
    been in the works for a while, and got reverted once. But it is likely to
    happen in the future. Ideally maintainers should keep an eye on this.
    Interesting thread to follow as [well.](https://gitlab.com/wireshark/wireshark/-/merge_requests/13747)

Create integration testing for wsdf generated plugins

    As of now, besides unit tests, theres not an end to end testing framework
    that will give a better outlook on parity of wsdf generated plugins and 
    wireshark native plugin functionality.

    A good approach would be to hook onto the test suite of wireshark which uses
    tshark to run against sample pcap files for integration testing.

    Testing should validate Lua API parity by comparing output from equivalent
    Lua and Rust dissectors against the same packet data. We can possibly do
    this using a tshark based flow.


Build System Enhancements (Probably will priotise this)

    Current Issues Identified:
        - macOS Wireshark.app bundle detection fails (libwireshark.18.dylib not found)
        - No platform-specific library path detection
        - Missing versioned library handling (libwireshark.18 vs libwireshark)
        - No soname generation for cdylibs (required for Linux packaging)
        - Limited cross-compilation support
        - No post-build rpath fixing for macOS app bundles
        - Poor error messages with no actionable guidance
        - No proper shared library link arguments for cross-platform compatibility

    Enhanced Multi-Tier Detection Strategy:
        1. Cargo.toml metadata configuration (target-specific overrides)
        2. Environment variables (WIRESHARK_LIB_DIR, WIRESHARK_VERSION)
        3. Platform-specific auto-detection with multiple search paths
        4. pkg-config fallback
        5. Smoke test compilation (libz-sys approach)
        6. Source build as last resort

    Platform-Specific Detection Paths:
        macOS:
            - /Applications/Wireshark.app/Contents/Frameworks (versioned dylibs)
            - /opt/homebrew/lib (Apple Silicon Homebrew)
            - /usr/local/lib (Intel Homebrew)
            - /opt/local/lib (MacPorts)

        Linux:
            - /usr/lib/x86_64-linux-gnu (Ubuntu/Debian multiarch)
            - /usr/lib64, /usr/lib (standard locations)
            - /usr/local/lib (custom builds)
            - Distribution-specific paths

        Windows:
            - C:\Program Files\Wireshark
            - Registry-based detection
            - DLL search path configuration

    Cargo.toml Metadata Integration:
        [package.metadata.wsdf]
        verbose_build = true
        generate_soname = true
        fix_rpaths = true

        [package.metadata.wsdf.target."aarch64-apple-darwin"]
        wireshark_lib_dir = "/Applications/Wireshark.app/Contents/Frameworks"
        fix_app_bundle_rpaths = true
        preferred_version = "18"

    User Workflow Support:
        Zero Config (90% users):
            cargo build --example builder
            cargo post build --example builder (with post-processing)

        Environment Override (8% users):
            WIRESHARK_LIB_DIR=/path cargo build
            WIRESHARK_VERSION=18 cargo build

        Advanced Configuration (2% users):
            Target-specific Cargo.toml metadata
            Cross-compilation support
            CI/CD integration

    cdylib soname Generation (inspired by cdylib-link-lines crate):
        - Automatic soname for versions >= 1.0.0
        - Format: libname.so.{major_version}
        - Linux: -Wl,-soname,libname.so.1
        - macOS: -Wl,-install_name,@rpath/libname.dylib
        - Reference: https://github.com/lu-zero/cdylib-link-lines

    Post-Build Processing (post_build.rs):
        macOS:
            - Fix rpath for Wireshark.app bundles
            - Set proper install_name with @rpath
            - install_name_tool integration

        Linux:
            - Verify soname is set correctly
            - Optional plugin installation

        All Platforms:
            - Automatic plugin directory installation
            - Build artifact validation

    Professional Error Handling:
        - Clear platform-specific installation instructions
        - Actionable error messages with solutions
        - Library version compatibility checking
        - Development headers validation

    Dependencies to Add:
        build-target = "0.4"     # Target detection
        cargo_metadata = "0.18"  # Metadata reading
        semver = "1.0"          # Version parsing
        cargo-post (user install) # Post-build processing

    Implementation Priority:
        1. Enhanced platform detection in build.rs
        2. Cargo.toml metadata support
        3. Post-build script for rpath/soname
        4. Professional error handling
        5. Cross-compilation testing
        6. Documentation and examples

    Windows Testing:
        Currently untested and needs investigation for:
        - Library detection methods
        - DLL search path configuration
        - Visual Studio vs MinGW compatibility

Code Generation Research and Future Automation

    Wireshark's Lua API is largely auto-generated from C code using macro-based
    annotation and Python scripts. Understanding this system could enable similar
    automation for the Rust port:

    Wireshark's Code Generation System:

    Annotation Macros: C source uses WSLUA_CLASS_DEFINE, WSLUA_FUNCTION,
    WSLUA_METHOD, WSLUA_CONSTRUCTOR macros to mark exportable functions.

    Registration Generation: make-reg.py (epan/wslua/make-reg.py) scans C
    files for these macros and generates register_wslua.c and declare_wslua.h
    automatically.

    Documentation Generation: make-wsluarm.py extracts Doxygen-style comments
    from macro-annotated functions to generate AsciiDoc API documentation.

    Build Integration: CMake integrates these scripts to regenerate binding
    code when C sources change, maintaining API consistency.

    Potential Rust Automation Approaches:

    Macro-based Annotations: Develop Rust macros that annotate functions for
    Lua-style API export, similar to Wireshark's WSLUA_* macros?

    Use proc macros to generate boilerplate registration code, field builders,
    and FFI bindings from high-level declarations.

    Build Script Integration: Enhance build.rs to scan annotated Rust code
    and auto-generate plugin registration, similar to make-reg.py workflow.

    Documentation Extraction: Extract doc comments from annotated functions
    to generate API documentation matching Wireshark's style.

    Research Priority: Analyze feasibility of proc macro system that could
    generate Protocol builders, field definitions, and registration code from
    declarative syntax, reducing boilerplate while maintaining type safety.

Add logs to generated code

    Currently, the generated code does not log anything. This makes it hard to
    file bug reports and try to reproduce stuff.

    We could use the `log` crate, but then we'd have to re-export both `log`
    and something like `env_logger` from `wsdf`, so that the generated code can
    call `wsdf::log::info!` etc.


Use the "smoke-test" thing in build.rs

    See https://github.com/rust-lang/libz-sys/blob/main/src/smoke.c and how
    they use it in their build.rs.

    Basically there may be funky situations where the libwireshark and its
    headers are installed on the system but pkg config cannot find it. In that
    case, we have a smoke.c file pulling in the headers we want. If that
    compiles, that means the headers and dynamic library can be resolved
    somehow. We don't need to clone down the whole wireshark repo in that case.

Improve CI

    Currently, we call Wireshark's debian setup script each time to set up some
    system deps. Obviously in ci we don't need wireshark or tshark. So we
    should prune the useless ones (e.g. alot of QT dependencies!)

    This step is not too slow though, so it is not that important.
