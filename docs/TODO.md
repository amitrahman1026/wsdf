# wsdf TODO


API Improvements - Lua API Parity Focus

    The overarching goal is to provide a Lua-like API with Rust ergonomics and
    native C performance. After benchmarking it may turn out that the performance
    gain is minimal, however, it might be more important for usability of this
    crate to at least reach parity with the Lua API.

    Generating Wireshark's Lua API documentation by running make-wsluarm.py, we
    are currently missing the following for decent-ish parity:

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
    with add(), remove(), try(), get_dissector() equivalent to Lua's
    DissectorTable class methods.

    -- 2. Advanced Protocol Features --

    Heuristic Dissector Support: Implement proto:register_heuristic() equivalent
    and DissectorTable.try_heuristics() for protocol auto-detection.

    Field Access System: Add Field and FieldInfo classes for accessing fields
    from other dissectors, enabling cross-protocol field references.

    Address Manipulation: Implement Address class with ip(), ipv6(), ether()
    constructors and comparison operations for network address handling.

    -- 3. Extended Functionality --

    Int64/UInt64 Classes: Large integer manipulation with arithmetic, bitwise
    operations, and conversions for protocols requiring 64-bit precision.

    Listener/Tap System: Packet statistics and analysis framework with
    Listener.new() equivalent and tap registration.

    Tree API: Implement RAII-style tree management to eliminate end_subtree
    calls, probably via a SubtreeGuard<'parent> pattern.

    Error type: Unify error handling before implementing the above — currently
    inconsistent across the codebase.


Be aware of possible incoming changes to the plugin API

    There is discussion on the wireshark-dev mailing list about changes to the
    plugin API (https://lists.wireshark.org/archives/wireshark-dev/202312/msg00000.html).
    This has been in the works for a while, and got reverted once. MR !13747
    (https://gitlab.com/wireshark/wireshark/-/merge_requests/13747) is still open
    as of 2026-04-26 and represents a revert of a prior redesign. No action
    needed until it merges, but check before any 5.0 branch cut.

    Wireshark 5.0 milestone expired 2026-04-01 at ~45% complete and is currently
    undated. Both 4.4 and 4.6 are still actively supported.


Multi-version Wireshark support

    Homebrew ships 4.6.4 while the submodule tracks 4.4.14. macOS users on the
    Homebrew install get a plugin_want_minor mismatch at load time today. The
    fix follows the openssl-sys pattern: commit bindings_44.rs and bindings_46.rs
    side by side, emit cargo:rustc-cfg=wireshark44 / wireshark46 flags from
    build.rs, and cfg-gate any ABI differences in lib.rs.

    Next concrete step is to bump the submodule to 4.6.4, regenerate
    bindings_46.rs, and verify that the 4.6.1 ABI break (Issue 20881) does not
    touch proto_plugin, proto_tree_add_item, or field_info in a way that breaks
    wsdf source. Windows hardcodes C:\Program Files\Wireshark which covers ~90%
    of installs; registry detection is deferred.


Integration testing for wsdf generated plugins

    Basic integration testing is in place in tests/integration_test.rs. The
    dissect_bytes() helper wraps raw bytes in an Ethernet+IP frame using
    text2pcap, loads the built plugin via the personal Wireshark plugin directory,
    runs tshark -T json, and asserts on the parsed serde_json::Value. The
    test_dissection_uncompressed_packet test covers the builder example end to end.

    What is still missing is Lua API parity diffing: running the same pcap through
    an equivalent Lua dissector and an equivalent wsdf dissector and asserting the
    JSON output is identical. A good approach would be to run two tshark
    invocations (one with WIRESHARK_EXTRA_PLUGIN_DIRS pointing at the built .so,
    one with -X lua_script:equivalent.lua) and diff the wsdf_example layer. This
    is the most direct way to catch parity regressions as the API grows.


Code Generation Research and Future Automation

    Wireshark's Lua API is largely auto-generated from C code using macro-based
    annotation and Python scripts. Understanding this system could enable similar
    automation for the Rust port.

    Wireshark's C sources use WSLUA_CLASS_DEFINE, WSLUA_FUNCTION, WSLUA_METHOD,
    WSLUA_CONSTRUCTOR macros to mark exportable functions. make-reg.py scans
    those annotations and generates register_wslua.c and declare_wslua.h
    automatically; make-wsluarm.py extracts the adjacent Doxygen comments to
    produce AsciiDoc API docs. CMake hooks both scripts so bindings regenerate
    when C sources change.

    The interesting question for wsdf is whether a proc macro system could do
    something analogous: generate Protocol builders, field definitions, and
    registration code from a high-level declarative syntax, the way
    WSLUA_CLASS_DEFINE does for Lua. This is speculative and should be researched
    before committing to an approach, given that proc macros already do a lot of
    the heavy lifting in wsdf today.


Add logs to generated code

    Currently the generated code does not log anything, which makes it hard to
    file bug reports and reproduce issues. We could use the log crate, but then
    we would need to re-export both log and something like env_logger from wsdf,
    so that the generated code can call wsdf::log::info! etc.


Improve CI

    Docker multi-distro environments (ubuntu/fedora/alpine) are in docker/ and
    docker-compose.yml. The integration test job still needs wiring up in CI now
    that dissect_bytes() is implemented.

    On the Debian/Ubuntu runner we still call Wireshark's debian-setup.sh each
    time to install system deps. That script pulls in a lot of Qt dependencies
    that are not needed for headless tshark testing. Pruning the dep list would
    speed up CI noticeably even if it is not critical right now.
