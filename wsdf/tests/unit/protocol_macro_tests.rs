// Test for essential protocol registration api. In wsdf, we export the dylib meaning to be used
// as a plugin in wireshark

#[cfg(test)]
mod test_protocol_plugin_registration_capi {
    use crate::assert_wireshark_api;
    use crate::util::get_expanded_code_string;

    const FILE_PATH: &str = "tests/expand/simple_plugin.rs";
    const EXPANDED_FILE_PATH: &str = "tests/expand/simple_plugin.expanded.rs";

    #[test]
    fn test_simple_protocol_expansion() {
        // This test will fail on panic on any breaking changes to
        // expanded code generated, as well as acts as a convenient
        // inspection point for sanity checking.
        macrotest::expand(FILE_PATH);
    }

    #[test]
    fn test_plugin_registration_capi() {
        let expanded = get_expanded_code_string(EXPANDED_FILE_PATH);

        // Minimally required plugin registratino symbols such that a dylib
        // can be recognised as a plugin
        assert_wireshark_api!(expanded, "plugin_register");
        assert_wireshark_api!(expanded, "plugin_want_major");
        assert_wireshark_api!(expanded, "plugin_want_minor");
        assert_wireshark_api!(expanded, "plugin_register");
        assert_wireshark_api!(expanded, "plugin_describe");
        assert_wireshark_api!(expanded, "proto_register_plugin");
    }

    // Currently, the basic protocol registration is coupled tightly with creating a plugin
    #[test]
    fn test_protocol_registration_capi() {
        let expanded = get_expanded_code_string(EXPANDED_FILE_PATH);

        // Minimally required protocol registration symbols

        // This is the field where proto_register_XXXX is set, when called, creates a
        // unique protocol number for dissector
        assert_wireshark_api!(expanded, "register_protoinfo");
        // This sets the proto_reg_handoff function which gives a handle to your protocol dissector,
        // allowing it to be called by wireshark
        assert_wireshark_api!(expanded, "register_handoff");
    }
}
