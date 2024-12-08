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
    fn test_protocol_registration_capi() {
        let expanded = get_expanded_code_string(EXPANDED_FILE_PATH);

        assert_wireshark_api!(expanded, "plugin_register");
    }
}
