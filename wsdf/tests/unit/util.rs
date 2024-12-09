use std::fs;

pub fn get_expanded_code_string(file: &str) -> String {
    fs::read_to_string(file).unwrap_or_else(|_| panic!("Failed to read expanded file: {}", file))
}

#[macro_export]
macro_rules! assert_wireshark_api {
    ($expanded:expr, $symbol:expr) => {
        assert!(
            $expanded.contains($symbol),
            "Missing required Wireshark cAPI: {}()\n",
            $symbol
        );
    };
}
