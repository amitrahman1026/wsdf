use wsdf::version;

version!("0.0.1", 4, 4);

fn main() {
    assert_eq!(
        PLUGIN_VERSION,
        ['0' as i8, '.' as i8, '0' as i8, '.' as i8, '1' as i8, 0_i8]
    );
    assert_eq!(PLUGIN_WANT_MAJOR, 4_i32);
    assert_eq!(PLUGIN_WANT_MINOR, 4_i32);
}
