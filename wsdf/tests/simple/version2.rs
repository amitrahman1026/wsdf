use wsdf::version;

version!("5.10.01", 10, 100);

fn main() {
    assert_eq!(
        PLUGIN_VERSION,
        ['5' as i8, '.' as i8, '1' as i8, '0' as i8, '.' as i8, '0' as i8, '1' as i8, 0_i8]
    );
    assert_eq!(PLUGIN_WANT_MAJOR, 10_i32);
    assert_eq!(PLUGIN_WANT_MINOR, 100_i32);
}
