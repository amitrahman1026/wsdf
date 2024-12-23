#[allow(unused)]
pub mod ffi {

    use epan_sys::{self, tvbuff};
    use std::ffi::CString;

    pub struct PacketInfo {
        ptr: *mut epan_sys::_packet_info,
    }

    impl PacketInfo {
        pub fn new(ptr: *mut epan_sys::_packet_info) -> Self {
            Self { ptr }
        }

        pub fn clear_col_info(&self) {
            unsafe {
                epan_sys::col_clear((*self.ptr).cinfo, epan_sys::COL_INFO as _);
            }
        }

        pub fn set_col_protocol(&self, proto_name: &str) {
            let c_str = match CString::new(proto_name) {
                Ok(s) => s,
                Err(_) => CString::new("").unwrap(),
            };

            unsafe {
                epan_sys::col_set_str(
                    (*self.ptr).cinfo,
                    epan_sys::COL_PROTOCOL as _,
                    c_str.as_ptr(),
                );
            }
        }
    }

    pub struct TvBuffer {
        ptr: *mut epan_sys::tvbuff,
    }

    impl TvBuffer {
        pub fn new(ptr: *mut epan_sys::tvbuff) -> Self {
            Self { ptr }
        }
    }

    pub struct ProtoTree {
        ptr: *mut epan_sys::_proto_node,
    }

    impl ProtoTree {
        pub fn new(ptr: *mut epan_sys::_proto_node) -> Self {
            Self { ptr }
        }
        fn add_item(&self /* hfindex : ?, tvb : TvBuffer, start, length, encoding */) {
            unimplemented!()
        }
        fn add_uint_format_value(
            &self, /* hfindex: ?, tvb : TvBuffer, start, length, value, format : &str, ...*/
        ) {
            unimplemented!()
        }
        fn add_int_format_value(
            &self, /* hfindex: ?, tvb : TvBuffer, start, length, value, format : &str, ...*/
        ) {
            unimplemented!()
        }
        fn add_none_format(
            &self, /* hfindex: ?, tvb : TvBuffer, start, length, value, format : &str, ...*/
        ) {
            unimplemented!()
        }
        fn add_bytes_format_value(
            &self, /* hfindex: ?, tvb : TvBuffer, start, length, start_ptr */
        ) {
            unimplemented!()
        }
    }
}
