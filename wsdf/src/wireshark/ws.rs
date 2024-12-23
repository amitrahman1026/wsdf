#[allow(unused)]
mod ws_wrappers {

    use epan_sys;
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
}
