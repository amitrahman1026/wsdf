#![feature(prelude_import)]
#![allow(dead_code)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
use wsdf::{version, Protocol};
#[no_mangle]
#[used]
static plugin_version: [std::ffi::c_char; 6usize] = [48i8, 46i8, 48i8, 46i8, 49i8, 0i8];
#[no_mangle]
#[used]
static plugin_want_major: std::ffi::c_int = 4;
#[no_mangle]
#[used]
static plugin_want_minor: std::ffi::c_int = 4;
#[wsdf(
    proto_desc = "Baby UDP by wsdf",
    proto_name = "Baby UDP",
    proto_filter = "baby_udp",
    decode_from = [("ip.proto", 17)],
)]
struct BabyUDP {
    source_port: u16,
    dest_port: u16,
    length: u16,
    checksum: u16,
    #[wsdf(subdissector = ("baby_udp.port", "dest_port", "source_port"))]
    payload: Vec<u8>,
}
#[no_mangle]
extern "C" fn plugin_register() {
    static mut plug: wsdf::epan_sys::proto_plugin = wsdf::epan_sys::proto_plugin {
        register_protoinfo: None,
        register_handoff: None,
    };
    extern "C" fn proto_register_baby_udp() {
        <BabyUDP as wsdf::Protocol>::proto_register()
    }
    extern "C" fn proto_reg_handoff_baby_udp() {
        <BabyUDP as wsdf::Protocol>::proto_reg_handoff()
    }
    unsafe {
        plug.register_protoinfo = std::option::Option::Some(proto_register_baby_udp);
        plug.register_handoff = std::option::Option::Some(proto_reg_handoff_baby_udp);
        wsdf::epan_sys::proto_register_plugin(&plug);
    }
}
#[no_mangle]
pub extern "C" fn plugin_describe() -> u32 {
    wsdf::epan_sys::WS_PLUGIN_DESC_DISSECTOR
}
impl wsdf::Protocol for BabyUDP {
    unsafe extern "C" fn dissect_main(
        __wsdf_tvb: *mut wsdf::epan_sys::tvbuff,
        __wsdf_pinfo: *mut wsdf::epan_sys::_packet_info,
        __wsdf_proto_tree_root: *mut wsdf::epan_sys::_proto_node,
        __wsdf_data: *mut std::ffi::c_void,
    ) -> std::ffi::c_int {
        wsdf::epan_sys::col_set_str(
            (*__wsdf_pinfo).cinfo,
            wsdf::epan_sys::COL_PROTOCOL as std::ffi::c_int,
            "Baby UDP by wsdf\u{0}".as_ptr() as *const std::ffi::c_char,
        );
        wsdf::epan_sys::col_clear(
            (*__wsdf_pinfo).cinfo,
            wsdf::epan_sys::COL_INFO as std::ffi::c_int,
        );
        let __wsdf_tvb_buf_size = unsafe {
            wsdf::epan_sys::tvb_reported_length(__wsdf_tvb) as usize
        };
        let mut __wsdf_tvb_buf = Vec::new();
        __wsdf_tvb_buf.resize(__wsdf_tvb_buf_size, 0);
        unsafe {
            wsdf::epan_sys::tvb_memcpy(
                __wsdf_tvb,
                __wsdf_tvb_buf.as_mut_ptr() as *mut std::ffi::c_void,
                0,
                __wsdf_tvb_buf_size,
            );
        }
        let mut __wsdf_fields_store = wsdf::FieldsStore::default();
        <BabyUDP as wsdf::ProtocolField>::dissect(
            0,
            __wsdf_tvb,
            __wsdf_proto_tree_root,
            "baby_udp",
            wsdf::VariantDispatch::None,
            wsdf::SubtreeLabel::new("Baby UDP\u{0}".as_ptr() as *const std::ffi::c_char),
            &__wsdf_tvb_buf,
            __wsdf_pinfo,
            __wsdf_proto_tree_root,
            &mut __wsdf_fields_store,
        )
    }
    extern "C" fn proto_register() {
        let proto_id = unsafe {
            wsdf::epan_sys::proto_register_protocol(
                "Baby UDP by wsdf\u{0}".as_ptr() as *const std::ffi::c_char,
                "Baby UDP\u{0}".as_ptr() as *const std::ffi::c_char,
                "baby_udp\u{0}".as_ptr() as *const std::ffi::c_char,
            )
        };
        <BabyUDP as wsdf::ProtocolField>::register(
            "baby_udp",
            proto_id,
            wsdf::FieldIdent::null(),
            wsdf::FieldBlurb::null(),
        );
    }
    extern "C" fn proto_reg_handoff() {
        unsafe {
            let handle = wsdf::epan_sys::create_dissector_handle(
                std::option::Option::Some(<BabyUDP as wsdf::Protocol>::dissect_main),
                *<BabyUDP as wsdf::ProtocolField>::proto_id(),
            );
            wsdf::epan_sys::dissector_add_uint(
                "ip.proto\u{0}".as_ptr() as *const std::ffi::c_char,
                17u32 as std::ffi::c_uint,
                handle,
            );
        }
    }
}
impl wsdf::ProtocolField for BabyUDP {
    #[allow(clippy::too_many_arguments, clippy::ptr_arg, clippy::int_plus_one)]
    fn dissect<'a>(
        __wsdf_start: std::ffi::c_int,
        __wsdf_tvb: *mut wsdf::epan_sys::tvbuff,
        __wsdf_parent: *mut wsdf::epan_sys::_proto_node,
        __wsdf_prefix: &str,
        __wsdf_dispatch: wsdf::VariantDispatch,
        __wsdf_subtree_label: wsdf::SubtreeLabel,
        __wsdf_tvb_buf: &'a [u8],
        __wsdf_pinfo: *mut wsdf::epan_sys::_packet_info,
        __wsdf_proto_tree_root: *mut wsdf::epan_sys::_proto_node,
        __wsdf_fields_store: &mut wsdf::FieldsStore<'a>,
    ) -> std::ffi::c_int {
        let __wsdf_parent = unsafe {
            let ti = wsdf::epan_sys::proto_tree_add_item(
                __wsdf_parent,
                *<BabyUDP as wsdf::ProtocolField>::proto_id(),
                __wsdf_tvb,
                __wsdf_start,
                -1,
                wsdf::epan_sys::ENC_NA,
            );
            wsdf::epan_sys::proto_item_set_text(
                ti,
                __wsdf_subtree_label
                    .unwrap_or("Baby Udp\u{0}".as_ptr() as *const std::ffi::c_char),
            );
            wsdf::epan_sys::proto_item_add_subtree(
                ti,
                <BabyUDP as wsdf::ProtocolField>::ett(),
            )
        };
        let mut __wsdf_offset = 0;
        let __wsdf_prefix_next = __wsdf_prefix.to_owned() + "." + "source_port";
        let __wsdf_hf = <BabyUDP as wsdf::ProtocolField>::hf_map(
                wsdf::HfMapOp::Get(__wsdf_prefix_next.as_str()),
            )
            .unwrap_or_else(|| {
                ::core::panicking::panic_fmt(
                    format_args!("expected hf for {0} to exist", __wsdf_prefix_next),
                );
            });
        let source_port = unsafe {
            wsdf::epan_sys::tvb_get_uint16(
                __wsdf_tvb,
                __wsdf_start + __wsdf_offset,
                wsdf::epan_sys::ENC_BIG_ENDIAN,
            )
        };
        unsafe {
            wsdf::epan_sys::proto_tree_add_item(
                __wsdf_parent,
                __wsdf_hf,
                __wsdf_tvb,
                __wsdf_start + __wsdf_offset,
                2 as std::ffi::c_int,
                wsdf::epan_sys::ENC_BIG_ENDIAN,
            );
        }
        __wsdf_offset += 2 as std::ffi::c_int;
        let __wsdf_prefix_next = __wsdf_prefix.to_owned() + "." + "dest_port";
        let __wsdf_hf = <BabyUDP as wsdf::ProtocolField>::hf_map(
                wsdf::HfMapOp::Get(__wsdf_prefix_next.as_str()),
            )
            .unwrap_or_else(|| {
                ::core::panicking::panic_fmt(
                    format_args!("expected hf for {0} to exist", __wsdf_prefix_next),
                );
            });
        let dest_port = unsafe {
            wsdf::epan_sys::tvb_get_uint16(
                __wsdf_tvb,
                __wsdf_start + __wsdf_offset,
                wsdf::epan_sys::ENC_BIG_ENDIAN,
            )
        };
        unsafe {
            wsdf::epan_sys::proto_tree_add_item(
                __wsdf_parent,
                __wsdf_hf,
                __wsdf_tvb,
                __wsdf_start + __wsdf_offset,
                2 as std::ffi::c_int,
                wsdf::epan_sys::ENC_BIG_ENDIAN,
            );
        }
        __wsdf_offset += 2 as std::ffi::c_int;
        let __wsdf_prefix_next = __wsdf_prefix.to_owned() + "." + "length";
        let __wsdf_hf = <BabyUDP as wsdf::ProtocolField>::hf_map(
                wsdf::HfMapOp::Get(__wsdf_prefix_next.as_str()),
            )
            .unwrap_or_else(|| {
                ::core::panicking::panic_fmt(
                    format_args!("expected hf for {0} to exist", __wsdf_prefix_next),
                );
            });
        unsafe {
            wsdf::epan_sys::proto_tree_add_item(
                __wsdf_parent,
                __wsdf_hf,
                __wsdf_tvb,
                __wsdf_start + __wsdf_offset,
                2 as std::ffi::c_int,
                wsdf::epan_sys::ENC_BIG_ENDIAN,
            );
        }
        __wsdf_offset += 2 as std::ffi::c_int;
        let __wsdf_prefix_next = __wsdf_prefix.to_owned() + "." + "checksum";
        let __wsdf_hf = <BabyUDP as wsdf::ProtocolField>::hf_map(
                wsdf::HfMapOp::Get(__wsdf_prefix_next.as_str()),
            )
            .unwrap_or_else(|| {
                ::core::panicking::panic_fmt(
                    format_args!("expected hf for {0} to exist", __wsdf_prefix_next),
                );
            });
        unsafe {
            wsdf::epan_sys::proto_tree_add_item(
                __wsdf_parent,
                __wsdf_hf,
                __wsdf_tvb,
                __wsdf_start + __wsdf_offset,
                2 as std::ffi::c_int,
                wsdf::epan_sys::ENC_BIG_ENDIAN,
            );
        }
        __wsdf_offset += 2 as std::ffi::c_int;
        let __wsdf_prefix_next = __wsdf_prefix.to_owned() + "." + "payload";
        let __wsdf_next_tvb = unsafe {
            wsdf::epan_sys::tvb_new_subset_length(
                __wsdf_tvb,
                __wsdf_start + __wsdf_offset,
                (unsafe {
                    wsdf::epan_sys::tvb_reported_length(__wsdf_tvb) as std::ffi::c_int
                } - __wsdf_start - __wsdf_offset) as std::ffi::c_int,
            )
        };
        let mut __wsdf_nr_bytes_dissected = 0;
        let __wsdf_dissector_table = <BabyUDP as wsdf::ProtocolField>::subdissector_map(
                wsdf::SubdissectorMapOp::Get("baby_udp.port"),
            )
            .unwrap_or_else(|| {
                ::core::panicking::panic_fmt(
                    format_args!(
                        "subdissector table for {0} should have been registered",
                        "baby_udp.port",
                    ),
                );
            });
        if __wsdf_nr_bytes_dissected == 0 {
            __wsdf_nr_bytes_dissected = unsafe {
                wsdf::epan_sys::dissector_try_uint(
                    __wsdf_dissector_table,
                    dest_port as std::ffi::c_uint,
                    __wsdf_next_tvb,
                    __wsdf_pinfo,
                    __wsdf_proto_tree_root,
                )
            };
        }
        if __wsdf_nr_bytes_dissected == 0 {
            __wsdf_nr_bytes_dissected = unsafe {
                wsdf::epan_sys::dissector_try_uint(
                    __wsdf_dissector_table,
                    source_port as std::ffi::c_uint,
                    __wsdf_next_tvb,
                    __wsdf_pinfo,
                    __wsdf_proto_tree_root,
                )
            };
        }
        if __wsdf_nr_bytes_dissected == 0 {
            __wsdf_nr_bytes_dissected = unsafe {
                wsdf::epan_sys::call_data_dissector(
                    __wsdf_next_tvb,
                    __wsdf_pinfo,
                    __wsdf_proto_tree_root,
                )
            };
        }
        __wsdf_offset += __wsdf_nr_bytes_dissected;
        unsafe {
            wsdf::epan_sys::proto_item_set_len(__wsdf_parent, __wsdf_offset);
        }
        __wsdf_offset
    }
    fn register(
        __wsdf_prefix: &str,
        __wsdf_proto_id: std::ffi::c_int,
        __wsdf_field_ident: wsdf::FieldIdent,
        __wsdf_field_blurb: wsdf::FieldBlurb,
    ) {
        let mut __wsdf_hfs: Vec<wsdf::epan_sys::hf_register_info> = Vec::new();
        let __wsdf_prefix_next = __wsdf_prefix.to_owned() + "." + "source_port";
        let __wsdf_hf = std::boxed::Box::leak(std::boxed::Box::new(-1i32))
            as *mut std::ffi::c_int;
        unsafe {
            let _p = <BabyUDP as wsdf::ProtocolField>::hf_map(
                wsdf::HfMapOp::Set(&__wsdf_prefix_next, __wsdf_hf),
            );
            if true {
                if !_p.is_none() {
                    ::core::panicking::panic("assertion failed: _p.is_none()")
                }
            }
        }
        __wsdf_hfs
            .push(wsdf::epan_sys::hf_register_info {
                p_id: __wsdf_hf,
                hfinfo: wsdf::epan_sys::header_field_info {
                    name: "Source Port\u{0}".as_ptr() as *const std::ffi::c_char,
                    abbrev: std::boxed::Box::leak(
                            std::ffi::CString::new(__wsdf_prefix_next)
                                .unwrap()
                                .into_boxed_c_str(),
                        )
                        .as_ptr() as *const std::ffi::c_char,
                    type_: wsdf::epan_sys::ftenum_FT_UINT16,
                    display: wsdf::epan_sys::field_display_e_BASE_DEC as std::ffi::c_int
                        | 0 as std::ffi::c_int,
                    strings: std::ptr::null(),
                    bitmask: 0,
                    blurb: std::ptr::null(),
                    id: -1,
                    parent: 0,
                    ref_type: wsdf::epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                    same_name_prev_id: -1,
                    same_name_next: std::ptr::null_mut(),
                },
            });
        let __wsdf_prefix_next = __wsdf_prefix.to_owned() + "." + "dest_port";
        let __wsdf_hf = std::boxed::Box::leak(std::boxed::Box::new(-1i32))
            as *mut std::ffi::c_int;
        unsafe {
            let _p = <BabyUDP as wsdf::ProtocolField>::hf_map(
                wsdf::HfMapOp::Set(&__wsdf_prefix_next, __wsdf_hf),
            );
            if true {
                if !_p.is_none() {
                    ::core::panicking::panic("assertion failed: _p.is_none()")
                }
            }
        }
        __wsdf_hfs
            .push(wsdf::epan_sys::hf_register_info {
                p_id: __wsdf_hf,
                hfinfo: wsdf::epan_sys::header_field_info {
                    name: "Dest Port\u{0}".as_ptr() as *const std::ffi::c_char,
                    abbrev: std::boxed::Box::leak(
                            std::ffi::CString::new(__wsdf_prefix_next)
                                .unwrap()
                                .into_boxed_c_str(),
                        )
                        .as_ptr() as *const std::ffi::c_char,
                    type_: wsdf::epan_sys::ftenum_FT_UINT16,
                    display: wsdf::epan_sys::field_display_e_BASE_DEC as std::ffi::c_int
                        | 0 as std::ffi::c_int,
                    strings: std::ptr::null(),
                    bitmask: 0,
                    blurb: std::ptr::null(),
                    id: -1,
                    parent: 0,
                    ref_type: wsdf::epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                    same_name_prev_id: -1,
                    same_name_next: std::ptr::null_mut(),
                },
            });
        let __wsdf_prefix_next = __wsdf_prefix.to_owned() + "." + "length";
        let __wsdf_hf = std::boxed::Box::leak(std::boxed::Box::new(-1i32))
            as *mut std::ffi::c_int;
        unsafe {
            let _p = <BabyUDP as wsdf::ProtocolField>::hf_map(
                wsdf::HfMapOp::Set(&__wsdf_prefix_next, __wsdf_hf),
            );
            if true {
                if !_p.is_none() {
                    ::core::panicking::panic("assertion failed: _p.is_none()")
                }
            }
        }
        __wsdf_hfs
            .push(wsdf::epan_sys::hf_register_info {
                p_id: __wsdf_hf,
                hfinfo: wsdf::epan_sys::header_field_info {
                    name: "Length\u{0}".as_ptr() as *const std::ffi::c_char,
                    abbrev: std::boxed::Box::leak(
                            std::ffi::CString::new(__wsdf_prefix_next)
                                .unwrap()
                                .into_boxed_c_str(),
                        )
                        .as_ptr() as *const std::ffi::c_char,
                    type_: wsdf::epan_sys::ftenum_FT_UINT16,
                    display: wsdf::epan_sys::field_display_e_BASE_DEC as std::ffi::c_int
                        | 0 as std::ffi::c_int,
                    strings: std::ptr::null(),
                    bitmask: 0,
                    blurb: std::ptr::null(),
                    id: -1,
                    parent: 0,
                    ref_type: wsdf::epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                    same_name_prev_id: -1,
                    same_name_next: std::ptr::null_mut(),
                },
            });
        let __wsdf_prefix_next = __wsdf_prefix.to_owned() + "." + "checksum";
        let __wsdf_hf = std::boxed::Box::leak(std::boxed::Box::new(-1i32))
            as *mut std::ffi::c_int;
        unsafe {
            let _p = <BabyUDP as wsdf::ProtocolField>::hf_map(
                wsdf::HfMapOp::Set(&__wsdf_prefix_next, __wsdf_hf),
            );
            if true {
                if !_p.is_none() {
                    ::core::panicking::panic("assertion failed: _p.is_none()")
                }
            }
        }
        __wsdf_hfs
            .push(wsdf::epan_sys::hf_register_info {
                p_id: __wsdf_hf,
                hfinfo: wsdf::epan_sys::header_field_info {
                    name: "Checksum\u{0}".as_ptr() as *const std::ffi::c_char,
                    abbrev: std::boxed::Box::leak(
                            std::ffi::CString::new(__wsdf_prefix_next)
                                .unwrap()
                                .into_boxed_c_str(),
                        )
                        .as_ptr() as *const std::ffi::c_char,
                    type_: wsdf::epan_sys::ftenum_FT_UINT16,
                    display: wsdf::epan_sys::field_display_e_BASE_DEC as std::ffi::c_int
                        | 0 as std::ffi::c_int,
                    strings: std::ptr::null(),
                    bitmask: 0,
                    blurb: std::ptr::null(),
                    id: -1,
                    parent: 0,
                    ref_type: wsdf::epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                    same_name_prev_id: -1,
                    same_name_next: std::ptr::null_mut(),
                },
            });
        let __wsdf_prefix_next = __wsdf_prefix.to_owned() + "." + "payload";
        if <BabyUDP as wsdf::ProtocolField>::subdissector_map(
                wsdf::SubdissectorMapOp::Get("baby_udp.port"),
            )
            .is_none()
        {
            let __wsdf_dissector_table = unsafe {
                wsdf::epan_sys::register_dissector_table(
                    "baby_udp.port\u{0}".as_ptr() as *const std::ffi::c_char,
                    "baby_udp.port\u{0}".as_ptr() as *const std::ffi::c_char,
                    __wsdf_proto_id,
                    wsdf::epan_sys::ftenum_FT_UINT16,
                    wsdf::epan_sys::field_display_e_BASE_DEC as std::ffi::c_int
                        | 0 as std::ffi::c_int,
                )
            };
            <BabyUDP as wsdf::ProtocolField>::subdissector_map(
                wsdf::SubdissectorMapOp::Set("baby_udp.port", __wsdf_dissector_table),
            );
        }
        let __wsdf_hfs = std::boxed::Box::leak(__wsdf_hfs.into_boxed_slice());
        unsafe {
            wsdf::epan_sys::proto_register_field_array(
                __wsdf_proto_id,
                __wsdf_hfs.as_mut_ptr() as *mut wsdf::epan_sys::hf_register_info,
                __wsdf_hfs.len() as std::ffi::c_int,
            );
        }
        *<BabyUDP as wsdf::ProtocolField>::proto_id() = __wsdf_proto_id;
    }
    fn ett() -> std::ffi::c_int {
        static mut ETT: std::ffi::c_int = -1;
        static INIT_ETT: std::sync::Once = std::sync::Once::new();
        INIT_ETT
            .call_once(|| unsafe {
                if true {
                    match (&ETT, &-1) {
                        (left_val, right_val) => {
                            if !(*left_val == *right_val) {
                                let kind = ::core::panicking::AssertKind::Eq;
                                ::core::panicking::assert_failed(
                                    kind,
                                    &*left_val,
                                    &*right_val,
                                    ::core::option::Option::None,
                                );
                            }
                        }
                    };
                }
                wsdf::epan_sys::proto_register_subtree_array(
                    [unsafe { &mut ETT as *mut _ }].as_mut_ptr(),
                    1,
                );
            });
        unsafe { ETT }
    }
    fn proto_id() -> &'static mut std::ffi::c_int {
        static mut PROTO_ID: std::ffi::c_int = -1;
        unsafe { &mut PROTO_ID }
    }
    fn subdissector_map(
        op: wsdf::SubdissectorMapOp,
    ) -> std::option::Option<wsdf::epan_sys::dissector_table_t> {
        const SUBDISSECTORS: ::std::thread::LocalKey<wsdf::SubdissectorMap> = {
            #[inline]
            fn __init() -> wsdf::SubdissectorMap {
                wsdf::SubdissectorMap::default()
            }
            unsafe {
                ::std::thread::LocalKey::new(const {
                    if ::std::mem::needs_drop::<wsdf::SubdissectorMap>() {
                        |init| {
                            #[thread_local]
                            static VAL: ::std::thread::local_impl::LazyStorage<
                                wsdf::SubdissectorMap,
                                (),
                            > = ::std::thread::local_impl::LazyStorage::new();
                            VAL.get_or_init(init, __init)
                        }
                    } else {
                        |init| {
                            #[thread_local]
                            static VAL: ::std::thread::local_impl::LazyStorage<
                                wsdf::SubdissectorMap,
                                !,
                            > = ::std::thread::local_impl::LazyStorage::new();
                            VAL.get_or_init(init, __init)
                        }
                    }
                })
            }
        };
        SUBDISSECTORS.with(|subdissectors| subdissectors.accept(op))
    }
    fn hf_map(op: wsdf::HfMapOp) -> std::option::Option<std::ffi::c_int> {
        const HFS: ::std::thread::LocalKey<wsdf::HfMap> = {
            #[inline]
            fn __init() -> wsdf::HfMap {
                wsdf::HfMap::default()
            }
            unsafe {
                ::std::thread::LocalKey::new(const {
                    if ::std::mem::needs_drop::<wsdf::HfMap>() {
                        |init| {
                            #[thread_local]
                            static VAL: ::std::thread::local_impl::LazyStorage<
                                wsdf::HfMap,
                                (),
                            > = ::std::thread::local_impl::LazyStorage::new();
                            VAL.get_or_init(init, __init)
                        }
                    } else {
                        |init| {
                            #[thread_local]
                            static VAL: ::std::thread::local_impl::LazyStorage<
                                wsdf::HfMap,
                                !,
                            > = ::std::thread::local_impl::LazyStorage::new();
                            VAL.get_or_init(init, __init)
                        }
                    }
                })
            }
        };
        HFS.with(|hfs| hfs.accept(op))
    }
}
