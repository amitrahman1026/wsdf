use wsdf::{protocol, version, Dissect, Proto};
#[no_mangle]
#[used]
static plugin_version: [std::ffi::c_char; 6usize] = [48i8, 46i8, 48i8, 46i8, 49i8, 0i8];
#[no_mangle]
#[used]
static plugin_want_major: std::ffi::c_int = 4;
#[no_mangle]
#[used]
static plugin_want_minor: std::ffi::c_int = 4;
#[no_mangle]
pub extern "C" fn plugin_describe() -> u32 {
    wsdf::epan_sys::WS_PLUGIN_DESC_EPAN
}
const __WSDF_HF_INDICES: ::std::thread::LocalKey<std::cell::RefCell<wsdf::HfIndices>> = {
    #[inline]
    fn __init() -> std::cell::RefCell<wsdf::HfIndices> {
        wsdf::HfIndices::default().into()
    }
    unsafe {
        ::std::thread::LocalKey::new(const {
            if ::std::mem::needs_drop::<std::cell::RefCell<wsdf::HfIndices>>() {
                |init| {
                    #[thread_local]
                    static VAL: ::std::thread::local_impl::LazyStorage<
                        std::cell::RefCell<wsdf::HfIndices>,
                        (),
                    > = ::std::thread::local_impl::LazyStorage::new();
                    VAL.get_or_init(init, __init)
                }
            } else {
                |init| {
                    #[thread_local]
                    static VAL: ::std::thread::local_impl::LazyStorage<
                        std::cell::RefCell<wsdf::HfIndices>,
                        !,
                    > = ::std::thread::local_impl::LazyStorage::new();
                    VAL.get_or_init(init, __init)
                }
            }
        })
    }
};
const __WSDF_ETT_INDICES: ::std::thread::LocalKey<
    std::cell::RefCell<wsdf::EttIndices>,
> = {
    #[inline]
    fn __init() -> std::cell::RefCell<wsdf::EttIndices> {
        wsdf::EttIndices::default().into()
    }
    unsafe {
        ::std::thread::LocalKey::new(const {
            if ::std::mem::needs_drop::<std::cell::RefCell<wsdf::EttIndices>>() {
                |init| {
                    #[thread_local]
                    static VAL: ::std::thread::local_impl::LazyStorage<
                        std::cell::RefCell<wsdf::EttIndices>,
                        (),
                    > = ::std::thread::local_impl::LazyStorage::new();
                    VAL.get_or_init(init, __init)
                }
            } else {
                |init| {
                    #[thread_local]
                    static VAL: ::std::thread::local_impl::LazyStorage<
                        std::cell::RefCell<wsdf::EttIndices>,
                        !,
                    > = ::std::thread::local_impl::LazyStorage::new();
                    VAL.get_or_init(init, __init)
                }
            }
        })
    }
};
const __WSDF_DTABLES: ::std::thread::LocalKey<
    std::cell::RefCell<wsdf::DissectorTables>,
> = {
    #[inline]
    fn __init() -> std::cell::RefCell<wsdf::DissectorTables> {
        wsdf::DissectorTables::default().into()
    }
    unsafe {
        ::std::thread::LocalKey::new(const {
            if ::std::mem::needs_drop::<std::cell::RefCell<wsdf::DissectorTables>>() {
                |init| {
                    #[thread_local]
                    static VAL: ::std::thread::local_impl::LazyStorage<
                        std::cell::RefCell<wsdf::DissectorTables>,
                        (),
                    > = ::std::thread::local_impl::LazyStorage::new();
                    VAL.get_or_init(init, __init)
                }
            } else {
                |init| {
                    #[thread_local]
                    static VAL: ::std::thread::local_impl::LazyStorage<
                        std::cell::RefCell<wsdf::DissectorTables>,
                        !,
                    > = ::std::thread::local_impl::LazyStorage::new();
                    VAL.get_or_init(init, __init)
                }
            }
        })
    }
};
#[no_mangle]
extern "C" fn plugin_register() {
    static mut PLUG_0: wsdf::epan_sys::proto_plugin = wsdf::epan_sys::proto_plugin {
        register_protoinfo: None,
        register_handoff: None,
    };
    unsafe {
        PLUG_0.register_protoinfo = std::option::Option::Some(
            <UdpProto as wsdf::Proto>::register_protoinfo,
        );
        PLUG_0.register_handoff = std::option::Option::Some(
            <UdpProto as wsdf::Proto>::register_handoff,
        );
        wsdf::epan_sys::proto_register_plugin(&PLUG_0);
    }
}
#[wsdf(
    decode_from = [("udp.port", 1234)],
    proto_desc = "Test UDP Protocol",
    proto_name = "TestUDP",
    proto_filter = "test_udp"
)]
struct UdpProto {
    field: u32,
}
impl wsdf::Proto for UdpProto {
    #[allow(clippy::missing_safety_doc)]
    unsafe extern "C" fn dissect_main(
        tvb: *mut wsdf::epan_sys::tvbuff,
        pinfo: *mut wsdf::epan_sys::_packet_info,
        tree: *mut wsdf::epan_sys::_proto_node,
        data: *mut std::ffi::c_void,
    ) -> std::ffi::c_int {
        wsdf::epan_sys::col_set_str(
            (*pinfo).cinfo,
            wsdf::epan_sys::COL_PROTOCOL as std::ffi::c_int,
            "Test UDP Protocol\u{0}".as_ptr() as *const std::ffi::c_char,
        );
        wsdf::epan_sys::col_clear(
            (*pinfo).cinfo,
            wsdf::epan_sys::COL_INFO as std::ffi::c_int,
        );
        let tvb_len = unsafe { wsdf::epan_sys::tvb_reported_length(tvb) as usize };
        let mut tvb_buf = Vec::new();
        tvb_buf.resize(tvb_len, 0);
        unsafe {
            wsdf::epan_sys::tvb_memcpy(
                tvb,
                tvb_buf.as_mut_ptr() as *mut std::ffi::c_void,
                0,
                tvb_len,
            );
        }
        __WSDF_HF_INDICES
            .with(|hf_indices| {
                __WSDF_ETT_INDICES
                    .with(|etts| {
                        __WSDF_DTABLES
                            .with(|dtables| {
                                let mut fields = wsdf::FieldsStore::default();
                                let hf_indices = hf_indices.borrow();
                                let etts = etts.borrow();
                                let dtables = dtables.borrow();
                                let args = wsdf::DissectorArgs {
                                    hf_indices: &hf_indices,
                                    etts: &etts,
                                    dtables: &dtables,
                                    tvb,
                                    pinfo,
                                    proto_root: tree,
                                    data: &tvb_buf,
                                    prefix: "test_udp",
                                    prefix_local: "test_udp",
                                    offset: 0,
                                    parent: tree,
                                    variant: std::option::Option::None,
                                    list_len: std::option::Option::None,
                                    ws_enc: std::option::Option::None,
                                };
                                <UdpProto as Dissect<
                                    '_,
                                    (),
                                >>::add_to_tree(&args, &mut fields) as _
                            })
                    })
            })
    }
    unsafe extern "C" fn register_protoinfo() {
        let proto_id = unsafe {
            wsdf::epan_sys::proto_register_protocol(
                "Test UDP Protocol\u{0}".as_ptr() as *const std::ffi::c_char,
                "TestUDP\u{0}".as_ptr() as *const std::ffi::c_char,
                "test_udp\u{0}".as_ptr() as *const std::ffi::c_char,
            )
        };
        __WSDF_HF_INDICES
            .with(|hf_indices| {
                __WSDF_ETT_INDICES
                    .with(|etts| {
                        __WSDF_DTABLES
                            .with(|dtables| {
                                let mut hf = hf_indices.borrow_mut();
                                let mut ett = etts.borrow_mut();
                                let mut dtable = dtables.borrow_mut();
                                let mut ws_indices = wsdf::WsIndices {
                                    hf: &mut hf,
                                    ett: &mut ett,
                                    dtable: &mut dtable,
                                };
                                ws_indices.hf.insert("test_udp", proto_id);
                                let args = wsdf::RegisterArgs {
                                    proto_id,
                                    name: "TestUDP\u{0}".as_ptr() as *const std::ffi::c_char,
                                    prefix: "test_udp",
                                    blurb: std::ptr::null(),
                                    ws_type: std::option::Option::None,
                                    ws_display: std::option::Option::None,
                                };
                                <UdpProto as Dissect<
                                    '_,
                                    (),
                                >>::register(&args, &mut ws_indices);
                            })
                    })
            });
    }
    unsafe extern "C" fn register_handoff() {
        __WSDF_HF_INDICES
            .with(|hf_indices| {
                let hf_indices = hf_indices.borrow();
                let proto_id = hf_indices.get("test_udp").unwrap();
                unsafe {
                    let handle = wsdf::epan_sys::create_dissector_handle(
                        std::option::Option::Some(
                            <UdpProto as wsdf::Proto>::dissect_main,
                        ),
                        proto_id,
                    );
                    wsdf::epan_sys::dissector_add_uint(
                        "udp.port\u{0}".as_ptr() as *const std::ffi::c_char,
                        1234u32 as std::ffi::c_uint,
                        handle,
                    );
                }
            });
    }
}
impl<'tvb> wsdf::Dissect<'tvb, ()> for UdpProto {
    type Emit = ();
    fn add_to_tree(
        args: &wsdf::DissectorArgs<'_, 'tvb>,
        fields: &mut wsdf::FieldsStore<'tvb>,
    ) -> usize {
        let mut fields_local = wsdf::FieldsStore::default();
        let offset = args.offset;
        let parent = args.add_subtree();
        let prefix_next = args.prefix.to_owned() + "." + "field";
        let args_next = wsdf::DissectorArgs {
            hf_indices: args.hf_indices,
            etts: args.etts,
            dtables: args.dtables,
            tvb: args.tvb,
            pinfo: args.pinfo,
            proto_root: args.proto_root,
            data: args.data,
            prefix: &prefix_next,
            prefix_local: "field",
            offset,
            parent,
            variant: std::option::Option::None,
            list_len: std::option::Option::None,
            ws_enc: std::option::Option::None,
        };
        let offset = offset
            + <u32 as wsdf::Dissect<'tvb, ()>>::add_to_tree(&args_next, fields);
        unsafe {
            wsdf::epan_sys::proto_item_set_len(parent, (offset - args.offset) as _);
        }
        offset - args.offset
    }
    fn size(
        args: &wsdf::DissectorArgs<'_, 'tvb>,
        fields: &mut wsdf::FieldsStore<'tvb>,
    ) -> usize {
        let mut fields_local = wsdf::FieldsStore::default();
        let offset = args.offset;
        let parent = args.parent;
        let prefix_next = args.prefix.to_owned() + "." + "field";
        let args_next = wsdf::DissectorArgs {
            hf_indices: args.hf_indices,
            etts: args.etts,
            dtables: args.dtables,
            tvb: args.tvb,
            pinfo: args.pinfo,
            proto_root: args.proto_root,
            data: args.data,
            prefix: &prefix_next,
            prefix_local: "field",
            offset,
            parent,
            variant: std::option::Option::None,
            list_len: std::option::Option::None,
            ws_enc: std::option::Option::None,
        };
        let offset = offset + <u32 as wsdf::Dissect<'tvb, ()>>::size(&args_next, fields);
        offset - args.offset
    }
    fn register(args: &wsdf::RegisterArgs, ws_indices: &mut wsdf::WsIndices) {
        let _ = ws_indices.ett.get_or_create_ett(args);
        let _ = ws_indices.hf.get_or_create_text_node(args);
        let prefix_next = args.prefix.to_owned() + "." + "field";
        let args_next = wsdf::RegisterArgs {
            proto_id: args.proto_id,
            name: "Field\u{0}".as_ptr() as *const std::ffi::c_char,
            prefix: &prefix_next,
            blurb: std::ptr::null(),
            ws_type: std::option::Option::None,
            ws_display: std::option::Option::None,
        };
        <u32 as wsdf::Dissect<'tvb, ()>>::register(&args_next, ws_indices);
    }
    fn emit(_args: &wsdf::DissectorArgs) {}
}
