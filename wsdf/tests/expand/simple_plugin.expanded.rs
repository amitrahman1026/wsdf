use wsdf::{protocol, version};
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
            <TestPlugin as wsdf::Proto>::register_protoinfo,
        );
        PLUG_0.register_handoff = std::option::Option::Some(
            <TestPlugin as wsdf::Proto>::register_handoff,
        );
        wsdf::epan_sys::proto_register_plugin(&PLUG_0);
    }
}
