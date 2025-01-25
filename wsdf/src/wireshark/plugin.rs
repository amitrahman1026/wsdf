use super::protocol::*;
use super::types::*;

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

pub struct Plugin {
    protocols: HashMap<String, Rc<RefCell<Protocol>>>,
}

thread_local! {
    static PLUGIN: RefCell<Option<Plugin>> = RefCell::new(None);
}

impl Plugin {
    fn new() -> Self {
        Self {
            protocols: HashMap::new(),
        }
    }

    pub fn add_protocol(&mut self, protocol: Protocol) {
        let id = protocol.abbrev.clone();
        self.protocols.insert(id, Rc::new(RefCell::new(protocol)));
    }

    pub fn get_protocol(&self, id: &str) -> Option<Rc<RefCell<Protocol>>> {
        self.protocols.get(id).cloned()
    }

    pub fn register_protocols(&mut self) {
        let protocol_ids: Vec<String> = self.protocols.keys().cloned().collect();

        for id in protocol_ids {
            if let Some(protocol) = self.protocols.get(&id) {
                protocol.borrow_mut().register();
            }
        }
    }

    pub fn handoff_protocols(&self) {
        for protocol in self.protocols.values() {
            let protocol = protocol.borrow();
            unsafe {
                let handle = epan_sys::create_dissector_handle(
                    Some(Protocol::dissector_handler),
                    protocol.proto_handle,
                );

                // Decode-from definitions
                if let Some(defs) = &protocol.match_definitions {
                    for def in defs {
                        match def {
                            DissectorDecodeFrom::DecodeAs(table) => {
                                let table = std::ffi::CString::new(table.as_str()).unwrap();
                                epan_sys::dissector_add_for_decode_as(table.as_ptr(), handle);
                            }
                            DissectorDecodeFrom::Uint(table, values) => {
                                let table = std::ffi::CString::new(table.as_str()).unwrap();
                                for &value in values {
                                    epan_sys::dissector_add_uint(table.as_ptr(), value, handle);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Plugin {
    pub fn initialize() {
        PLUGIN.with(|plugin| {
            if plugin.borrow().is_none() {
                *plugin.borrow_mut() = Some(Plugin::new());
            }
        });
    }

    pub fn with<F, R>(f: F) -> R
    where
        F: FnOnce(&mut Plugin) -> R,
    {
        PLUGIN.with(|plugin| {
            let mut plugin = plugin.borrow_mut();
            let plugin = plugin.as_mut().expect("Plugin not initialized");
            f(plugin)
        })
    }
}

#[macro_export]
macro_rules! plugin {
    ($build_fn:expr) => {
        #[no_mangle]
        pub extern "C" fn plugin_register() {
            Plugin::initialize();

            static PLUG: epan_sys::proto_plugin = epan_sys::proto_plugin {
                register_protoinfo: Some(proto_register_protos),
                register_handoff: Some(proto_reg_handoff),
            };

            unsafe {
                epan_sys::proto_register_plugin(&PLUG);
            }
        }

        #[no_mangle]
        pub unsafe extern "C" fn proto_register_protos() {
            Plugin::with(|plugin| {
                if let Ok(protocol) = $build_fn() {
                    plugin.add_protocol(protocol);
                }
                plugin.register_protocols();
            });
        }

        #[no_mangle]
        pub unsafe extern "C" fn proto_reg_handoff() {
            Plugin::with(|plugin| {
                plugin.handoff_protocols();
            });
        }

        // Plugin metadata
        #[no_mangle]
        #[used]
        #[allow(non_upper_case_globals)]
        static plugin_version: [std::ffi::c_char; 6usize] = [48i8, 46i8, 48i8, 46i8, 49i8, 0i8];
        #[no_mangle]
        #[used]
        #[allow(non_upper_case_globals)]
        static plugin_want_major: std::ffi::c_uint = epan_sys::WIRESHARK_VERSION_MAJOR;
        #[no_mangle]
        #[used]
        #[allow(non_upper_case_globals)]
        static plugin_want_minor: std::ffi::c_uint = epan_sys::WIRESHARK_VERSION_MINOR;
    };
}
