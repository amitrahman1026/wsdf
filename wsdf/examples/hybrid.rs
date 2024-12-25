struct Protocol {
    id: i32,
    name: String,
    filter: String,
    // Static data for this protocol
    hf_indices: HfIndices,
    ett_indices: EttIndices,
    dtables: DissectorTables,
    // The actual dissector implementation
    dissector: Box<dyn ProtoImpl>,
}

// This trait represents the user's implementation
trait ProtoImpl {
    fn dissect(&self, tvb: &Tvb, pinfo: &PacketInfo, tree: &mut Tree) -> i32;
}

// The Proto trait should implemented by Protocol / proc macros -> the selling point of wsdf, users can create a dylib plugin transparently
// Power users can use this at their own risk
trait Proto {
    unsafe extern "C" fn dissect_main(
        &self,
        tvb: *mut epan_sys::tvbuff,
        pinfo: *mut epan_sys::_packet_info,
        tree: *mut epan_sys::_proto_node,
        data: *mut std::ffi::c_void,
    ) -> std::ffi::c_int;

    unsafe extern "C" fn register_protoinfo(&self);
    unsafe extern "C" fn register_handoff(&self);
}

impl Proto for Protocol {
    unsafe extern "C" fn dissect_main(
        &self,
        tvb: *mut epan_sys::tvbuff,
        pinfo: *mut epan_sys::_packet_info,
        tree: *mut epan_sys::_proto_node,
        _data: *mut std::ffi::c_void,
    ) -> std::ffi::c_int {
        // Safe wrapper that calls the user's ProtoImpl::dissect
        let tvb = Tvb::new(tvb);
        let pinfo = PacketInfo::new(pinfo);
        let mut tree = Tree::new(tree);

        self.dissector.dissect(&tvb, &pinfo, &mut tree)
    }

    unsafe extern "C" fn register_protoinfo(&self) {
        // Registration using Protocol's fields
    }

    unsafe extern "C" fn register_handoff(&self) {
        // Handoff using Protocol's fields
    }
}

// Potential macros
use proc_macro::TokenStream;
use quote::{format_ident, quote, ToTokens};
use syn::Token;

// For plugin registration, the idea should be to do something like plugin!(...).

#[proc_macro_derive(Proto)]
pub fn derive_proto(_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // Instead of implementing Proto directly, we generate:
    let proto_derive_impl = quote! {
        // impl ProtoImpl for #ident {
        //     unimplemented!()
        // }
        // impl From<#ident> for Protocol {
        //     unimplemented!()
        // }
    };
    proto_derive_impl.to_token_stream().into()
}

// The current protocol!(...) is actually close to what we need and exposes things correctly,
// renaming and modifying to use the above abstraction should work

// Internal input parser for plugin! macro that takes a list of user defined protocol types
struct PluginProtocols {
    protocols: Vec<syn::Type>,
}

impl syn::parse::Parse for PluginProtocols {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let protocols = input
            .parse_terminated(syn::Type::parse, Token![,])?
            .into_iter()
            .collect();
        Ok(PluginProtocols { protocols })
    }
}

#[proc_macro]
pub fn plugin(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as PluginProtocols);

    let register_protos = input.protocols.iter().enumerate().map(|(i, proto_ty)| {
        let handler_ident = format_ident!("PROTO_{}", i);

        let ret = quote! {
            static mut #handler_ident: wsdf::epan_sys::proto_plugin = wsdf::epan_sys::proto_plugin {
                register_protoinfo: None,
                register_handoff: None,
            };
            unsafe {
                #handler_ident.register_protoinfo =
                    std::option::Option::Some(<#proto_ty as wsdf::Proto>::register_protoinfo);
                #handler_ident.register_handoff =
                    std::option::Option::Some(<#proto_ty as wsdf::Proto>::register_handoff);
                wsdf::epan_sys::proto_register_plugin(&#handler_ident);
            }
        };
        ret
    });

    quote! {
        // Wireshark will call this function to load our plugin.
        #[no_mangle]
        extern "C" fn plugin_register() {
            #(#register_protos)*
        }
        // Plugin required symbols for version check
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
    }
    .into()
}

// Unimplemented
struct Tvb {
    ptr: *mut epan_sys::tvbuff,
}
impl Tvb {
    pub fn new(ptr: *mut epan_sys::tvbuff) -> Self {
        Self { ptr }
    }
}
struct PacketInfo {
    ptr: *mut epan_sys::_packet_info,
}
impl PacketInfo {
    pub fn new(ptr: *mut epan_sys::_packet_info) -> Self {
        Self { ptr }
    }
}
struct Tree {
    ptr: *mut epan_sys::_proto_node,
}
impl Tree {
    pub fn new(ptr: *mut epan_sys::_proto_node) -> Self {
        Self { ptr }
    }
}

struct HfIndices {}
struct EttIndices {}
struct DissectorTables {}
