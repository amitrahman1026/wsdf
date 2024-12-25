use epan_sys;
use std::borrow::Borrow;
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::ffi::{c_int, CString};
struct Protocol {
    id: c_int,
    name: CString,
    abbrev: CString,
    filter: CString,
    // Static data for this protocol
    hf_indices: HfIndices,
    ett_indices: EttIndices,
    dtables: DissectorTables,
    dissector_handle: Option<DissectorHandle>,
    // The actual dissector implementation
    dissector: Box<dyn ProtoImpl>,
}

impl Protocol {
    fn new(name: &str, abbrev: &str, filter: &str, dissector: Box<dyn ProtoImpl>) -> Self {
        let ett_indices = EttIndices::default();

        Self {
            id: -1, // Register routine sets this
            name: CString::new(name).unwrap(),
            abbrev: CString::new(abbrev).unwrap(),
            filter: CString::new(filter).unwrap(),
            hf_indices: HfIndices::default(),
            ett_indices: ett_indices,
            dtables: DissectorTables::default(),
            dissector_handle: None,
            dissector: dissector,
        }
    }
    fn register_field(&mut self, field: FieldDefinition) {
        let field_id = field.id.clone();
        let field_info = field.into_hf_info(&self.name);
        self.hf_indices.add_field(field_id, field_info);
    }
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

// TODO: return to this once api is stable
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

// WIP: Data structures needed to support the object oriented API
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

#[derive(Default)]
struct HfIndices {
    // Map field name to storage index
    fields: HashMap<String, usize>,
    storage: Box<UnsafeCell<Vec<FieldInfo>>>,
}
impl HfIndices {
    pub fn add_field(&self, field_id: String, field_info: FieldInfo) {
        unimplemented!()
    }
}

struct FieldInfo {
    id: c_int,
    hf_info: epan_sys::hf_register_info,
}

#[derive(Default)]
struct EttIndices {
    // Storage for ETT indices, must live beyond registration, initialised to -1
    storage: Box<UnsafeCell<Vec<c_int>>>,
    // Storage for pointers to the indices above for registration
    ptr_storage: Box<UnsafeCell<Vec<*mut c_int>>>,
}
impl EttIndices {
    pub fn new(num_ett: usize) -> Self {
        Self {
            storage: Box::new(UnsafeCell::new(vec![-1; num_ett])),
            ptr_storage: Box::new(UnsafeCell::new(Vec::with_capacity(num_ett))),
        }
    }

    pub fn register_all(&self) {
        // unsafe {
        // epan_sys::proto_register_subtree_array(ptr_storage as _, ptr_storage.len() as i32);
        // }
        unimplemented!()
    }

    pub fn get_ett(&self, idx: usize) -> c_int {
        unsafe { (*self.storage.get())[idx] }
    }
}

#[derive(Default)]
struct DissectorTables {
    tables: HashMap<String, epan_sys::dissector_table_t>,
}
struct DissectorHandle(epan_sys::dissector_handle);

struct FieldDefinition {
    id: String,
    name: String,
    field_type: FieldType,
    display: FieldDisplay,
    strings: Option<Vec<(u32, String)>>,
    // bitmask
    // blurb
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
enum FieldType {
    None,
    Protocol,
    Boolean,
    Char,
    Uint8,
    Uint16,
    Uint24,
    Uint32,
    Uint40,
    Uint48,
    Uint56,
    Uint64,
    Int8,
    Int16,
    Int24,
    Int32,
    Int40,
    Int48,
    Int56,
    Int64,
    IEEE_11073_SFLOAT,
    IEEE_11073_FLOAT,
    Float,
    Double,
    AbsoluteTime,
    RelativeTime,
    String,
    Stringz,
    UintString,
    Ether,
    Bytes,
    UintBytes,
    IPv4,
    IPv6,
    IPXNET,
    Framenum,
    Guid,
    Oid,
    EUI64,
    Ax25,
    Vines,
    RelOid,
    SystemId,
    StringzPad,
    Fcwwn,
    StringzTrunc,
    Scalar,
}
impl FieldType {
    pub fn to_wireshark_enum(self) -> epan_sys::ftenum {
        match self {
            FieldType::None => epan_sys::ftenum_FT_NONE,
            FieldType::Protocol => epan_sys::ftenum_FT_PROTOCOL,
            FieldType::Boolean => epan_sys::ftenum_FT_BOOLEAN,
            FieldType::Char => epan_sys::ftenum_FT_CHAR,
            FieldType::Uint8 => epan_sys::ftenum_FT_UINT8,
            FieldType::Uint16 => epan_sys::ftenum_FT_UINT16,
            FieldType::Uint24 => epan_sys::ftenum_FT_UINT24,
            FieldType::Uint32 => epan_sys::ftenum_FT_UINT32,
            FieldType::Uint40 => epan_sys::ftenum_FT_UINT40,
            FieldType::Uint48 => epan_sys::ftenum_FT_UINT48,
            FieldType::Uint56 => epan_sys::ftenum_FT_UINT56,
            FieldType::Uint64 => epan_sys::ftenum_FT_UINT64,
            FieldType::Int8 => epan_sys::ftenum_FT_INT8,
            FieldType::Int16 => epan_sys::ftenum_FT_INT16,
            FieldType::Int24 => epan_sys::ftenum_FT_INT24,
            FieldType::Int32 => epan_sys::ftenum_FT_INT32,
            FieldType::Int40 => epan_sys::ftenum_FT_INT40,
            FieldType::Int48 => epan_sys::ftenum_FT_INT48,
            FieldType::Int56 => epan_sys::ftenum_FT_INT56,
            FieldType::Int64 => epan_sys::ftenum_FT_INT64,
            FieldType::IEEE_11073_SFLOAT => epan_sys::ftenum_FT_IEEE_11073_SFLOAT,
            FieldType::IEEE_11073_FLOAT => epan_sys::ftenum_FT_IEEE_11073_FLOAT,
            FieldType::Float => epan_sys::ftenum_FT_FLOAT,
            FieldType::Double => epan_sys::ftenum_FT_DOUBLE,
            FieldType::AbsoluteTime => epan_sys::ftenum_FT_ABSOLUTE_TIME,
            FieldType::RelativeTime => epan_sys::ftenum_FT_RELATIVE_TIME,
            FieldType::String => epan_sys::ftenum_FT_STRING,
            FieldType::Stringz => epan_sys::ftenum_FT_STRINGZ,
            FieldType::UintString => epan_sys::ftenum_FT_UINT_STRING,
            FieldType::Ether => epan_sys::ftenum_FT_ETHER,
            FieldType::Bytes => epan_sys::ftenum_FT_BYTES,
            FieldType::UintBytes => epan_sys::ftenum_FT_UINT_BYTES,
            FieldType::IPv4 => epan_sys::ftenum_FT_IPv4,
            FieldType::IPv6 => epan_sys::ftenum_FT_IPv6,
            FieldType::IPXNET => epan_sys::ftenum_FT_IPXNET,
            FieldType::Framenum => epan_sys::ftenum_FT_FRAMENUM,
            FieldType::Guid => epan_sys::ftenum_FT_GUID,
            FieldType::Oid => epan_sys::ftenum_FT_OID,
            FieldType::EUI64 => epan_sys::ftenum_FT_EUI64,
            FieldType::Ax25 => epan_sys::ftenum_FT_AX25,
            FieldType::Vines => epan_sys::ftenum_FT_VINES,
            FieldType::RelOid => epan_sys::ftenum_FT_REL_OID,
            FieldType::SystemId => epan_sys::ftenum_FT_SYSTEM_ID,
            FieldType::StringzPad => epan_sys::ftenum_FT_STRINGZPAD,
            FieldType::Fcwwn => epan_sys::ftenum_FT_FCWWN,
            FieldType::StringzTrunc => epan_sys::ftenum_FT_STRINGZTRUNC,
            FieldType::Scalar => epan_sys::ftenum_FT_SCALAR,
        }
    }
}

#[derive(Copy, Clone)]
enum FieldDisplay {
    None,
    BaseDec,
    BaseHex,
    BaseOct,
    BaseDecHex,
    BaseHexDec,
    BaseCustom,
    BaseExp,
    SepDot,
    SepDash,
    SepColon,
    SepSpace,
    BaseNetmask,
    BasePtUdp,
    BasePtTcp,
    BasePtDccp,
    BasePtSctp,
    BaseOui,
    AbsoluteTimeLocal,
    AbsoluteTimeUtc,
    AbsoluteTimeDoyUtc,
    AbsoluteTimeNtpUtc,
    AbsoluteTimeUnix,
    BaseStrWsp,
}

impl FieldDisplay {
    pub fn to_wireshark_enum(self) -> epan_sys::field_display_e {
        match self {
            FieldDisplay::None => epan_sys::field_display_e_BASE_NONE,
            FieldDisplay::BaseDec => epan_sys::field_display_e_BASE_DEC,
            FieldDisplay::BaseHex => epan_sys::field_display_e_BASE_HEX,
            FieldDisplay::BaseOct => epan_sys::field_display_e_BASE_OCT,
            FieldDisplay::BaseDecHex => epan_sys::field_display_e_BASE_DEC_HEX,
            FieldDisplay::BaseHexDec => epan_sys::field_display_e_BASE_HEX_DEC,
            FieldDisplay::BaseCustom => epan_sys::field_display_e_BASE_CUSTOM,
            FieldDisplay::BaseExp => epan_sys::field_display_e_BASE_EXP,
            FieldDisplay::SepDot => epan_sys::field_display_e_SEP_DOT,
            FieldDisplay::SepDash => epan_sys::field_display_e_SEP_DASH,
            FieldDisplay::SepColon => epan_sys::field_display_e_SEP_COLON,
            FieldDisplay::SepSpace => epan_sys::field_display_e_SEP_SPACE,
            FieldDisplay::BaseNetmask => epan_sys::field_display_e_BASE_NETMASK,
            FieldDisplay::BasePtUdp => epan_sys::field_display_e_BASE_PT_UDP,
            FieldDisplay::BasePtTcp => epan_sys::field_display_e_BASE_PT_TCP,
            FieldDisplay::BasePtDccp => epan_sys::field_display_e_BASE_PT_DCCP,
            FieldDisplay::BasePtSctp => epan_sys::field_display_e_BASE_PT_SCTP,
            FieldDisplay::BaseOui => epan_sys::field_display_e_BASE_OUI,
            FieldDisplay::AbsoluteTimeLocal => epan_sys::field_display_e_ABSOLUTE_TIME_LOCAL,
            FieldDisplay::AbsoluteTimeUtc => epan_sys::field_display_e_ABSOLUTE_TIME_UTC,
            FieldDisplay::AbsoluteTimeDoyUtc => epan_sys::field_display_e_ABSOLUTE_TIME_DOY_UTC,
            FieldDisplay::AbsoluteTimeNtpUtc => epan_sys::field_display_e_ABSOLUTE_TIME_NTP_UTC,
            FieldDisplay::AbsoluteTimeUnix => epan_sys::field_display_e_ABSOLUTE_TIME_UNIX,
            FieldDisplay::BaseStrWsp => epan_sys::field_display_e_BASE_STR_WSP,
        }
    }
}

impl FieldDefinition {
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            field_type: FieldType::None,
            display: FieldDisplay::None,
            strings: None,
        }
    }

    fn into_hf_info(self, proto_name: &CString) -> FieldInfo {
        // Convert the field definition into Wireshark's hf_register_info
        // This would construct the actual C struct hf_register_info to be added to hf array
        unimplemented!()
    }
}
