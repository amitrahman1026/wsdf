use epan_sys;
use std::{
    collections::HashMap,
    ffi::{c_int, c_void, CString},
};

pub struct Protocol {
    // Static data for this protocol
    proto_handle: c_int,
    // Holds the collapse state of the subtree
    ett_handles: Vec<c_int>,
    // Pointers to ett_handles vector above, registered to the protocol
    ett_handles_ptrs: Vec<*mut c_int>,
    // The actual dissector implementation
    pub(crate) dissector_fn: Dissector,
    field_defs: Vec<Field>,
    // All registered fields for this protocol
    field_handles: Vec<FieldHandle>,
    // Pending match conditions for this protocol that have not yet been registered
    match_definitions: Option<Vec<DissectorDecodeFrom>>,
}

impl Protocol {
    unsafe fn register_field(&mut self, field: &Field) -> Result<(), RegistrationError> {
        let mut handle: c_int = -1;

        // Convert strings for value_string if present
        let values_ptr = if let Some(strings) = &field.strings {
            let values: Vec<epan_sys::_value_string> = strings
                .iter()
                .map(|(val, str)| epan_sys::_value_string {
                    value: *val,
                    strptr: to_c_str(str),
                })
                .collect();

            Box::into_raw(values.into_boxed_slice()) as *const epan_sys::_value_string
        // TODO: Check memory
        } else {
            std::ptr::null()
        };

        let hf_info = epan_sys::hf_register_info {
            p_id: &mut handle,
            hfinfo: epan_sys::header_field_info {
                name: to_c_str(&field.name),
                abbrev: to_c_str(&field.abbrev),
                type_: field.field_type.to_u32(),
                display: field.display.to_u32() as i32,
                strings: values_ptr as *const c_void,
                bitmask: field.bitmask,
                blurb: field
                    .blurb
                    .as_ref()
                    .map_or(std::ptr::null(), |s| to_c_str(s)),
                id: -1,
                parent: 0,
                ref_type: epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
            },
        };

        let hf_ptr: *mut epan_sys::hf_register_info = Box::into_raw(Box::new(hf_info)); // TODO: stop intentially leaking?
        epan_sys::proto_register_field_array(self.get_proto_handle(), hf_ptr, 1);

        if handle != -1 {
            self.field_handles.push(FieldHandle {
                handle,
                id: field.id.clone(),
                _ptr: hf_ptr,
            });
            self.field_defs.push(field.clone());

            Ok(())
        } else {
            Err(RegistrationError::RegistrationFailed)
        }
    }
    fn get_ett_handle(&self, idx: c_int) -> c_int {
        if idx < 0 {
            panic!("ETT handle index must be >= 0");
        }

        self.ett_handles.get(idx as usize).expect("ETT handle index out of bounds, use set_num_ett during protocol creation to set the number of ETT fields").clone()
    }
    // Get the handle to the protocol's ETT
    fn get_proto_handle(&self) -> c_int {
        self.proto_handle
    }
    // Get the handle to a field that has already been registered
    fn get_field_handle(&self, abbrev: &str) -> Option<&FieldHandle> {
        self.field_handles.iter().find(|field| field.id == abbrev)
    }
}

#[derive(Clone)]
pub struct Field {
    id: String,
    name: String,
    abbrev: String,
    field_type: FieldType,
    display: FieldDisplay,
    strings: Option<Vec<(u32, String)>>,
    bitmask: u64,
    blurb: Option<String>,
}

// #[derive(Default)]
pub struct FieldBuilder {
    id: String,
    name: String,
    abbrev: String,
    field_type: Option<FieldType>,
    display: Option<FieldDisplay>,
    strings: Option<Vec<(u32, String)>>,
    bitmask: u64,
    blurb: Option<String>,
}
impl FieldBuilder {
    pub fn new(id: impl Into<String>, name: impl Into<String>, abbrev: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            abbrev: abbrev.into(),
            field_type: None,
            display: None,
            strings: None,
            bitmask: 0,
            blurb: None,
        }
    }

    pub fn field_type(mut self, field_type: FieldType) -> Self {
        self.field_type = Some(field_type);
        self
    }

    pub fn display(mut self, display: FieldDisplay) -> Self {
        self.display = Some(display);
        self
    }

    pub fn strings(mut self, strings: Vec<(u32, String)>) -> Self {
        self.strings = Some(strings);
        self
    }

    pub fn bitmask(mut self, bitmask: u64) -> Self {
        self.bitmask = bitmask;
        self
    }

    pub fn blurb(mut self, blurb: impl Into<String>) -> Self {
        self.blurb = Some(blurb.into());
        self
    }

    pub fn build(self) -> Result<Field, RegistrationError> {
        Ok(Field {
            id: self.id,
            name: self.name,
            abbrev: self.abbrev,
            field_type: self.field_type.ok_or(RegistrationError::MissingFieldType)?,
            display: self.display.unwrap_or_default(),
            strings: self.strings,
            bitmask: self.bitmask,
            blurb: self.blurb,
        })
    }
}

pub struct FieldHandle {
    handle: c_int,
    id: String,
    _ptr: *mut epan_sys::hf_register_info,
}

pub struct ProtocolBuilder {
    name: String,
    id: String,
    filter: String,
    dissector_fn: Option<Dissector>,
    fields: Vec<Field>,
    match_definitions: Vec<DissectorDecodeFrom>,
}

impl ProtocolBuilder {
    pub fn new(name: impl Into<String>, id: impl Into<String>, filter: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            id: id.into(),
            filter: filter.into(),
            dissector_fn: None,
            fields: Vec::new(),
            match_definitions: Vec::new(),
        }
    }

    pub fn dissector(mut self, dissector: Dissector) -> Self {
        self.dissector_fn = Some(dissector);
        self
    }

    pub fn field(mut self, field: Field) -> Self {
        self.fields.push(field);
        self
    }

    pub fn decode_from(mut self, decode_from: DissectorDecodeFrom) -> Self {
        self.match_definitions.push(decode_from);
        self
    }
    pub fn build(self) -> Result<Protocol, RegistrationError> {
        let dissector = self
            .dissector_fn
            .ok_or(RegistrationError::MissingDissector)?;

        unsafe {
            let proto_handle = epan_sys::proto_register_protocol(
                to_c_str(&self.name),
                to_c_str(&self.id),
                to_c_str(&self.filter),
            );
            debug_assert!(proto_handle != -1);
            Ok(Protocol {
                proto_handle,
                ett_handles: vec![-1; 1],
                ett_handles_ptrs: Vec::new(),
                dissector_fn: dissector,
                field_defs: self.fields,   // Store the field definitions
                field_handles: Vec::new(), // Will be populated during registration
                match_definitions: Some(self.match_definitions),
            })
        }
    }
}

// WIP: Data structures needed to support the object oriented API
pub struct Tvb {
    ptr: *mut epan_sys::tvbuff,
}
impl Tvb {
    pub fn new(ptr: *mut epan_sys::tvbuff) -> Self {
        Self { ptr }
    }
}
pub struct PacketInfo {
    ptr: *mut epan_sys::_packet_info,
}
impl PacketInfo {
    pub fn new(ptr: *mut epan_sys::_packet_info) -> Self {
        Self { ptr }
    }
    pub fn set_column_text(&self, col: Column, text: &str) -> Result<(), RegistrationError> {
        let text = CString::new(text)?;
        unsafe {
            epan_sys::col_add_str((*self.ptr).cinfo, col as i32, text.as_ptr());
        }
        Ok(())
    }

    pub fn clear_column(&self, col: Column) {
        unsafe {
            epan_sys::col_clear((*self.ptr).cinfo, col as i32);
        }
    }
}

pub struct Tree<'a> {
    pinfo: *mut epan_sys::packet_info,
    tree: *mut epan_sys::proto_tree,
    tvb: *mut epan_sys::tvbuff,
    parent: *mut epan_sys::proto_node,
    proto: &'a Protocol,
    offset: i32,
}

impl<'a> Tree<'a> {
    unsafe fn new(
        pinfo: *mut epan_sys::packet_info,
        protocol: &'a Protocol,
        tree: *mut epan_sys::proto_tree,
        tvb: *mut epan_sys::tvbuff,
        parent: *mut epan_sys::proto_node,
        offset: i32,
    ) -> Self {
        Self {
            pinfo,
            tree,
            tvb,
            parent,
            proto: protocol,
            offset,
        }
    }
    pub fn add_item(&mut self, field_id: &str, length: i32) -> Option<TreeItem> {
        unsafe {
            let item = epan_sys::proto_tree_add_item(
                self.tree,
                self.proto.get_field_handle(field_id)?.handle,
                self.tvb,
                self.offset,
                length,
                epan_sys::ENC_NA,
            );

            self.offset += length;

            if !item.is_null() {
                Some(TreeItem { item })
            } else {
                None
            }
        }
    }
    pub fn add_subtree(&mut self, field_id: &str, length: i32) -> Option<Tree<'a>> {
        let item = self.add_item(field_id, length)?;
        unsafe {
            let subtree = epan_sys::proto_item_add_subtree(item.item, self.proto.get_ett_handle(0));

            Some(Tree::new(
                self.pinfo,
                self.proto,
                subtree,
                self.tvb,
                self.parent,
                self.offset,
            ))
        }
    }
}

pub struct TreeItem {
    item: *mut epan_sys::proto_item,
}

impl TreeItem {
    pub fn set_text(&mut self, text: &str) -> Result<(), RegistrationError> {
        let text = CString::new(text)?;
        unsafe {
            epan_sys::proto_item_set_text(self.item, text.as_ptr());
        }
        Ok(())
    }

    pub fn append_text(&mut self, text: &str) -> Result<(), RegistrationError> {
        let text = CString::new(text)?;
        unsafe {
            epan_sys::proto_item_append_text(self.item, text.as_ptr());
        }
        Ok(())
    }
}

/// The dissector table where subdissectors you want to call are registered.
/// For more information https://gitlab.com/wireshark/wireshark/blob/ccd96c6f65ac507b8f2785385f31b874b3459f6b/doc/README.dissector#L2339
#[derive(Clone)]
pub enum DissectorDecodeFrom {
    DecodeAs(String),
    Uint(String, Vec<u32>),
}

pub struct Dissector {
    inner: Box<dyn Fn(&mut Tree) -> i32>,
}

impl Dissector {
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(&mut Tree) -> i32 + 'static,
    {
        Dissector { inner: Box::new(f) }
    }

    // This is where wireshark presents a packet to the ffi interface
    pub unsafe fn dispatch(
        &self,
        tvb: *mut epan_sys::tvbuff,
        pinfo: *mut epan_sys::packet_info,
        proto_tree: *mut epan_sys::proto_tree,
        protocol: &Protocol,
    ) -> c_int {
        let mut tree = Tree::new(pinfo, protocol, proto_tree, tvb, proto_tree, 0);
        //
        (self.inner)(&mut tree)
    }
}

// Enum wrappers

#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
pub enum FieldType {
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
    pub fn to_u32(self) -> epan_sys::ftenum {
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

#[derive(Copy, Clone, Default)]
pub enum FieldDisplay {
    #[default]
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
    pub fn to_u32(self) -> epan_sys::field_display_e {
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

#[repr(i32)]
pub enum Column {
    Protocol = epan_sys::COL_PROTOCOL as i32,
    Info = epan_sys::COL_INFO as i32,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("Protocol registration failed")]
    RegistrationFailed,
    #[error("Missing required dissector")]
    MissingDissector,
    #[error("Missing required field type")]
    MissingFieldType,
    #[error("CString conversion error: {0}")]
    CStringError(#[from] std::ffi::NulError),
}

fn to_c_str(s: &str) -> *const i8 {
    CString::new(s)
        .expect("String contains null byte")
        .into_raw() as *const i8
}

static mut PLUGIN: Option<Plugin> = None;

pub struct Plugin {
    // Right now I tied the lifetime of all the protocols to the static PLUGIN
    // But we can move to use an allocator as we simplify
    protocols: HashMap<String, Protocol>,
}

impl Plugin {
    pub fn new() -> Self {
        Self {
            protocols: HashMap::new(),
        }
    }
    pub fn add_protocol(&mut self, id: &str, protocol: Protocol) {
        self.protocols.insert(id.to_owned(), protocol);
    }
    pub unsafe fn get() -> &'static mut Self {
        PLUGIN.as_mut().expect("Plugin not initialized")
    }
}

pub unsafe extern "C" fn proto_register_protos() {
    let plugin = Plugin::get();
    let id = "example";
    let protocol = build_example_protocol(id).unwrap();
    // TODO: we can even move this plugin add_protocol to
    // inside build because of the singleton pattern
    plugin.add_protocol(id, protocol);

    let _: Vec<_> = plugin
        .protocols
        .iter_mut()
        .map(|(_, protocol)| {
            // Register each Protocol's header fields
            let fields_to_register = protocol.field_defs.clone();
            for field in fields_to_register {
                protocol
                    .register_field(&field)
                    .expect("Failed to register field");
            }
            // Then register ETT either here or via Tree -> need to simplify Tree
        })
        .collect();
}

pub unsafe extern "C" fn proto_reg_handoff() {
    // Handoff implementation for subdissector tables
    let plugin = Plugin::get();

    // NOTE: This registers the dissector for ALL of the protocols
    // this can also be made an associative function of plugin / access via singleton
    let _: Vec<_> = plugin
        .protocols
        .iter()
        .map(|(_, protocol)| {
            // Create dissector handle
            let handle =
                epan_sys::create_dissector_handle(Some(dissector_handler), protocol.proto_handle);

            // Register for each decode-from definition
            if let Some(defs) = &protocol.match_definitions {
                for def in defs {
                    match def {
                        DissectorDecodeFrom::DecodeAs(table) => {
                            let table = CString::new(table.as_str()).unwrap();
                            epan_sys::dissector_add_for_decode_as(table.as_ptr(), handle);
                        }
                        DissectorDecodeFrom::Uint(table, values) => {
                            let table = CString::new(table.as_str()).unwrap();
                            for &value in values {
                                epan_sys::dissector_add_uint(table.as_ptr(), value, handle);
                            }
                        }
                    }
                }
            }
        })
        .collect();
}

// This would be a free function that would be expetected by create_dissector_handle()
// TODO: figure out how to encapsulate this
pub unsafe extern "C" fn dissector_handler(
    tvb: *mut epan_sys::tvbuff,
    pinfo: *mut epan_sys::_packet_info,
    tree: *mut epan_sys::proto_tree,
    _data: *mut c_void,
) -> c_int {
    let curr_proto = (*pinfo).current_proto;

    // Here we can always retrieve the name of protocol from pinfo

    let id = std::ffi::CStr::from_ptr(curr_proto).to_str().unwrap();
    let plugin = Plugin::get();
    let protocol = plugin.protocols.get(id).unwrap();
    (protocol.dissector_fn).dispatch(tvb, pinfo, tree, protocol)
}

#[no_mangle]
pub extern "C" fn plugin_describe() -> u32 {
    // TODO: this + metadata about wireshark version etc can all be put into a marcro
    epan_sys::WS_PLUGIN_DESC_EPAN
}

#[no_mangle]
pub extern "C" fn plugin_register() {
    unsafe {
        if PLUGIN.is_none() {
            PLUGIN = Some(Plugin::new());
        }
    }

    static PLUG: epan_sys::proto_plugin = epan_sys::proto_plugin {
        register_protoinfo: Some(proto_register_protos),
        register_handoff: Some(proto_reg_handoff),
    };

    unsafe {
        epan_sys::proto_register_plugin(&PLUG);
    }
}

pub fn build_example_protocol(id: &str) -> Result<Protocol, RegistrationError> {
    let name = "Example Protocol";
    let filter = "example";
    let protocol = ProtocolBuilder::new(name, id, filter)
        .dissector(Dissector::new(|tree: &mut Tree<'_>| {
            tree.add_item("version", 1).unwrap();
            let _ = tree.add_subtree("header", 0);
            unsafe {
                epan_sys::col_clear((*tree.pinfo).cinfo, epan_sys::COL_INFO as i32);
                epan_sys::col_set_str(
                    (*tree.pinfo).cinfo,
                    epan_sys::COL_PROTOCOL as _,
                    b"WSDF PROTO\0".as_ptr() as _,
                );
                epan_sys::tvb_reported_length(tree.tvb) as i32
            }
        }))
        .field(
            FieldBuilder::new("version", "Version", "example.version")
                .field_type(FieldType::Uint8)
                .display(FieldDisplay::BaseDec)
                .build()?,
        )
        .decode_from(DissectorDecodeFrom::Uint("ip.proto".into(), vec![17]))
        .build()?;
    // TODO: We can move registration into the build step because at this point,
    //  we have all the information we need to build + fully register
    Ok(protocol)
}

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
