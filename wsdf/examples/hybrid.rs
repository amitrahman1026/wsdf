use epan_sys;
use std::{
    collections::HashMap,
    ffi::{c_int, c_void, CString},
};

pub struct Protocol {
    name: String,
    abbrev: String,
    filter: String,
    // Static data for this protocol
    proto_handle: c_int,
    // Holds the collapse state of the subtree
    ett_handles: Vec<c_int>,
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
    // Register ETT array during protocol registration
    unsafe fn register_ett_array(&mut self, num_ett: usize) {
        // Initialize ett handles with -1
        self.ett_handles.resize(num_ett, -1);

        // Create array of pointers to ett handles for registration
        let ett_ptrs: Vec<*mut c_int> = self
            .ett_handles
            .iter_mut()
            .map(|h| h as *mut c_int)
            .collect();

        // Register the ETT array with Wireshark
        epan_sys::proto_register_subtree_array(ett_ptrs.as_ptr(), num_ett as c_int);
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
    abbrev: String,
    filter: String,
    dissector_fn: Option<Dissector>,
    fields: Vec<Field>,
    match_definitions: Vec<DissectorDecodeFrom>,
}

impl ProtocolBuilder {
    pub fn new(
        name: impl Into<String>,
        abbrev: impl Into<String>,
        filter: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            abbrev: abbrev.into(),
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
                to_c_str(&self.abbrev),
                to_c_str(&self.filter),
            );
            debug_assert!(proto_handle != -1);
            Ok(Protocol {
                name: self.name,
                abbrev: self.abbrev,
                filter: self.filter,
                proto_handle,
                ett_handles: vec![-1; 1], // Consider improving ergonomics of registering types of trees
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
    offset: i32,
}
impl Tvb {
    pub fn new(ptr: *mut epan_sys::tvbuff) -> Self {
        Self { ptr, offset: 0 }
    }
    pub fn get_uint8(&self, offset: i32) -> u8 {
        unsafe { epan_sys::tvb_get_uint8(self.ptr, offset) }
    }

    pub fn get_uint16(&self, offset: i32, encoding: Encoding) -> u16 {
        unsafe {
            match encoding {
                Encoding::BigEndian => epan_sys::tvb_get_ntohs(self.ptr, offset),
                // everything that is not Big Endian (enc as 0) is Litte endian in wireshark
                _ => epan_sys::tvb_get_letohs(self.ptr, offset),
            }
        }
    }
    pub fn length(&self) -> i32 {
        unsafe { epan_sys::tvb_reported_length(self.ptr) as i32 }
    }
    pub fn remaining_length(&self, offset: i32) -> i32 {
        unsafe { epan_sys::tvb_captured_length_remaining(self.ptr, offset) }
    }
}
#[derive(Clone, Copy)]
pub struct PacketInfo {
    ptr: *mut epan_sys::_packet_info,
}
impl PacketInfo {
    pub fn new(ptr: *mut epan_sys::_packet_info) -> Self {
        Self { ptr }
    }
    // This raw pointer is maba
    pub fn alloc_string(&self, s: &str) -> *const i8 {
        let c_str = std::ffi::CString::new(s).unwrap();
        unsafe {
            let size = s.len() + 1; // +1 for null terminator
            let ptr = epan_sys::wmem_alloc((*self.ptr).pool, size) as *mut i8;
            std::ptr::copy_nonoverlapping(c_str.as_ptr(), ptr, size);
            ptr
        }
    }
    pub fn alloc_bytes(&self, bytes: &[u8]) -> *mut u8 {
        unsafe {
            let ptr = epan_sys::wmem_alloc((*self.ptr).pool, bytes.len()) as *mut u8;
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
            ptr
        }
    }
    pub fn set_column_text(&self, col: Column, text: &str) {
        let text = self.alloc_string(text);
        unsafe {
            epan_sys::col_clear((*self.ptr).cinfo, col as i32);
            epan_sys::col_add_str((*self.ptr).cinfo, col as i32, text);
        }
    }
    pub fn clear_column(&self, col: Column) {
        unsafe {
            epan_sys::col_clear((*self.ptr).cinfo, col as i32);
        }
    }
}

pub struct Tree<'a> {
    protocol: &'a Protocol,
    pinfo: PacketInfo,
    tvb: Tvb,
    current_node: *mut epan_sys::proto_node,
    _parent_node: *mut epan_sys::proto_node,
    offset: i32,
}

impl<'a> Tree<'a> {
    // This should be called before top level dissector function, when the whole packet is first dissected
    unsafe fn new(
        protocol: &'a Protocol,
        pinfo: *mut epan_sys::packet_info,
        parent: *mut epan_sys::proto_node,
        tvb: *mut epan_sys::tvbuff,
        offset: i32,
    ) -> Self {
        let item = epan_sys::proto_tree_add_item(
            parent,
            protocol.get_proto_handle(),
            tvb,
            offset,
            -1,
            epan_sys::ENC_NA,
        );
        // The actual subtree for display
        let current = epan_sys::proto_item_add_subtree(item, protocol.get_ett_handle(0));

        Self {
            protocol,
            pinfo: PacketInfo::new(pinfo),
            tvb: Tvb::new(tvb),
            current_node: current,
            _parent_node: parent,
            offset,
        }
    }
    pub fn add_item(
        &mut self,
        field_id: &str,
        length: i32,
        encoding: Encoding,
    ) -> Option<TreeItem> {
        unsafe {
            let item = epan_sys::proto_tree_add_item(
                self.current_node,
                self.protocol.get_field_handle(field_id)?.handle,
                self.tvb.ptr,
                self.offset,
                length,
                encoding.to_u32(),
            );

            self.offset += length;

            if !item.is_null() {
                Some(TreeItem::new(item, self.pinfo))
            } else {
                None
            }
        }
    }
}

#[derive(Clone, Copy)]
pub struct TreeItem {
    ptr: *mut epan_sys::proto_item,
    pinfo: PacketInfo,
}

impl TreeItem {
    pub(crate) fn new(ptr: *mut epan_sys::proto_item, pinfo: PacketInfo) -> Self {
        Self { ptr, pinfo }
    }
    pub fn set_text(&mut self, text: &str) {
        let text = self.pinfo.alloc_string(text);
        unsafe {
            epan_sys::proto_item_set_text(self.ptr, text);
        }
    }

    pub fn append_text(&mut self, text: &str) {
        let text = self.pinfo.alloc_string(text);
        unsafe {
            epan_sys::proto_item_append_text(self.ptr, text);
        }
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
        let mut tree = Tree::new(protocol, pinfo, proto_tree, tvb, 0);
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

#[derive(Copy, Clone)]
pub enum Encoding {
    BigEndian,
    LittleEndian,
    HostEndian,
    AntiHostEndian,
    NA,
    UTF8,
    UTF16,
    UCS2,
    UCS4,
    ISO8859_1,
    ISO8859_2,
    ISO8859_3,
    ISO8859_4,
    ISO8859_5,
    ISO8859_6,
    ISO8859_7,
    ISO8859_8,
    ISO8859_9,
    ISO8859_10,
    ISO8859_11,
    ISO8859_13,
    ISO8859_14,
    ISO8859_15,
    ISO8859_16,
    Windows1250,
    Windows1252,
    Windows1251,
    CP437,
    ASCII7Bits,
    T61,
    EBCDIC_CP037,
    CP855,
    CP866,
    ISO646Basic,
    BCDDigits0_9,
    KeypadABC_TBCD,
    KeypadBC_TBCD,
    GpppTS23_038_7BitsPacked,
    GpppTS23_038_7Bits,
    ETSITS102221AnnexA,
    GB18030,
    EUCKR,
    APNStr,
    DECTStandard8Bits,
    DECTStandard4BitsTBCD,
    EBCDIC_CP500,
    Zigbee,
    BOM,
    StrNum,
    StrHex,
    String,
    StrMask,
    NumPref,
    SepNone,
    SepColon,
    SepDash,
    SepDot,
    SepSpace,
    SepMask,
    BCDOddNumDig,
    BCDSkipFirst,
    TimeSecsNsecs,
    TimeTimespec,
    TimeNTP,
    TimeTOD,
    TimeRTPS,
    TimeNTPBaseZero,
    TimeSecsUsecs,
    TimeTimeval,
    TimeSecs,
    TimeMsecs,
    TimeSecsNTP,
    TimeRFC3971,
    TimeMsecNTP,
    TimeMip6,
    TimeMp4FileSecs,
    TimeClassicMacOSSecs,
    TimeNsecs,
    TimeUsecs,
    TimeZBeeZCL,
    ISO8601Date,
    ISO8601Time,
    ISO8601DateTime,
    IMFDateTime,
    RFC822,
    RFC1123,
    ISO8601DateTimeBasic,
    StrTimeMask,
    VarintProtobuf,
    VarintQUIC,
    VarintZigzag,
    VarintSDNV,
    VarintMask,
}

impl Encoding {
    pub fn to_u32(self) -> u32 {
        match self {
            Encoding::BigEndian => epan_sys::ENC_BIG_ENDIAN,
            Encoding::LittleEndian => epan_sys::ENC_LITTLE_ENDIAN,
            Encoding::HostEndian => epan_sys::ENC_HOST_ENDIAN,
            Encoding::AntiHostEndian => epan_sys::ENC_ANTI_HOST_ENDIAN,
            Encoding::NA => epan_sys::ENC_NA,
            Encoding::UTF8 => epan_sys::ENC_UTF_8,
            Encoding::UTF16 => epan_sys::ENC_UTF_16,
            Encoding::UCS2 => epan_sys::ENC_UCS_2,
            Encoding::UCS4 => epan_sys::ENC_UCS_4,
            Encoding::ISO8859_1 => epan_sys::ENC_ISO_8859_1,
            Encoding::ISO8859_2 => epan_sys::ENC_ISO_8859_2,
            Encoding::ISO8859_3 => epan_sys::ENC_ISO_8859_3,
            Encoding::ISO8859_4 => epan_sys::ENC_ISO_8859_4,
            Encoding::ISO8859_5 => epan_sys::ENC_ISO_8859_5,
            Encoding::ISO8859_6 => epan_sys::ENC_ISO_8859_6,
            Encoding::ISO8859_7 => epan_sys::ENC_ISO_8859_7,
            Encoding::ISO8859_8 => epan_sys::ENC_ISO_8859_8,
            Encoding::ISO8859_9 => epan_sys::ENC_ISO_8859_9,
            Encoding::ISO8859_10 => epan_sys::ENC_ISO_8859_10,
            Encoding::ISO8859_11 => epan_sys::ENC_ISO_8859_11,
            Encoding::ISO8859_13 => epan_sys::ENC_ISO_8859_13,
            Encoding::ISO8859_14 => epan_sys::ENC_ISO_8859_14,
            Encoding::ISO8859_15 => epan_sys::ENC_ISO_8859_15,
            Encoding::ISO8859_16 => epan_sys::ENC_ISO_8859_16,
            Encoding::Windows1250 => epan_sys::ENC_WINDOWS_1250,
            Encoding::Windows1252 => epan_sys::ENC_WINDOWS_1252,
            Encoding::Windows1251 => epan_sys::ENC_WINDOWS_1251,
            Encoding::CP437 => epan_sys::ENC_CP437,
            Encoding::ASCII7Bits => epan_sys::ENC_ASCII_7BITS,
            Encoding::T61 => epan_sys::ENC_T61,
            Encoding::EBCDIC_CP037 => epan_sys::ENC_EBCDIC_CP037,
            Encoding::CP855 => epan_sys::ENC_CP855,
            Encoding::CP866 => epan_sys::ENC_CP866,
            Encoding::ISO646Basic => epan_sys::ENC_ISO_646_BASIC,
            Encoding::BCDDigits0_9 => epan_sys::ENC_BCD_DIGITS_0_9,
            Encoding::KeypadABC_TBCD => epan_sys::ENC_KEYPAD_ABC_TBCD,
            Encoding::KeypadBC_TBCD => epan_sys::ENC_KEYPAD_BC_TBCD,
            Encoding::GpppTS23_038_7BitsPacked => epan_sys::ENC_3GPP_TS_23_038_7BITS_PACKED,
            Encoding::GpppTS23_038_7Bits => epan_sys::ENC_3GPP_TS_23_038_7BITS,
            Encoding::ETSITS102221AnnexA => epan_sys::ENC_ETSI_TS_102_221_ANNEX_A,
            Encoding::GB18030 => epan_sys::ENC_GB18030,
            Encoding::EUCKR => epan_sys::ENC_EUC_KR,
            Encoding::APNStr => epan_sys::ENC_APN_STR,
            Encoding::DECTStandard8Bits => epan_sys::ENC_DECT_STANDARD_8BITS,
            Encoding::DECTStandard4BitsTBCD => epan_sys::ENC_DECT_STANDARD_4BITS_TBCD,
            Encoding::EBCDIC_CP500 => epan_sys::ENC_EBCDIC_CP500,
            Encoding::Zigbee => epan_sys::ENC_ZIGBEE,
            Encoding::BOM => epan_sys::ENC_BOM,
            Encoding::StrNum => epan_sys::ENC_STR_NUM,
            Encoding::StrHex => epan_sys::ENC_STR_HEX,
            Encoding::String => epan_sys::ENC_STRING,
            Encoding::StrMask => epan_sys::ENC_STR_MASK,
            Encoding::NumPref => epan_sys::ENC_NUM_PREF,
            Encoding::SepNone => epan_sys::ENC_SEP_NONE,
            Encoding::SepColon => epan_sys::ENC_SEP_COLON,
            Encoding::SepDash => epan_sys::ENC_SEP_DASH,
            Encoding::SepDot => epan_sys::ENC_SEP_DOT,
            Encoding::SepSpace => epan_sys::ENC_SEP_SPACE,
            Encoding::SepMask => epan_sys::ENC_SEP_MASK,
            Encoding::BCDOddNumDig => epan_sys::ENC_BCD_ODD_NUM_DIG,
            Encoding::BCDSkipFirst => epan_sys::ENC_BCD_SKIP_FIRST,
            Encoding::TimeSecsNsecs => epan_sys::ENC_TIME_SECS_NSECS,
            Encoding::TimeTimespec => epan_sys::ENC_TIME_TIMESPEC,
            Encoding::TimeNTP => epan_sys::ENC_TIME_NTP,
            Encoding::TimeTOD => epan_sys::ENC_TIME_TOD,
            Encoding::TimeRTPS => epan_sys::ENC_TIME_RTPS,
            Encoding::TimeNTPBaseZero => epan_sys::ENC_TIME_NTP_BASE_ZERO,
            Encoding::TimeSecsUsecs => epan_sys::ENC_TIME_SECS_USECS,
            Encoding::TimeTimeval => epan_sys::ENC_TIME_TIMEVAL,
            Encoding::TimeSecs => epan_sys::ENC_TIME_SECS,
            Encoding::TimeMsecs => epan_sys::ENC_TIME_MSECS,
            Encoding::TimeSecsNTP => epan_sys::ENC_TIME_SECS_NTP,
            Encoding::TimeRFC3971 => epan_sys::ENC_TIME_RFC_3971,
            Encoding::TimeMsecNTP => epan_sys::ENC_TIME_MSEC_NTP,
            Encoding::TimeMip6 => epan_sys::ENC_TIME_MIP6,
            Encoding::TimeMp4FileSecs => epan_sys::ENC_TIME_MP4_FILE_SECS,
            Encoding::TimeClassicMacOSSecs => epan_sys::ENC_TIME_CLASSIC_MAC_OS_SECS,
            Encoding::TimeNsecs => epan_sys::ENC_TIME_NSECS,
            Encoding::TimeUsecs => epan_sys::ENC_TIME_USECS,
            Encoding::TimeZBeeZCL => epan_sys::ENC_TIME_ZBEE_ZCL,
            Encoding::ISO8601Date => epan_sys::ENC_ISO_8601_DATE,
            Encoding::ISO8601Time => epan_sys::ENC_ISO_8601_TIME,
            Encoding::ISO8601DateTime => epan_sys::ENC_ISO_8601_DATE_TIME,
            Encoding::IMFDateTime => epan_sys::ENC_IMF_DATE_TIME,
            Encoding::RFC822 => epan_sys::ENC_RFC_822,
            Encoding::RFC1123 => epan_sys::ENC_RFC_1123,
            Encoding::ISO8601DateTimeBasic => epan_sys::ENC_ISO_8601_DATE_TIME_BASIC,
            Encoding::StrTimeMask => epan_sys::ENC_STR_TIME_MASK,
            Encoding::VarintProtobuf => epan_sys::ENC_VARINT_PROTOBUF,
            Encoding::VarintQUIC => epan_sys::ENC_VARINT_QUIC,
            Encoding::VarintZigzag => epan_sys::ENC_VARINT_ZIGZAG,
            Encoding::VarintSDNV => epan_sys::ENC_VARINT_SDNV,
            Encoding::VarintMask => epan_sys::ENC_VARINT_MASK,
        }
    }
}

#[derive(Clone, Copy)]
pub enum ExpertSeverity {
    Comment,
    Chat,
    Note,
    Warn,
    Error,
}

impl ExpertSeverity {
    pub fn to_u32(self) -> u32 {
        match self {
            ExpertSeverity::Comment => epan_sys::PI_COMMENT,
            ExpertSeverity::Chat => epan_sys::PI_CHAT,
            ExpertSeverity::Note => epan_sys::PI_NOTE,
            ExpertSeverity::Warn => epan_sys::PI_WARN,
            ExpertSeverity::Error => epan_sys::PI_ERROR,
        }
    }
}

#[derive(Clone, Copy)]
pub enum ExpertGroup {
    Checksum,
    Sequence,
    ResponseCode,
    RequestCode,
    Undecoded,
    Reassemble,
    Malformed,
    Debug,
    Protocol,
    Security,
    CommentsGroup,
    Decryption,
    Assumption,
    Deprecated,
    Receive,
    Interface,
    DissectorBug,
}

impl ExpertGroup {
    pub fn to_u32(self) -> u32 {
        match self {
            ExpertGroup::Checksum => epan_sys::PI_CHECKSUM,
            ExpertGroup::Sequence => epan_sys::PI_SEQUENCE,
            ExpertGroup::ResponseCode => epan_sys::PI_RESPONSE_CODE,
            ExpertGroup::RequestCode => epan_sys::PI_REQUEST_CODE,
            ExpertGroup::Undecoded => epan_sys::PI_UNDECODED,
            ExpertGroup::Reassemble => epan_sys::PI_REASSEMBLE,
            ExpertGroup::Malformed => epan_sys::PI_MALFORMED,
            ExpertGroup::Debug => epan_sys::PI_DEBUG,
            ExpertGroup::Protocol => epan_sys::PI_PROTOCOL,
            ExpertGroup::Security => epan_sys::PI_SECURITY,
            ExpertGroup::CommentsGroup => epan_sys::PI_COMMENTS_GROUP,
            ExpertGroup::Decryption => epan_sys::PI_DECRYPTION,
            ExpertGroup::Assumption => epan_sys::PI_ASSUMPTION,
            ExpertGroup::Deprecated => epan_sys::PI_DEPRECATED,
            ExpertGroup::Receive => epan_sys::PI_RECEIVE,
            ExpertGroup::Interface => epan_sys::PI_INTERFACE,
            ExpertGroup::DissectorBug => epan_sys::PI_DISSECTOR_BUG,
        }
    }
}

#[repr(i32)]
#[derive(Clone, Copy)]
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
            // Registering ETT is basically saying how many types of trees you have
            protocol.register_ett_array(1);
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
            let _ = tree.add_item("version", 1, Encoding::BigEndian).unwrap();
            // let _ = tree.add_subtree("header", 0);
            // tree.pinfo.set_column_text(Column::Protocol, "test");
            unsafe {
                // epan_sys::col_clear((*tree.pinfo).cinfo, epan_sys::COL_INFO as i32);
                // epan_sys::col_set_str(
                //     (*tree.pinfo).cinfo,
                //     epan_sys::COL_PROTOCOL as _,
                //     b"WSDF PROTO\0".as_ptr() as _,
                // );
                epan_sys::tvb_reported_length(tree.tvb.ptr) as i32
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
