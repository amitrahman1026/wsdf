use std::ffi::c_char;

pub fn to_c_str(s: &str) -> *const c_char {
    // +1 for null terminator
    let size = s.len() + 1;
    let c_str = unsafe {
        let ptr = epan_sys::wmem_alloc(epan_sys::wmem_epan_scope(), size) as *mut c_char;
        ptr.copy_from(s.as_ptr() as *const c_char, s.len());
        *ptr.add(s.len()) = 0;
        ptr
    };

    c_str
}

pub enum DissectorDecodeFrom {
    DecodeAs(String),
    Uint(String, Vec<u32>),
}

/// Field types supported by Wireshark.
///
/// These correspond to the FT_* types in Wireshark's ftypes.h.
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

#[allow(non_camel_case_types)]
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

#[derive(Copy, Clone)]
pub enum PluginType {
    Dissector,
    FileType,
    Codec,
    Epan,
    TapListener,
    DFilter,
}

impl PluginType {
    pub fn to_constant(&self) -> u32 {
        match self {
            PluginType::Dissector => epan_sys::WS_PLUGIN_DESC_DISSECTOR,
            PluginType::FileType => epan_sys::WS_PLUGIN_DESC_FILE_TYPE,
            PluginType::Codec => epan_sys::WS_PLUGIN_DESC_CODEC,
            PluginType::Epan => epan_sys::WS_PLUGIN_DESC_EPAN,
            PluginType::TapListener => epan_sys::WS_PLUGIN_DESC_TAP_LISTENER,
            PluginType::DFilter => epan_sys::WS_PLUGIN_DESC_DFILTER,
        }
    }
}

pub type WiresharkResult<T> = Result<T, WiresharkError>;
pub type DissectorResult<T> = Result<T, DissectorError>;
pub type TreeResult<T> = Result<T, TreeError>;

#[derive(Debug, thiserror::Error)]
pub enum WiresharkError {
    #[error("Protocol registration failed: {0}")]
    RegistrationError(#[from] RegistrationError),
    #[error("Dissector error: {0}")]
    DissectorError(#[from] DissectorError),
    #[error("Expert info error: {0}")]
    ExpertError(#[from] ExpertError),
    #[error("Tree operation error: {0}")]
    TreeError(#[from] TreeError),
}

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("Protocol registration failed")]
    RegistrationFailed,
    #[error("Missing required dissector")]
    MissingDissector,
    #[error("Missing required field type")]
    MissingFieldType,
    #[error("Invalid field name: {0}")]
    InvalidFieldName(String),
    #[error("CString conversion error: {0}")]
    CStringError(#[from] std::ffi::NulError),
}

#[derive(Debug, thiserror::Error)]
pub enum DissectorError {
    #[error("TVB error: {0}")]
    TvbError(#[from] TvbError),
    #[error("Field not found: {0}")]
    FieldNotFound(String),
    #[error("Invalid packet data")]
    InvalidPacketData,
}

#[derive(Debug, thiserror::Error)]
pub enum TreeError {
    #[error("Failed to add item to tree: {0}")]
    AddItemFailed(String),
    #[error("Invalid subtree operation: {0}")]
    InvalidSubtreeOperation(String),
    #[error("Ett not found: {0}")]
    EttNotFound(String),
}

#[derive(Debug, thiserror::Error)]
pub enum TvbError {
    #[error("Range out of bounds")]
    OutOfBounds,
    #[error("Invalid range parameters")]
    InvalidRange,
    #[error("Invalid length: expected {expected}, got {actual}")]
    InvalidLength { expected: i32, actual: i32 },
    #[error("Invalid encoding for operation")]
    InvalidEncoding,
    #[error("Failed to create subset TVB")]
    SubsetFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum ExpertError {
    #[error("Expert field not found: {0}")]
    FieldNotFound(String),
    #[error("Failed to add expert info")]
    AddFailed,
}

