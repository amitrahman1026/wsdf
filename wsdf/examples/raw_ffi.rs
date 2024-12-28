#[allow(unused, static_mut_refs)]
// Requires a few things when setting up a protocol dissector
use epan_sys;

// Protocol and registered fields (eg. headers, expert fields)
static mut PROTO_WSDFPROTO: i32 = -1; // protocol id number

// Header field
static mut HF_FIELD_VERSION: i32 = -1;
static mut HF_FIELD_TYPE: i32 = -1;
static mut HF_FIELD_LENGTH: i32 = -1;
static mut HF_FIELD_PAYLOAD: i32 = -1;

// Expert info fields
static mut EI_MALFORMED_LENGTH: epan_sys::expert_field = epan_sys::expert_field { ei: -1, hf: -1 };
static mut EI_UNKNOWN_TYPE: epan_sys::expert_field = epan_sys::expert_field { ei: -1, hf: -1 };

// Subtree indices
static mut ETT_WSDFPROTO: i32 = -1;
static mut ETT_PAYLOAD: i32 = -1;

// Protocol handles
static mut WSDFPROTO_HANDLE: epan_sys::dissector_handle_t = std::ptr::null_mut();
// static mut WSDFPROTO_TLS_HANDLE: epan_sys::dissector_handle_t = std::ptr::null_mut();

// For constant protocol-level strings, we should use some statics:
static PROTO_ABBREV: &[u8] = b"WSDFPROTO\0";
static PROTO_NAME: &[u8] = b"WSDF Protocol\0";
static PROTO_FILTER: &[u8] = b"wsdfproto\0";

// Static & constants for a protocol
// Some examples of heuristics included in wireshark
// This is done as a define to indicate min number of bytes otherwise reject this package
const WSDFPROTO_MIN_LENGTH: u32 = 8;
const WSDFPROTO_HEADER_LENGTH: u32 = 4;

const TYPE_REQUEST: u8 = 1;
const TYPE_RESPONSE: u8 = 2;

/*
// Global protocol preferences
static mut PREF_HEX: bool = false;

// Global sample port preference ->
// need to support both a range taken in as ""(for a range) or 0 (for single uint)
// or a specific IANA registered port if there is one for this protocol
// you can set with
const WSDFPROTO_TLS_PORT_PREF_FALLBACK: u32 = 5678;
static mut TLS_PORT_PREF: u32 = 0;

const WSDFPROTO_TCP_PORT_PREF_FALLBACK: &str = "1234";
static mut TCP_PORT_RANGE: *mut epan_sys::range_t = std::ptr::null_mut(); // this is the
 */

#[no_mangle]
unsafe extern "C" fn dissect_wsdfproto(
    tvb: *mut epan_sys::tvbuff,
    pinfo: *mut epan_sys::packet_info,
    tree: *mut epan_sys::proto_tree,
    _data: *mut std::ffi::c_void,
) -> i32 {
    /* Heuristics */

    // Basic heuristic of minimum length for packets -> could be an optional attribute
    let tvb_length = epan_sys::tvb_reported_length(tvb);
    if tvb_length < WSDFPROTO_MIN_LENGTH {
        return 0;
    }

    /* Column data */
    // Theres two sections the 'Protocol' column (convention is to contain the protocol abbreviation)
    // and the 'Info' column which will be arbitrary misc. information
    // Safest api to expose are col_set_tr, col_append_str

    // Clear and set protocol column when you dissect a packet (good practice used by many packet-* in wireshark)
    epan_sys::col_clear((*pinfo).cinfo, epan_sys::COL_INFO as i32);
    epan_sys::col_set_str(
        (*pinfo).cinfo,
        epan_sys::COL_PROTOCOL as _,
        PROTO_ABBREV.as_ptr() as _,
    );

    // Some dissection and packet analysis -> in wsdf, we would be getting this from the layout of user Rust code
    let version = epan_sys::tvb_get_uint8(tvb, 0);
    let msg_type = epan_sys::tvb_get_uint8(tvb, 1);
    let length = epan_sys::tvb_get_ntohs(tvb, 2) as u32;

    // Format source/destination info
    let src_port = std::net::Ipv4Addr::from((*pinfo).srcport).to_string();
    // let dst_port = std::net::Ipv4Addr::from((*pinfo).destport).to_string();
    let dst_port = (*pinfo).destport;

    // Add information to the INFO column
    let msg_typ = match msg_type {
        TYPE_REQUEST => "Request",
        TYPE_RESPONSE => "Response",
        _ => "Unknown",
    };
    let formatted_str = format!(
        "{} (v{}) {} -> {} Len={}",
        version, msg_typ, src_port, dst_port, length
    );
    let info_col_str = wmem_strdup_printf((*pinfo).pool, formatted_str);

    epan_sys::col_clear((*pinfo).cinfo, epan_sys::COL_INFO as i32);
    epan_sys::col_set_str((*pinfo).cinfo, epan_sys::COL_INFO as _, info_col_str);

    /* Protocol Tree Construction */
    // Create the main protocol tree item for this packet
    // The tree is displayed in the packet details pane
    let tree_item: *mut epan_sys::proto_node = epan_sys::proto_tree_add_item(
        tree,
        PROTO_WSDFPROTO,
        tvb,
        0,
        -1, // Length -1 means "to the end of the buffer"
        epan_sys::ENC_NA,
    );

    // Add fields to subtree
    // Sub-trees are somewhat stylistic, but generally are used for protocol sub-elements
    // that have multiple elements of their own. Without sub-trees, every element in your
    // protocol would be in a flat list under the protocol tree.
    let wsdfproto_subtree: *mut epan_sys::proto_node =
        epan_sys::proto_item_add_subtree(tree_item, ETT_WSDFPROTO);

    let mut offset = 0;

    epan_sys::proto_tree_add_item(
        wsdfproto_subtree,
        HF_FIELD_VERSION,
        tvb,
        offset,
        1,
        epan_sys::ENC_BIG_ENDIAN,
    );
    offset += 1;

    let type_tree_item: *mut epan_sys::proto_node = epan_sys::proto_tree_add_item(
        wsdfproto_subtree,
        HF_FIELD_TYPE,
        tvb,
        offset,
        1,
        epan_sys::ENC_BIG_ENDIAN,
    );
    offset += 1;

    // Add expert info for unknown message type
    if msg_type != TYPE_REQUEST && msg_type != TYPE_RESPONSE {
        epan_sys::expert_add_info(pinfo, type_tree_item, &raw mut EI_UNKNOWN_TYPE);
    }

    let length_tree_item = epan_sys::proto_tree_add_item(
        wsdfproto_subtree,
        HF_FIELD_LENGTH,
        tvb,
        offset,
        2,
        epan_sys::ENC_BIG_ENDIAN,
    );

    offset += 2;

    // Check for malformed length
    if length > tvb_length - WSDFPROTO_HEADER_LENGTH {
        epan_sys::expert_add_info(pinfo, length_tree_item, &raw mut EI_MALFORMED_LENGTH);
    }

    offset as i32
}

// Protocol registration
#[no_mangle]
pub unsafe extern "C" fn proto_register_wsdfproto() {
    // Register protocol fields

    static mut hf: [epan_sys::hf_register_info; 4] = [
        epan_sys::hf_register_info {
            /* ---------- set by dissector --------- */
            p_id: &raw mut HF_FIELD_VERSION,
            hfinfo: epan_sys::header_field_info {
                name: b"Version\00".as_ptr() as *const i8,
                abbrev: b"wsdfproto.version\0".as_ptr() as *const i8,
                type_: epan_sys::ftenum_FT_UINT8,
                display: epan_sys::field_display_e_BASE_DEC as i32,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: b"WSDF Protocol Version\0".as_ptr() as *const i8,
                /* ------- set by register routines (prefilled with some conventional default values) ------ */
                // HFILL macro would set this (set by proto routines) {
                id: -1,
                parent: 0,
                ref_type: epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
                // }
            },
        },
        epan_sys::hf_register_info {
            /* ---------- set by dissector --------- */
            p_id: &raw mut HF_FIELD_TYPE,
            hfinfo: epan_sys::header_field_info {
                name: b"Type\0".as_ptr() as *const i8,
                abbrev: b"wsdfproto.type\0".as_ptr() as *const i8,
                type_: epan_sys::ftenum_FT_UINT8,
                display: epan_sys::field_display_e_BASE_DEC as i32,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: b"WSDF Protocol Type\0".as_ptr() as *const i8,
                /* ------- set by register routines (prefilled with some conventional default values) ------ */
                // HFILL macro would set this (set by proto routines) {
                id: -1,
                parent: 0,
                ref_type: epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
                // }
            },
        },
        epan_sys::hf_register_info {
            /* ---------- set by dissector --------- */
            p_id: &raw mut HF_FIELD_LENGTH,
            hfinfo: epan_sys::header_field_info {
                name: b"Length\0".as_ptr() as *const i8,
                abbrev: b"wsdfproto.length\0".as_ptr() as *const i8,
                type_: epan_sys::ftenum_FT_UINT16,
                display: epan_sys::field_display_e_BASE_DEC as i32,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: b"WSDF Protocol Length\0".as_ptr() as *const i8,
                /* ------- set by register routines (prefilled with some conventional default values) ------ */
                // HFILL macro would set this (set by proto routines) {
                id: -1,
                parent: 0,
                ref_type: epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
                // }
            },
        },
        epan_sys::hf_register_info {
            /* ---------- set by dissector --------- */
            p_id: &raw mut HF_FIELD_PAYLOAD,
            hfinfo: epan_sys::header_field_info {
                name: b"Length\0".as_ptr() as *const i8,
                abbrev: b"wsdfproto.length\0".as_ptr() as *const i8,
                type_: epan_sys::ftenum_FT_UINT_BYTES,
                display: epan_sys::field_display_e_SEP_DOT as i32,
                strings: std::ptr::null(),
                bitmask: 0,
                blurb: b"WSDF Protocol Length\0".as_ptr() as *const i8,
                /* ------- set by register routines (prefilled with some conventional default values) ------ */
                // HFILL macro would set this (set by proto routines) {
                id: -1,
                parent: 0,
                ref_type: epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                same_name_prev_id: -1,
                same_name_next: std::ptr::null_mut(),
                // }
            },
        },
    ];

    // Register subtrees
    static mut ett: [*mut i32; 2] = [
        &raw mut ETT_WSDFPROTO as *mut i32,
        &raw mut ETT_PAYLOAD as *mut i32,
    ];

    // Register expert info
    static mut ei: [epan_sys::ei_register_info; 2] = [
        epan_sys::ei_register_info {
            ids: &raw mut EI_MALFORMED_LENGTH,
            eiinfo: epan_sys::expert_field_info {
                /* ---------- set by dissector --------- */
                name: b"wsdfproto.malformed_length\0".as_ptr() as *const i8,
                group: epan_sys::PI_MALFORMED as i32,
                severity: epan_sys::PI_ERROR as i32,
                summary: b"WSDF Protocol malformed length\0".as_ptr() as *const i8,
                /* ------- set by register routines (prefilled with some conventional default values) ------ */
                // EXPFILL macro would set this (set by expert routines) {
                id: 0,
                protocol: std::ptr::null(),
                orig_severity: 0,
                hf_info: epan_sys::hf_register_info {
                    p_id: std::ptr::null_mut() as *mut i32,
                    hfinfo: epan_sys::_header_field_info {
                        name: std::ptr::null(),
                        abbrev: std::ptr::null(),
                        type_: epan_sys::ftenum_FT_NONE,
                        display: epan_sys::field_display_e_BASE_NONE as i32,
                        strings: std::ptr::null(),
                        bitmask: 0,
                        blurb: std::ptr::null(),
                        // HFILL macro would set this (set by proto routines) {
                        id: -1,
                        parent: 0,
                        ref_type: epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                        same_name_prev_id: -1,
                        same_name_next: std::ptr::null_mut(),
                        // }
                    },
                    // }
                },
            },
        },
        epan_sys::ei_register_info {
            ids: &raw mut EI_UNKNOWN_TYPE,
            eiinfo: epan_sys::expert_field_info {
                /* ---------- set by dissector --------- */
                name: b"wsdfproto.unknown_type\0".as_ptr() as *const i8,
                group: epan_sys::PI_MALFORMED as i32,
                severity: epan_sys::PI_ERROR as i32,
                summary: b"WSDF Protocol unknown type\0".as_ptr() as *const i8,
                /* ------- set by register routines (prefilled with some conventional default values) ------ */
                // EXPFILL macro would set this (set by expert routines) {
                id: 0,
                protocol: std::ptr::null(),
                orig_severity: 0,
                hf_info: epan_sys::hf_register_info {
                    p_id: std::ptr::null_mut() as *mut i32,
                    hfinfo: epan_sys::_header_field_info {
                        name: std::ptr::null(),
                        abbrev: std::ptr::null(),
                        type_: epan_sys::ftenum_FT_NONE,
                        display: epan_sys::field_display_e_BASE_NONE as i32,
                        strings: std::ptr::null(),
                        bitmask: 0,
                        blurb: std::ptr::null(),
                        // HFILL macro would set this (set by proto routines) {
                        id: -1,
                        parent: 0,
                        ref_type: epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
                        same_name_prev_id: -1,
                        same_name_next: std::ptr::null_mut(),
                        // }
                    },
                    // }
                },
            },
        },
    ];

    /* Protocol id Registration */

    // Register the protocol name and description and get protocol id
    PROTO_WSDFPROTO = epan_sys::proto_register_protocol(
        PROTO_NAME.as_ptr() as *const i8,
        PROTO_ABBREV.as_ptr() as *const i8,
        PROTO_FILTER.as_ptr() as *const i8,
    );

    // Register (header) fieds
    epan_sys::proto_register_field_array(
        PROTO_WSDFPROTO,
        hf.as_ptr() as *mut epan_sys::hf_register_info,
        hf.len() as i32,
    );

    // Register subtree types
    // The ett_* variables identify particular type of subtree so that if you expand
    // one of them, Wireshark keeps track of that and, when you click on
    // another packet, it automatically opens all subtrees of that type.
    // If you close one of them, all subtrees of that type will be closed when
    // you move to another packet.
    epan_sys::proto_register_subtree_array(ett.as_ptr() as *const *mut i32, ett.len() as i32);

    // Register expert info
    let expert_module = epan_sys::expert_register_protocol(PROTO_WSDFPROTO);
    epan_sys::expert_register_field_array(
        expert_module,
        ei.as_ptr() as *mut epan_sys::ei_register_info,
        ei.len() as i32,
    );
}

// Protocol handoff registration
#[no_mangle]
pub unsafe extern "C" fn proto_reg_handoff_wsdfproto() {
    // Register dissector, using create_dissector_handle is the new reccomended way
    WSDFPROTO_HANDLE = epan_sys::create_dissector_handle(Some(dissect_wsdfproto), PROTO_WSDFPROTO);
    // Subdissectors will register themselves with the dissector table using their unique identifier using one of the following APIs:
    epan_sys::dissector_add_uint(
        b"ip.proto\0".as_ptr() as *const i8, // Register for IP protocol
        17,                                  // UDP protocol number
        WSDFPROTO_HANDLE,
    );
}
// Final step: Protocol dissector -> pluginisation needs, pluging_describe() plugin_register(),  plugin_want_major, plugin_want_minor MUST publicly visible symbols
// Optionally plugin_version maybe be made visible as well
#[no_mangle]
pub extern "C" fn plugin_describe() -> u32 {
    wsdf::epan_sys::WS_PLUGIN_DESC_EPAN
}
#[no_mangle]
pub extern "C" fn plugin_register() {
    static PLUG_0: wsdf::epan_sys::proto_plugin = wsdf::epan_sys::proto_plugin {
        register_protoinfo: Some(proto_register_wsdfproto),
        register_handoff: Some(proto_reg_handoff_wsdfproto),
    };
    unsafe {
        wsdf::epan_sys::proto_register_plugin(&raw const PLUG_0);
    }
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

// Helper function to allocate memory for strings to be used within the lifetime of dissection
unsafe fn wmem_strdup_printf(
    allocator: *mut epan_sys::wmem_allocator_t,
    text: String,
) -> *const i8 {
    let c_str = std::ffi::CString::new(text).unwrap();
    epan_sys::wmem_strdup(allocator, c_str.as_ptr())
}
