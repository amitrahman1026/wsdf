#[allow(unused, static_mut_refs)]
// Requires a few things when setting up a protocol dissector
// mod wsdfproto_protocol {
use epan_sys;

// Protocol and registered fields
static mut PROTO_WSDFPROTO: i32 = -1; // protocol number?
static mut HF_FIELD_WSDFPROTO: i32 = -1; // headerfield table number?
static mut EI_WSDFPROTO_EXPERT: epan_sys::expert_field = // ei table number
    epan_sys::expert_field { ei: -1, hf: -1 };

// Protocol dissector handles
static mut WSDFPROTO_HANDLE: epan_sys::dissector_handle_t = std::ptr::null_mut();
// static mut WSDFPROTO_TLS_HANDLE: epan_sys::dissector_handle_t = std::ptr::null_mut();

// Global protocol preferences
// static mut PREF_HEX: bool = false;

// Global sample port preference ->
// need to support both a range taken in as ""(for a range) or 0 (for single uint)
// or a specific IANA registered port if there is one for this protocol
// you can set with
// const WSDFPROTO_TLS_PORT_PREF_FALLBACK: u32 = 5678;
// static mut TLS_PORT_PREF: u32 = 0;

// const WSDFPROTO_TCP_PORT_PREF_FALLBACK: &str = "1234";
// static mut TCP_PORT_RANGE: *mut epan_sys::range_t = std::ptr::null_mut(); // this is the

// Subtree index pointer(s)
static mut ETT_WSDFPROTO: i32 = -1;

// Some examples of heuristics included in wireshark
// This is done as a define to indicate min number of bytes otherwise reject this package
const WSDFPROTO_MIN_LENGTH: u32 = 8;
const WSDFPROTO_MAX_LENGTH_LENGTH_NEEDED_FOR_HEURISTIC: u32 = 8; // Seems like an uncommon usage
const WSDFPROTO_BOOLEAN_HEURISTIC: bool = false;

#[no_mangle]
unsafe extern "C" fn dissect_wsdfproto(
    tvb: *mut epan_sys::tvbuff,
    pinfo: *mut epan_sys::packet_info,
    tree: *mut epan_sys::proto_tree,
    data: *mut std::ffi::c_void,
) -> i32 {
    /* Heuristics */

    // Basic heuristic of minimum length for packets -> could be an optional attribute
    if (epan_sys::tvb_reported_length(tvb) < WSDFPROTO_MIN_LENGTH) {
        return 0;
    }

    if (epan_sys::tvb_reported_length(tvb) < WSDFPROTO_MAX_LENGTH_LENGTH_NEEDED_FOR_HEURISTIC) {
        return 0;
    }

    // Stranger heuristic in the example perhaps it should be bundled up into some
    // injectible function that has access to args (tvb, packet_info, proto_tree, data)
    // but retruns some thing covertible to bool, but this should be done with caution
    // or a panic handle that will signal into info col.
    // This could also remain like the decode_with() functionality we have right now
    if (WSDFPROTO_BOOLEAN_HEURISTIC) {
        return 0;
    }

    /* Column data */
    // Theres two sections the 'Protocol' column (convention is to contain the protocol abbreviation)
    // and the 'Info' column which will be arbitrary misc. information
    // Safest api to expose are col_set_tr, col_append_str
    epan_sys::col_clear((*pinfo).cinfo, epan_sys::COL_INFO as _); // Clear info column before filling it (looks like good practice from moldudp64)
    let proto_abbvr_str = std::ffi::CString::new("WSDFPROTO").unwrap(); // this needs to be leaked? given?
    epan_sys::col_set_str(
        (*pinfo).cinfo,
        epan_sys::COL_INFO as _,
        proto_abbvr_str.as_ptr(),
    );

    let info_col_str = Box::leak(
        std::ffi::CString::new("wsdf proto message")
            .unwrap()
            .into_boxed_c_str(),
    );

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
    let len = 4; // Example length

    let expert_ti = epan_sys::proto_tree_add_item(
        wsdfproto_subtree,
        HF_FIELD_WSDFPROTO,
        tvb,
        offset,
        len,
        epan_sys::ENC_BIG_ENDIAN,
    );

    offset += len;

    // Example expert info addition
    if WSDFPROTO_BOOLEAN_HEURISTIC {
        epan_sys::expert_add_info(pinfo, expert_ti, &mut EI_WSDFPROTO_EXPERT);
    }

    epan_sys::tvb_captured_length(tvb) as i32
}

// Protocol registration
#[no_mangle]
pub unsafe extern "C" fn proto_register_wsdfproto() {
    // Register protocol fields
    let hf = [epan_sys::hf_register_info {
        /* ---------- set by dissector --------- */
        p_id: &mut HF_FIELD_WSDFPROTO,
        hfinfo: epan_sys::header_field_info {
            name: b"WSDF Field\0".as_ptr() as *const i8,
            abbrev: b"wsdfproto.field\0".as_ptr() as *const i8,
            type_: epan_sys::ftenum_FT_NONE,
            display: epan_sys::field_display_e_BASE_NONE as i32,
            strings: std::ptr::null(),
            bitmask: 0,
            blurb: b"Example WSDF Protocol Field\0".as_ptr() as *const i8,
            /* ------- set by register routines (prefilled with some conventional default values) ------ */
            // HFILL macro would set this (set by proto routines) {
            id: -1,
            parent: 0,
            ref_type: epan_sys::hf_ref_type_HF_REF_TYPE_NONE,
            same_name_prev_id: -1,
            same_name_next: std::ptr::null_mut(),
            // }
        },
    }];

    // Register subtrees
    let ett = [&mut ETT_WSDFPROTO];

    // Register expert info
    let ei = [epan_sys::ei_register_info {
        ids: &mut EI_WSDFPROTO_EXPERT,
        eiinfo: epan_sys::expert_field_info {
            /* ---------- set by dissector --------- */
            name: b"wsdfproto.expertabbrev\0".as_ptr() as *const i8,
            group: epan_sys::PI_MALFORMED as i32,
            severity: epan_sys::PI_WARN as i32,
            summary: b"WSDF Protocol Expert Info\0".as_ptr() as *const i8,
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
    }];

    // Register the protocol
    let proto_name = std::ffi::CString::new("WSDF Protocol").unwrap();
    let proto_short = std::ffi::CString::new("WSDFPROTO").unwrap();
    let proto_filter = std::ffi::CString::new("wsdfproto").unwrap();

    // Register the rpotocol name and description and get protocol id
    PROTO_WSDFPROTO = epan_sys::proto_register_protocol(
        proto_name.as_ptr(),
        proto_short.as_ptr(),
        proto_filter.as_ptr(),
    );

    // Register (header) fieds
    epan_sys::proto_register_field_array(
        PROTO_WSDFPROTO,
        hf.as_ptr() as *mut epan_sys::hf_register_info,
        hf.len() as i32,
    );

    // Register subtree types
    // The ett_ variables identify particular type of subtree so that if you expand
    // one of them, Wireshark keeps track of that and, when you click on
    // another packet, it automatically opens all subtrees of that type.
    // If you close one of them, all subtrees of that type will be closed when
    // you move to another packet.
    epan_sys::proto_register_subtree_array(ett.as_ptr() as *mut *mut i32, ett.len() as i32);

    // Register expert info
    let expert_module = epan_sys::expert_register_protocol(PROTO_WSDFPROTO);
    epan_sys::expert_register_field_array(
        expert_module,
        ei.as_ptr() as *mut epan_sys::ei_register_info,
        ei.len() as i32,
    );

    // // Register dissector
    // WSDFPROTO_HANDLE = epan_sys::register_dissector(
    //     b"wsdfproto\0".as_ptr() as *const i8,
    //     Some(dissect_wsdfproto),
    //     PROTO_WSDFPROTO,
    // );
    WSDFPROTO_HANDLE = epan_sys::create_dissector_handle(Some(dissect_wsdfproto), PROTO_WSDFPROTO);
}

// Protocol handoff registration
#[no_mangle]
pub unsafe extern "C" fn proto_reg_handoff_wsdfproto() {
    // Subdissectors will register themselves with the dissector table using their unique identifier using one of the following APIs:
    // epan_sys::dissector_add_for_decode_as(
    //     b"tcp.port\0".as_ptr() as *const i8,
    //     WSDFPROTO_HANDLE,
    // );
    epan_sys::dissector_add_uint(b"ip.port\0".as_ptr() as *const i8, 17, WSDFPROTO_HANDLE);
}
// Final step: Protocol dissector -> pluginisation needs
#[no_mangle]
pub extern "C" fn plugin_describe() -> u32 {
    wsdf::epan_sys::WS_PLUGIN_DESC_EPAN
}
#[no_mangle]
pub extern "C" fn plugin_register() {
    static mut PLUG_0: wsdf::epan_sys::proto_plugin = wsdf::epan_sys::proto_plugin {
        register_protoinfo: Some(proto_reg_handoff_wsdfproto),
        register_handoff: Some(proto_reg_handoff_wsdfproto),
    };
    unsafe {
        wsdf::epan_sys::proto_register_plugin(&PLUG_0);
    }
}
#[no_mangle]
#[used]
#[allow(non_upper_case_globals)]
static plugin_version: [std::ffi::c_char; 6usize] = [48i8, 46i8, 48i8, 46i8, 49i8, 0i8];
#[no_mangle]
#[used]
#[allow(non_upper_case_globals)]
static plugin_want_major: std::ffi::c_int = 4;
#[no_mangle]
#[used]
#[allow(non_upper_case_globals)]
static plugin_want_minor: std::ffi::c_int = 4;
// }
