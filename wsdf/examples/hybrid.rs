use epan_sys;
use std::{
    collections::HashMap,
    ffi::{c_int, c_void, CString},
};
use wsdf::wireshark::*;

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
    pub fn add_protocol(&mut self, protocol: Protocol) {
        let id = protocol.abbrev.clone();
        self.protocols.insert(id, protocol);
    }
    pub unsafe fn get() -> &'static mut Self {
        PLUGIN.as_mut().expect("Plugin not initialized")
    }
}

pub unsafe extern "C" fn proto_register_protos() {
    let plugin = Plugin::get();
    let protocol = build_example_protocol().unwrap();
    // TODO: we can even move this plugin add_protocol to
    // inside build because of the singleton pattern
    plugin.add_protocol(protocol);

    let _: Vec<_> = plugin
        .protocols
        .iter_mut()
        .map(|(_, protocol)| {
            protocol.register();
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
// TODO: figure out how to encapsulate this. Can this be part of protocol? and we pass the function
// pointer from this to create_dissector_handle()
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

pub fn build_example_protocol() -> Result<Protocol, RegistrationError> {
    let name = "WSDF Example Protocol";
    let abbrev = "wsdf";
    let filter = "wsdf_example";
    let protocol = ProtocolBuilder::new(name, abbrev, filter)
        .dissector(Dissector::new(|tree: &mut Tree<'_>| {
            // Set protocol columns
            tree.pinfo.set_column_text(Column::Protocol, "WSDF Example");

            // Creating a subtree to represent the header of the protocol
            let mut header_tree = tree
                .add_subtree("header_field", "header")
                .expect("Unable to create header tree! Have you registered field_id and ett_id?");
            // First field demonstrates basic field addition and expert info
            let mut field1_item = header_tree
                .add_item("field1", 1, Encoding::BigEndian)
                .unwrap();
            header_tree.add_expert_info(&mut field1_item, "expert_condition1", None);

            // Second field shows text manipulation
            let mut field2_item = header_tree
                .add_item("field2", 2, Encoding::BigEndian)
                .unwrap();
            header_tree.add_expert_info(
                &mut field2_item,
                "expert_condition2",
                Some("Custom expert info with dynamic text!"),
            );

            tree.end_subtree(&header_tree);

            // Creating a subtree to represent the payload of the protocol
            let mut payload_tree = tree.add_subtree("payload_field", "payload").expect(
                "Unable to create payload tree! Have you registered the field_id and ett_id?",
            );

            // Compression flag and original size
            let mut flag_item: TreeItem = payload_tree
                .add_item("comp_flag", 1, Encoding::BigEndian)
                .unwrap();
            let flag_value = flag_item.tvb.get_uint8(payload_tree.tvb.start);

            let mut size_item = payload_tree
                .add_item("orig_size", 2, Encoding::BigEndian)
                .unwrap();
            let orig_size = size_item
                .tvb
                .get_uint16(payload_tree.tvb.offset, Encoding::BigEndian)
                as u32;

            tree.end_subtree(&payload_tree);

            // Example transformation based on flag
            if flag_value & 0x80 != 0 {
                // Check MSB for compression flag
                flag_item.append_text(" (Compressed data)");
                size_item.append_text(
                    format!(" ({} bytes after decompression)", orig_size * 2).as_str(),
                );

                // Our example "decompression" function simply duplicates each byte
                // In real protocols this would be actual decompression
                if let Some(mut decompressed_tree) =
                    payload_tree.transform_data(orig_size, |src, dst| {
                        let mut dst_idx = 0;
                        for &byte in src.iter() {
                            if dst_idx + 1 < dst.len() {
                                dst[dst_idx] = byte;
                                dst[dst_idx + 1] = byte;
                                dst_idx += 2;
                            }
                        }
                        Ok(())
                    })
                {
                    // Transformed decompressed data can be added as a new field
                    let mut payload_item = decompressed_tree
                        .add_item("decompressed_data", orig_size as i32, Encoding::NA)
                        .unwrap();

                    tree.add_expert_info(
                        &mut payload_item,
                        "expert_transform",
                        Some("Data was decompressed - each byte duplicated"),
                    );

                    tree.pinfo.set_column_text(
                        Column::Info,
                        &format!("Decompressed {} bytes of data", orig_size),
                    );
                }
            } else {
                flag_item.append_text(" (Uncompressed data)");

                // Just show raw bytes for uncompressed data
                let mut payload_item = tree.add_item("raw_data", 4, Encoding::NA).unwrap();
                tree.add_expert_info(
                    &mut payload_item,
                    "expert_transform",
                    Some("Uncompressed data shown directly!"),
                );

                tree.pinfo
                    .set_column_text(Column::Info, "Uncompressed data");
            }

            tree.get_reported_length()
        }))
        .ett("header", "Header Fields")
        .ett("payload", "Payload Fields")
        .field(
            FieldBuilder::new("header_field", "Header Field", "wsdf.header_field")
                .field_type(FieldType::None)
                .display(FieldDisplay::None)
                .build()?,
        )
        .field(
            FieldBuilder::new("payload_field", "Payload Field", "wsdf.payload_field")
                .field_type(FieldType::None)
                .display(FieldDisplay::None)
                .build()?,
        )
        .field(
            FieldBuilder::new("field1", "First Field", "wsdf.field1")
                .field_type(FieldType::Uint8)
                .display(FieldDisplay::BaseDec)
                .build()?,
        )
        .field(
            FieldBuilder::new("field2", "Second Field", "wsdf.field2")
                .field_type(FieldType::Uint16)
                .display(FieldDisplay::BaseHex)
                .build()?,
        )
        .field(
            FieldBuilder::new("comp_flag", "Compression Flag", "wsdf.comp_flag")
                .field_type(FieldType::Uint8)
                .display(FieldDisplay::BaseHex)
                .build()?,
        )
        .field(
            FieldBuilder::new("orig_size", "Original Size", "wsdf.orig_size")
                .field_type(FieldType::Uint16)
                .display(FieldDisplay::BaseDec)
                .build()?,
        )
        .field(
            FieldBuilder::new(
                "decompressed_data",
                "Decompressed Data",
                "wsdf.decompressed",
            )
            .field_type(FieldType::Bytes)
            .display(FieldDisplay::None)
            .build()?,
        )
        .field(
            FieldBuilder::new("raw_data", "Raw Data", "wsdf.raw")
                .field_type(FieldType::Bytes)
                .display(FieldDisplay::None)
                .build()?,
        )
        .expert_info(
            "expert_condition1",
            ExpertGroup::Assumption,
            ExpertSeverity::Note,
            "Basic field processing completed",
        )
        .expert_info(
            "expert_condition2",
            ExpertGroup::Sequence,
            ExpertSeverity::Chat,
            "Field manipulation demonstration",
        )
        .expert_info(
            "expert_transform",
            ExpertGroup::Protocol,
            ExpertSeverity::Note,
            "Data transformation status",
        )
        .decode_from(DissectorDecodeFrom::Uint("ip.proto".into(), vec![17]))
        .build()?;

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
