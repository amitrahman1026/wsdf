use wsdf::{plugin, wireshark::*};

plugin!(build_example_protocol);

pub fn build_example_protocol() -> Result<Protocol, RegistrationError> {
    let name = "WSDF Example Protocol";
    let abbrev = "wsdf";
    let filter = "wsdf_example";
    let protocol = ProtocolBuilder::new(name, abbrev, filter)
        .dissector(Dissector::new(
            |tree, tvb| -> Result<i32, Box<dyn std::error::Error>> {
                // Set protocol columns
                tree.pinfo.set_column_text(Column::Protocol, "WSDF Example");

                // Create ranges for data access. Analogous to Lua API tvb(offset, length)
                // Reference: wslua_tvb.c Tvb_range() - see test/lua/tvb.lua:268 for usage
                let header_range = tvb.range(0, 3)?; // Header is 3 bytes (1 + 2)
                let payload_range = tvb.range(3, -1)?; // Rest of packet

                // Add header subtree using range. Analogous to Lua API tree:add(field, range)
                // Reference: wslua_tree.c TreeItem_add() - see test/lua/tvb.lua:283 for usage
                let mut header_tree: Tree<'_> = tree.add("header_field", header_range)?;

                // Create sub-ranges for individual fields
                let field1_range = header_range.range(0, 1)?;
                let field2_range = header_range.range(1, 2)?;

                // Add fields to tree and extract values
                // field1 demonstrates basic field addition and expert info
                let mut field1_item: TreeItem = header_tree.add_item("field1", field1_range)?;
                let _ = tree.add_expert_info(&mut field1_item, "expert_condition1", None);

                // field2 demonstrates text manipulation
                let mut field2_item: TreeItem = header_tree.add_item("field2", field2_range)?;
                let _ = tree.add_expert_info(
                    &mut field2_item,
                    "expert_condition2",
                    Some("Custom expert info with dynamic text!"),
                );

                // Creating a subtree to represent the payload of the protocol
                let mut payload_tree: Tree<'_> = tree.add("payload_field", payload_range)?;

                // Create ranges for payload fields
                let flag_range = payload_range.range(0, 1)?;
                let size_range = payload_range.range(1, 2)?;

                // Add payload fields and extract values
                // Analogous to Lua API tree:add() and range:uint() - see test/lua/tvb.lua:315-322
                let mut flag_item: TreeItem = payload_tree.add_item("comp_flag", flag_range)?;
                let flag_value = flag_range.uint8()?; // Like Lua's TvbRange:uint()

                let mut size_item: TreeItem = payload_tree.add_item("orig_size", size_range)?;
                let orig_size = size_range.uint16(Encoding::BigEndian)? as u32; // Like Lua's TvbRange:uint()

                // Example transformation based on flag
                if flag_value & 0x80 != 0 {
                    // Check MSB for compression flag
                    flag_item.append_text(" (Compressed data)");
                    size_item
                        .append_text(&format!(" ({} bytes after decompression)", orig_size * 2));

                    // Get the remaining payload data range for transformation
                    let compressed_range = payload_range.range(3, -1)?;

                    // Our example "decompression" function simply duplicates each byte
                    // In real protocols this would be actual decompression
                    let decompressed_tvb = tree.transform_data(
                        compressed_range,
                        |src| {
                            let mut dst = Vec::with_capacity(src.len() * 2);
                            for &byte in src {
                                dst.push(byte);
                                dst.push(byte); // Duplicate each byte
                            }
                            Ok(dst)
                        },
                        "Decompressed Data",
                    )?;

                    // Add the decompressed data as a new field
                    let decompressed_range = decompressed_tvb.range_all();
                    let mut payload_item =
                        tree.add_item("decompressed_data", decompressed_range)?;

                    let _ = tree.add_expert_info(
                        &mut payload_item,
                        "expert_transform",
                        Some("Data was decompressed - each byte duplicated"),
                    );

                    tree.pinfo.set_column_text(
                        Column::Info,
                        &format!("Decompressed {} bytes of data", orig_size),
                    );
                } else {
                    flag_item.append_text(" (Uncompressed data)");

                    // Show raw bytes for uncompressed data
                    let raw_data_range = payload_range.range(3, 4)?;
                    let mut payload_item: TreeItem = tree.add_item("raw_data", raw_data_range)?;
                    let _ = tree.add_expert_info(
                        &mut payload_item,
                        "expert_transform",
                        Some("Uncompressed data shown directly!"),
                    );

                    tree.pinfo
                        .set_column_text(Column::Info, "Uncompressed data");
                }

                Ok(tvb.reported_length())
            },
        ))
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
