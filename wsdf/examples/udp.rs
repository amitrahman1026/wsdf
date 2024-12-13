#![allow(dead_code)]

use wsdf::{
    protocol,
    tap::{Field, Offset, PacketInfo},
    version, Dissect, Proto,
};

protocol!(Udp);
version!("0.0.1", 4, 4);

// The ip.proto field obtained from http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml

#[derive(Proto, Dissect)]
#[wsdf(
    proto_desc = "Baby UDP by wsdf",
    proto_name = "Baby UDP",
    proto_filter = "baby_udp",
    decode_from = [("ip.proto", 17)],
)]
struct Udp {
    #[wsdf(tap = "describe_src_port")]
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
    #[wsdf(bytes, subdissector = ("baby_udp.port", "src_port", "dst_port"), tap = "describe_payload")]
    payload: Vec<u8>,
}

fn describe_src_port(pinfo: PacketInfo, Field(x): Field<u16>) {
    pinfo.append_col_info(&format!("Source Port = {} | ", x));
}

// The tap system allows us to combine different types of field information:
// - Field gives us access to the actual field value
// - Packet gives us access to the raw packet data
// - Offset tells us where in the packet we are
fn describe_payload(
    pinfo: PacketInfo,
    Field(payload): Field<&[u8]>, // Get the actual payload bytes
    Offset(offset): Offset,       // Get the offset where this field starts
) {
    if payload.is_empty() {
        pinfo.append_col_info("No payload");
        return;
    }

    const MAX_DISPLAY_BYTES: usize = 8;
    let display_len = payload.len().min(MAX_DISPLAY_BYTES);

    let hex_bytes: Vec<String> = payload[..display_len]
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    let payload_preview = hex_bytes.join(":");

    if payload.len() > MAX_DISPLAY_BYTES {
        pinfo.append_col_info(&format!(
            "Payload[{}] = {}...",
            payload.len(),
            payload_preview
        ));
    } else {
        pinfo.append_col_info(&format!("Payload[{}] = {}", payload.len(), payload_preview));
    }

    // Just for visibility we can show the offset where payload starts
    pinfo.append_col_info(&format!(" @offset {}", offset));
}
