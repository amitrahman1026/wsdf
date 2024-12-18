#![allow(dead_code)]

use wsdf::{
    protocol,
    tap::{Field, Fields, FieldsLocal, Packet, PacketInfo, PacketNanos},
    version, Dissect, Proto,
};

// This example will demonstrate how to use multiple protocol dissectors included in a single wireshark plug-in
//
protocol!(Arp, Icmp, Tcp);
version!("0.0.1", 4, 4);

#[derive(Proto, Dissect)]
#[wsdf(
    proto_desc = "Baby ARP by wsdf",
    proto_name = "Baby ARP",
    proto_filter = "baby_arp",
    decode_from = [("ethertype", 0x0806)], 
)]
struct Arp {
    hardware_type: u16,
    protocol_type: u16,
    hardware_size: u8,
    protocol_size: u8,
    // The save attribute allows us to access this field's value later via Fields
    // This is useful when we need to reference field values during analysis of other fields
    // NOTE: if we do not use the save attribute on a field, it will not be accesible except via FieldsLocal
    #[wsdf(save, decode_with = "decode_arp_operation")]
    operation: u16,
    // Using bytes attribute for MAC addresses since they should be treated as a contiguous byte string
    #[wsdf(bytes, save, decode_with = "decode_mac_address")]
    sender_mac: [u8; 6],
    #[wsdf(save)]
    sender_ip: u32,
    #[wsdf(bytes, save)]
    target_mac: [u8; 6],
    // In the final field we can use a tap fn to analyze the complete context
    #[wsdf(save, tap = "analyze_arp_transaction")]
    target_ip: u32,
}

fn decode_arp_operation(Field(op): Field<u16>) -> String {
    match op {
        1 => "REQUEST".to_string(),
        2 => "REPLY".to_string(),
        _ => format!("Unknown({})", op),
    }
}

fn decode_mac_address(Field(mac): Field<&[u8]>) -> String {
    mac.iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<_>>()
        .join(":")
}

// Shows how to use FieldsLocal vs Fields:
// - FieldsLocal gives access to fields within the current struct
// - Fields provides access to all saved fields in the packet
fn analyze_arp_transaction(
    pinfo: PacketInfo,
    FieldsLocal(local): FieldsLocal,
    Fields(fields): Fields,
    PacketNanos(ts): PacketNanos,
) {
    let op = local.get_u16("operation").unwrap();
    let sender_ip = fields.get_u32("baby_arp.sender_ip").unwrap();
    let target_ip = fields.get_u32("baby_arp.target_ip").unwrap();

    // Example of using PacketInfo to build rich protocol information
    pinfo.append_col_info(&format!(
        "{} {} -> {} at {} ns",
        if *op == 1 { "Who has" } else { "Here is" },
        format_ip(sender_ip),
        format_ip(target_ip),
        ts
    ));
}

// The ip.proto fields for the following protocols are obtained from http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml

#[derive(Proto, Dissect)]
#[wsdf(
    proto_desc = "Baby ICMP by wsdf",
    proto_name = "Baby ICMP", 
    proto_filter = "baby_icmp",
    decode_from = [("ip.proto", 1)],
)]
struct Icmp {
    // Using save + tap pattern to track ICMP message types
    #[wsdf(save, tap = "track_icmp_type")]
    type_: u8,
    code: u8,
    checksum: u16,
    rest_of_header: u32,
    // Demonstrates subdissector pattern for ICMP payloads
    #[wsdf(bytes, subdissector = "icmp.payload", tap = "analyze_icmp_payload")]
    payload: Vec<u8>,
}

// Example of complex protocol analysis using both saved fields and timestamp
fn track_icmp_type(pinfo: PacketInfo, Field(type_): Field<u8>, PacketNanos(ts): PacketNanos) {
    let type_str = match type_ {
        0 => "Echo Reply",
        3 => "Destination Unreachable",
        8 => "Echo Request",
        11 => "Time Exceeded",
        _ => "Other",
    };

    pinfo.append_col_info(&format!("ICMP {} at {} ns", type_str, ts));
}

fn analyze_icmp_payload(pinfo: PacketInfo, Field(payload): Field<&[u8]>, Packet(full_pkt): Packet) {
    if payload.is_empty() {
        return;
    }

    let payload_ratio = (payload.len() as f32 / full_pkt.len() as f32) * 100.0;

    pinfo.append_col_info(&format!(
        " Data: {} bytes ({:.1}% of packet)",
        payload.len(),
        payload_ratio
    ));
}

#[derive(Proto, Dissect)]
#[wsdf(
    proto_desc = "Baby TCP by wsdf",
    proto_name = "Baby TCP", 
    proto_filter = "baby_tcp",
    decode_from = [("ip.proto", 6)],
)]
struct Tcp {
    #[wsdf(save)]
    src_port: u16,
    #[wsdf(save, tap = "track_tcp_port")]
    dst_port: u16,
    #[wsdf(save)]
    sequence_number: u32,
    acknowledgment_number: u32,
    #[wsdf(decode_with = "decode_tcp_flags", save, tap = "track_tcp_state")]
    flags: u16,
    window: u16,
    checksum: u16,
    urgent_pointer: u16,
    #[wsdf(bytes, subdissector = ("baby_tcp.port", "src_port", "dst_port"), tap = "analyze_tcp_segment")]
    payload: Vec<u8>,
}

fn track_tcp_port(pinfo: PacketInfo, Fields(fields): Fields, Field(src_port): Field<u16>) {
    pinfo.append_col_info(&format!(
        "TCP Port: {} -> {}",
        src_port,
        fields.get_u16("baby_tcp.dst_port").unwrap()
    ));
}

fn track_tcp_state(pinfo: PacketInfo, Field(flags): Field<u16>, PacketNanos(ts): PacketNanos) {
    let is_syn = (flags & 0x002) != 0;
    let is_ack = (flags & 0x010) != 0;
    let is_fin = (flags & 0x001) != 0;

    let state = match (is_syn, is_ack, is_fin) {
        (true, false, false) => "SYN",
        (true, true, false) => "SYN-ACK",
        (false, true, false) => "ACK",
        (false, true, true) => "FIN-ACK",
        _ => "OTHER",
    };

    pinfo.append_col_info(&format!(" State={} at {} ns", state, ts));
}

fn analyze_tcp_segment(
    pinfo: PacketInfo,
    Field(payload): Field<&[u8]>,
    Fields(fields): Fields,
    Packet(full_pkt): Packet,
) {
    let seq: &u32 = fields.get_u32("baby_tcp.sequence_number").unwrap();

    if payload.is_empty() {
        pinfo.append_col_info(&format!(" [Control Segment] Seq={}", seq));
        return;
    }

    let payload_offset = full_pkt.len() - payload.len();
    pinfo.append_col_info(&format!(
        " [Data Segment] Seq={} Size={} Offset={}",
        seq,
        payload.len(),
        payload_offset
    ));
}

fn decode_tcp_flags(Field(flags): Field<u16>) -> String {
    let mut flag_strings = Vec::new();

    if flags & 0x020 != 0 {
        flag_strings.push("URG");
    }
    if flags & 0x010 != 0 {
        flag_strings.push("ACK");
    }
    if flags & 0x008 != 0 {
        flag_strings.push("PSH");
    }
    if flags & 0x004 != 0 {
        flag_strings.push("RST");
    }
    if flags & 0x002 != 0 {
        flag_strings.push("SYN");
    }
    if flags & 0x001 != 0 {
        flag_strings.push("FIN");
    }

    format!("Flags=[{}]", flag_strings.join("|"))
}

fn format_ip(ip: &u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xff,
        (ip >> 16) & 0xff,
        (ip >> 8) & 0xff,
        ip & 0xff
    )
}
