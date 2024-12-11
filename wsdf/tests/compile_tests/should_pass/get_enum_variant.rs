//! Tests the get_variant feature for enum decoding
//!
//! Things to note:
//! 1. Fields must be marked with #[wsdf(save)] to be accessible in get_variant
//! 2. get_variant function can access saved fields via FieldsLocal
//! 3. get_variant must return exact variant names as &'static str
//!
//! Use cases:
//! - Protocol messages with different payload types based on message type field
//! - Packets where structure depends on flags/type fields
//! - Any protocol needing dynamic variant selection based on parsed fields

#![allow(dead_code)]

use wsdf::{protocol, tap::FieldsLocal, Dissect, Proto};

protocol!(Message);

#[derive(Proto, Dissect)]
#[wsdf(decode_from = "test.payload")]
struct Message {
    #[wsdf(save)] // Here Field must be saved to be accessible in get_variant
    msg_type: u8,
    #[wsdf(get_variant = "get_message_type")]
    payload: MessageType,
}

#[derive(Dissect)]
enum MessageType {
    Data { length: u16, payload: Vec<u8> },
    Control { code: u8 },
    Heartbeat,
}

fn get_message_type(FieldsLocal(fields): FieldsLocal) -> &'static str {
    let typ = fields.get_u8("msg_type").unwrap();
    match typ {
        1 => "Data",
        2 => "Control",
        _ => "Heartbeat",
    }
}

fn main() {}
