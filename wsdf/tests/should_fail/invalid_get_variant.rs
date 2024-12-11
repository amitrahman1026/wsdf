//! Tests that accessing a non-saved field in get_variant should fail at compile time
//! Error: Cannot access field 'msg_type' because it wasn't marked with #[wsdf(save)]

use wsdf::{protocol, Dissect, Proto, tap::FieldsLocal};


protocol!(Message);

#[derive(Proto, Dissect)]
#[wsdf(decode_from = "test.payload")]
struct Message {
    // Missing #[wsdf(save)]
    message_type: u8,
    #[wsdf(get_variant = "get_message_type")] // Will fail because returns invalid variant
    payload: MessageType,
}

#[derive(Dissect)]
enum MessageType {
    Data { len: u16, data: Vec<u8> },
    Heartbeat,
}

fn get_message_type(FieldsLocal(fields): FieldsLocal) -> &'static str {
    // Should fail: field wasn't saved
    let typ = fields.get_u8("msg_type").unwrap();
    match typ {
        1 => "Data",
        _ => "Control"
    }
}

fn main() {}

// #[derive(Protocol)]
// #[wsdf(decode_from = "moldudp.payload")]
// struct ProtoFoo {
//     bar: Bar,
//     #[wsdf(dispatch_field = "bar")]
//     qux: Qux,
// }

// struct Bar {
//     baz: u32,
// }

// enum Qux {
//     Hot,
//     Cold,
// }

// impl Qux {
//     fn dispatch_bar(bar: &Bar) -> usize {
//         0
//     }
// }

// fn main() { }
