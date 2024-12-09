#![allow(dead_code)]
// Tests that array fields can compile

use wsdf::{protocol, version, Dissect, Proto};
version!("0.0.1", 4, 4);
protocol!(ProtoFoo);

#[derive(Proto, Dissect)]
#[wsdf(
    proto_desc = "protocol foo",
    proto_name = "Protocol foo",
    proto_filter = "proto_foo",
    decode_from = "moldudp.payload"
)]
struct ProtoFoo {
    bar: [u64; 10],
    baz: [Bar; 10],
}

#[derive(Dissect)]
struct Bar {
    qux: u64,
}

fn main() {}
