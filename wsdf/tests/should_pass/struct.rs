#![allow(dead_code)]

// Tests that structs can derive Protocol

use wsdf::{protocol, version, Dissect, Proto};
version!("0.0.1", 4, 4);
protocol!(ProtoFoo);

#[derive(Proto, Dissect)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    bar: u64,
    baz: [u8; 9],
}

fn main() {}
