#![allow(dead_code)]

// Tests that structs with nested structs work fine (in case our code generation gets confused
// somewhere between structs which are fields and the root struct)

use wsdf::{protocol, version, Dissect, Proto};
version!("0.0.1", 4, 4);
protocol!(ProtoFoo);

#[derive(Proto, Dissect)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    bar: Bar,
    qux: u32,
}

#[derive(Dissect)]
struct Bar {
    baz: u64,
    bat: [u8; 9],
}

fn main() {}
