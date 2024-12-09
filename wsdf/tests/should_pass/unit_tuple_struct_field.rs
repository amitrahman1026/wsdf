#![allow(dead_code)]

// Tests that field types which are a unit tuple struct work fine

use wsdf::{protocol, version, Dissect, Proto};
version!("0.0.1", 4, 4);
protocol!(ProtoFoo);

#[derive(Proto, Dissect)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    foo: Foo,
}

#[derive(Dissect)]
struct Foo(u8);

fn main() {}
