#![allow(dead_code)]
// Tests that variants of unit tuple with primitive types work

use wsdf::{protocol, tap::FieldsLocal, version, Dissect, Proto};
version!("0.0.1", 4, 4);
protocol!(ProtoFoo);

#[derive(Proto, Dissect)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    #[wsdf(save)]
    typ: u8,
    #[wsdf(get_variant = "get_bar_variant")]
    bar: Bar,
}

#[derive(Dissect)]
enum Bar {
    Foo(u8),
    Qux(Qux),
}

fn get_bar_variant(FieldsLocal(_fields): FieldsLocal) -> &'static str {
    unimplemented!();
}

#[derive(Dissect)]
struct Qux {
    baz: u8,
}

fn main() {}
