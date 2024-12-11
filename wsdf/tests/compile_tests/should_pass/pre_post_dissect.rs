#![allow(dead_code)]

use wsdf::{protocol, Dissect, Proto};

protocol!(ProtoFoo);

#[derive(Proto, Dissect)]
#[wsdf(decode_from = "udp.port", pre_dissect = "f", post_dissect = "g")]
struct ProtoFoo {
    bar: Bar,
}

#[derive(Dissect)]
#[wsdf(pre_dissect = "f", post_dissect = ["f", "g"])]
struct Bar(u16);

use wsdf::tap::Fields;

fn f() {}
fn g(_fs: Fields) {}

fn main() {}
