#![allow(dead_code)]

// Tests that multiple types of subdissectors can be added to dissection table
// and both decode_from = [("some.suddisctor", 420)] and decode_from = [ "some.other_subdissector" ]
// is accepted

use wsdf::{protocol, version, Dissect, Proto};
version!("0.0.1", 4, 4);
protocol!(ProtoFoo);

#[derive(Proto, Dissect)]
#[wsdf(decode_from = [("udp.port", 1234), "udp.payload"])]
struct ProtoFoo {
    bar: u64,
    baz: [u8; 9],
}

fn main() {}
