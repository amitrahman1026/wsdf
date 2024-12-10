#![allow(dead_code)]

use wsdf::tap::{Field, Fields, Offset, Packet, PacketNanos};
use wsdf::{protocol, Dissect, Proto};

protocol!(ProtoFoo);

#[derive(Proto, Dissect)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    #[wsdf(tap = ["f", "g", "h", "i", "j", "k"])]
    x: u8,
    // Check that taps work for non-primitive types too.
    #[wsdf(bytes, len_field = "x", tap = ["f", "g3"])]
    xs: Vec<u8>,
    #[wsdf(tap = ["f", "g2"])]
    bar: Bar,
}

#[derive(Dissect)]
struct Bar(u16);

fn f() {}
fn g(_x: Field<u8>) {}
fn h(_x: Field<u8>, _fields: Fields) {}
fn i(_x: Field<u8>, _fields: Fields, _nanos: PacketNanos) {}
fn j(_x: Field<u8>, _fields: Fields, _nanos: PacketNanos, _pkt: Packet) {}
fn k(_x: Field<u8>, _fields: Fields, _nanos: PacketNanos, _pkt: Packet, _offset: Offset) {}

fn g2(_x: Field<()>) {}
fn g3(_x: Field<&[u8]>) {}

fn main() {}
