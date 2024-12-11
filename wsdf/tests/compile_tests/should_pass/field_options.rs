#![allow(dead_code)]

// Tests that we are able to compose FieldOoptions via #[wsdf(*)] attributes,
// both directly on primitives, and through other StructInnards that derive Dissect

use wsdf::{protocol, version, Dissect, Proto};
version!("0.0.1", 4, 4);
protocol!(ProtoFoo);

#[derive(Proto, Dissect)]
#[wsdf(decode_from = "moldudp.payload")]
struct ProtoFoo {
    #[wsdf(
        typ = "FT_ABSOLUTE_TIME",
        enc = "ENC_TIME_SECS",
        display = "ABSOLUTE_TIME_LOCAL"
    )]
    time: u32,
    space: Mass,
    // todo: add rest of the variants
}

#[derive(Dissect)]
struct Mass(#[wsdf(enc = "ENC_LITTLE_ENDIAN", display = "BASE_HEX")] u32);

fn main() {}
