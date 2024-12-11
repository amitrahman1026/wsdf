// Tests what happens if we try to use an invalid field and a size hint

use wsdf::{protocol, Dissect, Proto};

protocol!(ProtoFoo);

#[derive(Proto, Dissect)]
#[wsdf(decode_from = "test.payload")]
struct ProtoFoo {
    n: u32,
    #[wsdf(len_field = "n")]
    xs: Vec<u32>,
    #[wsdf(len_field = "xs")]
    ys: Vec<u32>,
}

fn main() {}
