// Tests that unions cannot derive Protocol

use wsdf::*;

#[derive(Proto, Dissect)]
union MyUnion {
    f1: u32,
    f2: f32,
}

fn main() {}
