use wsdf::{protocol, version};

// Here we are verifying that the minimum required symbols are being exported by the generated
// dylib

version!("0.0.1", 4, 4);
protocol!(TestPlugin);
