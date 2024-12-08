use wsdf::{protocol, version, Dissect, Proto};

version!("0.0.1", 4, 4);
protocol!(UdpProto);

#[derive(Proto, Dissect)]
#[wsdf(
    decode_from = [("udp.port", 1234)],
    proto_desc = "Test UDP Protocol",
    proto_name = "TestUDP",
    proto_filter = "test_udp"
)]
struct UdpProto {
    field: u32,
}
