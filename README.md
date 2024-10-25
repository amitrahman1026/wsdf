[![docs.rs](https://img.shields.io/badge/docs.rs-wsdf-latest)](https://docs.rs/wsdf)
[![crates.io](https://img.shields.io/crates/v/wsdf.svg)](https://crates.io/crates/wsdf)
[![CI](https://github.com/ghpr-asia/wsdf/actions/workflows/ci.yml/badge.svg)](https://github.com/ghpr-asia/wsdf/actions/workflows/ci.yml)

**wsdf** (**W**ire**s**hark **D**issector **F**ramework) is a proc-macro based
framework to generate Wireshark dissectors from your Rust data types. Using
wsdf, you can write dissectors in a declarative way, all from within Rust.

Dissectors are a core part of Wireshark's packet analysing engine,
[EPAN](https://www.wireshark.org/docs/wsdg_html_chunked/ChWorksOverview.html).
They're responsible for interpreting the data within packets and breaking it
down into readable and structured protocol fields. Each protocol, such as TCP,
UDP, or DNS, has its own dissector to parse its specific format. To learn more
about how Wireshark dissects packets and the role of dissectors, you can refer
to Wireshark’s documentation
[here](https://www.wireshark.org/docs/wsdg_html_chunked/ChWorksDissectPackets.html).

Here is what a dissector for UDP looks like:

```rust
#[derive(wsdf::Protocol)]
#[wsdf(decode_from = [("ip.proto", 17)])]
struct UDP {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
    #[wsdf(subdissector = ("udp.port", "dst_port", "src_port"))]
    payload: Vec<u8>,
}
```

Check out the [docs](https://docs.rs/wsdf) for more information. Some
[examples](wsdf/examples/) are also available, including a simple dissector for
DNS, showcased below.

![DNS dissector showcase](https://raw.githubusercontent.com/ghpr-asia/wsdf/main/docs/dns_dissector.gif)

wsdf has been tested on Linux against Wireshark 4.0.

**License**

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>

______________________________________________________________________

## Compilation testing:

The required `wireshark-devel` files are required for builing this crate.

On macOS, the most convenient way is to use brew:

`brew install wireshark`

On windows there has been issue whereby we see that

## How dissectors work


Note: In principle dissector headers are internal to libwireshark and not part
of any public API. The only possible reason I can see to expose these symbols is to allow
dissector plugins to share code with static dissectors (arguably there should be better mechanisms
for that too, that are more dynamic at runtime and more friendly to language bindings but I digress).
So at most only a small part of dissector header content belongs in any
sort of public API but historically there has been no separation and everything is balled
up as a DISSECTOR_PUBLIC_HEADER more or less automatically and indiscriminately (because of a lack
of clear guidelines). In the future this unsatisfactory situation should be fixed somehow.


## Binary compatibility
Theres no guarantee made that wireshark is binary compatible between different versions
and assumptions should not be made expecting so, plugins generated with a certain version of 
libwireshark may not be portable to other versions.
