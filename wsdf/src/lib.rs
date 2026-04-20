//! # About wsdf
//!
//! WSDF is an ergonomic Rust framework for building Wireshark dissector plugins, with similar
//! interface to teh lua API, yes providing fast native speeds.
//!
//! It provides:
//! - Safe object oriented wrappers around Wireshark's C API
//! - Builder pattern for easy protocol definition
//! - Memory-safe packet analysis backed by wireshark's native memory allocators
//! - Automatic plugin registration & installation
//!
//! Keep in mind, as this crate generate "out-of-tree" plugins, meaning they link against
//! libwireshark rather than being built in the same source, plugins need to be recompiled
//! for each mamajor.minor Wireshark version release, as Wireshark does not ABI compatibily
//! acress these versions!
//!
//! ## Quick Start Guide
//!
//! ```rust,no_run
//! use wsdf::wireshark::{
//!     ProtocolBuilder, Dissector, FieldBuilder, FieldType, Encoding, 
//!     Protocol, RegistrationError, ExpertGroup, ExpertSeverity, Plugin
//! };
//! use wsdf::plugin;
//!
//! // Define your protocol fields
//! fn build_protocol() -> Result<Protocol, RegistrationError> {
//!     ProtocolBuilder::new(
//!         "Example Protocol",  // Protocol name
//!         "example",          // Protocol abbreviation
//!         "example"           // Filter name
//!     )
//!     .field(
//!         FieldBuilder::new("version", "Version", "example.version")
//!             .field_type(FieldType::Uint8)
//!             .build()?
//!     )
//!     .ett("header", "Header Fields")
//!     .expert_info(
//!         "malformed",
//!         ExpertGroup::Malformed,
//!         ExpertSeverity::Error,
//!         "Malformed packet"
//!     )
//!     .dissector(Dissector::new(|tree, tvb| {
//!         // Dissection logic here
//!         Ok(0)
//!     }))
//!     .build()
//! }
//!
//! // Register the plugin
//! plugin! {
//!     build_protocol
//! }
//! ```
//!
//! ## Architecture
//!
//! WSDF uses a layered architecture:
//!
//! ```text
//! +-------------------+
//! |     User Code     |
//! +-------------------+
//! |   WSDF Public API | <- factories, builders & lua-like interface
//! +-------------------+
//! |    Raw FFI (epan) |
//! +-------------------+
//! ```
//! ## Key Components
//!
//! - [`Protocol`] - Defines packet structure and fields
//! - [`Tree`] - Represents the protocol tree for a packet
//! - [`Dissector`] - Contains packet analysis logic
//! - [`Plugin`] - Manages protocol registration with Wireshark
//!
//! ## Memory Management
//!
//! WSDF handles memory allocation through Wireshark's packet pool allocator,
//! ensuring memory is properly freed when packet analysis completes.
//!

pub use epan_sys;
pub mod wireshark;

