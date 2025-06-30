// Written in 2025 by Joshua Doman <joshsdoman@gmail.com>
// SPDX-License-Identifier: CC0-1.0

//! # Descriptor Codec
//!
//! A library to efficiently encode and decode Bitcoin wallet descriptors.
//!
//! ## Overview
//!
//! Bitcoin wallet descriptors encode the spending conditions for Bitcoin outputs, including
//! keys, scripts, and other requirements. Descriptors are typically represented as human-readable
//! strings, but this adds unnecessary overhead, which is not ideal for QR codes and other forms
//! of machine-to-machine communication.
//!
//! This library efficiently encodes descriptors using tag-based and variable-length encoding,
//! reducing the number of bytes by 30-40%, depending on the number of keys used. It supports
//! all public key descriptors.
//!
//! ## Usage
//! ```rust
//! use std::str::FromStr;
//! use descriptor_codec::{encode, decode};
//! use miniscript::descriptor::{Descriptor, DescriptorPublicKey};
//!
//! // Create a descriptor - a 2-of-3 multisig in this example
//! let desc_str = "wsh(sortedmulti(2,\
//!     03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,\
//!     036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00,\
//!     02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29\
//! ))";
//! let descriptor = Descriptor::<DescriptorPublicKey>::from_str(desc_str).unwrap();
//!
//! // Encode the descriptor
//! let encoded_descriptor = encode(descriptor.clone());
//!
//! // Recover the original descriptor
//! let decoded_descriptor = decode(&encoded_descriptor).unwrap();
//! assert_eq!(descriptor.to_string(), decoded_descriptor.to_string());
//! ```
//!

// Coding conventions
#![deny(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
// #![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

#[cfg(not(any(feature = "std")))]
compile_error!("`std` must be enabled");

pub mod decode;
mod dummy;
pub mod encode;
mod tag;
mod varint;

pub use decode::Error;

use miniscript::{Descriptor, DescriptorPublicKey, descriptor::KeyMap};

/// Encodes a Bitcoin wallet descriptor
pub fn encode(descriptor: Descriptor<DescriptorPublicKey>) -> Vec<u8> {
    let (mut template, mut payload) = encode::encode(descriptor, &KeyMap::new());
    template.append(&mut payload);
    template
}

/// Decodes a Bitcoin wallet descriptor from bytes
pub fn decode(bytes: &[u8]) -> Result<Descriptor<DescriptorPublicKey>, Error> {
    let (_, size) = decode::decode_template(bytes)?;
    decode::decode_with_payload(&bytes[..size], &bytes[size..])
}
