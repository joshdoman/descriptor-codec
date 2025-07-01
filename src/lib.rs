// Written in 2025 by Joshua Doman <joshsdoman@gmail.com>
// SPDX-License-Identifier: CC0-1.0

//! # Descriptor Codec
//!
//! Efficiently encode and decode Bitcoin wallet descriptors with a 30-40% size reduction.
//!
//! ## Overview
//!
//! Bitcoin wallet descriptors encode the spending conditions for Bitcoin outputs, including
//! keys, scripts, and other requirements. Descriptors are typically represented as human-readable
//! strings, but this adds unnecessary overhead, which is not ideal for QR codes and other forms
//! of machine-to-machine communication.
//!
//! This library efficiently encodes descriptors using tag-based and variable-length encoding,
//! reducing the number of bytes by 30-40%. It supports all descriptors, including those with
//! private keys.
//!
//! ## Usage
//! ```rust
//! use std::str::FromStr;
//! use descriptor_codec::{encode, decode};
//! use miniscript::descriptor::{Descriptor, DescriptorPublicKey};
//!
//! // Create a descriptor - a 2-of-3 multisig in this example
//! let descriptor = "wsh(sortedmulti(2,\
//!     03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,\
//!     036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00,\
//!     02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29\
//! ))#hfj7wz7l";
//!
//! // Encode the descriptor
//! let encoded_descriptor = encode(descriptor).unwrap();
//!
//! // Recover the original descriptor
//! let decoded_descriptor = decode(&encoded_descriptor).unwrap();
//! assert_eq!(descriptor.to_string(), decoded_descriptor);
//! ```
//!

// Coding conventions
#![deny(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

#[cfg(not(any(feature = "std")))]
compile_error!("`std` must be enabled");

pub mod decode;
mod dummy;
pub mod encode;
mod tag;
mod test_helpers;
mod varint;

pub use decode::Error;

use bitcoin::{
    hashes::{hash160, ripemd160, sha256},
    secp256k1,
};
use miniscript::{
    Descriptor, TranslatePk, Translator,
    descriptor::{DescriptorPublicKey, DescriptorSecretKey, KeyMap},
    hash256,
};
use std::collections::BTreeMap;
use std::str::FromStr;

/// Parses and encodes a Bitcoin descriptor
pub fn encode(s: &str) -> Result<Vec<u8>, miniscript::Error> {
    let secp = secp256k1::Secp256k1::new();
    let (descriptor, key_map) = parse_descriptor(&secp, s)?;
    let (mut template, mut payload) = encode::encode(descriptor, &key_map);
    template.append(&mut payload);
    Ok(template)
}

/// Decodes a Bitcoin descriptor
pub fn decode(bytes: &[u8]) -> Result<String, Error> {
    let (_, _, size) = decode::decode_template(bytes)?;
    let (descriptor, key_map) = decode::decode_with_payload(&bytes[..size], &bytes[size..])?;
    Ok(descriptor.to_string_with_secret(&key_map))
}

/// Parse a descriptor that may contain secret keys
///
/// Internally turns every secret key found into the corresponding public key and then returns a
/// a descriptor that only contains public keys and a map to lookup the secret key given a public key.
///
/// Re-implements `parse_descriptor` from `miniscript/descriptor` to handle MultiXPrivs by replacing
/// each MultiXPriv with an indexed dummy SinglePub and adding the MultiXpriv to the key map.
fn parse_descriptor<C: secp256k1::Signing>(
    secp: &secp256k1::Secp256k1<C>,
    s: &str,
) -> Result<(Descriptor<DescriptorPublicKey>, KeyMap), miniscript::Error> {
    fn parse_key<C: secp256k1::Signing>(
        s: &str,
        key_map: &mut KeyMap,
        secp: &secp256k1::Secp256k1<C>,
    ) -> Result<DescriptorPublicKey, miniscript::Error> {
        let (public_key, secret_key) = match DescriptorSecretKey::from_str(s) {
            Ok(sk) => (
                sk.to_public(secp)
                    .unwrap_or(test_helpers::create_dpk_single_compressed_no_origin(
                        1 + key_map.len() as u32,
                    )),
                Some(sk),
            ),
            Err(_) => (
                DescriptorPublicKey::from_str(s)
                    .map_err(|e| miniscript::Error::Unexpected(e.to_string()))?,
                None,
            ),
        };

        if let Some(secret_key) = secret_key {
            key_map.insert(public_key.clone(), secret_key);
        }

        Ok(public_key)
    }

    let mut keymap_pk = KeyMapWrapper(BTreeMap::new(), secp);

    struct KeyMapWrapper<'a, C: secp256k1::Signing>(KeyMap, &'a secp256k1::Secp256k1<C>);

    impl<C: secp256k1::Signing> Translator<String, DescriptorPublicKey, miniscript::Error>
        for KeyMapWrapper<'_, C>
    {
        fn pk(&mut self, pk: &String) -> Result<DescriptorPublicKey, miniscript::Error> {
            parse_key(pk, &mut self.0, self.1)
        }

        fn sha256(&mut self, sha256: &String) -> Result<sha256::Hash, miniscript::Error> {
            let hash = sha256::Hash::from_str(sha256)
                .map_err(|e| miniscript::Error::Unexpected(e.to_string()))?;
            Ok(hash)
        }

        fn hash256(&mut self, hash256: &String) -> Result<hash256::Hash, miniscript::Error> {
            let hash = hash256::Hash::from_str(hash256)
                .map_err(|e| miniscript::Error::Unexpected(e.to_string()))?;
            Ok(hash)
        }

        fn ripemd160(&mut self, ripemd160: &String) -> Result<ripemd160::Hash, miniscript::Error> {
            let hash = ripemd160::Hash::from_str(ripemd160)
                .map_err(|e| miniscript::Error::Unexpected(e.to_string()))?;
            Ok(hash)
        }

        fn hash160(&mut self, hash160: &String) -> Result<hash160::Hash, miniscript::Error> {
            let hash = hash160::Hash::from_str(hash160)
                .map_err(|e| miniscript::Error::Unexpected(e.to_string()))?;
            Ok(hash)
        }
    }

    let descriptor = Descriptor::<String>::from_str(s)?;
    let descriptor = descriptor
        .translate_pk(&mut keymap_pk)
        .map_err(miniscript::TranslateErr::flatten)?;

    Ok((descriptor, keymap_pk.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration() {
        let descriptors = vec![
            "sh(sortedmulti(2,[2c49202a/45'/0'/0'/0]xpub6EigxozzGaNVWUwEFnbyX6oHPdpWTKgJgbfpRbAcdiGpGMrdpPinCoHBXehu35sqJHpgLDTxigAnFQG3opKjXQoSmGMrMNHz81ALZSBRCWw/0/*,[55b43a50/45'/0'/0'/0]xpub6EAtA5XJ6pwFQ7L32iAJMgiWQEcrwU75NNWQ6H6eavwznDFeGFzTbSFdDKNdbG2HQdZvzrXuCyEYSSJ4cGsmfoPkKUKQ6haNKMRqG4pD4xi/0/*,[35931b5e/0/0/0/0]xpub6EDykLBC5EfaDNC7Mpg2H8veCaJHDgxH2JQvRtxJrbyeAhXWV2jJzB9XL4jMiFN5TzQefYi4V4nDiH4bxhkrweQ3Smxc8uP4ux9HrMGV81P/0/*))#2esvpcaf",
            "wsh(sortedmulti(2,[3abf21c8/48'/0'/0'/2']xpub6DYotmPf2kXFYhJMFDpfydjiXG1RzmH1V7Fnn2Z38DgN2oSYruczMyTFZZPz6yXq47Re8anhXWGj4yMzPTA3bjPDdpA96TLUbMehrH3sBna/<0;1>/*,[a1a4bd46/48'/0'/0'/2']xpub6DvXYo8BwnRACos42ME7tNL48JQhLMQ33ENfniLM9KZmeZGbBhyh1Jkfo3hUKmmjW92o3r7BprTPPdrTr4QLQR7aRnSBfz1UFMceW5ibhTc/<0;1>/*,[ed91913d/48'/0'/0'/2']xpub6EQUho4Z4pwh2UQGdPjoPrbtjd6qqseKZCEBLcZbJ7y6c9XBWHRkhERiADJfwRcUs14nQsxF3hvx7aFkbk3tfp4dnKfkcns217kBTVVN5gY/<0;1>/*))#e7m305nf",
            "sh(wsh(sortedmulti(2,[2c49202a/45'/0'/0'/0]xpub6EigxozzGaNVWUwEFnbyX6oHPdpWTKgJgbfpRbAcdiGpGMrdpPinCoHBXehu35sqJHpgLDTxigAnFQG3opKjXQoSmGMrMNHz81ALZSBRCWw/0/*,[55b43a50/45'/0'/0'/0]xpub6EAtA5XJ6pwFQ7L32iAJMgiWQEcrwU75NNWQ6H6eavwznDFeGFzTbSFdDKNdbG2HQdZvzrXuCyEYSSJ4cGsmfoPkKUKQ6haNKMRqG4pD4xi/0/*,[35931b5e/0/0/0/0]xpub6EDykLBC5EfaDNC7Mpg2H8veCaJHDgxH2JQvRtxJrbyeAhXWV2jJzB9XL4jMiFN5TzQefYi4V4nDiH4bxhkrweQ3Smxc8uP4ux9HrMGV81P/0/*)))#c0t8r3nk",
            "wsh(multi(2,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,023e9be8b82c7469c88b1912a61611dffb9f65bbf5a176952727e0046513eca0de))#qdgya3w5",
            "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)#8zl0zxma",
            "sh(wsh(or_d(pk(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),and_v(v:pk(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e),older(1000)))))#ky8du3e6",
            "wsh(thresh(4,pk([7258e4f9/44'/1'/0']tpubDCZrkQoEU3845aFKUu9VQBYWZtrTwxMzcxnBwKFCYXHD6gEXvtFcxddCCLFsEwmxQaG15izcHxj48SXg1QS5FQGMBx5Ak6deXKPAL7wauBU/0/*),s:pk([c80b1469/44'/1'/0']tpubDD3UwwHoNUF4F3Vi5PiUVTc3ji1uThuRfFyBexTSHoAcHuWW2z8qEE2YujegcLtgthr3wMp3ZauvNG9eT9xfJyxXCfNty8h6rDBYU8UU1qq/0/*),s:pk([4e5024fe/44'/1'/0']tpubDDLrpPymPLSCJyCMLQdmcWxrAWwsqqssm5NdxT2WSdEBPSXNXxwbeKtsHAyXPpLkhUyKovtZgCi47QxVpw9iVkg95UUgeevyAqtJ9dqBqa1/0/*),s:pk([3b1d1ee9/44'/1'/0']tpubDCmDTANBWPzf6d8Ap1J5Ku7J1Ay92MpHMrEV7M5muWxCrTBN1g5f1NPcjMEL6dJHxbvEKNZtYCdowaSTN81DAyLsmv6w6xjJHCQNkxrsrfu/0/*),sln:after(840000),sln:after(1050000),sln:after(1260000)))#fk029528",
            "tr(c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,{pk(fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556),pk(e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)})#2rqrdjrh",
            "pkh(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/0)#m6s0eyht",
            "pkh(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/<2147483647';0>/0)#s0hk8xf9",
        ];

        for desc_str in descriptors {
            assert_eq!(desc_str, decode(&encode(desc_str).unwrap()).unwrap());
        }
    }
}
