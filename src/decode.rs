// SPDX-License-Identifier: CC0-1.0

//! # Descriptor Decode

use super::{tag::Tag, test_helpers, varint, *};
use bitcoin::{
    NetworkKind, PrivateKey, PublicKey, XOnlyPublicKey,
    bip32::{ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub},
    hashes::{
        Hash, hash160::Hash as Hash160, ripemd160::Hash as Ripemd160, sha256::Hash as Sha256,
        sha256d,
    },
    secp256k1::{Secp256k1, SecretKey, constants::SECRET_KEY_SIZE},
};
use miniscript::{
    AbsLockTime, BareCtx, Legacy, Miniscript, RelLockTime, ScriptContext, Segwitv0, Tap, Threshold,
    descriptor::{
        Bare, DerivPaths, Descriptor, DescriptorMultiXKey, DescriptorPublicKey,
        DescriptorSecretKey, DescriptorXKey, KeyMap, Pkh, Sh, SinglePriv, SinglePub, SinglePubKey,
        SortedMultiVec, TapTree, Tr, Wildcard, Wpkh, Wsh,
    },
    hash256::Hash as Hash256,
    miniscript::decode::Terminal,
};

use std::error;
use std::fmt;
use std::sync::Arc;

/// Error
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Input is missing bytes
    MissingBytes,
    /// Unrecognized tag
    UnrecognizedTag(usize),
    /// Invalid tag
    InvalidTag(usize),
    /// Invalid miniscript
    InvalidMiniscript(usize, String),
    /// Invalid var int
    InvalidVarInt(usize, String),
    /// Missing derivation paths
    MissingDerivPaths(usize),
    /// Invalid payload
    InvalidPayload(usize, String),
    /// Payload too large
    PayloadTooLarge(usize, usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::MissingBytes => write!(f, "missing bytes"),
            Self::UnrecognizedTag(idx) => write!(f, "unrecognized tag (index: {idx})"),
            Self::InvalidTag(idx) => write!(f, "invalid tag (index: {idx})"),
            Self::InvalidMiniscript(idx, err) => {
                write!(f, "invalid miniscript (index: {idx}, error: {err})")
            }
            Self::InvalidVarInt(idx, err) => {
                write!(f, "invalid varint (index: {idx}, error: {err})")
            }
            Self::MissingDerivPaths(idx) => write!(f, "missing derivation paths (index: {idx})"),
            Self::InvalidPayload(idx, err) => {
                write!(f, "invalid payload (payload index: {idx}, error: {err})")
            }
            Self::PayloadTooLarge(expected, actual) => {
                write!(
                    f,
                    "payload too large (expected {expected} bytes, found {actual} bytes)"
                )
            }
        }
    }
}

impl error::Error for Error {}

/// Returns a template descriptor with dummy keys, fingerprints, hashes, and timelocks and
/// the number of decoded bytes.
pub fn decode_template(
    input: &[u8],
) -> Result<(Descriptor<DescriptorPublicKey>, KeyMap, usize), Error> {
    let mut index = 0;
    let mut key_map = KeyMap::new();
    let descriptor = Descriptor::from_template(input, &mut index, &[], &mut 0, &mut key_map)?;

    Ok((descriptor, key_map, index))
}

/// Returns a fully decoded descriptor applying a payload containing the keys, fingerprints,
/// hashes, and timelocks to a template.
pub fn decode_with_payload(
    input: &[u8],
    payload: &[u8],
) -> Result<(Descriptor<DescriptorPublicKey>, KeyMap), Error> {
    let mut payload_index = 0;
    let mut key_map = KeyMap::new();
    let descriptor =
        Descriptor::from_template(input, &mut 0, payload, &mut payload_index, &mut key_map)?;

    if payload_index < payload.len() {
        return Err(Error::PayloadTooLarge(payload_index, payload.len()));
    }

    Ok((descriptor, key_map))
}

trait FromTemplate: Sized {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error>;
}

trait FromPayload: Sized {
    fn from_payload(payload: &[u8], payload_index: &mut usize) -> Result<Self, Error>;
}

trait FromCompressablePayload: Sized {
    fn from_payload(
        compressed: bool,
        payload: &[u8],
        payload_index: &mut usize,
    ) -> Result<Self, Error>;
}

impl FromTemplate for Descriptor<DescriptorPublicKey> {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        if *index >= input.len() {
            return Err(Error::MissingBytes);
        }

        let current_index = *index;
        let descriptor = match Tag::from(input[current_index]) {
            Tag::Unrecognized => return Err(Error::UnrecognizedTag(current_index)),
            Tag::Sh => Descriptor::Sh(Sh::<DescriptorPublicKey>::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?),
            Tag::Wsh => Descriptor::Wsh(Wsh::<DescriptorPublicKey>::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?),
            Tag::Tr => Descriptor::Tr(Tr::<DescriptorPublicKey>::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?),
            Tag::Wpkh => Descriptor::Wpkh(Wpkh::<DescriptorPublicKey>::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?),
            Tag::Pkh => Descriptor::Pkh(Pkh::<DescriptorPublicKey>::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?),
            Tag::Bare => Descriptor::Bare(Bare::<DescriptorPublicKey>::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?),
            _ => return Err(Error::InvalidTag(current_index)),
        };

        Ok(descriptor)
    }
}

impl FromTemplate for Sh<DescriptorPublicKey> {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        let current_index = *index;
        *index += 1;

        if current_index + 1 >= input.len() {
            return Err(Error::MissingBytes);
        }

        let sh = match Tag::from(input[current_index + 1]) {
            Tag::Unrecognized => return Err(Error::UnrecognizedTag(current_index + 1)),
            Tag::SortedMulti => {
                let sorted_multi = SortedMultiVec::<DescriptorPublicKey, Legacy>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?;
                Sh::new_sortedmulti(sorted_multi.k(), sorted_multi.pks().to_vec())
            }
            Tag::Wsh => Ok(Sh::new_with_wsh(Wsh::<DescriptorPublicKey>::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?)),
            Tag::Wpkh => Ok(Sh::new_with_wpkh(
                Wpkh::<DescriptorPublicKey>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?,
            )),
            _ => Sh::new(Miniscript::<DescriptorPublicKey, Legacy>::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?),
        };

        match sh {
            Ok(sh) => Ok(sh),
            Err(err) => Err(Error::InvalidMiniscript(current_index, err.to_string())),
        }
    }
}

impl FromTemplate for Wsh<DescriptorPublicKey> {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        let current_index = *index;
        *index += 1;

        if current_index + 1 >= input.len() {
            return Err(Error::MissingBytes);
        }

        let wsh = match Tag::from(input[current_index + 1]) {
            Tag::Unrecognized => return Err(Error::UnrecognizedTag(current_index + 1)),
            Tag::SortedMulti => {
                let sorted_multi = SortedMultiVec::<DescriptorPublicKey, Segwitv0>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?;
                Wsh::new_sortedmulti(sorted_multi.k(), sorted_multi.pks().to_vec())
            }
            _ => Wsh::new(Miniscript::<DescriptorPublicKey, Segwitv0>::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?),
        };

        match wsh {
            Ok(wsh) => Ok(wsh),
            Err(err) => Err(Error::InvalidMiniscript(current_index, err.to_string())),
        }
    }
}

impl FromTemplate for Tr<DescriptorPublicKey> {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        let current_index = *index;
        *index += 1;

        if current_index + 1 >= input.len() {
            return Err(Error::MissingBytes);
        }

        let internal_key =
            DescriptorPublicKey::from_template(input, index, payload, payload_index, key_map)?;

        let tree = if *index < input.len() && Tag::from(input[*index]) == Tag::TapTree {
            Some(TapTree::<DescriptorPublicKey>::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?)
        } else {
            None
        };

        match Tr::new(internal_key, tree) {
            Ok(tr) => Ok(tr),
            Err(err) => Err(Error::InvalidMiniscript(current_index, err.to_string())),
        }
    }
}

impl FromTemplate for Wpkh<DescriptorPublicKey> {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        let current_index = *index;
        *index += 1;

        match Wpkh::new(DescriptorPublicKey::from_template(
            input,
            index,
            payload,
            payload_index,
            key_map,
        )?) {
            Ok(wpkh) => Ok(wpkh),
            Err(err) => Err(Error::InvalidMiniscript(current_index, err.to_string())),
        }
    }
}

impl FromTemplate for Pkh<DescriptorPublicKey> {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        let current_index = *index;
        *index += 1;

        match Pkh::new(DescriptorPublicKey::from_template(
            input,
            index,
            payload,
            payload_index,
            key_map,
        )?) {
            Ok(pkh) => Ok(pkh),
            Err(err) => Err(Error::InvalidMiniscript(current_index, err.to_string())),
        }
    }
}

impl FromTemplate for Bare<DescriptorPublicKey> {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        let current_index = *index;
        *index += 1;

        let ms = Miniscript::<DescriptorPublicKey, BareCtx>::from_template(
            input,
            index,
            payload,
            payload_index,
            key_map,
        )?;
        let bare = Bare::new(ms);
        match bare {
            Ok(bare) => Ok(bare),
            Err(err) => Err(Error::InvalidMiniscript(current_index, err.to_string())),
        }
    }
}

impl FromTemplate for TapTree<DescriptorPublicKey> {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        let current_index = *index;
        *index += 1;

        if current_index + 1 >= input.len() {
            return Err(Error::MissingBytes);
        }

        if Tag::from(input[current_index + 1]) == Tag::TapTree {
            // Tree
            let left = TapTree::<DescriptorPublicKey>::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?;

            if *index < input.len() && Tag::from(input[*index]) == Tag::TapTree {
                let right = TapTree::<DescriptorPublicKey>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?;

                Ok(Self::combine(left, right))
            } else {
                Err(Error::MissingBytes)
            }
        } else {
            // Leaf
            let ms = Miniscript::<DescriptorPublicKey, Tap>::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?;

            Ok(TapTree::Leaf(Arc::new(ms)))
        }
    }
}

impl<Ctx: ScriptContext> FromTemplate for SortedMultiVec<DescriptorPublicKey, Ctx> {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        let current_index = *index;
        *index += 1;

        if current_index + 1 >= input.len() {
            return Err(Error::MissingBytes);
        }

        let (k, size_k) = varint::decode(&input[(current_index + 1)..])
            .map_err(|e| Error::InvalidVarInt(current_index + 1, e.to_string()))?;
        let (n, size_n) = varint::decode(&input[(current_index + 1 + size_k)..])
            .map_err(|e| Error::InvalidVarInt(current_index + 1 + size_k, e.to_string()))?;

        if k > usize::MAX as u128 {
            return Err(Error::InvalidVarInt(current_index + 1, "overflow".into()));
        }

        *index += size_k + size_n;

        let mut pks = Vec::new();
        for _ in 0..n {
            let pk =
                DescriptorPublicKey::from_template(input, index, payload, payload_index, key_map)?;
            pks.push(pk);
        }

        match SortedMultiVec::<DescriptorPublicKey, Ctx>::new(k as usize, pks) {
            Ok(sorted_multi) => Ok(sorted_multi),
            Err(err) => Err(Error::InvalidMiniscript(current_index, err.to_string())),
        }
    }
}

impl<Ctx: ScriptContext> FromTemplate for Miniscript<DescriptorPublicKey, Ctx> {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        let current_index = *index;
        let ast = Terminal::<DescriptorPublicKey, Ctx>::from_template(
            input,
            index,
            payload,
            payload_index,
            key_map,
        )?;
        match Self::from_ast(ast) {
            Ok(ms) => Ok(ms),
            Err(err) => Err(Error::InvalidMiniscript(current_index, err.to_string())),
        }
    }
}

impl<Ctx: ScriptContext> FromTemplate for Terminal<DescriptorPublicKey, Ctx> {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        if *index >= input.len() {
            return Err(Error::MissingBytes);
        }

        let current_index = *index;
        *index += 1;

        let terminal = match Tag::from(input[current_index]) {
            Tag::Unrecognized => return Err(Error::UnrecognizedTag(current_index)),
            Tag::True => Self::True,
            Tag::False => Self::False,
            Tag::PkK => Self::PkK(DescriptorPublicKey::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?),
            Tag::PkH => Self::PkH(DescriptorPublicKey::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?),
            Tag::RawPkH => Self::RawPkH(Hash160::from_payload(payload, payload_index)?),
            Tag::After => Self::After(AbsLockTime::from_payload(payload, payload_index)?),
            Tag::Older => Self::Older(RelLockTime::from_payload(payload, payload_index)?),
            Tag::Sha256 => Self::Sha256(Sha256::from_payload(payload, payload_index)?),
            Tag::Hash256 => Self::Hash256(Hash256::from_payload(payload, payload_index)?),
            Tag::Ripemd160 => Self::Ripemd160(Ripemd160::from_payload(payload, payload_index)?),
            Tag::Hash160 => Self::Hash160(Hash160::from_payload(payload, payload_index)?),
            Tag::Alt => Self::Alt(
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
            ),
            Tag::Swap => Self::Swap(
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
            ),
            Tag::Check => Self::Check(
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
            ),
            Tag::DupIf => Self::DupIf(
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
            ),
            Tag::Verify => Self::Verify(
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
            ),
            Tag::NonZero => Self::NonZero(
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
            ),
            Tag::ZeroNotEqual => Self::ZeroNotEqual(
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
            ),
            Tag::AndV => Self::AndV(
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
            ),
            Tag::AndB => Self::AndB(
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
            ),
            Tag::AndOr => Self::AndOr(
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
            ),
            Tag::OrB => Self::OrB(
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
            ),
            Tag::OrC => Self::OrC(
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
            ),
            Tag::OrD => Self::OrD(
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
            ),
            Tag::OrI => Self::OrI(
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
                Miniscript::<DescriptorPublicKey, Ctx>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?
                .into(),
            ),
            Tag::Thresh => Self::Thresh(
                Threshold::<Arc<Miniscript<DescriptorPublicKey, Ctx>>, 0>::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?,
            ),
            Tag::Multi => Self::Multi(Threshold::<DescriptorPublicKey, 20>::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?),
            Tag::MultiA => Self::MultiA(Threshold::<DescriptorPublicKey, 125000>::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?),
            _ => return Err(Error::InvalidTag(current_index)),
        };

        Ok(terminal)
    }
}

impl<T: FromTemplate> FromTemplate for Arc<T> {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        Ok(Arc::new(T::from_template(
            input,
            index,
            payload,
            payload_index,
            key_map,
        )?))
    }
}

impl<T: FromTemplate, const MAX: usize> FromTemplate for Threshold<T, MAX> {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        if *index >= input.len() {
            return Err(Error::MissingBytes);
        }

        let current_index = *index;
        let (k, size_k) = varint::decode(&input[*index..])
            .map_err(|e| Error::InvalidVarInt(*index, e.to_string()))?;
        let (n, size_n) = varint::decode(&input[(*index + size_k)..])
            .map_err(|e| Error::InvalidVarInt(*index + size_k, e.to_string()))?;

        if k > usize::MAX as u128 {
            return Err(Error::InvalidVarInt(*index, "overflow".into()));
        }

        *index += size_k + size_n;

        let mut ts = Vec::new();
        for _ in 0..n {
            let t = T::from_template(input, index, payload, payload_index, key_map)?;
            ts.push(t);
        }

        match Threshold::<T, MAX>::new(k as usize, ts) {
            Ok(thresh) => Ok(thresh),
            Err(err) => Err(Error::InvalidMiniscript(current_index, err.to_string())),
        }
    }
}

impl FromTemplate for DescriptorPublicKey {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        if *index + 1 >= input.len() {
            return Err(Error::MissingBytes);
        }

        // Check if this is a private key
        let tag = Tag::from(input[*index]);
        match tag {
            Tag::XPriv
            | Tag::MultiXPriv
            | Tag::CompressedSinglePriv
            | Tag::UncompressedSinglePriv => {
                let secret_key = DescriptorSecretKey::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?;

                // Convert secret key to public key
                let secp = Secp256k1::new();
                let public_key = secret_key.to_public(&secp).unwrap_or(
                    // multi-xpriv cannot be converted to a public key, so instead
                    // use a dummy public key indexed to the map size
                    test_helpers::create_dpk_single_compressed_no_origin(1 + key_map.len() as u32),
                );

                // Insert key mapping
                key_map.insert(public_key.clone(), secret_key);

                return Ok(public_key);
            }
            _ => {}
        }

        let current_index = *index;
        *index += 2;

        let origin = match Tag::from(input[current_index + 1]) {
            Tag::Unrecognized => return Err(Error::UnrecognizedTag(current_index + 1)),
            Tag::Origin => {
                let fingerprint_dummy = Fingerprint::from_payload(payload, payload_index)?;
                let derivation_path =
                    DerivationPath::from_template(input, index, payload, payload_index, key_map)?;

                Some((fingerprint_dummy, derivation_path))
            }
            Tag::NoOrigin => None,
            _ => return Err(Error::InvalidTag(current_index + 1)),
        };

        let template = match Tag::from(input[current_index]) {
            Tag::Unrecognized => return Err(Error::UnrecognizedTag(current_index)),
            Tag::UncompressedFullKey => DescriptorPublicKey::Single(SinglePub {
                key: SinglePubKey::FullKey(PublicKey::from_payload(false, payload, payload_index)?),
                origin,
            }),
            Tag::CompressedFullKey => DescriptorPublicKey::Single(SinglePub {
                key: SinglePubKey::FullKey(PublicKey::from_payload(true, payload, payload_index)?),
                origin,
            }),
            Tag::XOnly => DescriptorPublicKey::Single(SinglePub {
                key: SinglePubKey::XOnly(XOnlyPublicKey::from_payload(payload, payload_index)?),
                origin,
            }),
            Tag::XPub => DescriptorPublicKey::XPub(DescriptorXKey {
                origin,
                xkey: Xpub::from_payload(payload, payload_index)?,
                derivation_path: DerivationPath::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?,
                wildcard: Wildcard::from_template(input, index, payload, payload_index, key_map)?,
            }),
            Tag::MultiXPub => DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
                origin,
                xkey: Xpub::from_payload(payload, payload_index)?,
                derivation_paths: DerivPaths::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?,
                wildcard: Wildcard::from_template(input, index, payload, payload_index, key_map)?,
            }),
            _ => return Err(Error::InvalidTag(current_index)),
        };

        Ok(template)
    }
}

impl FromTemplate for DescriptorSecretKey {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        if *index + 1 >= input.len() {
            return Err(Error::MissingBytes);
        }

        let current_index = *index;
        *index += 2;

        let origin = match Tag::from(input[current_index + 1]) {
            Tag::Unrecognized => return Err(Error::UnrecognizedTag(current_index + 1)),
            Tag::Origin => {
                let fingerprint = Fingerprint::from_payload(payload, payload_index)?;
                let derivation_path =
                    DerivationPath::from_template(input, index, payload, payload_index, key_map)?;

                Some((fingerprint, derivation_path))
            }
            Tag::NoOrigin => None,
            _ => return Err(Error::InvalidTag(current_index + 1)),
        };

        let secret_key = match Tag::from(input[current_index]) {
            Tag::Unrecognized => return Err(Error::UnrecognizedTag(current_index)),
            Tag::CompressedSinglePriv => DescriptorSecretKey::Single(SinglePriv {
                key: PrivateKey::from_payload(true, payload, payload_index)?,
                origin,
            }),
            Tag::UncompressedSinglePriv => DescriptorSecretKey::Single(SinglePriv {
                key: PrivateKey::from_payload(false, payload, payload_index)?,
                origin,
            }),
            Tag::XPriv => DescriptorSecretKey::XPrv(DescriptorXKey {
                origin,
                xkey: Xpriv::from_payload(payload, payload_index)?,
                derivation_path: DerivationPath::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?,
                wildcard: Wildcard::from_template(input, index, payload, payload_index, key_map)?,
            }),
            Tag::MultiXPriv => DescriptorSecretKey::MultiXPrv(DescriptorMultiXKey {
                origin,
                xkey: Xpriv::from_payload(payload, payload_index)?,
                derivation_paths: DerivPaths::from_template(
                    input,
                    index,
                    payload,
                    payload_index,
                    key_map,
                )?,
                wildcard: Wildcard::from_template(input, index, payload, payload_index, key_map)?,
            }),
            _ => return Err(Error::InvalidTag(current_index)),
        };

        Ok(secret_key)
    }
}

impl FromCompressablePayload for PrivateKey {
    fn from_payload(
        compressed: bool,
        payload: &[u8],
        payload_index: &mut usize,
    ) -> Result<Self, Error> {
        if payload.is_empty() {
            if compressed {
                return Ok(PrivateKey::new(dummy::sk(), NetworkKind::Main));
            } else {
                return Ok(PrivateKey::new_uncompressed(dummy::sk(), NetworkKind::Main));
            };
        }

        let current_index = *payload_index;
        *payload_index += SECRET_KEY_SIZE;

        if *payload_index > payload.len() {
            return Err(Error::MissingBytes);
        }

        let sk = SecretKey::from_slice(&payload[current_index..current_index + SECRET_KEY_SIZE])
            .map_err(|e| Error::InvalidPayload(current_index, e.to_string()))?;

        if compressed {
            Ok(PrivateKey::new(sk, NetworkKind::Main))
        } else {
            Ok(PrivateKey::new_uncompressed(sk, NetworkKind::Main))
        }
    }
}

impl FromPayload for Xpriv {
    fn from_payload(payload: &[u8], payload_index: &mut usize) -> Result<Self, Error> {
        if payload.is_empty() {
            return Ok(dummy::xpriv());
        }

        let current_index = *payload_index;
        *payload_index += 78;

        if *payload_index > payload.len() {
            return Err(Error::MissingBytes);
        }

        match Self::decode(&payload[current_index..current_index + 78]) {
            Ok(xpriv) => Ok(xpriv),
            Err(err) => Err(Error::InvalidPayload(current_index, err.to_string())),
        }
    }
}

impl FromPayload for Fingerprint {
    fn from_payload(payload: &[u8], payload_index: &mut usize) -> Result<Self, Error> {
        if payload.is_empty() {
            return Ok(dummy::fp());
        }

        let current_index = *payload_index;
        *payload_index += 4;

        if *payload_index > payload.len() {
            return Err(Error::MissingBytes);
        }

        let mut data = [0u8; 4];
        data.copy_from_slice(&payload[current_index..current_index + 4]);

        Ok(Fingerprint::from(data))
    }
}

impl FromCompressablePayload for PublicKey {
    fn from_payload(
        compressed: bool,
        payload: &[u8],
        payload_index: &mut usize,
    ) -> Result<Self, Error> {
        if payload.is_empty() {
            return Ok(PublicKey {
                inner: dummy::pk(),
                compressed,
            });
        }

        let size = if compressed { 33 } else { 65 };

        let current_index = *payload_index;
        *payload_index += size;

        if *payload_index > payload.len() {
            return Err(Error::MissingBytes);
        }

        match Self::from_slice(&payload[current_index..current_index + size]) {
            Ok(pk) => Ok(pk),
            Err(err) => Err(Error::InvalidPayload(current_index, err.to_string())),
        }
    }
}

impl FromPayload for XOnlyPublicKey {
    fn from_payload(payload: &[u8], payload_index: &mut usize) -> Result<Self, Error> {
        if payload.is_empty() {
            return Ok(XOnlyPublicKey::from(dummy::pk()));
        }

        let current_index = *payload_index;
        *payload_index += 32;

        if *payload_index > payload.len() {
            return Err(Error::MissingBytes);
        }

        match Self::from_slice(&payload[current_index..current_index + 32]) {
            Ok(x_only) => Ok(x_only),
            Err(err) => Err(Error::InvalidPayload(current_index, err.to_string())),
        }
    }
}

impl FromPayload for Xpub {
    fn from_payload(payload: &[u8], payload_index: &mut usize) -> Result<Self, Error> {
        if payload.is_empty() {
            return Ok(dummy::xpub());
        }

        let current_index = *payload_index;
        *payload_index += 78;

        if *payload_index > payload.len() {
            return Err(Error::MissingBytes);
        }

        match Self::decode(&payload[current_index..current_index + 78]) {
            Ok(xpub) => Ok(xpub),
            Err(err) => Err(Error::InvalidPayload(current_index, err.to_string())),
        }
    }
}

impl FromTemplate for DerivationPath {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        if *index >= input.len() {
            return Err(Error::MissingBytes);
        }

        let (len, size) = varint::decode(&input[*index..])
            .map_err(|e| Error::InvalidVarInt(*index, e.to_string()))?;

        *index += size;

        let mut numbers = Vec::new();
        for _ in 0..len {
            numbers.push(ChildNumber::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?);
        }

        Ok(DerivationPath::from(numbers))
    }
}

impl FromTemplate for ChildNumber {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        _payload: &[u8],
        _payload_index: &mut usize,
        _key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        if *index >= input.len() {
            return Err(Error::MissingBytes);
        }

        let (value, size) = varint::decode(&input[*index..])
            .map_err(|e| Error::InvalidVarInt(*index, e.to_string()))?;

        *index += size;

        if value >> 1 > u32::MAX.into() {
            return Err(Error::InvalidVarInt(*index, "overflow".into()));
        }

        let child_index = (value >> 1) as u32;
        let number = if value & 1 == 1 {
            ChildNumber::Hardened { index: child_index }
        } else {
            ChildNumber::Normal { index: child_index }
        };

        Ok(number)
    }
}

impl FromTemplate for DerivPaths {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        payload: &[u8],
        payload_index: &mut usize,
        key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        if *index >= input.len() {
            return Err(Error::MissingBytes);
        }

        let (len, size) = varint::decode(&input[*index..])
            .map_err(|e| Error::InvalidVarInt(*index, e.to_string()))?;

        let current_index = *index;
        *index += size;

        let mut paths = Vec::new();
        for _ in 0..len {
            paths.push(DerivationPath::from_template(
                input,
                index,
                payload,
                payload_index,
                key_map,
            )?);
        }

        if let Some(deriv_paths) = DerivPaths::new(paths) {
            Ok(deriv_paths)
        } else {
            Err(Error::MissingDerivPaths(current_index))
        }
    }
}

impl FromTemplate for Wildcard {
    fn from_template(
        input: &[u8],
        index: &mut usize,
        _payload: &[u8],
        _payload_index: &mut usize,
        _key_map: &mut KeyMap,
    ) -> Result<Self, Error> {
        if *index >= input.len() {
            return Err(Error::MissingBytes);
        }

        let current_index = *index;
        *index += 1;

        let wildcard = match Tag::from(input[current_index]) {
            Tag::Unrecognized => return Err(Error::UnrecognizedTag(current_index)),
            Tag::NoWildcard => Wildcard::None,
            Tag::UnhardenedWildcard => Wildcard::Unhardened,
            Tag::HardenedWildcard => Wildcard::Hardened,
            _ => return Err(Error::InvalidTag(current_index)),
        };

        Ok(wildcard)
    }
}

impl FromPayload for AbsLockTime {
    fn from_payload(payload: &[u8], payload_index: &mut usize) -> Result<Self, Error> {
        if payload.is_empty() {
            return Ok(dummy::after());
        }

        if *payload_index >= payload.len() {
            return Err(Error::MissingBytes);
        }

        let current_index = *payload_index;
        let (after, size) = varint::decode(&payload[current_index..])
            .map_err(|e| Error::InvalidPayload(current_index, e.to_string()))?;

        *payload_index += size;

        if after > u32::MAX.into() {
            return Err(Error::InvalidPayload(current_index, "overflow".into()));
        }

        match Self::from_consensus(after as u32) {
            Ok(after) => Ok(after),
            Err(err) => Err(Error::InvalidPayload(current_index, err.to_string())),
        }
    }
}

impl FromPayload for RelLockTime {
    fn from_payload(payload: &[u8], payload_index: &mut usize) -> Result<Self, Error> {
        if payload.is_empty() {
            return Ok(dummy::older());
        }

        if *payload_index >= payload.len() {
            return Err(Error::MissingBytes);
        }

        let current_index = *payload_index;
        let (older, size) = varint::decode(&payload[current_index..])
            .map_err(|e| Error::InvalidPayload(current_index, e.to_string()))?;

        *payload_index += size;

        if older > u32::MAX.into() {
            return Err(Error::InvalidPayload(current_index, "overflow".into()));
        }

        match Self::from_consensus(older as u32) {
            Ok(older) => Ok(older),
            Err(err) => Err(Error::InvalidPayload(current_index, err.to_string())),
        }
    }
}

impl FromPayload for Hash160 {
    fn from_payload(payload: &[u8], payload_index: &mut usize) -> Result<Self, Error> {
        if payload.is_empty() {
            return Ok(dummy::hash160());
        }

        let current_index = *payload_index;
        *payload_index += 20;

        if *payload_index > payload.len() {
            return Err(Error::MissingBytes);
        }

        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&payload[current_index..current_index + 20]);

        Ok(Self::from_byte_array(bytes))
    }
}

impl FromPayload for Ripemd160 {
    fn from_payload(payload: &[u8], payload_index: &mut usize) -> Result<Self, Error> {
        if payload.is_empty() {
            return Ok(dummy::ripemd160());
        }

        let current_index = *payload_index;
        *payload_index += 20;

        if *payload_index > payload.len() {
            return Err(Error::MissingBytes);
        }

        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&payload[current_index..current_index + 20]);

        Ok(Self::from_byte_array(bytes))
    }
}

impl FromPayload for Sha256 {
    fn from_payload(payload: &[u8], payload_index: &mut usize) -> Result<Self, Error> {
        if payload.is_empty() {
            return Ok(dummy::sha256());
        }

        let current_index = *payload_index;
        *payload_index += 32;

        if *payload_index > payload.len() {
            return Err(Error::MissingBytes);
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&payload[current_index..current_index + 32]);

        Ok(Self::from_byte_array(bytes))
    }
}

impl FromPayload for Hash256 {
    fn from_payload(payload: &[u8], payload_index: &mut usize) -> Result<Self, Error> {
        if payload.is_empty() {
            return Ok(dummy::hash256());
        }

        let current_index = *payload_index;
        *payload_index += 32;

        if *payload_index > payload.len() {
            return Err(Error::MissingBytes);
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&payload[current_index..current_index + 32]);

        Ok(Self::from_raw_hash(sha256d::Hash::from_byte_array(bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dummy, test_helpers::*};
    use std::str::FromStr;

    // Generic Miniscript helpers
    type TerminalBare = Terminal<DescriptorPublicKey, BareCtx>;
    type TerminalLeg = Terminal<DescriptorPublicKey, Legacy>;
    type TerminalSw0 = Terminal<DescriptorPublicKey, Segwitv0>;
    type TerminalTap = Terminal<DescriptorPublicKey, Tap>;

    type MsBare = Miniscript<DescriptorPublicKey, BareCtx>;
    type MsLeg = Miniscript<DescriptorPublicKey, Legacy>;
    type MsSw0 = Miniscript<DescriptorPublicKey, Segwitv0>;
    type MsTap = Miniscript<DescriptorPublicKey, Tap>;

    #[test]
    fn test_wildcard() {
        assert_eq!(
            Wildcard::None,
            Wildcard::from_template(
                &template_of(Wildcard::None),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            Wildcard::Unhardened,
            Wildcard::from_template(
                &template_of(Wildcard::Unhardened),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            Wildcard::Hardened,
            Wildcard::from_template(
                &template_of(Wildcard::Hardened),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_derivation_path() {
        // Empty path: "m"
        let dp_empty = DerivationPath::master();
        assert_eq!(
            dp_empty.clone(),
            DerivationPath::from_template(
                &template_of(dp_empty),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // Path: "m/0"
        let dp_0 = dp_from_str("m/0");
        assert_eq!(
            dp_0.clone(),
            DerivationPath::from_template(
                &template_of(dp_0),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // Path: "m/1'"
        let dp_1h = dp_from_str("m/1'");
        assert_eq!(
            dp_1h.clone(),
            DerivationPath::from_template(
                &template_of(dp_1h),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // Path: "m/42/23h/0/1h"
        let dp_complex = dp_from_str("m/42/23h/0/1h");
        assert_eq!(
            dp_complex.clone(),
            DerivationPath::from_template(
                &template_of(dp_complex),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_deriv_paths() {
        // Single path
        let dp1_str = "m/0";
        let deriv_paths_one = DerivPaths::new(vec![dp_from_str(dp1_str)]).unwrap();
        assert_eq!(
            deriv_paths_one.clone(),
            DerivPaths::from_template(
                &template_of(deriv_paths_one),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // Multiple paths
        let dp2_str = "m/1h";
        let deriv_paths_multi =
            DerivPaths::new(vec![dp_from_str(dp1_str), dp_from_str(dp2_str)]).unwrap();
        assert_eq!(
            deriv_paths_multi.clone(),
            DerivPaths::from_template(
                &template_of(deriv_paths_multi),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_descriptor_public_key() {
        // Single FullKey Compressed, No Origin
        let (_, dpk1) = create_dpk_single_full(true, None, 2);
        assert_eq!(
            create_dpk_single_full(true, None, 1).1,
            DescriptorPublicKey::from_template(
                &template_of(dpk1.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            dpk1.clone(),
            DescriptorPublicKey::from_template(
                &template_of(dpk1.clone()),
                &mut 0,
                &payload_of(dpk1.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // Single FullKey Uncompressed, No Origin
        let (_, dpk2) = create_dpk_single_full(false, None, 2);
        assert_eq!(
            create_dpk_single_full(false, None, 1).1,
            DescriptorPublicKey::from_template(
                &template_of(dpk2.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            dpk2.clone(),
            DescriptorPublicKey::from_template(
                &template_of(dpk2.clone()),
                &mut 0,
                &payload_of(dpk2.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // Single XOnlyKey, No Origin
        let (_, dpk_xonly) = create_dpk_xonly_no_origin(2);
        assert_eq!(
            create_dpk_xonly_no_origin(1).1,
            DescriptorPublicKey::from_template(
                &template_of(dpk_xonly.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            dpk_xonly.clone(),
            DescriptorPublicKey::from_template(
                &template_of(dpk_xonly.clone()),
                &mut 0,
                &payload_of(dpk_xonly.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // Single FullKey Compressed, With Origin
        let origin_fp = fp_from_str("12345678");
        let origin_path = dp_from_str("m/84h/0h/0h");
        let (_, dpk3) = create_dpk_single_full(true, Some((origin_fp, origin_path.clone())), 3);
        assert_eq!(
            create_dpk_single_full(true, Some((dummy::fp(), origin_path.clone())), 1).1,
            DescriptorPublicKey::from_template(
                &template_of(dpk3.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            dpk3.clone(),
            DescriptorPublicKey::from_template(
                &template_of(dpk3.clone()),
                &mut 0,
                &payload_of(dpk3.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // XPub, No Origin, specific derivation path, NoWildcard
        let xpub_path_str = "m/0/0";
        let xpub = Xpub::from_str("xpub6DYotmPf2kXFYhJMFDpfydjiXG1RzmH1V7Fnn2Z38DgN2oSYruczMyTFZZPz6yXq47Re8anhXWGj4yMzPTA3bjPDdpA96TLUbMehrH3sBna").unwrap();
        let (_, dpk_xpub1) = create_dpk_xpub(None, xpub_path_str, xpub, Wildcard::None);
        assert_eq!(
            create_dpk_xpub(None, xpub_path_str, dummy::xpub(), Wildcard::None).1,
            DescriptorPublicKey::from_template(
                &template_of(dpk_xpub1.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            dpk_xpub1.clone(),
            DescriptorPublicKey::from_template(
                &template_of(dpk_xpub1.clone()),
                &mut 0,
                &payload_of(dpk_xpub1.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // XPub, With Origin, different derivation path, UnhardenedWildcard
        let (_, dpk_xpub2) = create_dpk_xpub(
            Some((origin_fp, origin_path.clone())),
            "m/1",
            xpub,
            Wildcard::Unhardened,
        );
        let (_, expected_dpk_xpub2) = create_dpk_xpub(
            Some((dummy::fp(), origin_path.clone())),
            "m/1",
            dummy::xpub(),
            Wildcard::Unhardened,
        );
        assert_eq!(
            expected_dpk_xpub2,
            DescriptorPublicKey::from_template(
                &template_of(dpk_xpub2.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            dpk_xpub2.clone(),
            DescriptorPublicKey::from_template(
                &template_of(dpk_xpub2.clone()),
                &mut 0,
                &payload_of(dpk_xpub2.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // MultiXPub, No Origin, specific derivation paths, HardenedWildcard
        let multixpub_paths_str = ["m/0/0", "m/0/1"];
        let (_, dpk_multixpub1) =
            create_dpk_multixpub(None, &multixpub_paths_str, xpub, Wildcard::Hardened);
        assert_eq!(
            create_dpk_multixpub(
                None,
                &multixpub_paths_str,
                dummy::xpub(),
                Wildcard::Hardened
            )
            .1,
            DescriptorPublicKey::from_template(
                &template_of(dpk_multixpub1.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            dpk_multixpub1.clone(),
            DescriptorPublicKey::from_template(
                &template_of(dpk_multixpub1.clone()),
                &mut 0,
                &payload_of(dpk_multixpub1.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_descriptor_secret_key() {
        let secp = Secp256k1::new();

        // Single Key Compressed, No Origin
        let (_, dsk1) = create_dsk_single(true, None, 2);
        assert_eq!(
            create_dpk_single_full(true, None, 1).1,
            DescriptorPublicKey::from_template(
                &template_of(dsk1.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        let dpk1 = dsk1.to_public(&secp).unwrap();
        let mut km = KeyMap::new();
        assert_eq!(
            dpk1.clone(),
            DescriptorPublicKey::from_template(
                &template_of(dsk1.clone()),
                &mut 0,
                &payload_of(dsk1.clone()),
                &mut 0,
                &mut km
            )
            .unwrap()
        );
        assert_eq!(&dsk1.clone(), km.get(&dpk1).unwrap());

        // Single Key Uncompressed, No Origin
        let (_, dsk2) = create_dsk_single(false, None, 2);
        assert_eq!(
            create_dpk_single_full(false, None, 1).1,
            DescriptorPublicKey::from_template(
                &template_of(dsk2.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        let dpk2 = dsk2.to_public(&secp).unwrap();
        let mut km = KeyMap::new();
        assert_eq!(
            dpk2.clone(),
            DescriptorPublicKey::from_template(
                &template_of(dsk2.clone()),
                &mut 0,
                &payload_of(dsk2.clone()),
                &mut 0,
                &mut km
            )
            .unwrap()
        );
        assert_eq!(&dsk2.clone(), km.get(&dpk2).unwrap());

        // Single Key Compressed, With Origin
        let origin_fp = fp_from_str("12345678");
        let origin_path = dp_from_str("m/84h/0h/0h");
        let (_, dsk3) = create_dsk_single(true, Some((origin_fp, origin_path.clone())), 3);
        assert_eq!(
            create_dpk_single_full(true, Some((dummy::fp(), origin_path.clone())), 1).1,
            DescriptorPublicKey::from_template(
                &template_of(dsk3.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        let dpk3 = dsk3.to_public(&secp).unwrap();
        let mut km = KeyMap::new();
        assert_eq!(
            dpk3.clone(),
            DescriptorPublicKey::from_template(
                &template_of(dsk3.clone()),
                &mut 0,
                &payload_of(dsk3.clone()),
                &mut 0,
                &mut km
            )
            .unwrap()
        );
        assert_eq!(&dsk3.clone(), km.get(&dpk3).unwrap());

        // XPriv, No Origin, specific derivation path, NoWildcard
        let xpriv_path_str = "m/0/0";
        let xpriv = Xpriv::new_master(NetworkKind::Main, &[1u8; 32]).unwrap();
        let (_, dsk_xpriv1) = create_dsk_xpriv(None, xpriv_path_str, xpriv, Wildcard::None);
        assert_eq!(
            create_dpk_xpub(None, xpriv_path_str, dummy::xpub(), Wildcard::None).1,
            DescriptorPublicKey::from_template(
                &template_of(dsk_xpriv1.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        let dpk_xpub1 = dsk_xpriv1.to_public(&secp).unwrap();
        let mut km = KeyMap::new();
        assert_eq!(
            dpk_xpub1.clone(),
            DescriptorPublicKey::from_template(
                &template_of(dsk_xpriv1.clone()),
                &mut 0,
                &payload_of(dsk_xpriv1.clone()),
                &mut 0,
                &mut km
            )
            .unwrap()
        );
        assert_eq!(&dsk_xpriv1.clone(), km.get(&dpk_xpub1).unwrap());

        // XPub, With Origin, different derivation path, UnhardenedWildcard
        let (_, dsk_xpriv2) = create_dsk_xpriv(
            Some((origin_fp, origin_path.clone())),
            "m/1",
            xpriv,
            Wildcard::Unhardened,
        );
        assert_eq!(
            create_dpk_xpub(
                Some((dummy::fp(), origin_path.clone())),
                "m/1",
                dummy::xpub(),
                Wildcard::Unhardened
            )
            .1,
            DescriptorPublicKey::from_template(
                &template_of(dsk_xpriv2.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        let dpk_xpub2 = dsk_xpriv2.to_public(&secp).unwrap();
        let mut km = KeyMap::new();
        assert_eq!(
            dpk_xpub2.clone(),
            DescriptorPublicKey::from_template(
                &template_of(dsk_xpriv2.clone()),
                &mut 0,
                &payload_of(dsk_xpriv2.clone()),
                &mut 0,
                &mut km
            )
            .unwrap()
        );
        assert_eq!(&dsk_xpriv2.clone(), km.get(&dpk_xpub2).unwrap());

        // MultiXPub, No Origin, specific derivation paths, HardenedWildcard
        let multixpriv_paths_str = ["m/0/0", "m/0/1"];
        let (_, dsk_multixpriv1) =
            create_dsk_multixpriv(None, &multixpriv_paths_str, xpriv, Wildcard::Hardened);
        assert_eq!(
            create_dpk_single_compressed_no_origin(1),
            DescriptorPublicKey::from_template(
                &template_of(dsk_multixpriv1.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        let dpk_multixpub1 = create_dpk_single_compressed_no_origin(2);
        assert_eq!(
            dpk_multixpub1.clone(),
            DescriptorPublicKey::from_template(
                &template_of(dsk_multixpriv1.clone()),
                &mut 0,
                &payload_of(dsk_multixpriv1.clone()),
                &mut 0,
                &mut km
            )
            .unwrap()
        );
        assert_eq!(&dsk_multixpriv1.clone(), km.get(&dpk_multixpub1).unwrap());
    }

    #[test]
    fn test_miniscript_terminals() {
        let pk = create_dpk_single_compressed_no_origin(1);

        let ms_true = MsSw0::TRUE;
        assert_eq!(
            ms_true.clone(),
            MsSw0::from_template(
                &template_of(ms_true),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ms_false = MsSw0::FALSE;
        assert_eq!(
            ms_false.clone(),
            MsSw0::from_template(
                &template_of(ms_false),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ms_pkk = MsSw0::from_ast(TerminalSw0::PkK(pk.clone())).unwrap();
        assert_eq!(
            ms_pkk.clone(),
            MsSw0::from_template(
                &template_of(ms_pkk),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ms_pkh = MsSw0::from_ast(TerminalSw0::PkH(pk.clone())).unwrap();
        assert_eq!(
            ms_pkh.clone(),
            MsSw0::from_template(
                &template_of(ms_pkh),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // Terminals with ignored values
        let hash160 = Hash160::from_slice(&[1u8; 20]).unwrap();
        let ms_raw_pkh = MsSw0::from_ast(TerminalSw0::RawPkH(hash160)).unwrap();
        assert_eq!(
            MsSw0::from_ast(TerminalSw0::RawPkH(dummy::hash160())).unwrap(),
            MsSw0::from_template(
                &template_of(ms_raw_pkh.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            ms_raw_pkh.clone(),
            MsSw0::from_template(
                &template_of(ms_raw_pkh.clone()),
                &mut 0,
                &payload_of(ms_raw_pkh.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ms_hash160 = MsSw0::from_ast(TerminalSw0::Hash160(hash160)).unwrap();
        assert_eq!(
            MsSw0::from_ast(TerminalSw0::Hash160(dummy::hash160())).unwrap(),
            MsSw0::from_template(
                &template_of(ms_hash160.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            ms_hash160.clone(),
            MsSw0::from_template(
                &template_of(ms_hash160.clone()),
                &mut 0,
                &payload_of(ms_hash160.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let after = AbsLockTime::from_consensus(50000).unwrap();
        let ms_after = MsSw0::from_ast(TerminalSw0::After(after)).unwrap();
        assert_eq!(
            MsSw0::from_ast(TerminalSw0::After(dummy::after())).unwrap(),
            MsSw0::from_template(
                &template_of(ms_after.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            ms_after.clone(),
            MsSw0::from_template(
                &template_of(ms_after.clone()),
                &mut 0,
                &payload_of(ms_after.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let older = RelLockTime::from_consensus(50000).unwrap();
        let ms_older = MsSw0::from_ast(TerminalSw0::Older(older)).unwrap();
        assert_eq!(
            MsSw0::from_ast(TerminalSw0::Older(dummy::older())).unwrap(),
            MsSw0::from_template(
                &template_of(ms_older.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            ms_older.clone(),
            MsSw0::from_template(
                &template_of(ms_older.clone()),
                &mut 0,
                &payload_of(ms_older.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let sha256 = Sha256::from_slice(&[1u8; 32]).unwrap();
        let ms_sha256 = MsSw0::from_ast(TerminalSw0::Sha256(sha256)).unwrap();
        assert_eq!(
            MsSw0::from_ast(TerminalSw0::Sha256(dummy::sha256())).unwrap(),
            MsSw0::from_template(
                &template_of(ms_sha256.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            ms_sha256.clone(),
            MsSw0::from_template(
                &template_of(ms_sha256.clone()),
                &mut 0,
                &payload_of(ms_sha256.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let hash256 = Hash256::from_raw_hash(sha256d::Hash::from_slice(&[1u8; 32]).unwrap());
        let ms_hash256 = MsSw0::from_ast(TerminalSw0::Hash256(hash256)).unwrap();
        assert_eq!(
            MsSw0::from_ast(TerminalSw0::Hash256(dummy::hash256())).unwrap(),
            MsSw0::from_template(
                &template_of(ms_hash256.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            ms_hash256.clone(),
            MsSw0::from_template(
                &template_of(ms_hash256.clone()),
                &mut 0,
                &payload_of(ms_hash256.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ripemd160 = Ripemd160::from_slice(&[1u8; 20]).unwrap();
        let ms_ripemd160 = MsSw0::from_ast(TerminalSw0::Ripemd160(ripemd160)).unwrap();
        assert_eq!(
            MsSw0::from_ast(TerminalSw0::Ripemd160(dummy::ripemd160())).unwrap(),
            MsSw0::from_template(
                &template_of(ms_ripemd160.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            ms_ripemd160.clone(),
            MsSw0::from_template(
                &template_of(ms_ripemd160.clone()),
                &mut 0,
                &payload_of(ms_ripemd160.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let k = 1;
        let pk1 = create_dpk_single_compressed_no_origin(1);
        let pk2 = create_dpk_single_compressed_no_origin(2);

        // Multi
        let pks = vec![pk1.clone(), pk2.clone()];
        let pks_expected = vec![pk1.clone(), pk1.clone()];
        let multi = TerminalSw0::Multi(Threshold::new(k, pks.clone()).unwrap());
        let multi_expected = TerminalSw0::Multi(Threshold::new(k, pks_expected.clone()).unwrap());
        assert_eq!(
            multi_expected.clone(),
            TerminalSw0::from_template(
                &template_of(multi.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            multi.clone(),
            TerminalSw0::from_template(
                &template_of(multi.clone()),
                &mut 0,
                &payload_of(multi.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // MultiA
        let multi_a = TerminalTap::MultiA(Threshold::new(k, pks.clone()).unwrap());
        let multi_a_expected =
            TerminalTap::MultiA(Threshold::new(k, pks_expected.clone()).unwrap());
        assert_eq!(
            multi_a_expected,
            TerminalTap::from_template(
                &template_of(multi_a.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            multi_a.clone(),
            TerminalTap::from_template(
                &template_of(multi_a.clone()),
                &mut 0,
                &payload_of(multi_a.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_miniscript_ops() {
        let pk = create_dpk_single_compressed_no_origin(1);
        let ms_true = Arc::new(MsSw0::TRUE);
        let ms_false = Arc::new(MsSw0::FALSE);
        let ms_hash160 = Arc::new(MsSw0::from_ast(TerminalSw0::Hash160(dummy::hash160())).unwrap());
        let pk_k = TerminalSw0::PkK(pk);
        let ms_pk_k = Arc::new(MsSw0::from_ast(pk_k.clone()).unwrap());

        // Unary
        let ms_alt = MsSw0::from_ast(TerminalSw0::Alt(ms_true.clone())).unwrap();
        assert_eq!(
            ms_alt.clone(),
            MsSw0::from_template(
                &template_of(ms_alt),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ms_swap = MsSw0::from_ast(TerminalSw0::Swap(ms_hash160.clone())).unwrap();
        assert_eq!(
            ms_swap.clone(),
            MsSw0::from_template(
                &template_of(ms_swap.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ms_check = MsSw0::from_ast(TerminalSw0::Check(ms_pk_k.clone())).unwrap();
        assert_eq!(
            ms_check.clone(),
            MsSw0::from_template(
                &template_of(ms_check),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ms_verify = MsSw0::from_ast(TerminalSw0::Verify(ms_true.clone())).unwrap();
        assert_eq!(
            ms_verify.clone(),
            MsSw0::from_template(
                &template_of(ms_verify.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ms_dupif = MsSw0::from_ast(TerminalSw0::DupIf(ms_verify.clone().into())).unwrap();
        assert_eq!(
            ms_dupif.clone(),
            MsSw0::from_template(
                &template_of(ms_dupif),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ms_zerone = MsSw0::from_ast(TerminalSw0::ZeroNotEqual(ms_true.clone())).unwrap();
        assert_eq!(
            ms_zerone.clone(),
            MsSw0::from_template(
                &template_of(ms_zerone),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // Binary
        let ms_andv =
            MsSw0::from_ast(TerminalSw0::AndV(ms_verify.clone().into(), ms_true.clone())).unwrap();
        assert_eq!(
            ms_andv.clone(),
            MsSw0::from_template(
                &template_of(ms_andv),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ms_andb =
            MsSw0::from_ast(TerminalSw0::AndB(ms_true.clone(), ms_swap.clone().into())).unwrap();
        assert_eq!(
            ms_andb.clone(),
            MsSw0::from_template(
                &template_of(ms_andb),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ms_orb =
            MsSw0::from_ast(TerminalSw0::OrB(ms_false.clone(), ms_swap.clone().into())).unwrap();
        assert_eq!(
            ms_orb.clone(),
            MsSw0::from_template(
                &template_of(ms_orb),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ms_orc =
            MsSw0::from_ast(TerminalSw0::OrC(ms_false.clone(), ms_verify.clone().into())).unwrap();
        assert_eq!(
            ms_orc.clone(),
            MsSw0::from_template(
                &template_of(ms_orc),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ms_ord = MsSw0::from_ast(TerminalSw0::OrD(ms_false.clone(), ms_true.clone())).unwrap();
        assert_eq!(
            ms_ord.clone(),
            MsSw0::from_template(
                &template_of(ms_ord),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ms_ori = MsSw0::from_ast(TerminalSw0::OrI(ms_true.clone(), ms_false.clone())).unwrap();
        assert_eq!(
            ms_ori.clone(),
            MsSw0::from_template(
                &template_of(ms_ori),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // Ternary
        let ms_andor = MsSw0::from_ast(TerminalSw0::AndOr(
            ms_false.clone(),
            ms_true.clone(),
            ms_true.clone(),
        ))
        .unwrap();
        assert_eq!(
            ms_andor.clone(),
            MsSw0::from_template(
                &template_of(ms_andor),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let k = 1;

        // Thresh
        let subs = vec![ms_false.clone(), ms_swap.clone().into()];
        let thresh = MsSw0::from_ast(TerminalSw0::Thresh(
            Threshold::new(k, subs.clone()).unwrap(),
        ))
        .unwrap();
        assert_eq!(
            thresh.clone(),
            MsSw0::from_template(
                &template_of(thresh),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_sorted_multi() {
        let pk1 = create_dpk_single_compressed_no_origin(1);
        let pk2 = create_dpk_single_compressed_no_origin(2);
        let pk3 = create_dpk_single_compressed_no_origin(3);

        type SortedMultiSw0 = SortedMultiVec<DescriptorPublicKey, Segwitv0>;

        let k = 2;
        let pks = vec![pk1.clone(), pk2.clone(), pk3.clone()];
        let expected_pks = vec![pk1.clone(), pk1.clone(), pk1.clone()];
        let sorted_multi = SortedMultiSw0::new(k, pks.clone()).unwrap();
        let expected_sorted_multi = SortedMultiSw0::new(k, expected_pks.clone()).unwrap();
        assert_eq!(
            expected_sorted_multi.clone(),
            SortedMultiSw0::from_template(
                &template_of(sorted_multi),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_taptree() {
        let pk1 = create_dpk_xonly_no_origin(1).1;
        let pk2 = create_dpk_xonly_no_origin(2).1;
        let ms_leaf1 = Arc::new(MsTap::from_ast(TerminalTap::PkK(pk1.clone())).unwrap());
        let ms_leaf2 = Arc::new(MsTap::from_ast(TerminalTap::PkK(pk2.clone())).unwrap());

        // Leaf
        let tap_leaf = TapTree::Leaf(ms_leaf1.clone());
        assert_eq!(
            tap_leaf.clone(),
            TapTree::from_template(
                &template_of(tap_leaf.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // Tree
        let tap_leaf2 = TapTree::Leaf(ms_leaf2.clone());
        let tap_tree = TapTree::Tree {
            left: Arc::new(tap_leaf.clone()),
            right: Arc::new(tap_leaf2.clone()),
            height: 1,
        };
        let expected_tap_tree = TapTree::Tree {
            left: Arc::new(tap_leaf.clone()),
            right: Arc::new(tap_leaf.clone()),
            height: 1,
        };
        assert_eq!(
            expected_tap_tree.clone(),
            TapTree::from_template(
                &template_of(tap_tree),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_bare_pkh_wpkh() {
        let pk_full = create_dpk_single_compressed_no_origin(1);
        let ms_bare_pkk = MsBare::from_ast(TerminalBare::PkK(pk_full.clone())).unwrap();
        let ms_bare_check_pkk = MsBare::from_ast(TerminalBare::Check(ms_bare_pkk.into())).unwrap();

        // Bare
        let bare = Bare::new(ms_bare_check_pkk.clone()).unwrap();
        assert_eq!(
            bare.clone(),
            Bare::from_template(&template_of(bare), &mut 0, &[], &mut 0, &mut KeyMap::new())
                .unwrap()
        );

        // Pkh
        let pkh = Pkh::new(pk_full.clone()).unwrap();
        assert_eq!(
            pkh.clone(),
            Pkh::from_template(&template_of(pkh), &mut 0, &[], &mut 0, &mut KeyMap::new()).unwrap()
        );

        // Wpkh
        let wpkh = Wpkh::new(pk_full.clone()).unwrap();
        assert_eq!(
            wpkh.clone(),
            Wpkh::from_template(&template_of(wpkh), &mut 0, &[], &mut 0, &mut KeyMap::new())
                .unwrap()
        );
    }

    #[test]
    fn test_sh() {
        let pk1 = create_dpk_single_compressed_no_origin(1);
        let pk2 = create_dpk_single_compressed_no_origin(2);

        // Sh(Wpkh)
        let wpkh_inner = Wpkh::new(pk1.clone()).unwrap();
        let sh_wpkh = Sh::new_with_wpkh(wpkh_inner.clone());
        assert_eq!(
            sh_wpkh.clone(),
            Sh::from_template(
                &template_of(sh_wpkh),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // Sh(Wsh)
        let ms_wsh = MsSw0::from_ast(TerminalSw0::True).unwrap();
        let wsh = Wsh::new(ms_wsh).unwrap();
        let sh_wsh = Sh::new_with_wsh(wsh.clone());
        assert_eq!(
            sh_wsh.clone(),
            Sh::from_template(
                &template_of(sh_wsh),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // Sh(SortedMulti)
        let pks = vec![pk1.clone(), pk2.clone()];
        let expected_pks = vec![pk1.clone(), pk1.clone()];
        let sh_sortedmulti = Sh::new_sortedmulti(1, pks).unwrap();
        let expected_sh_sortedmulti = Sh::new_sortedmulti(1, expected_pks).unwrap();
        assert_eq!(
            expected_sh_sortedmulti.clone(),
            Sh::from_template(
                &template_of(sh_sortedmulti),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // Sh(Miniscript)
        let ms_sh = MsLeg::from_ast(TerminalLeg::True).unwrap();
        let sh_ms = Sh::new(ms_sh.clone()).unwrap();
        assert_eq!(
            sh_ms.clone(),
            Sh::from_template(&template_of(sh_ms), &mut 0, &[], &mut 0, &mut KeyMap::new())
                .unwrap()
        );
    }

    #[test]
    fn test_wsh() {
        let pk1 = create_dpk_single_compressed_no_origin(1);
        let pk2 = create_dpk_single_compressed_no_origin(2);

        // Wsh(SortedMulti)
        let pks = vec![pk1.clone(), pk2.clone()];
        let expected_pks = vec![pk1.clone(), pk1.clone()];
        let wsh_sortedmulti = Wsh::new_sortedmulti(1, pks).unwrap();
        let expected_wsh_sortedmulti = Wsh::new_sortedmulti(1, expected_pks).unwrap();
        assert_eq!(
            expected_wsh_sortedmulti.clone(),
            Wsh::from_template(
                &template_of(wsh_sortedmulti),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // Wsh(Miniscript)
        let ms_wsh = MsSw0::from_ast(TerminalSw0::True).unwrap();
        let wsh_ms = Wsh::new(ms_wsh.clone()).unwrap();
        assert_eq!(
            wsh_ms.clone(),
            Wsh::from_template(
                &template_of(wsh_ms),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_tr() {
        let internal_key = create_dpk_xonly_no_origin(1).1;

        // Tr with no TapTree
        let tr_no_tree = Tr::new(internal_key.clone(), None).unwrap();
        assert_eq!(
            tr_no_tree.clone(),
            Tr::from_template(
                &template_of(tr_no_tree),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        // Tr with TapTree
        let leaf_ms = MsTap::from_ast(TerminalTap::True).unwrap();
        let tap_tree = TapTree::Leaf(leaf_ms.into());
        let tr_with_tree = Tr::new(internal_key.clone(), Some(tap_tree.clone())).unwrap();
        assert_eq!(
            tr_with_tree.clone(),
            Tr::from_template(
                &template_of(tr_with_tree),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_descriptor() {
        let pk1 = create_dpk_single_compressed_no_origin(1);
        let pk2 = create_dpk_single_compressed_no_origin(1);

        let ms_bare_pkk = MsBare::from_ast(TerminalBare::PkK(pk1.clone())).unwrap();
        let ms_bare_check_pkk = MsBare::from_ast(TerminalBare::Check(ms_bare_pkk.into())).unwrap();
        let bare = Bare::new(ms_bare_check_pkk.clone()).unwrap();
        let descriptor1 = Descriptor::Bare(bare);

        let ms_bare_pkk = MsBare::from_ast(TerminalBare::PkK(pk2.clone())).unwrap();
        let ms_bare_check_pkk = MsBare::from_ast(TerminalBare::Check(ms_bare_pkk.into())).unwrap();
        let bare = Bare::new(ms_bare_check_pkk.clone()).unwrap();
        let descriptor2 = Descriptor::Bare(bare);

        assert_eq!(
            descriptor1.clone(),
            Descriptor::from_template(
                &template_of(descriptor2.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            descriptor2.clone(),
            Descriptor::from_template(
                &template_of(descriptor2.clone()),
                &mut 0,
                &payload_of(descriptor2.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let pkh1 = Pkh::new(pk1.clone()).unwrap();
        let pkh2 = Pkh::new(pk2.clone()).unwrap();
        let descriptor1 = Descriptor::Pkh(pkh1);
        let descriptor2 = Descriptor::Pkh(pkh2);

        assert_eq!(
            descriptor1.clone(),
            Descriptor::from_template(
                &template_of(descriptor2.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            descriptor2.clone(),
            Descriptor::from_template(
                &template_of(descriptor2.clone()),
                &mut 0,
                &payload_of(descriptor2.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ms_sh = MsLeg::from_ast(TerminalLeg::True).unwrap();
        let sh_ms = Sh::new(ms_sh.clone()).unwrap();
        let descriptor = Descriptor::Sh(sh_ms);
        assert_eq!(
            descriptor.clone(),
            Descriptor::from_template(
                &template_of(descriptor),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let wpkh1 = Wpkh::new(pk1.clone()).unwrap();
        let wpkh2 = Wpkh::new(pk2.clone()).unwrap();
        let descriptor1 = Descriptor::Wpkh(wpkh1);
        let descriptor2 = Descriptor::Wpkh(wpkh2);

        assert_eq!(
            descriptor1.clone(),
            Descriptor::from_template(
                &template_of(descriptor2.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            descriptor2.clone(),
            Descriptor::from_template(
                &template_of(descriptor2.clone()),
                &mut 0,
                &payload_of(descriptor2.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let ms_wsh = MsSw0::from_ast(TerminalSw0::True).unwrap();
        let wsh_ms = Wsh::new(ms_wsh.clone()).unwrap();
        let descriptor = Descriptor::Wsh(wsh_ms);
        assert_eq!(
            descriptor.clone(),
            Descriptor::from_template(
                &template_of(descriptor),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );

        let tr1 = Tr::new(pk1.clone(), None).unwrap();
        let tr2 = Tr::new(pk1.clone(), None).unwrap();
        let descriptor1 = Descriptor::Tr(tr1);
        let descriptor2 = Descriptor::Tr(tr2);

        assert_eq!(
            descriptor1.clone(),
            Descriptor::from_template(
                &template_of(descriptor2.clone()),
                &mut 0,
                &[],
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
        assert_eq!(
            descriptor2.clone(),
            Descriptor::from_template(
                &template_of(descriptor2.clone()),
                &mut 0,
                &payload_of(descriptor2.clone()),
                &mut 0,
                &mut KeyMap::new()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_size() {
        let pk = create_dpk_single_compressed_no_origin(1);

        let pkh = Pkh::new(pk.clone()).unwrap();
        let descriptor = Descriptor::Pkh(pkh);
        let mut input = template_of(descriptor.clone());
        let expected_size = input.len();
        input.extend(vec![0, 1, 2, 3]);

        assert_eq!(
            decode_template(&input),
            Ok((descriptor, KeyMap::new(), expected_size))
        );
    }

    #[test]
    fn test_decode_with_payload() {
        let pk = create_dpk_single_compressed_no_origin(1);

        let pkh = Pkh::new(pk.clone()).unwrap();
        let descriptor = Descriptor::Pkh(pkh);
        let input = template_of(descriptor.clone());
        let payload = payload_of(descriptor.clone());

        assert_eq!(
            decode_with_payload(&input, &payload),
            Ok((descriptor, KeyMap::new()))
        );
    }
}
