// SPDX-License-Identifier: CC0-1.0

//! # Descriptor Encode

use super::tag::Tag;
use super::varint;

use bitcoin::{
    bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
    hashes::Hash,
};
use miniscript::{
    Miniscript, ScriptContext, Threshold,
    descriptor::{
        Bare, DerivPaths, Descriptor, DescriptorMultiXKey, DescriptorPublicKey,
        DescriptorSecretKey, DescriptorXKey, KeyMap, Pkh, Sh, ShInner, SinglePubKey,
        SortedMultiVec, TapTree, Tr, Wildcard, Wpkh, Wsh, WshInner,
    },
    miniscript::decode::Terminal,
};
use std::fmt::Debug;
use std::sync::Arc;

/// Encodes a descriptor as a template with a separate payload, containing the keys,
/// fingerprints, hashes, and timelocks.
pub fn encode(descriptor: Descriptor<DescriptorPublicKey>, key_map: &KeyMap) -> (Vec<u8>, Vec<u8>) {
    let mut template = Vec::new();
    let mut payload = Vec::new();
    descriptor.encode_template(&mut template, &mut payload, key_map);

    (template, payload)
}

/// A trait to create an encoded template
pub(crate) trait EncodeTemplate: Debug + PartialEq {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap);
}

impl EncodeTemplate for Descriptor<DescriptorPublicKey> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        match self {
            Descriptor::Sh(sh) => sh.encode_template(template, payload, key_map),
            Descriptor::Wsh(wsh) => wsh.encode_template(template, payload, key_map),
            Descriptor::Tr(tr) => tr.encode_template(template, payload, key_map),
            Descriptor::Wpkh(wpkh) => wpkh.encode_template(template, payload, key_map),
            Descriptor::Pkh(pk) => pk.encode_template(template, payload, key_map),
            Descriptor::Bare(bare) => bare.encode_template(template, payload, key_map),
        };
    }
}

impl EncodeTemplate for Sh<DescriptorPublicKey> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        template.push(Tag::Sh.value());

        match self.as_inner() {
            ShInner::SortedMulti(sortedmulti) => {
                sortedmulti.encode_template(template, payload, key_map)
            }
            ShInner::Wsh(wsh) => wsh.encode_template(template, payload, key_map),
            ShInner::Wpkh(wpkh) => wpkh.encode_template(template, payload, key_map),
            ShInner::Ms(ms) => ms.encode_template(template, payload, key_map),
        }
    }
}

impl EncodeTemplate for Wsh<DescriptorPublicKey> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        template.push(Tag::Wsh.value());

        match self.as_inner() {
            WshInner::SortedMulti(sortedmulti) => {
                sortedmulti.encode_template(template, payload, key_map)
            }
            WshInner::Ms(ms) => ms.encode_template(template, payload, key_map),
        };
    }
}

impl EncodeTemplate for Tr<DescriptorPublicKey> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        template.push(Tag::Tr.value());

        self.internal_key()
            .encode_template(template, payload, key_map);

        if let Some(tap_tree) = self.tap_tree() {
            tap_tree.encode_template(template, payload, key_map);
        }
    }
}

impl EncodeTemplate for Wpkh<DescriptorPublicKey> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        template.push(Tag::Wpkh.value());

        self.as_inner().encode_template(template, payload, key_map);
    }
}

impl EncodeTemplate for Pkh<DescriptorPublicKey> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        template.push(Tag::Pkh.value());

        self.as_inner().encode_template(template, payload, key_map);
    }
}

impl EncodeTemplate for Bare<DescriptorPublicKey> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        template.push(Tag::Bare.value());

        self.as_inner().encode_template(template, payload, key_map);
    }
}

impl EncodeTemplate for TapTree<DescriptorPublicKey> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        template.push(Tag::TapTree.value());

        match self {
            TapTree::Tree { left, right, .. } => {
                left.encode_template(template, payload, key_map);
                right.encode_template(template, payload, key_map);
            }
            TapTree::Leaf(ms) => ms.encode_template(template, payload, key_map),
        }
    }
}

impl<Ctx: ScriptContext> EncodeTemplate for SortedMultiVec<DescriptorPublicKey, Ctx> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        template.push(Tag::SortedMulti.value());
        template.extend(varint::encode(self.k() as u128));
        template.extend(varint::encode(self.n() as u128));

        self.pks()
            .iter()
            .for_each(|pk| pk.encode_template(template, payload, key_map));
    }
}

impl<Ctx: ScriptContext> EncodeTemplate for Miniscript<DescriptorPublicKey, Ctx> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        self.node.encode_template(template, payload, key_map);
    }
}

impl<Ctx: ScriptContext> EncodeTemplate for Terminal<DescriptorPublicKey, Ctx> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        match self {
            Terminal::True => {
                template.push(Tag::True.value());
            }
            Terminal::False => {
                template.push(Tag::False.value());
            }
            Terminal::PkK(pk) => {
                template.push(Tag::PkK.value());
                pk.encode_template(template, payload, key_map);
            }
            Terminal::PkH(pk) => {
                template.push(Tag::PkH.value());
                pk.encode_template(template, payload, key_map);
            }
            Terminal::RawPkH(hash) => {
                template.push(Tag::RawPkH.value());
                payload.extend(hash.as_byte_array().to_vec());
            }
            Terminal::After(after) => {
                template.push(Tag::After.value());
                payload.extend(varint::encode(after.to_consensus_u32().into()));
            }
            Terminal::Older(older) => {
                template.push(Tag::Older.value());
                payload.extend(varint::encode(older.to_consensus_u32().into()));
            }
            Terminal::Sha256(sha256) => {
                template.push(Tag::Sha256.value());
                payload.extend(sha256.as_byte_array().to_vec());
            }
            Terminal::Hash256(hash156) => {
                template.push(Tag::Hash256.value());
                payload.extend(hash156.as_byte_array().to_vec());
            }
            Terminal::Ripemd160(ripemd160) => {
                template.push(Tag::Ripemd160.value());
                payload.extend(ripemd160.as_byte_array().to_vec());
            }
            Terminal::Hash160(hash160) => {
                template.push(Tag::Hash160.value());
                payload.extend(hash160.as_byte_array().to_vec());
            }
            Terminal::Alt(ms) => {
                template.push(Tag::Alt.value());
                ms.encode_template(template, payload, key_map);
            }
            Terminal::Swap(ms) => {
                template.push(Tag::Swap.value());
                ms.encode_template(template, payload, key_map);
            }
            Terminal::Check(ms) => {
                template.push(Tag::Check.value());
                ms.encode_template(template, payload, key_map);
            }
            Terminal::DupIf(ms) => {
                template.push(Tag::DupIf.value());
                ms.encode_template(template, payload, key_map);
            }
            Terminal::Verify(ms) => {
                template.push(Tag::Verify.value());
                ms.encode_template(template, payload, key_map);
            }
            Terminal::NonZero(ms) => {
                template.push(Tag::NonZero.value());
                ms.encode_template(template, payload, key_map);
            }
            Terminal::ZeroNotEqual(ms) => {
                template.push(Tag::ZeroNotEqual.value());
                ms.encode_template(template, payload, key_map);
            }
            Terminal::AndV(ms0, ms1) => {
                template.push(Tag::AndV.value());
                ms0.encode_template(template, payload, key_map);
                ms1.encode_template(template, payload, key_map);
            }
            Terminal::AndB(ms0, ms1) => {
                template.push(Tag::AndB.value());
                ms0.encode_template(template, payload, key_map);
                ms1.encode_template(template, payload, key_map);
            }
            Terminal::AndOr(ms0, ms1, ms2) => {
                template.push(Tag::AndOr.value());
                ms0.encode_template(template, payload, key_map);
                ms1.encode_template(template, payload, key_map);
                ms2.encode_template(template, payload, key_map);
            }
            Terminal::OrB(ms0, ms1) => {
                template.push(Tag::OrB.value());
                ms0.encode_template(template, payload, key_map);
                ms1.encode_template(template, payload, key_map);
            }
            Terminal::OrC(ms0, ms1) => {
                template.push(Tag::OrC.value());
                ms0.encode_template(template, payload, key_map);
                ms1.encode_template(template, payload, key_map);
            }
            Terminal::OrD(ms0, ms1) => {
                template.push(Tag::OrD.value());
                ms0.encode_template(template, payload, key_map);
                ms1.encode_template(template, payload, key_map);
            }
            Terminal::OrI(ms0, ms1) => {
                template.push(Tag::OrI.value());
                ms0.encode_template(template, payload, key_map);
                ms1.encode_template(template, payload, key_map);
            }
            Terminal::Thresh(thresh) => {
                template.push(Tag::Thresh.value());
                thresh.encode_template(template, payload, key_map);
            }
            Terminal::Multi(thresh) => {
                template.push(Tag::Multi.value());
                thresh.encode_template(template, payload, key_map);
            }
            Terminal::MultiA(thresh) => {
                template.push(Tag::MultiA.value());
                thresh.encode_template(template, payload, key_map);
            }
        }
    }
}

impl<T: EncodeTemplate> EncodeTemplate for Arc<T> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        (**self).encode_template(template, payload, key_map);
    }
}

impl<T: EncodeTemplate, const MAX: usize> EncodeTemplate for Threshold<T, MAX> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        template.extend(varint::encode(self.k() as u128));
        template.extend(varint::encode(self.n() as u128));

        self.iter()
            .for_each(|t| t.encode_template(template, payload, key_map));
    }
}

impl EncodeTemplate for DescriptorPublicKey {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        if let Some(secret_key) = key_map.get(self) {
            secret_key.encode_template(template, payload, key_map);
            return;
        }

        let (tag, origin) = match self.clone() {
            DescriptorPublicKey::XPub(xpub) => (Tag::XPub, xpub.origin),
            DescriptorPublicKey::MultiXPub(xpub) => (Tag::MultiXPub, xpub.origin),
            DescriptorPublicKey::Single(single) => {
                let tag = match single.key {
                    SinglePubKey::FullKey(pk) => {
                        if pk.compressed {
                            Tag::CompressedFullKey
                        } else {
                            Tag::UncompressedFullKey
                        }
                    }
                    SinglePubKey::XOnly(_) => Tag::XOnly,
                };
                (tag, single.origin)
            }
        };

        template.push(tag.value());

        if let Some((fingerprint, derivation_path)) = origin {
            template.push(Tag::Origin.value());
            payload.extend(fingerprint.as_bytes().to_vec());

            derivation_path.encode_template(template, payload, key_map);
        } else {
            template.push(Tag::NoOrigin.value());
        }

        match self {
            DescriptorPublicKey::XPub(xpub) => xpub.encode_template(template, payload, key_map),
            DescriptorPublicKey::MultiXPub(xpub) => {
                xpub.encode_template(template, payload, key_map)
            }
            DescriptorPublicKey::Single(single) => {
                single.key.encode_template(template, payload, key_map)
            }
        }
    }
}

impl EncodeTemplate for DescriptorSecretKey {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        let (tag, origin) = match self.clone() {
            DescriptorSecretKey::XPrv(xprv) => (Tag::XPriv, xprv.origin),
            DescriptorSecretKey::MultiXPrv(xprv) => (Tag::MultiXPriv, xprv.origin),
            DescriptorSecretKey::Single(single) => {
                let tag = if single.key.compressed {
                    Tag::CompressedSinglePriv
                } else {
                    Tag::UncompressedSinglePriv
                };
                (tag, single.origin)
            }
        };

        template.push(tag.value());

        if let Some((fingerprint, derivation_path)) = origin {
            template.push(Tag::Origin.value());
            payload.extend(fingerprint.as_bytes().to_vec());

            derivation_path.encode_template(template, payload, key_map);
        } else {
            template.push(Tag::NoOrigin.value());
        }

        match self {
            DescriptorSecretKey::XPrv(xprv) => xprv.encode_template(template, payload, key_map),
            DescriptorSecretKey::MultiXPrv(xprv) => {
                xprv.encode_template(template, payload, key_map)
            }
            DescriptorSecretKey::Single(single) => {
                payload.extend(single.key.to_bytes());
            }
        }
    }
}

impl EncodeTemplate for DerivationPath {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        template.extend(varint::encode(self.len() as u128));

        self.into_iter()
            .for_each(|child| child.encode_template(template, payload, key_map));
    }
}

impl EncodeTemplate for ChildNumber {
    fn encode_template(&self, template: &mut Vec<u8>, _payload: &mut Vec<u8>, _key_map: &KeyMap) {
        let value = match *self {
            ChildNumber::Normal { index } => (index as u128) << 1,
            ChildNumber::Hardened { index } => 1 + ((index as u128) << 1),
        };

        template.extend(varint::encode(value));
    }
}

impl EncodeTemplate for SinglePubKey {
    fn encode_template(&self, _template: &mut Vec<u8>, payload: &mut Vec<u8>, _key_map: &KeyMap) {
        match self {
            SinglePubKey::FullKey(pk) => {
                payload.extend(pk.to_bytes());
            }
            SinglePubKey::XOnly(x_only) => {
                payload.extend(x_only.serialize().to_vec());
            }
        }
    }
}

impl EncodeTemplate for DescriptorXKey<Xpub> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        self.derivation_path
            .encode_template(template, payload, key_map);
        self.wildcard.encode_template(template, payload, key_map);

        payload.extend(self.xkey.encode().to_vec());
    }
}

impl EncodeTemplate for DescriptorMultiXKey<Xpub> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        self.derivation_paths
            .encode_template(template, payload, key_map);
        self.wildcard.encode_template(template, payload, key_map);

        payload.extend(self.xkey.encode().to_vec());
    }
}

impl EncodeTemplate for DescriptorXKey<Xpriv> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        self.derivation_path
            .encode_template(template, payload, key_map);
        self.wildcard.encode_template(template, payload, key_map);

        payload.extend(self.xkey.encode().to_vec());
    }
}

impl EncodeTemplate for DescriptorMultiXKey<Xpriv> {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        self.derivation_paths
            .encode_template(template, payload, key_map);
        self.wildcard.encode_template(template, payload, key_map);

        payload.extend(self.xkey.encode().to_vec());
    }
}

impl EncodeTemplate for DerivPaths {
    fn encode_template(&self, template: &mut Vec<u8>, payload: &mut Vec<u8>, key_map: &KeyMap) {
        template.extend(varint::encode(self.paths().len() as u128));

        self.paths()
            .iter()
            .for_each(|path| path.encode_template(template, payload, key_map));
    }
}

impl EncodeTemplate for Wildcard {
    fn encode_template(&self, template: &mut Vec<u8>, _payload: &mut Vec<u8>, _key_map: &KeyMap) {
        let tag = match self {
            Wildcard::None => Tag::NoWildcard,
            Wildcard::Unhardened => Tag::UnhardenedWildcard,
            Wildcard::Hardened => Tag::HardenedWildcard,
        };

        template.push(tag.value());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dummy, test_helpers::*};
    use bitcoin::bip32::DerivationPath;
    use miniscript::{BareCtx, Legacy, Miniscript, Segwitv0, Tap};

    /// Helper to check equality of any EncodeTemplate and template bytes
    fn assert_eq_template<T: EncodeTemplate>(t: T, expected: Vec<u8>) {
        assert_eq!(template_of(t), expected);
    }

    /// Helper to check equality of any EncodeTemplate and template and payload bytes
    fn assert_eq_template_and_payload<T: EncodeTemplate>(
        t: T,
        expected_template: Vec<u8>,
        expected_payload: Vec<u8>,
    ) {
        assert_eq_template_and_payload_with_key_map(
            t,
            expected_template,
            expected_payload,
            &KeyMap::new(),
        )
    }

    /// Helper to check equality of any EncodeTemplate and template and payload bytes
    fn assert_eq_template_and_payload_with_key_map<T: EncodeTemplate>(
        t: T,
        expected_template: Vec<u8>,
        expected_payload: Vec<u8>,
        key_map: &KeyMap,
    ) {
        let mut template = Vec::new();
        let mut payload = Vec::new();
        t.encode_template(&mut template, &mut payload, key_map);

        assert_eq!(template, expected_template);
        assert_eq!(payload, expected_payload);
    }

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
        assert_eq_template(Wildcard::None, vec![Tag::NoWildcard.value()]);
        assert_eq_template(Wildcard::Unhardened, vec![Tag::UnhardenedWildcard.value()]);
        assert_eq_template(Wildcard::Hardened, vec![Tag::HardenedWildcard.value()]);
    }

    #[test]
    fn test_derivation_path() {
        // Empty path: "m"
        let dp_empty = DerivationPath::master();
        let mut expected = varint::encode(0);
        assert_eq_template(dp_empty, expected);

        // Path: "m/0"
        let dp_0 = dp_from_str("m/0");
        expected = varint::encode(1);
        expected.extend(varint::encode(0 << 1));
        assert_eq_template(dp_0, expected);

        // Path: "m/1'"
        let dp_1h = dp_from_str("m/1'");
        expected = varint::encode(1);
        expected.extend(varint::encode(1 + (1u128 << 1)));
        assert_eq_template(dp_1h, expected);

        // Path: "m/42/23h/0/1h"
        let dp_complex = dp_from_str("m/42/23h/0/1h");
        expected = varint::encode(4);
        expected.extend(varint::encode(42u128 << 1));
        expected.extend(varint::encode(1 + (23u128 << 1)));
        expected.extend(varint::encode(0u128 << 1));
        expected.extend(varint::encode(1 + (1u128 << 1)));
        assert_eq_template(dp_complex, expected);
    }

    #[test]
    fn test_deriv_paths() {
        // Single path
        let dp1_str = "m/0";
        let deriv_paths_one = DerivPaths::new(vec![dp_from_str(dp1_str)]).unwrap();
        let mut expected = varint::encode(1);
        expected.extend(template_of(dp_from_str(dp1_str)));
        assert_eq_template(deriv_paths_one, expected);

        // Multiple paths
        let dp2_str = "m/1h";
        let deriv_paths_multi =
            DerivPaths::new(vec![dp_from_str(dp1_str), dp_from_str(dp2_str)]).unwrap();
        expected = varint::encode(2);
        expected.extend(template_of(dp_from_str(dp1_str)));
        expected.extend(template_of(dp_from_str(dp2_str)));
        assert_eq_template(deriv_paths_multi, expected);
    }

    #[test]
    fn test_descriptor_public_key() {
        // Single FullKey Compressed, No Origin
        let (pk1, dpk1) = create_dpk_single_full(true, None, 1);
        let expected_template_pk1 =
            [vec![Tag::CompressedFullKey.value(), Tag::NoOrigin.value()]].concat();
        assert_eq_template_and_payload(dpk1, expected_template_pk1, pk1.to_bytes());

        // Single FullKey Uncompressed, No Origin
        let (pk2, dpk2) = create_dpk_single_full(false, None, 2);
        let expected_template_pk2 = [vec![
            Tag::UncompressedFullKey.value(),
            Tag::NoOrigin.value(),
        ]]
        .concat();
        assert_eq_template_and_payload(dpk2, expected_template_pk2, pk2.to_bytes());

        // Single XOnlyKey, No Origin
        let (pk_xonly, dpk_xonly) = create_dpk_xonly_no_origin(1);
        let expected_pk_xonly = [vec![Tag::XOnly.value(), Tag::NoOrigin.value()]].concat();
        assert_eq_template_and_payload(dpk_xonly, expected_pk_xonly, pk_xonly.serialize().to_vec());

        // Single FullKey Compressed, With Origin
        let origin_fp = fp_from_str("12345678");
        let origin_path = dp_from_str("m/84h/0h/0h");
        let (pk3, dpk3) = create_dpk_single_full(true, Some((origin_fp, origin_path.clone())), 3);
        let expected_template = [
            vec![Tag::CompressedFullKey.value(), Tag::Origin.value()],
            template_of(origin_path.clone()),
        ]
        .concat();
        let expected_payload = [origin_fp.as_bytes().to_vec(), pk3.to_bytes()].concat();
        assert_eq_template_and_payload(dpk3, expected_template, expected_payload);

        // XPub, No Origin, specific derivation path, NoWildcard
        let xpub_path_str = "m/0/0";
        let (xpub1, dpk_xpub1) =
            create_dpk_xpub(None, xpub_path_str, dummy::xpub(), Wildcard::None);
        let expected_template = [
            vec![Tag::XPub.value(), Tag::NoOrigin.value()],
            template_of(dp_from_str(xpub_path_str)),
            template_of(Wildcard::None),
        ]
        .concat();
        assert_eq_template_and_payload(dpk_xpub1, expected_template, xpub1.encode().to_vec());

        // XPub, With Origin, different derivation path, UnhardenedWildcard
        let (xpub2, dpk_xpub2) = create_dpk_xpub(
            Some((origin_fp, origin_path.clone())),
            "m/1",
            dummy::xpub(),
            Wildcard::Unhardened,
        );
        let expected_template = [
            vec![Tag::XPub.value(), Tag::Origin.value()],
            template_of(origin_path.clone()),
            template_of(dp_from_str("m/1")),
            template_of(Wildcard::Unhardened),
        ]
        .concat();
        let expected_payload = [origin_fp.as_bytes().to_vec(), xpub2.encode().to_vec()].concat();
        assert_eq_template_and_payload(dpk_xpub2, expected_template, expected_payload);

        // MultiXPub, No Origin, specific derivation paths, HardenedWildcard
        let multixpub_paths_str = ["m/0/0", "m/0/1"];
        let (xpub1, dpk_multixpub1) = create_dpk_multixpub(
            None,
            &multixpub_paths_str,
            dummy::xpub(),
            Wildcard::Hardened,
        );
        let paths =
            DerivPaths::new(multixpub_paths_str.iter().map(|s| dp_from_str(s)).collect()).unwrap();
        let expected_dpk_multixpub1 = [
            vec![Tag::MultiXPub.value(), Tag::NoOrigin.value()],
            template_of(paths),
            template_of(Wildcard::Hardened),
        ]
        .concat();
        assert_eq_template_and_payload(
            dpk_multixpub1,
            expected_dpk_multixpub1,
            xpub1.encode().to_vec(),
        );
    }

    #[test]
    fn test_descriptor_secret_key() {
        // Dummy Descriptor Public Key
        let (_, dpk) = create_dpk_single_full(true, None, 1);
        let mut km = KeyMap::new();

        // Single Key Compressed, No Origin
        let (sk1, dsk1) = create_dsk_single(true, None, 1);
        km.insert(dpk.clone(), dsk1.clone());
        let expected_template_sk1 = [vec![
            Tag::CompressedSinglePriv.value(),
            Tag::NoOrigin.value(),
        ]]
        .concat();
        assert_eq_template_and_payload_with_key_map(
            dpk.clone(),
            expected_template_sk1,
            sk1.to_bytes(),
            &km,
        );

        // Single Key Uncompressed, No Origin
        let (sk2, dsk2) = create_dsk_single(false, None, 2);
        km.insert(dpk.clone(), dsk2.clone());
        let expected_template_sk2 = [vec![
            Tag::UncompressedSinglePriv.value(),
            Tag::NoOrigin.value(),
        ]]
        .concat();
        assert_eq_template_and_payload_with_key_map(
            dpk.clone(),
            expected_template_sk2,
            sk2.to_bytes(),
            &km,
        );

        // Single Key Compressed, With Origin
        let origin_fp = fp_from_str("12345678");
        let origin_path = dp_from_str("m/84h/0h/0h");
        let (sk3, dsk3) = create_dsk_single(true, Some((origin_fp, origin_path.clone())), 3);
        km.insert(dpk.clone(), dsk3.clone());
        let expected_template = [
            vec![Tag::CompressedSinglePriv.value(), Tag::Origin.value()],
            template_of(origin_path.clone()),
        ]
        .concat();
        let expected_payload = [origin_fp.as_bytes().to_vec(), sk3.to_bytes()].concat();
        assert_eq_template_and_payload_with_key_map(
            dpk.clone(),
            expected_template,
            expected_payload,
            &km,
        );

        // XPriv, No Origin, specific derivation path, NoWildcard
        let xpriv_path_str = "m/0/0";
        let (xpriv1, dsk_xpriv1) =
            create_dsk_xpriv(None, xpriv_path_str, dummy::xpriv(), Wildcard::None);
        km.insert(dpk.clone(), dsk_xpriv1.clone());
        let expected_template = [
            vec![Tag::XPriv.value(), Tag::NoOrigin.value()],
            template_of(dp_from_str(xpriv_path_str)),
            template_of(Wildcard::None),
        ]
        .concat();
        assert_eq_template_and_payload_with_key_map(
            dpk.clone(),
            expected_template,
            xpriv1.encode().to_vec(),
            &km,
        );

        // XPriv, With Origin, different derivation path, UnhardenedWildcard
        let (xpriv2, dsk_xpriv2) = create_dsk_xpriv(
            Some((origin_fp, origin_path.clone())),
            "m/1",
            dummy::xpriv(),
            Wildcard::Unhardened,
        );
        km.insert(dpk.clone(), dsk_xpriv2.clone());
        let expected_template = [
            vec![Tag::XPriv.value(), Tag::Origin.value()],
            template_of(origin_path.clone()),
            template_of(dp_from_str("m/1")),
            template_of(Wildcard::Unhardened),
        ]
        .concat();
        let expected_payload = [origin_fp.as_bytes().to_vec(), xpriv2.encode().to_vec()].concat();
        assert_eq_template_and_payload_with_key_map(
            dpk.clone(),
            expected_template,
            expected_payload,
            &km,
        );

        // MultiXPub, No Origin, specific derivation paths, HardenedWildcard
        let multixpriv_paths_str = ["m/0/0", "m/0/1"];
        let (xpriv1, dsk_multixpriv1) = create_dsk_multixpriv(
            None,
            &multixpriv_paths_str,
            dummy::xpriv(),
            Wildcard::Hardened,
        );
        km.insert(dpk.clone(), dsk_multixpriv1.clone());
        let paths = DerivPaths::new(
            multixpriv_paths_str
                .iter()
                .map(|s| dp_from_str(s))
                .collect(),
        )
        .unwrap();
        let expected_dsk_multixpriv1 = [
            vec![Tag::MultiXPriv.value(), Tag::NoOrigin.value()],
            template_of(paths),
            template_of(Wildcard::Hardened),
        ]
        .concat();
        assert_eq_template_and_payload_with_key_map(
            dpk.clone(),
            expected_dsk_multixpriv1,
            xpriv1.encode().to_vec(),
            &km,
        );
    }

    #[test]
    fn test_descriptor_xkey_multixkey() {
        let xpub = dummy::xpub();

        // DescriptorXKey
        let xkey = DescriptorXKey {
            origin: None,
            xkey: xpub,
            derivation_path: dp_from_str("m/0"),
            wildcard: Wildcard::Unhardened,
        };
        let expected_xkey_template = [
            template_of(dp_from_str("m/0")),
            template_of(Wildcard::Unhardened),
        ]
        .concat();
        assert_eq_template_and_payload(
            xkey.clone(),
            expected_xkey_template,
            xpub.clone().encode().to_vec(),
        );

        // DescriptorMultiXKey
        let multixkey_paths_str = ["m/0/0", "m/0/1"];
        let multixkey_paths =
            DerivPaths::new(multixkey_paths_str.iter().map(|s| dp_from_str(s)).collect()).unwrap();
        let multixkey = DescriptorMultiXKey {
            origin: None,
            xkey: xpub,
            derivation_paths: multixkey_paths.clone(),
            wildcard: Wildcard::None,
        };
        let expected_multixkey =
            [template_of(multixkey_paths), template_of(Wildcard::None)].concat();
        assert_eq_template_and_payload(
            multixkey,
            expected_multixkey,
            xpub.clone().encode().to_vec(),
        );
    }

    #[test]
    fn test_descriptor_xkey_multixkey_priv() {
        let xpriv = dummy::xpriv();

        // DescriptorXKey
        let xkey = DescriptorXKey {
            origin: None,
            xkey: xpriv,
            derivation_path: dp_from_str("m/0"),
            wildcard: Wildcard::Unhardened,
        };
        let expected_xkey_template = [
            template_of(dp_from_str("m/0")),
            template_of(Wildcard::Unhardened),
        ]
        .concat();
        assert_eq_template_and_payload(
            xkey.clone(),
            expected_xkey_template,
            xpriv.clone().encode().to_vec(),
        );

        // DescriptorMultiXKey
        let multixkey_paths_str = ["m/0/0", "m/0/1"];
        let multixkey_paths =
            DerivPaths::new(multixkey_paths_str.iter().map(|s| dp_from_str(s)).collect()).unwrap();
        let multixkey = DescriptorMultiXKey {
            origin: None,
            xkey: xpriv,
            derivation_paths: multixkey_paths.clone(),
            wildcard: Wildcard::None,
        };
        let expected_multixkey =
            [template_of(multixkey_paths), template_of(Wildcard::None)].concat();
        assert_eq_template_and_payload(
            multixkey,
            expected_multixkey,
            xpriv.clone().encode().to_vec(),
        );
    }

    #[test]
    fn test_miniscript_terminals() {
        let pk = create_dpk_single_compressed_no_origin(1);

        assert_eq_template(TerminalSw0::True, vec![Tag::True.value()]);
        assert_eq_template(TerminalSw0::False, vec![Tag::False.value()]);

        let expected_pk_k = [vec![Tag::PkK.value()], template_of(pk.clone())].concat();
        assert_eq_template(TerminalSw0::PkK(pk.clone()), expected_pk_k);

        let expected_pk_h = [vec![Tag::PkH.value()], template_of(pk.clone())].concat();
        assert_eq_template(TerminalSw0::PkH(pk.clone()), expected_pk_h);

        // Terminals with ignored values
        let hash160 = dummy::hash160();
        assert_eq_template_and_payload(
            TerminalSw0::RawPkH(hash160),
            vec![Tag::RawPkH.value()],
            hash160.as_byte_array().to_vec(),
        );
        assert_eq_template_and_payload(
            TerminalSw0::Hash160(hash160),
            vec![Tag::Hash160.value()],
            hash160.as_byte_array().to_vec(),
        );

        let after = dummy::after();
        assert_eq_template_and_payload(
            TerminalSw0::After(after),
            vec![Tag::After.value()],
            varint::encode(after.to_consensus_u32().into()),
        );

        let older = dummy::older();
        assert_eq_template_and_payload(
            TerminalSw0::Older(older),
            vec![Tag::Older.value()],
            varint::encode(after.to_consensus_u32().into()),
        );

        let sha256 = dummy::sha256();
        assert_eq_template_and_payload(
            TerminalSw0::Sha256(sha256),
            vec![Tag::Sha256.value()],
            sha256.as_byte_array().to_vec(),
        );

        let hash256 = dummy::hash256();
        assert_eq_template_and_payload(
            TerminalSw0::Hash256(hash256),
            vec![Tag::Hash256.value()],
            hash256.as_byte_array().to_vec(),
        );

        let ripemd160 = dummy::ripemd160();
        assert_eq_template_and_payload(
            TerminalSw0::Ripemd160(ripemd160),
            vec![Tag::Ripemd160.value()],
            ripemd160.as_byte_array().to_vec(),
        );
    }

    #[test]
    fn test_miniscript_ops() {
        let pk = create_dpk_single_compressed_no_origin(1);
        let ms_true = Arc::new(MsSw0::TRUE);
        let ms_false = Arc::new(MsSw0::FALSE);
        let ms_pk_k = Arc::new(MsSw0::from_ast(TerminalSw0::PkK(pk)).unwrap());

        // Unary
        assert_eq_template(
            TerminalSw0::Alt(ms_true.clone()),
            [vec![Tag::Alt.value()], template_of(ms_true.clone())].concat(),
        );
        assert_eq_template(
            TerminalSw0::Swap(ms_true.clone()),
            [vec![Tag::Swap.value()], template_of(ms_true.clone())].concat(),
        );
        assert_eq_template(
            TerminalSw0::Check(ms_true.clone()),
            [vec![Tag::Check.value()], template_of(ms_true.clone())].concat(),
        );
        assert_eq_template(
            TerminalSw0::DupIf(ms_true.clone()),
            [vec![Tag::DupIf.value()], template_of(ms_true.clone())].concat(),
        );
        assert_eq_template(
            TerminalSw0::Verify(ms_true.clone()),
            [vec![Tag::Verify.value()], template_of(ms_true.clone())].concat(),
        );
        assert_eq_template(
            TerminalSw0::NonZero(ms_true.clone()),
            [vec![Tag::NonZero.value()], template_of(ms_true.clone())].concat(),
        );
        assert_eq_template(
            TerminalSw0::ZeroNotEqual(ms_true.clone()),
            [
                vec![Tag::ZeroNotEqual.value()],
                template_of(ms_true.clone()),
            ]
            .concat(),
        );

        // Binary
        assert_eq_template(
            TerminalSw0::AndV(ms_true.clone(), ms_false.clone()),
            [
                vec![Tag::AndV.value()],
                template_of(ms_true.clone()),
                template_of(ms_false.clone()),
            ]
            .concat(),
        );
        assert_eq_template(
            TerminalSw0::AndB(ms_true.clone(), ms_false.clone()),
            [
                vec![Tag::AndB.value()],
                template_of(ms_true.clone()),
                template_of(ms_false.clone()),
            ]
            .concat(),
        );
        assert_eq_template(
            TerminalSw0::OrB(ms_true.clone(), ms_false.clone()),
            [
                vec![Tag::OrB.value()],
                template_of(ms_true.clone()),
                template_of(ms_false.clone()),
            ]
            .concat(),
        );
        assert_eq_template(
            TerminalSw0::OrC(ms_true.clone(), ms_false.clone()),
            [
                vec![Tag::OrC.value()],
                template_of(ms_true.clone()),
                template_of(ms_false.clone()),
            ]
            .concat(),
        );
        assert_eq_template(
            TerminalSw0::OrD(ms_true.clone(), ms_false.clone()),
            [
                vec![Tag::OrD.value()],
                template_of(ms_true.clone()),
                template_of(ms_false.clone()),
            ]
            .concat(),
        );
        assert_eq_template(
            TerminalSw0::OrI(ms_true.clone(), ms_false.clone()),
            [
                vec![Tag::OrI.value()],
                template_of(ms_true.clone()),
                template_of(ms_false.clone()),
            ]
            .concat(),
        );

        // Ternary
        assert_eq_template(
            TerminalSw0::AndOr(ms_true.clone(), ms_false.clone(), ms_pk_k.clone()),
            [
                vec![Tag::AndOr.value()],
                template_of(ms_true.clone()),
                template_of(ms_false.clone()),
                template_of(ms_pk_k),
            ]
            .concat(),
        );
    }

    #[test]
    fn test_threshold_miniscript() {
        let pk1 = create_dpk_single_compressed_no_origin(1);
        let pk2 = create_dpk_single_compressed_no_origin(2);
        let ms1 = Arc::new(MsSw0::from_ast(TerminalSw0::PkK(pk1.clone())).unwrap());
        let ms2 = Arc::new(MsSw0::from_ast(TerminalSw0::PkK(pk2.clone())).unwrap());

        let k = 1;
        let n = 2;

        // Thresh
        let subs = vec![ms1.clone(), ms2.clone()];
        let thresh = Threshold::<Arc<MsSw0>, 0>::new(k, subs.clone()).unwrap();
        let mut expected_thresh_inner = varint::encode(k as u128);
        expected_thresh_inner.extend(varint::encode(n as u128));
        for sub in subs {
            expected_thresh_inner.extend(template_of(sub));
        }
        let expected_template = [vec![Tag::Thresh.value()], expected_thresh_inner].concat();
        assert_eq_template(TerminalSw0::Thresh(thresh), expected_template);

        // Multi
        let pks = vec![pk1.clone(), pk2.clone()];
        let multi = Threshold::<DescriptorPublicKey, 20>::new(k, pks.clone()).unwrap();
        let mut expected_thresh_inner = varint::encode(k as u128);
        expected_thresh_inner.extend(varint::encode(n as u128));
        for pk in pks {
            expected_thresh_inner.extend(template_of(pk.clone()));
        }
        let expected_template = [vec![Tag::Multi.value()], expected_thresh_inner].concat();
        assert_eq_template(TerminalSw0::Multi(multi), expected_template);

        // MultiA
        let pks = vec![pk1.clone(), pk2.clone()];
        let multi_a = Threshold::<DescriptorPublicKey, 125000>::new(k, pks.clone()).unwrap();
        let mut expected_thresh_inner = varint::encode(k as u128);
        expected_thresh_inner.extend(varint::encode(n as u128));
        for pk in pks {
            expected_thresh_inner.extend(template_of(pk.clone()));
        }
        let expected_template = [vec![Tag::MultiA.value()], expected_thresh_inner].concat();
        assert_eq_template(TerminalSw0::MultiA(multi_a), expected_template);
    }

    #[test]
    fn test_sorted_multi() {
        let pk1 = create_dpk_single_compressed_no_origin(1);
        let pk2 = create_dpk_single_compressed_no_origin(2);
        let pk3 = create_dpk_single_compressed_no_origin(3);

        let k = 2;
        let n = 3;

        let pks = vec![pk1.clone(), pk2.clone(), pk3.clone()];
        let sorted_multi =
            SortedMultiVec::<DescriptorPublicKey, Segwitv0>::new(k, pks.clone()).unwrap();
        let mut expected_inner = varint::encode(k as u128);
        expected_inner.extend(varint::encode(n as u128));
        for pk_in_vec in pks {
            expected_inner.extend(template_of(pk_in_vec));
        }
        let expected_template = [vec![Tag::SortedMulti.value()], expected_inner].concat();
        assert_eq_template(sorted_multi, expected_template);
    }

    #[test]
    fn test_taptree() {
        let (_, pk1) = create_dpk_xonly_no_origin(1);
        let ms_leaf1 = Arc::new(MsTap::from_ast(TerminalTap::PkK(pk1.clone())).unwrap());

        // Leaf
        let tap_leaf = TapTree::Leaf(ms_leaf1.clone());
        let expected_leaf = [vec![Tag::TapTree.value()], template_of(ms_leaf1.clone())].concat();
        assert_eq_template(tap_leaf.clone(), expected_leaf);

        // Tree
        let (_, pk2) = create_dpk_xonly_no_origin(2);
        let ms_leaf2 = Arc::new(MsTap::from_ast(TerminalTap::PkK(pk2.clone())).unwrap());
        let tap_leaf2 = TapTree::Leaf(ms_leaf2.clone());

        let tap_tree = TapTree::Tree {
            left: Arc::new(tap_leaf.clone()),
            right: Arc::new(tap_leaf2.clone()),
            height: 1,
        };
        let expected_tree = [
            vec![Tag::TapTree.value()],
            template_of(tap_leaf),
            template_of(tap_leaf2),
        ]
        .concat();
        assert_eq_template(tap_tree, expected_tree);
    }

    #[test]
    fn test_bare_pkh_wpkh() {
        let pk_full = create_dpk_single_compressed_no_origin(1);
        let ms_bare_pkk = MsBare::from_ast(TerminalBare::PkK(pk_full.clone())).unwrap();
        let ms_bare_check_pkk = MsBare::from_ast(TerminalBare::Check(ms_bare_pkk.into())).unwrap();

        // Bare
        let bare_desc = Bare::new(ms_bare_check_pkk.clone()).unwrap();
        let expected_bare = [
            vec![Tag::Bare.value()],
            template_of(ms_bare_check_pkk.clone()),
        ]
        .concat();
        assert_eq_template(bare_desc, expected_bare);

        // Pkh
        let pkh_desc = Pkh::new(pk_full.clone()).unwrap();
        let expected_pkh = [vec![Tag::Pkh.value()], template_of(pk_full.clone())].concat();
        assert_eq_template(pkh_desc, expected_pkh);

        // Wpkh
        let wpkh_desc = Wpkh::new(pk_full.clone()).unwrap();
        let expected_wpkh = [vec![Tag::Wpkh.value()], template_of(pk_full.clone())].concat();
        assert_eq_template(wpkh_desc, expected_wpkh);
    }

    #[test]
    fn test_sh() {
        let pk1 = create_dpk_single_compressed_no_origin(1);
        let pk2 = create_dpk_single_compressed_no_origin(2);

        // Sh(Wpkh)
        let wpkh_inner = Wpkh::new(pk1.clone()).unwrap();
        let sh_wpkh = Sh::new_with_wpkh(wpkh_inner.clone());
        let expected_sh_wpkh = [vec![Tag::Sh.value()], template_of(wpkh_inner)].concat();
        assert_eq_template(sh_wpkh, expected_sh_wpkh);

        // Sh(Wsh)
        let ms_wsh = MsSw0::from_ast(TerminalSw0::True).unwrap();
        let wsh = Wsh::new(ms_wsh).unwrap();
        let sh_wsh = Sh::new_with_wsh(wsh.clone());
        let expected_sh_wsh = [vec![Tag::Sh.value()], template_of(wsh)].concat();
        assert_eq_template(sh_wsh, expected_sh_wsh);

        // Sh(SortedMulti)
        let pks = vec![pk1.clone(), pk2.clone()];
        let sorted_multi = SortedMultiVec::<_, Legacy>::new(1, pks.clone()).unwrap();
        let sh_sortedmulti = Sh::new_sortedmulti(1, pks).unwrap();
        let expected_sh_sortedmulti = [vec![Tag::Sh.value()], template_of(sorted_multi)].concat();
        assert_eq_template(sh_sortedmulti, expected_sh_sortedmulti);

        // Sh(Miniscript)
        let ms_sh = MsLeg::from_ast(TerminalLeg::True).unwrap();
        let sh_ms = Sh::new(ms_sh.clone()).unwrap();
        let expected_sh_ms = [vec![Tag::Sh.value()], template_of(ms_sh)].concat();
        assert_eq_template(sh_ms, expected_sh_ms);
    }

    #[test]
    fn test_wsh() {
        let pk1 = create_dpk_single_compressed_no_origin(1);
        let pk2 = create_dpk_single_compressed_no_origin(2);

        // Wsh(SortedMulti)
        let pks = vec![pk1.clone(), pk2.clone()];
        let sorted_multi = SortedMultiVec::<_, Segwitv0>::new(1, pks.clone()).unwrap();
        let wsh_sortedmulti = Wsh::new_sortedmulti(1, pks).unwrap();
        let expected_wsh_sortedmulti = [vec![Tag::Wsh.value()], template_of(sorted_multi)].concat();
        assert_eq_template(wsh_sortedmulti, expected_wsh_sortedmulti);

        // Wsh(Miniscript)
        let ms_wsh = MsSw0::from_ast(TerminalSw0::True).unwrap();
        let wsh_ms = Wsh::new(ms_wsh.clone()).unwrap();
        let expected_wsh_ms = [vec![Tag::Wsh.value()], template_of(ms_wsh)].concat();
        assert_eq_template(wsh_ms, expected_wsh_ms);
    }

    #[test]
    fn test_tr() {
        let (_, internal_key) = create_dpk_xonly_no_origin(1);

        // Tr with no TapTree
        let tr_no_tree = Tr::new(internal_key.clone(), None).unwrap();
        let expected_tr_no_tree =
            [vec![Tag::Tr.value()], template_of(internal_key.clone())].concat();
        assert_eq_template(tr_no_tree, expected_tr_no_tree);

        // Tr with TapTree
        let leaf_ms = MsTap::from_ast(TerminalTap::True).unwrap();
        let tap_tree = TapTree::Leaf(leaf_ms.into());
        let tr_with_tree = Tr::new(internal_key.clone(), Some(tap_tree.clone())).unwrap();
        let expected_tr_with_tree = [
            vec![Tag::Tr.value()],
            template_of(internal_key),
            template_of(tap_tree),
        ]
        .concat();
        assert_eq_template(tr_with_tree, expected_tr_with_tree);
    }

    #[test]
    fn test_descriptor() {
        let pk = create_dpk_single_compressed_no_origin(1);

        let ms_bare_pkk = MsBare::from_ast(TerminalBare::PkK(pk.clone())).unwrap();
        let ms_bare_check_pkk = MsBare::from_ast(TerminalBare::Check(ms_bare_pkk.into())).unwrap();
        let bare = Bare::new(ms_bare_check_pkk.clone()).unwrap();
        let descriptor = Descriptor::Bare(bare.clone());
        let (template, payload) = encode(descriptor.clone(), &KeyMap::new());
        assert_eq!(template, template_of(bare.clone()));
        assert_eq!(payload, payload_of(bare.clone()));

        let pkh = Pkh::new(pk.clone()).unwrap();
        let descriptor = Descriptor::Pkh(pkh.clone());
        let (template, payload) = encode(descriptor.clone(), &KeyMap::new());
        assert_eq!(template, template_of(pkh.clone()));
        assert_eq!(payload, payload_of(pkh));

        let ms_sh = MsLeg::from_ast(TerminalLeg::True).unwrap();
        let sh_ms = Sh::new(ms_sh.clone()).unwrap();
        let descriptor = Descriptor::Sh(sh_ms.clone());
        let (template, payload) = encode(descriptor.clone(), &KeyMap::new());
        assert_eq!(template, template_of(sh_ms.clone()));
        assert_eq!(payload, payload_of(sh_ms.clone()));

        let wpkh = Wpkh::new(pk.clone()).unwrap();
        let descriptor = Descriptor::Wpkh(wpkh.clone());
        let (template, payload) = encode(descriptor.clone(), &KeyMap::new());
        assert_eq!(template, template_of(wpkh.clone()));
        assert_eq!(payload, payload_of(wpkh.clone()));

        let ms_wsh = MsSw0::from_ast(TerminalSw0::True).unwrap();
        let wsh_ms = Wsh::new(ms_wsh.clone()).unwrap();
        let descriptor = Descriptor::Wsh(wsh_ms.clone());
        let (template, payload) = encode(descriptor.clone(), &KeyMap::new());
        assert_eq!(template, template_of(wsh_ms.clone()));
        assert_eq!(payload, payload_of(wsh_ms.clone()));

        let tr = Tr::new(pk.clone(), None).unwrap();
        let descriptor = Descriptor::Tr(tr.clone());
        let (template, payload) = encode(descriptor.clone(), &KeyMap::new());
        assert_eq!(template, template_of(tr.clone()));
        assert_eq!(payload, payload_of(tr.clone()));
    }
}
