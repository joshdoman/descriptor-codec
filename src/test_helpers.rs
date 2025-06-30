use crate::dummy;
#[cfg(test)]
use crate::encode::EncodeTemplate;
use bitcoin::PublicKey;
#[cfg(test)]
use bitcoin::{
    NetworkKind, PrivateKey, XOnlyPublicKey,
    bip32::{DerivationPath, Fingerprint, Xpriv, Xpub},
};
#[cfg(test)]
use miniscript::descriptor::{
    DerivPaths, DescriptorMultiXKey, DescriptorSecretKey, DescriptorXKey, KeyMap, SinglePriv,
    Wildcard,
};
use miniscript::descriptor::{DescriptorPublicKey, SinglePub, SinglePubKey};
#[cfg(test)]
use std::str::FromStr;

// Helper to create a DerivationPath from a string
#[cfg(test)]
pub(crate) fn dp_from_str(s: &str) -> DerivationPath {
    DerivationPath::from_str(s).unwrap()
}

// Helper to create a Fingerprint from a hex string
#[cfg(test)]
pub(crate) fn fp_from_str(s: &str) -> Fingerprint {
    Fingerprint::from_hex(s).unwrap()
}

// Helper to create a simple DescriptorPublicKey (Single, FullKey, Compressed, No Origin)
pub fn create_dpk_single_compressed_no_origin(index: u32) -> DescriptorPublicKey {
    let pk = PublicKey {
        inner: dummy::pk_at_index(index),
        compressed: true,
    };
    DescriptorPublicKey::Single(SinglePub {
        key: SinglePubKey::FullKey(pk),
        origin: None,
    })
}

// Helper to create an XOnly DescriptorPublicKey
#[cfg(test)]
pub(crate) fn create_dpk_xonly_no_origin(index: u32) -> (XOnlyPublicKey, DescriptorPublicKey) {
    let xonly_pk = XOnlyPublicKey::from(dummy::pk_at_index(index));
    let dpk = DescriptorPublicKey::Single(SinglePub {
        key: SinglePubKey::XOnly(xonly_pk),
        origin: None,
    });

    (xonly_pk, dpk)
}

// Helper to generate a DescriptorPublicKey::Single(FullKey)
#[cfg(test)]
pub(crate) fn create_dpk_single_full(
    compressed: bool,
    origin: Option<(Fingerprint, DerivationPath)>,
    index: u32,
) -> (PublicKey, DescriptorPublicKey) {
    let pk = PublicKey {
        inner: dummy::pk_at_index(index),
        compressed,
    };
    let dpk = DescriptorPublicKey::Single(SinglePub {
        key: SinglePubKey::FullKey(pk),
        origin,
    });

    (pk, dpk)
}

// Helper to generate a DescriptorPublicKey::XPub
#[cfg(test)]
pub(crate) fn create_dpk_xpub(
    origin: Option<(Fingerprint, DerivationPath)>,
    xpub_derivation_path_str: &str,
    xkey: Xpub,
    wildcard: Wildcard,
) -> (Xpub, DescriptorPublicKey) {
    let dpk = DescriptorPublicKey::XPub(DescriptorXKey {
        origin,
        xkey,
        derivation_path: dp_from_str(xpub_derivation_path_str),
        wildcard,
    });

    (xkey, dpk)
}

// Helper to generate a DescriptorPublicKey::MultiXPub
#[cfg(test)]
pub(crate) fn create_dpk_multixpub(
    origin: Option<(Fingerprint, DerivationPath)>,
    xpub_derivation_paths_str: &[&str],
    xkey: Xpub,
    wildcard: Wildcard,
) -> (Xpub, DescriptorPublicKey) {
    let paths: Vec<DerivationPath> = xpub_derivation_paths_str
        .iter()
        .map(|s| dp_from_str(s))
        .collect();
    let dpk = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
        origin,
        xkey,
        derivation_paths: DerivPaths::new(paths).unwrap(),
        wildcard,
    });

    (xkey, dpk)
}

// Helper to generate a DescriptorSecretKey::Single
#[cfg(test)]
pub(crate) fn create_dsk_single(
    compressed: bool,
    origin: Option<(Fingerprint, DerivationPath)>,
    index: u32,
) -> (PrivateKey, DescriptorSecretKey) {
    let sk = dummy::sk_at_index(index);
    let key = if compressed {
        PrivateKey::new(sk, NetworkKind::Main)
    } else {
        PrivateKey::new_uncompressed(sk, NetworkKind::Main)
    };
    let dsk = DescriptorSecretKey::Single(SinglePriv { key, origin });

    (key, dsk)
}

// Helper to generate a DescriptorSecretKey::XPub
#[cfg(test)]
pub(crate) fn create_dsk_xpriv(
    origin: Option<(Fingerprint, DerivationPath)>,
    xpriv_derivation_paths_str: &str,
    xkey: Xpriv,
    wildcard: Wildcard,
) -> (Xpriv, DescriptorSecretKey) {
    let dsk = DescriptorSecretKey::XPrv(DescriptorXKey {
        origin,
        xkey,
        derivation_path: dp_from_str(xpriv_derivation_paths_str),
        wildcard,
    });

    (xkey, dsk)
}

// Helper to generate a DescriptorSecretKey::MultiXPub
#[cfg(test)]
pub(crate) fn create_dsk_multixpriv(
    origin: Option<(Fingerprint, DerivationPath)>,
    xpriv_derivation_paths_str: &[&str],
    xkey: Xpriv,
    wildcard: Wildcard,
) -> (Xpriv, DescriptorSecretKey) {
    let paths: Vec<DerivationPath> = xpriv_derivation_paths_str
        .iter()
        .map(|s| dp_from_str(s))
        .collect();
    let dsk = DescriptorSecretKey::MultiXPrv(DescriptorMultiXKey {
        origin,
        xkey,
        derivation_paths: DerivPaths::new(paths).unwrap(),
        wildcard,
    });

    (xkey, dsk)
}

/// Helper to convert any EncodeTemplate to template bytes
#[cfg(test)]
pub(crate) fn template_of<T: EncodeTemplate>(t: T) -> Vec<u8> {
    let mut template = Vec::new();
    let mut payload = Vec::new();
    t.encode_template(&mut template, &mut payload, &KeyMap::new());
    template
}

/// Helper to convert any EncodeTemplate to payload bytes
#[cfg(test)]
pub(crate) fn payload_of<T: EncodeTemplate>(t: T) -> Vec<u8> {
    let mut template = Vec::new();
    let mut payload = Vec::new();
    t.encode_template(&mut template, &mut payload, &KeyMap::new());
    payload
}
