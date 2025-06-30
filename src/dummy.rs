// SPDX-License-Identifier: CC0-1.0

use bitcoin::{
    NetworkKind,
    bip32::{Fingerprint, Xpriv, Xpub},
    hashes::{Hash, hash160, ripemd160, sha256, sha256d},
    secp256k1::{PublicKey as SecpPublicKey, Secp256k1, SecretKey},
};
use miniscript::{AbsLockTime, RelLockTime, hash256};

pub fn sk_at_index(index: u32) -> SecretKey {
    let mut sk_bytes = [0u8; 32];
    sk_bytes[28..32].copy_from_slice(&index.to_be_bytes());
    SecretKey::from_slice(&sk_bytes).unwrap()
}

pub fn pk_at_index(index: u32) -> SecpPublicKey {
    let secp = Secp256k1::new();
    SecpPublicKey::from_secret_key(&secp, &sk_at_index(index))
}

pub fn sk() -> SecretKey {
    sk_at_index(1)
}

pub fn pk() -> SecpPublicKey {
    pk_at_index(1)
}

pub fn xpub() -> Xpub {
    let secp = Secp256k1::new();
    Xpub::from_priv(&secp, &xpriv())
}

pub fn xpriv() -> Xpriv {
    Xpriv::new_master(NetworkKind::Main, &[0u8; 32]).unwrap()
}

pub fn fp() -> Fingerprint {
    Fingerprint::from_hex("00000000").unwrap()
}

pub fn hash160() -> hash160::Hash {
    hash160::Hash::from_slice(&[0u8; 20]).unwrap()
}

pub fn ripemd160() -> ripemd160::Hash {
    ripemd160::Hash::from_slice(&[0u8; 20]).unwrap()
}

pub fn sha256() -> sha256::Hash {
    sha256::Hash::from_slice(&[0u8; 32]).unwrap()
}

pub fn hash256() -> hash256::Hash {
    hash256::Hash::from_raw_hash(sha256d::Hash::from_slice(&[0u8; 32]).unwrap())
}

pub fn after() -> AbsLockTime {
    AbsLockTime::from_consensus(1).unwrap()
}

pub fn older() -> RelLockTime {
    RelLockTime::from_consensus(1).unwrap()
}
