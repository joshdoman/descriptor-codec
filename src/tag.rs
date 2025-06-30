#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    False = 0x00,
    True = 0x01,
    Pkh = 0x02,
    Sh = 0x03,
    Wpkh = 0x04,
    Wsh = 0x05,
    Tr = 0x06,
    Bare = 0x07,
    TapTree = 0x08,
    SortedMulti = 0x09,
    Alt = 0x0A,
    Swap = 0x0B,
    Check = 0x0C,
    DupIf = 0x0D,
    Verify = 0x0E,
    NonZero = 0x0F,
    ZeroNotEqual = 0x10,
    AndV = 0x11,
    AndB = 0x12,
    AndOr = 0x13,
    OrB = 0x14,
    OrC = 0x15,
    OrD = 0x16,
    OrI = 0x17,
    Thresh = 0x18,
    Multi = 0x19,
    MultiA = 0x1A,
    PkK = 0x1B,
    PkH = 0x1C,
    RawPkH = 0x1D,
    After = 0x1E,
    Older = 0x1F,
    Sha256 = 0x20,
    Hash256 = 0x21,
    Ripemd160 = 0x22,
    Hash160 = 0x23,
    Origin = 0x24,
    NoOrigin = 0x25,
    UncompressedFullKey = 0x26,
    CompressedFullKey = 0x27,
    XOnly = 0x28,
    XPub = 0x29,
    MultiXPub = 0x2A,
    NoWildcard = 0x2B,
    UnhardenedWildcard = 0x2C,
    HardenedWildcard = 0x2D,
    Unrecognized,
}

impl Tag {
    pub fn value(&self) -> u8 {
        *self as u8
    }

    #[allow(unsafe_code)]
    pub fn from(value: u8) -> Self {
        match value {
            0x00..=0x2D => unsafe { std::mem::transmute::<u8, Tag>(value) },
            _ => Tag::Unrecognized,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_values() {
        assert_eq!(Tag::False.value(), 0x00);
        assert_eq!(Tag::True.value(), 0x01);
        assert_eq!(Tag::Pkh.value(), 0x02);
        assert_eq!(Tag::Sh.value(), 0x03);
        assert_eq!(Tag::Wpkh.value(), 0x04);
        assert_eq!(Tag::Wsh.value(), 0x05);
        assert_eq!(Tag::Tr.value(), 0x06);
        assert_eq!(Tag::Bare.value(), 0x07);
        assert_eq!(Tag::TapTree.value(), 0x08);
        assert_eq!(Tag::SortedMulti.value(), 0x09);
        assert_eq!(Tag::Alt.value(), 0x0A);
        assert_eq!(Tag::Swap.value(), 0x0B);
        assert_eq!(Tag::Check.value(), 0x0C);
        assert_eq!(Tag::DupIf.value(), 0x0D);
        assert_eq!(Tag::Verify.value(), 0x0E);
        assert_eq!(Tag::NonZero.value(), 0x0F);
        assert_eq!(Tag::ZeroNotEqual.value(), 0x10);
        assert_eq!(Tag::AndV.value(), 0x11);
        assert_eq!(Tag::AndB.value(), 0x12);
        assert_eq!(Tag::AndOr.value(), 0x13);
        assert_eq!(Tag::OrB.value(), 0x14);
        assert_eq!(Tag::OrC.value(), 0x15);
        assert_eq!(Tag::OrD.value(), 0x16);
        assert_eq!(Tag::OrI.value(), 0x17);
        assert_eq!(Tag::Thresh.value(), 0x18);
        assert_eq!(Tag::Multi.value(), 0x19);
        assert_eq!(Tag::MultiA.value(), 0x1A);
        assert_eq!(Tag::PkK.value(), 0x1B);
        assert_eq!(Tag::PkH.value(), 0x1C);
        assert_eq!(Tag::RawPkH.value(), 0x1D);
        assert_eq!(Tag::After.value(), 0x1E);
        assert_eq!(Tag::Older.value(), 0x1F);
        assert_eq!(Tag::Sha256.value(), 0x20);
        assert_eq!(Tag::Hash256.value(), 0x21);
        assert_eq!(Tag::Ripemd160.value(), 0x22);
        assert_eq!(Tag::Hash160.value(), 0x23);
        assert_eq!(Tag::Origin.value(), 0x24);
        assert_eq!(Tag::NoOrigin.value(), 0x25);
        assert_eq!(Tag::UncompressedFullKey.value(), 0x26);
        assert_eq!(Tag::CompressedFullKey.value(), 0x27);
        assert_eq!(Tag::XOnly.value(), 0x28);
        assert_eq!(Tag::XPub.value(), 0x29);
        assert_eq!(Tag::MultiXPub.value(), 0x2A);
        assert_eq!(Tag::NoWildcard.value(), 0x2B);
        assert_eq!(Tag::UnhardenedWildcard.value(), 0x2C);
        assert_eq!(Tag::HardenedWildcard.value(), 0x2D);
    }

    #[test]
    fn test_from() {
        assert_eq!(Tag::False, Tag::from(0x00));
        assert_eq!(Tag::True, Tag::from(0x01));
        assert_eq!(Tag::Pkh, Tag::from(0x02));
        assert_eq!(Tag::Sh, Tag::from(0x03));
        assert_eq!(Tag::Wpkh, Tag::from(0x04));
        assert_eq!(Tag::Wsh, Tag::from(0x05));
        assert_eq!(Tag::Tr, Tag::from(0x06));
        assert_eq!(Tag::Bare, Tag::from(0x07));
        assert_eq!(Tag::TapTree, Tag::from(0x08));
        assert_eq!(Tag::SortedMulti, Tag::from(0x09));
        assert_eq!(Tag::Alt, Tag::from(0x0A));
        assert_eq!(Tag::Swap, Tag::from(0x0B));
        assert_eq!(Tag::Check, Tag::from(0x0C));
        assert_eq!(Tag::DupIf, Tag::from(0x0D));
        assert_eq!(Tag::Verify, Tag::from(0x0E));
        assert_eq!(Tag::NonZero, Tag::from(0x0F));
        assert_eq!(Tag::ZeroNotEqual, Tag::from(0x10));
        assert_eq!(Tag::AndV, Tag::from(0x11));
        assert_eq!(Tag::AndB, Tag::from(0x12));
        assert_eq!(Tag::AndOr, Tag::from(0x13));
        assert_eq!(Tag::OrB, Tag::from(0x14));
        assert_eq!(Tag::OrC, Tag::from(0x15));
        assert_eq!(Tag::OrD, Tag::from(0x16));
        assert_eq!(Tag::OrI, Tag::from(0x17));
        assert_eq!(Tag::Thresh, Tag::from(0x18));
        assert_eq!(Tag::Multi, Tag::from(0x19));
        assert_eq!(Tag::MultiA, Tag::from(0x1A));
        assert_eq!(Tag::PkK, Tag::from(0x1B));
        assert_eq!(Tag::PkH, Tag::from(0x1C));
        assert_eq!(Tag::RawPkH, Tag::from(0x1D));
        assert_eq!(Tag::After, Tag::from(0x1E));
        assert_eq!(Tag::Older, Tag::from(0x1F));
        assert_eq!(Tag::Sha256, Tag::from(0x20));
        assert_eq!(Tag::Hash256, Tag::from(0x21));
        assert_eq!(Tag::Ripemd160, Tag::from(0x22));
        assert_eq!(Tag::Hash160, Tag::from(0x23));
        assert_eq!(Tag::Origin, Tag::from(0x24));
        assert_eq!(Tag::NoOrigin, Tag::from(0x25));
        assert_eq!(Tag::UncompressedFullKey, Tag::from(0x26));
        assert_eq!(Tag::CompressedFullKey, Tag::from(0x27));
        assert_eq!(Tag::XOnly, Tag::from(0x28));
        assert_eq!(Tag::XPub, Tag::from(0x29));
        assert_eq!(Tag::MultiXPub, Tag::from(0x2A));
        assert_eq!(Tag::NoWildcard, Tag::from(0x2B));
        assert_eq!(Tag::UnhardenedWildcard, Tag::from(0x2C));
        assert_eq!(Tag::HardenedWildcard, Tag::from(0x2D));
    }

    #[test]
    fn test_unrecognized() {
        for i in 0x2E..=0xFF {
            assert_eq!(Tag::Unrecognized, Tag::from(i));
        }
    }
}
