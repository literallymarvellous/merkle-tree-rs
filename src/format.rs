use std::borrow::Cow;

use ethers::types::Bytes;

pub trait FormatHash {
    type Out;

    fn format(hash: Cow<Bytes>) -> Self::Out;
}

/// Format hashes as 0x prefixed hexadecimal string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hex0x;

impl FormatHash for Hex0x {
    type Out = String;

    fn format(hash: Cow<Bytes>) -> Self::Out {
        format!("0x{}", ethers::utils::hex::encode(hash.as_ref()))
    }
}

/// Return hashes as bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Raw;

impl FormatHash for Raw {
    type Out = Bytes;

    fn format(hash: Cow<Bytes>) -> Self::Out {
        hash.into_owned()
    }
}
