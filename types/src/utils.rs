use bitcode::{Decode, Encode};
use tai64::Tai64N;
use zeroize::Zeroize;

use crate::FrostOpsResult;

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash, Encode, Decode)]
pub struct Tai64NTimestamp([u8; 12]);

impl Tai64NTimestamp {
    pub fn now() -> Self {
        Self(Tai64N::now().to_bytes())
    }

    pub fn epoch_timestamp() -> Tai64N {
        Tai64N::UNIX_EPOCH
    }

    pub fn parse(&self) -> FrostOpsResult<Tai64N> {
        Ok(Tai64N::try_from(self.0)?)
    }
}

impl Zeroize for Tai64NTimestamp {
    fn zeroize(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash, Encode, Decode)]
pub struct Blake3HashBytes([u8; 32]);

impl Blake3HashBytes {
    pub fn new(message: impl AsRef<[u8]>) -> Self {
        Self(*blake3::hash(message.as_ref()).as_bytes())
    }

    pub fn to_hash(&self) -> blake3::Hash {
        self.0.into()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Zeroize for Blake3HashBytes {
    fn zeroize(&mut self) {
        self.0.fill(0);
    }
}
