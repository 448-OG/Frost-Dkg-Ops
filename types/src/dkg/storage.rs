use bitcode::{Decode, DecodeOwned, Encode};

use crate::{EphemeralClientDeviceVerifyingKey, FrostCredentialSeed, SldTld, Tai64NTimestamp};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub struct FrostRoundPackage<T> {
    pub timestamp: Tai64NTimestamp,
    pub credential_seed: FrostCredentialSeed,
    pub ecdvk: EphemeralClientDeviceVerifyingKey,
    pub payload: T,
}

impl<T> FrostRoundPackage<T>
where
    T: Encode + DecodeOwned,
{
    pub fn to_storage_key(&self, sld_tld: &SldTld) -> Vec<u8> {
        let mut payload = Vec::<u8>::default();

        payload.extend_from_slice(sld_tld.to_storage_key().as_bytes());
        payload.extend_from_slice(self.credential_seed.as_bytes());

        payload
    }
}
