use bitcode::{Decode, Encode};
use frost_core::{Ciphersuite, keys::dkg::round2};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{AsymmetricVerifyingKeyBytes, FrostOpsError, FrostOpsResult, FrostProtocolError};

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Zeroize, Hash, ZeroizeOnDrop,
)]
pub struct Round2SecretBytes(Vec<u8>);

impl Round2SecretBytes {
    pub fn serialize<C: Ciphersuite>(
        round2_secret: &round2::SecretPackage<C>,
    ) -> FrostOpsResult<Self> {
        Ok(Self(bitcode::serialize(&round2_secret).or(Err(
            FrostProtocolError::UnableToSerializedRound1DkgSecret,
        ))?))
    }

    pub fn deserialize<C: Ciphersuite>(&self) -> FrostOpsResult<round2::SecretPackage<C>> {
        bitcode::deserialize(&self.0).or(Err(
            FrostProtocolError::UnableToDeserializedRound1DkgSecret.into(),
        ))
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub struct Round2PackageBytes {
    pub bytes: Vec<u8>,
    pub avk: AsymmetricVerifyingKeyBytes,
}

impl Round2PackageBytes {
    pub fn parse<C: Ciphersuite>(
        package: &frost_core::keys::dkg::round2::Package<C>,
        avk: AsymmetricVerifyingKeyBytes,
    ) -> FrostOpsResult<Self> {
        let bytes = package.serialize()?;

        Ok(Self { bytes, avk })
    }

    pub fn encode(&self) -> Vec<u8> {
        bitcode::encode(self)
    }

    pub fn decode(bytes: &[u8]) -> FrostOpsResult<Self> {
        bitcode::decode(bytes).or(Err(FrostOpsError::InvalidRound2PackageBytes))
    }

    pub fn to_frost_package<C: Ciphersuite>(
        &self,
    ) -> FrostOpsResult<frost_core::keys::dkg::round2::Package<C>> {
        Ok(frost_core::keys::dkg::round2::Package::<C>::deserialize(
            &self.bytes,
        )?)
    }

    pub fn asymmetric_verifying_key(&self) -> AsymmetricVerifyingKeyBytes {
        self.avk
    }
}
