use core::fmt;

use bitcode::{Decode, Encode};
use frost_core::{
    Ciphersuite, Signature, SigningPackage,
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::FrostOpsResult;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop)]
pub struct FrostSignatureBytes(Vec<u8>);

impl FrostSignatureBytes {
    pub fn encode<C: Ciphersuite>(signature: &Signature<C>) -> FrostOpsResult<Self> {
        Ok(Self(signature.serialize()?))
    }

    pub fn decode<C: Ciphersuite>(&self) -> FrostOpsResult<Signature<C>> {
        Ok(Signature::<C>::deserialize(&self.0)?)
    }
}

impl fmt::Debug for FrostSignatureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FrostSignatureBytes")
            .field(&faster_hex::hex_string_upper(&self.0))
            .finish()
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop)]
pub struct FrostSignatureShareBytes(Vec<u8>);

impl FrostSignatureShareBytes {
    pub fn encode<C: Ciphersuite>(signature_share: SignatureShare<C>) -> Self {
        Self(signature_share.serialize())
    }

    pub fn to_frost<C: Ciphersuite>(&self) -> FrostOpsResult<SignatureShare<C>> {
        Ok(SignatureShare::<C>::deserialize(&self.0)?)
    }
}

impl fmt::Debug for FrostSignatureShareBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FrostSignatureShareBytes")
            .field(&faster_hex::hex_string_upper(&self.0))
            .finish()
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop)]
pub struct FrostSigningPackageBytes(Vec<u8>);

impl FrostSigningPackageBytes {
    pub fn encode<C: Ciphersuite>(signing_package: &SigningPackage<C>) -> FrostOpsResult<Self> {
        Ok(Self(signing_package.serialize()?))
    }

    pub fn to_frost<C: Ciphersuite>(&self) -> FrostOpsResult<SigningPackage<C>> {
        Ok(SigningPackage::<C>::deserialize(&self.0)?)
    }
}

impl fmt::Debug for FrostSigningPackageBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FrostSigningPackageBytes")
            .field(&faster_hex::hex_string_upper(&self.0))
            .finish()
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop)]
pub struct FrostSigningNoncesBytes(Vec<u8>);

impl FrostSigningNoncesBytes {
    pub fn parse<C: Ciphersuite>(signing_nonce: &SigningNonces<C>) -> FrostOpsResult<Self> {
        Ok(Self(signing_nonce.serialize()?))
    }

    pub fn encode(&self) -> Vec<u8> {
        bitcode::encode(self)
    }

    pub fn to_frost<C: Ciphersuite>(&self) -> FrostOpsResult<SigningNonces<C>> {
        Ok(SigningNonces::<C>::deserialize(&self.0)?)
    }
}

impl fmt::Debug for FrostSigningNoncesBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FrostSigningNoncesBytes")
            .field(&faster_hex::hex_string_upper(&self.0))
            .finish()
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop)]
pub struct FrostSigningCommitmentsBytes(Vec<u8>);

impl FrostSigningCommitmentsBytes {
    pub fn parse<C: Ciphersuite>(signing_nonce: &SigningCommitments<C>) -> FrostOpsResult<Self> {
        Ok(Self(signing_nonce.serialize()?))
    }

    pub fn encode(&self) -> Vec<u8> {
        bitcode::encode(self)
    }

    pub fn to_frost<C: Ciphersuite>(&self) -> FrostOpsResult<SigningCommitments<C>> {
        Ok(SigningCommitments::<C>::deserialize(&self.0)?)
    }
}

impl fmt::Debug for FrostSigningCommitmentsBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FrostSigningCommitmentsBytes")
            .field(&faster_hex::hex_string_upper(&self.0))
            .finish()
    }
}
