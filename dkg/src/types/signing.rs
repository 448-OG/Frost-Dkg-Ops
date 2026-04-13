use bitcode::{Decode, Encode};
use frost_core::{
    Ciphersuite, Signature, SigningPackage,
    keys::PublicKeyPackage,
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::FrostOpsResult;

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct FrostSignatureBytes(Vec<u8>);

impl FrostSignatureBytes {
    pub fn encode<C: Ciphersuite>(signature: Signature<C>) -> FrostOpsResult<Self> {
        Ok(Self(signature.serialize()?))
    }

    pub fn decode<C: Ciphersuite>(&self) -> FrostOpsResult<Signature<C>> {
        Ok(Signature::<C>::deserialize(&self.0)?)
    }
}

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct FrostSignatureShareBytes(Vec<u8>);

impl FrostSignatureShareBytes {
    pub fn encode<C: Ciphersuite>(signature_share: SignatureShare<C>) -> Self {
        Self(signature_share.serialize())
    }

    pub fn decode<C: Ciphersuite>(&self) -> FrostOpsResult<SignatureShare<C>> {
        Ok(SignatureShare::<C>::deserialize(&self.0)?)
    }
}

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct FrostPublicKeyPackage(Vec<u8>);

impl FrostPublicKeyPackage {
    pub fn encode<C: Ciphersuite>(public_package: &PublicKeyPackage<C>) -> FrostOpsResult<Self> {
        Ok(Self(public_package.serialize()?))
    }

    pub fn decode<C: Ciphersuite>(&self) -> FrostOpsResult<PublicKeyPackage<C>> {
        Ok(PublicKeyPackage::<C>::deserialize(&self.0)?)
    }
}

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct FrostSigningPackageBytes(Vec<u8>);

impl FrostSigningPackageBytes {
    pub fn encode<C: Ciphersuite>(signing_package: SigningPackage<C>) -> FrostOpsResult<Self> {
        Ok(Self(signing_package.serialize()?))
    }

    pub fn decode<C: Ciphersuite>(&self) -> FrostOpsResult<SigningPackage<C>> {
        Ok(SigningPackage::<C>::deserialize(&self.0)?)
    }
}

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct SigningNoncesBytes(Vec<u8>);

impl SigningNoncesBytes {
    pub fn encode<C: Ciphersuite>(
        signing_nonce: &SigningNonces<C>,
    ) -> FrostOpsResult<SigningNoncesBytes> {
        Ok(Self(signing_nonce.serialize()?))
    }

    pub fn decode<C: Ciphersuite>(&self) -> FrostOpsResult<SigningNonces<C>> {
        Ok(SigningNonces::<C>::deserialize(&self.0)?)
    }
}

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct FrostSigningCommitmentsBytes(Vec<u8>);

impl FrostSigningCommitmentsBytes {
    pub fn encode<C: Ciphersuite>(signing_nonce: &SigningCommitments<C>) -> FrostOpsResult<Self> {
        Ok(Self(signing_nonce.serialize()?))
    }

    pub fn decode<C: Ciphersuite>(&self) -> FrostOpsResult<SigningCommitments<C>> {
        Ok(SigningCommitments::<C>::deserialize(&self.0)?)
    }
}
