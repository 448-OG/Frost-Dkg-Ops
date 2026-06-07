use core::fmt;

use bitcode::{Decode, Encode};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "frost_ops")]
use {
    crate::{FrostCredentialSeed, FrostOpsResult},
    frost_core::{
        Ciphersuite, Identifier,
        keys::{SigningShare, VerifiableSecretSharingCommitment},
    },
};

#[derive(
    Default, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash, Zeroize, ZeroizeOnDrop,
)]
pub struct FrostIdentifierBytes(Vec<u8>);

#[cfg(feature = "frost_ops")]
impl FrostIdentifierBytes {
    pub fn encode<C: Ciphersuite>(identifier: &Identifier<C>) -> Self {
        Self(identifier.serialize())
    }

    pub fn decode<C: Ciphersuite>(&self) -> FrostOpsResult<Identifier<C>> {
        Ok(Identifier::<C>::deserialize(&self.0)?)
    }
}

impl fmt::Debug for FrostIdentifierBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FrostIdentifierBytes")
            .field(&faster_hex::hex_string_upper(&self.0))
            .finish()
    }
}

#[cfg(feature = "frost_ops")]
#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct FrostCredentialBytes {
    frost_identifier: FrostIdentifierBytes,
    ciphersuite: String,
    seed: FrostCredentialSeed,
}

#[derive(Default, Clone, Encode, Decode, Zeroize)]
pub struct FrostSigningShareBytes(Vec<u8>);

#[cfg(feature = "frost_ops")]
impl FrostSigningShareBytes {
    pub fn encode<C: Ciphersuite>(signing_share: &SigningShare<C>) -> Self {
        Self(signing_share.serialize())
    }

    pub fn decode<C: Ciphersuite>(&self) -> FrostOpsResult<SigningShare<C>> {
        Ok(SigningShare::<C>::deserialize(&self.0)?)
    }
}

impl fmt::Debug for FrostSigningShareBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FrostSigningShareBytes")
            .field(&faster_hex::hex_string_upper(&self.0))
            .finish()
    }
}

impl PartialEq for FrostSigningShareBytes {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;

        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for FrostSigningShareBytes {}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Zeroize, Hash)]
pub struct FrostCommitmentBytes(pub(crate) Vec<Vec<u8>>);

#[cfg(feature = "frost_ops")]
impl FrostCommitmentBytes {
    pub fn encode<C: Ciphersuite>(
        commitments: &VerifiableSecretSharingCommitment<C>,
    ) -> FrostOpsResult<Self> {
        Ok(Self(commitments.serialize()?))
    }

    pub fn decode<C: Ciphersuite>(
        commitments_bytes: Self,
    ) -> FrostOpsResult<VerifiableSecretSharingCommitment<C>> {
        Ok(VerifiableSecretSharingCommitment::<C>::deserialize(
            commitments_bytes.0,
        )?)
    }
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Zeroize, Hash)]
pub struct ProofOfKnowledgeBytes(pub(crate) Vec<u8>);

#[cfg(feature = "frost_ops")]
impl ProofOfKnowledgeBytes {
    pub fn encode<C: Ciphersuite>(proof: &frost_core::Signature<C>) -> FrostOpsResult<Self> {
        Ok(Self(proof.serialize()?))
    }

    pub fn decode<C: Ciphersuite>(proof: &[u8]) -> FrostOpsResult<frost_core::Signature<C>> {
        Ok(frost_core::Signature::<C>::deserialize(proof)?)
    }
}
