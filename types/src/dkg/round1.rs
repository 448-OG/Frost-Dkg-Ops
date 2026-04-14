use bitcode::{Decode, Encode};
use frost_core::{
    Ciphersuite,
    keys::{VerifiableSecretSharingCommitment, dkg::round1},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{FrostCommitmentBytes, FrostOpsResult, FrostProtocolError, ProofOfKnowledgeBytes};

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Zeroize, Hash, ZeroizeOnDrop,
)]
pub struct Round1SecretBytes(Vec<u8>);

impl Round1SecretBytes {
    pub fn serialize<C: Ciphersuite>(
        round1_secret: &round1::SecretPackage<C>,
    ) -> FrostOpsResult<Self> {
        Ok(Self(bitcode::serialize(&round1_secret).or(Err(
            FrostProtocolError::UnableToSerializedRound1DkgSecret,
        ))?))
    }

    pub fn deserialize<C: Ciphersuite>(&self) -> FrostOpsResult<round1::SecretPackage<C>> {
        bitcode::deserialize(&self.0).or(Err(
            FrostProtocolError::UnableToDeserializedRound1DkgSecret.into(),
        ))
    }
}

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Zeroize, Hash, ZeroizeOnDrop,
)]
pub struct Round1PackageBytes {
    proof_of_knowledge: ProofOfKnowledgeBytes,
    commitment: FrostCommitmentBytes,
}

impl Round1PackageBytes {
    pub fn encode<C: Ciphersuite>(
        round1_public_package: &round1::Package<C>,
    ) -> FrostOpsResult<Self> {
        let commitment = FrostCommitmentBytes::encode(round1_public_package.commitment())?;
        let proof_of_knowledge =
            ProofOfKnowledgeBytes::encode(round1_public_package.proof_of_knowledge())?;

        Ok(Self {
            proof_of_knowledge,
            commitment,
        })
    }

    pub fn decode<C: Ciphersuite>(&self) -> FrostOpsResult<round1::Package<C>> {
        let commitment = VerifiableSecretSharingCommitment::<C>::deserialize(&self.commitment.0)?;
        let proof_of_knowledge =
            frost_core::Signature::<C>::deserialize(&self.proof_of_knowledge.0)?;

        Ok(round1::Package::<C>::new(commitment, proof_of_knowledge))
    }
}

#[cfg(test)]
mod sanity_checks {
    #[test]
    fn types_sanity() {
        use frost_ed25519::{self as frost};

        use crate::Round1SecretBytes;

        let rng = rand::rngs::OsRng;

        let max_signers = 2;
        let min_signers = 2;

        let party1 = "foo@example.com";

        let party1_identifier = frost_ed25519::Identifier::derive(party1.as_bytes()).unwrap();

        let (party1_round1_secret_package, party1_round1_package) =
            frost::keys::dkg::part1(party1_identifier, max_signers, min_signers, rng).unwrap();

        let serialize_round1_secret =
            Round1SecretBytes::serialize(&party1_round1_secret_package).unwrap();
        let deserialize_round1_secret = Round1SecretBytes::deserialize::<
            frost_ed25519::Ed25519Sha512,
        >(&serialize_round1_secret)
        .unwrap();
        assert!(party1_round1_secret_package == deserialize_round1_secret);

        // Round 1 Public Package tests

        use crate::Round1PackageBytes;
        let encoded_round1_public_commitment =
            Round1PackageBytes::encode::<frost_ed25519::Ed25519Sha512>(&party1_round1_package)
                .unwrap();
        let decoded_round1_commitment = encoded_round1_public_commitment
            .decode::<frost_ed25519::Ed25519Sha512>()
            .unwrap();
        assert!(party1_round1_package == decoded_round1_commitment);
    }
}
