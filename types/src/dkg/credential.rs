use core::fmt;

use bitcode::{Decode, Encode};
use frost_core::{
    Ciphersuite, Identifier,
    keys::{SigningShare, VerifiableSecretSharingCommitment},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{FrostCredentialSeed, FrostOpsResult};

#[derive(
    Default, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash, Zeroize, ZeroizeOnDrop,
)]
pub struct FrostIdentifierBytes(Vec<u8>);

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

impl ProofOfKnowledgeBytes {
    pub fn encode<C: Ciphersuite>(proof: &frost_core::Signature<C>) -> FrostOpsResult<Self> {
        Ok(Self(proof.serialize()?))
    }

    pub fn decode<C: Ciphersuite>(proof: &[u8]) -> FrostOpsResult<frost_core::Signature<C>> {
        Ok(frost_core::Signature::<C>::deserialize(proof)?)
    }
}

#[cfg(test)]
mod sanity_checks {
    use crate::FrostCredentialSeed;
    use crate::FrostOpsError;

    pub type FrostEd25519 = frost_ed25519::Ed25519Sha512;

    #[test]
    fn invalid_seed() {
        use crate::FrostCredentialSeed;

        let anonymous = FrostCredentialSeed::new_with_username("ff");
        assert_eq!(
            Some(FrostOpsError::InvalidFrostCredentialSeed),
            anonymous.err()
        );

        let anonymous = FrostCredentialSeed::new_with_username("fff");
        assert_eq!(None, anonymous.err());
    }

    #[test]
    fn ed25519_anonymous_identifier_creation() {
        use crate::FrostCredentialType;

        let anonymous = FrostCredentialSeed::new_anonymous().unwrap();
        assert_eq!(anonymous.credential_type(), FrostCredentialType::Anonymous);
        assert!(!anonymous.seed().as_bytes().is_empty());
        let encoded = anonymous.encode();
        let decoded = FrostCredentialSeed::decode(&encoded).unwrap();

        assert_eq!(anonymous.credential_type(), decoded.credential_type());
        assert_eq!(
            anonymous.frost_identifier::<FrostEd25519>(),
            decoded.frost_identifier()
        );
    }

    #[test]
    fn ed25519_email_identifier_creation() {
        use crate::FrostCredentialType;

        let email_address = "superuser@example.com";

        let email_cred = FrostCredentialSeed::new_with_email(email_address).unwrap();
        assert_eq!(email_cred.credential_type(), FrostCredentialType::Email);
        assert_eq!(
            email_cred,
            FrostCredentialSeed::new_with_email(email_address).unwrap()
        );
        let encoded = email_cred.encode();
        let decoded = FrostCredentialSeed::decode(&encoded).unwrap();

        assert_eq!(email_cred.credential_type(), decoded.credential_type());
        assert_eq!(
            email_cred.frost_identifier::<FrostEd25519>(),
            decoded.frost_identifier()
        );

        assert!(FrostCredentialSeed::new_with_email("+00-imaginary-number").is_err());
        assert!(FrostCredentialSeed::new_with_email("localhost").is_err());
    }

    #[test]
    fn ed25519_username_identifier_creation() {
        use crate::FrostCredentialType;

        let phone_number = "+00-imaginary-number";

        let phone_number_cred = FrostCredentialSeed::new_with_username(phone_number).unwrap();
        assert_eq!(
            phone_number_cred.credential_type(),
            FrostCredentialType::Username
        );
        assert_eq!(
            phone_number_cred,
            FrostCredentialSeed::new_with_username(phone_number).unwrap()
        );
        let encoded = phone_number_cred.encode();
        let decoded = FrostCredentialSeed::decode(&encoded).unwrap();

        assert_eq!(
            phone_number_cred.credential_type(),
            decoded.credential_type()
        );
        assert_eq!(
            phone_number_cred.frost_identifier::<FrostEd25519>(),
            decoded.frost_identifier()
        );
    }
}
