use core::fmt;

use bitcode::{Decode, Encode};
use frost_core::{
    Ciphersuite, Identifier,
    keys::{SigningShare, VerifiableSecretSharingCommitment},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{FrostCredentialSeed, FrostCredentialType, FrostOpsResult, FrostProtocolError};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub struct FrostCredential<C: Ciphersuite + Clone + Copy> {
    frost_identifier: Identifier<C>,
    seed: FrostCredentialSeed,
}

impl<C: Ciphersuite + Clone + Copy> FrostCredential<C> {
    pub fn new_anonymous() -> FrostOpsResult<Self> {
        let frost_credential_seed = FrostCredentialSeed::new_anonymous()?;

        let frost_identifier = frost_credential_seed.frost_identifier()?;

        Ok(Self {
            frost_identifier,
            seed: frost_credential_seed,
        })
    }

    #[cfg(feature = "email")]
    pub fn new_with_email(email_address: &str) -> FrostOpsResult<Self> {
        let frost_credential_seed = FrostCredentialSeed::new_with_email(email_address)?;

        let frost_identifier = frost_credential_seed.frost_identifier()?;

        Ok(Self {
            frost_identifier,
            seed: frost_credential_seed,
        })
    }

    /// Enforces that the email domain is part of the same organization
    #[cfg(feature = "email")]
    pub fn new_with_email_strict(username: &str, sld_tld: &str) -> FrostOpsResult<Self> {
        let frost_credential_seed = FrostCredentialSeed::new_with_email_strict(username, sld_tld)?;

        let frost_identifier = frost_credential_seed.frost_identifier()?;

        Ok(Self {
            frost_identifier,
            seed: frost_credential_seed,
        })
    }

    /// Can be a username or even a phone number (as long as the phone number is a String)
    pub fn new_with_username(username: &str) -> FrostOpsResult<Self> {
        let frost_credential_seed = FrostCredentialSeed::new_with_username(username)?;

        let frost_identifier = frost_credential_seed.frost_identifier()?;

        Ok(Self {
            frost_identifier,
            seed: frost_credential_seed,
        })
    }

    pub fn encode(&self) -> FrostCredentialBytes {
        FrostCredentialBytes {
            frost_identifier: FrostIdentifierBytes::encode(&self.frost_identifier),
            ciphersuite: C::ID.to_string(),
            seed: self.seed.clone(),
        }
    }

    pub fn encode_to_bytes(&self) -> Vec<u8> {
        bitcode::encode(&FrostCredentialBytes {
            frost_identifier: FrostIdentifierBytes::encode(&self.frost_identifier),
            ciphersuite: C::ID.to_string(),
            seed: self.seed.clone(),
        })
    }

    pub fn decode(encoded: &[u8]) -> FrostOpsResult<Self> {
        let decoded = bitcode::decode::<FrostCredentialBytes>(encoded)
            .or(Err(FrostProtocolError::UnableToDecodeFrostCredential))?;

        let frost_identifier = FrostIdentifierBytes::decode(&decoded.frost_identifier)?;

        Ok(Self {
            frost_identifier,
            seed: decoded.seed.clone(),
        })
    }

    pub fn credential_type(&self) -> FrostCredentialType {
        self.seed().credential_type()
    }

    pub fn frost_identifier(&self) -> Identifier<C> {
        self.frost_identifier
    }

    pub fn seed(&self) -> &FrostCredentialSeed {
        &self.seed
    }

    pub fn seed_take(self) -> FrostCredentialSeed {
        self.seed
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

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Zeroize, Hash)]
pub struct MinimumSigners(u16);

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Zeroize, Hash)]
pub struct MaximumSigners(u16);

#[cfg(test)]
mod sanity_checks {
    use crate::FrostCredential;
    use crate::FrostCredentialSeed;
    use crate::FrostOpsError;

    type FrostCredentialEd25519 = FrostCredential<frost_ed25519::Ed25519Sha512>;

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

        let anonymous = FrostCredentialEd25519::new_anonymous().unwrap();
        assert_eq!(anonymous.credential_type(), FrostCredentialType::Anonymous);
        assert!(!anonymous.seed().as_bytes().is_empty());
        let encoded = anonymous.encode_to_bytes();
        let decoded = FrostCredentialEd25519::decode(&encoded).unwrap();

        assert_eq!(anonymous.credential_type(), decoded.credential_type());
        assert_eq!(anonymous.frost_identifier(), decoded.frost_identifier());
    }

    #[test]
    fn ed25519_email_identifier_creation() {
        use crate::FrostCredentialType;

        let email_address = "superuser@example.com";

        let email_cred = FrostCredentialEd25519::new_with_email(email_address).unwrap();
        assert_eq!(email_cred.credential_type(), FrostCredentialType::Email);
        assert_eq!(
            email_cred.seed(),
            &FrostCredentialSeed::new_with_email(email_address).unwrap()
        );
        let encoded = email_cred.encode_to_bytes();
        let decoded = FrostCredentialEd25519::decode(&encoded).unwrap();

        assert_eq!(email_cred.credential_type(), decoded.credential_type());
        assert_eq!(email_cred.frost_identifier(), decoded.frost_identifier());

        assert!(FrostCredentialEd25519::new_with_email("+00-imaginary-number").is_err());
        assert!(FrostCredentialEd25519::new_with_email("localhost").is_err());
    }

    #[test]
    fn ed25519_username_identifier_creation() {
        use crate::FrostCredentialType;

        let phone_number = "+00-imaginary-number";

        let phone_number_cred = FrostCredentialEd25519::new_with_username(phone_number).unwrap();
        assert_eq!(
            phone_number_cred.credential_type(),
            FrostCredentialType::Username
        );
        assert_eq!(
            phone_number_cred.seed(),
            &FrostCredentialSeed::new_with_username(phone_number).unwrap()
        );
        let encoded = phone_number_cred.encode_to_bytes();
        let decoded = FrostCredentialEd25519::decode(&encoded).unwrap();

        assert_eq!(
            phone_number_cred.credential_type(),
            decoded.credential_type()
        );
        assert_eq!(
            phone_number_cred.frost_identifier(),
            decoded.frost_identifier()
        );
    }
}
