use bitcode::{Decode, Encode};
use email_address::{EmailAddress, Options as EmailOptions};
use frost_core::{
    Ciphersuite, Identifier,
    keys::{SigningShare, VerifiableSecretSharingCommitment},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{FrostOpsError, FrostOpsResult, RandomBytes};

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct Blake3HashBytes([u8; 32]);

#[cfg(feature = "ed25519")]
pub type FrostCredentialEd25519 = FrostCredential<frost_ed25519::Ed25519Sha512>;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub struct FrostCredential<C: Ciphersuite + Clone + Copy> {
    credential_type: FrostCredentialType,
    frost_identifier: Identifier<C>,
    seed: Vec<u8>,
}

impl<C: Ciphersuite + Clone + Copy> FrostCredential<C> {
    pub fn new_anonymous() -> FrostOpsResult<Self> {
        let bytes = RandomBytes::<32>::generate();
        let mut seed = faster_hex::hex_string_upper(bytes.expose().as_slice());

        let frost_identifier = Self::credential_type_to_identifier(&seed)?;

        let seed_bytes = seed.as_bytes().to_vec();
        seed.zeroize();

        Ok(Self {
            credential_type: FrostCredentialType::Anonymous,
            frost_identifier,
            seed: seed_bytes,
        })
    }

    pub fn new_with_email(email_address: &str) -> FrostOpsResult<Self> {
        let email_address = email_address.trim();

        let options = EmailOptions::default().with_required_tld();
        EmailAddress::parse_with_options(email_address, options)
            .or(Err(FrostOpsError::InvalidEmailAddress))?;

        let frost_identifier = Self::credential_type_to_identifier(email_address)?;

        Ok(Self {
            credential_type: FrostCredentialType::Email,
            frost_identifier,
            seed: email_address.as_bytes().to_vec(),
        })
    }

    /// Can be a username or even a phone number (as long as the phone number is a String)
    pub fn new_username(username: &str) -> FrostOpsResult<Self> {
        let username = username.trim();

        let frost_identifier = Self::credential_type_to_identifier(username)?;

        Ok(Self {
            credential_type: FrostCredentialType::Username,
            frost_identifier,
            seed: username.as_bytes().to_vec(),
        })
    }

    fn credential_type_to_identifier(key: impl AsRef<[u8]>) -> FrostOpsResult<Identifier<C>> {
        Ok(Identifier::derive(key.as_ref())?)
    }

    pub fn credential_type(&self) -> FrostCredentialType {
        self.credential_type
    }

    pub fn frost_identifier(&self) -> Identifier<C> {
        self.frost_identifier
    }

    pub fn seed(&self) -> String {
        core::str::from_utf8(&self.seed)
            .map(|value| value.to_string())
            .unwrap_or_default()
    }

    pub fn encode(&self) -> Vec<u8> {
        bitcode::encode(&FrostCredentialEncoded {
            credential_type: self.credential_type,
            frost_identifier: FrostIdentifierBytes::encode(&self.frost_identifier),
            ciphersuite: C::ID.to_string(),
            seed: self.seed.clone(),
        })
    }

    pub fn decode(encoded: &[u8]) -> FrostOpsResult<Self> {
        let decoded = bitcode::decode::<FrostCredentialEncoded>(encoded)
            .or(Err(FrostOpsError::UnableToDecodeFrostCredential))?;

        let frost_identifier = FrostIdentifierBytes::decode(&decoded.frost_identifier)?;

        Ok(Self {
            credential_type: decoded.credential_type,
            frost_identifier,
            seed: decoded.seed.clone(),
        })
    }
}

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct FrostCredentialEncoded {
    credential_type: FrostCredentialType,
    frost_identifier: FrostIdentifierBytes,
    ciphersuite: String,
    seed: Vec<u8>,
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Encode, Decode)]
pub enum FrostCredentialType {
    Anonymous,
    Email,
    Username,
    #[default]
    Uninitialized,
}

impl Zeroize for FrostCredentialType {
    fn zeroize(&mut self) {
        *self = Self::Uninitialized
    }
}

impl From<FrostCredentialType> for u8 {
    fn from(identifier_type: FrostCredentialType) -> Self {
        match identifier_type {
            FrostCredentialType::Anonymous => 0,
            FrostCredentialType::Email => 1,
            FrostCredentialType::Username => 2,
            FrostCredentialType::Uninitialized => FrostCredentialType::default().into(),
        }
    }
}

impl From<u8> for FrostCredentialType {
    fn from(identifier_byte: u8) -> Self {
        match identifier_byte {
            0 => Self::Anonymous,
            1 => Self::Email,
            2 => Self::Username,
            _ => Self::Uninitialized,
        }
    }
}

#[derive(
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Encode,
    Decode,
    Hash,
    Zeroize,
    ZeroizeOnDrop,
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

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Zeroize, Hash)]
pub struct FrostSigningShareBytes(Vec<u8>);

impl FrostSigningShareBytes {
    pub fn encode<C: Ciphersuite>(signing_share: &SigningShare<C>) -> Self {
        Self(signing_share.serialize())
    }

    pub fn decode<C: Ciphersuite>(&self) -> FrostOpsResult<SigningShare<C>> {
        Ok(SigningShare::<C>::deserialize(&self.0)?)
    }
}

#[cfg(feature = "ed25519")]
#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Zeroize, Hash)]
pub struct FrostScalarBytes([u8; 32]);

#[cfg(feature = "ed25519")]
impl FrostScalarBytes {
    pub fn encode(scalar: curve25519_dalek::Scalar) -> Self {
        Self(scalar.to_bytes())
    }

    pub fn decode(scalar_array: Self) -> curve25519_dalek::Scalar {
        curve25519_dalek::Scalar::from_bytes_mod_order(scalar_array.0)
    }
}

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
    #[cfg(feature = "ed25519")]
    use crate::FrostCredentialEd25519;

    #[test]
    #[cfg(feature = "ed25519")]
    fn ed25519_anonymous_identifier_creation() {
        use crate::FrostCredentialType;

        let anonymous = FrostCredentialEd25519::new_anonymous().unwrap();
        assert_eq!(anonymous.credential_type(), FrostCredentialType::Anonymous);
        assert!(!anonymous.seed().is_empty());
        let encoded = anonymous.encode();
        let decoded = FrostCredentialEd25519::decode(&encoded).unwrap();

        assert_eq!(anonymous.credential_type(), decoded.credential_type());
        assert_eq!(anonymous.frost_identifier(), decoded.frost_identifier());
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn ed25519_email_identifier_creation() {
        use crate::FrostCredentialType;

        let email_address = "superuser@example.com";

        let email_cred = FrostCredentialEd25519::new_with_email(email_address).unwrap();
        assert_eq!(email_cred.credential_type(), FrostCredentialType::Email);
        assert_eq!(email_cred.seed(), email_address);
        let encoded = email_cred.encode();
        let decoded = FrostCredentialEd25519::decode(&encoded).unwrap();

        assert_eq!(email_cred.credential_type(), decoded.credential_type());
        assert_eq!(email_cred.frost_identifier(), decoded.frost_identifier());

        assert!(FrostCredentialEd25519::new_with_email("+00-imaginary-number").is_err());
        assert!(FrostCredentialEd25519::new_with_email("localhost").is_err());
    }

    #[test]
    #[cfg(feature = "ed25519")]
    fn ed25519_username_identifier_creation() {
        use crate::FrostCredentialType;

        let phone_number = "+00-imaginary-number";

        let phone_number_cred = FrostCredentialEd25519::new_username(phone_number).unwrap();
        assert_eq!(
            phone_number_cred.credential_type(),
            FrostCredentialType::Username
        );
        assert_eq!(phone_number_cred.seed(), phone_number);
        let encoded = phone_number_cred.encode();
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
