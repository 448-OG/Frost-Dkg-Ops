use core::fmt;

use bitcode::{Decode, Encode};

use zeroize::{Zeroize, ZeroizeOnDrop};
#[cfg(feature = "frost_ops")]
use {
    crate::{FrostOpsError, FrostOpsResult, RandomBytes},
    frost_core::Ciphersuite,
    std::borrow::Cow,
};

#[cfg(feature = "email")]
use email_address::{EmailAddress, Options as EmailOptions};

/// The `seed` can reconstruct the frost_identifier and is useful in keeping
/// the bytes sent over a network small instead of sending the FROST Identifier
/// together with the seed.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop)]
pub struct FrostCredentialSeed(Vec<u8>);

#[cfg(feature = "frost_ops")]
impl FrostCredentialSeed {
    pub fn new<C: Ciphersuite>(
        credential_type: FrostCredentialType,
        seed: impl AsRef<[u8]> + ToString,
    ) -> FrostOpsResult<Self> {
        let seed = seed.as_ref();

        if seed.len() < 3 || credential_type == FrostCredentialType::Uninitialized {
            return Err(FrostOpsError::InvalidFrostCredentialSeed);
        }

        let ciphersuite = C::ID;
        let ciphersuite: FrostCiphersuite = ciphersuite.into();

        if ciphersuite == FrostCiphersuite::UNSPECIFIED {
            return Err(FrostOpsError::UnsupportedFrostCiphersuite);
        }

        let mut seed_outcome = vec![credential_type as u8, ciphersuite as u8];

        seed_outcome.extend_from_slice(seed);

        Ok(Self(seed_outcome))
    }

    pub fn new_anonymous<C: Ciphersuite>() -> FrostOpsResult<Self> {
        let bytes = RandomBytes::<32>::generate();
        let seed = faster_hex::hex_string_upper(bytes?.expose().as_slice());

        Self::new::<C>(FrostCredentialType::Anonymous, seed)
    }

    #[cfg(feature = "email")]
    pub fn new_with_email<C: Ciphersuite>(email_address: &str) -> FrostOpsResult<Self> {
        let email_address = email_address.trim();

        let options = EmailOptions::default().with_required_tld();
        EmailAddress::parse_with_options(email_address, options)
            .or(Err(FrostOpsError::InvalidEmailAddress))?;

        Self::new::<C>(FrostCredentialType::Email, email_address)
    }

    #[cfg(feature = "email")]
    pub fn new_with_email_strict<C: Ciphersuite>(
        username: &str,
        sld_tld: &str,
    ) -> FrostOpsResult<Self> {
        let options = EmailOptions::default().with_required_tld();

        if EmailAddress::parse_with_options(username, options).is_ok() {
            return Err(FrostOpsError::InvalidUsernameForStrictEmailConfig(
                username.to_string(),
            ))?;
        }

        let email_address = username.trim().to_string() + "@" + sld_tld.trim();

        let options = EmailOptions::default().with_required_tld();
        EmailAddress::parse_with_options(&email_address, options).or(Err(
            FrostOpsError::InvalidDomainSldTldForEmail(sld_tld.to_string()),
        ))?;

        Self::new::<C>(FrostCredentialType::Email, email_address)
    }

    /// Can be a username or even a phone number (as long as the phone number is a String)
    pub fn new_with_username<C: Ciphersuite>(username: &str) -> FrostOpsResult<Self> {
        let username = username.trim();

        Self::new::<C>(FrostCredentialType::Username, username)
    }

    pub fn credential_type(&self) -> FrostCredentialType {
        self.0
            .first()
            .cloned()
            .unwrap_or(FrostCredentialType::Uninitialized as u8)
            .into()
    }

    pub fn ciphersuite(&self) -> FrostCiphersuite {
        self.0
            .get(1)
            .cloned()
            .unwrap_or(FrostCredentialType::Uninitialized as u8)
            .into()
    }

    pub fn frost_identifier<C: Ciphersuite>(&self) -> FrostOpsResult<frost_core::Identifier<C>> {
        let outcome = frost_core::Identifier::derive(self.seed_bytes())?;

        let stored = self.ciphersuite();
        if stored == FrostCiphersuite::UNSPECIFIED {
            return Err(FrostOpsError::InvalidStoredFrostCiphersuite);
        }
        let stored = stored.context_str();
        let provided = C::ID;
        if stored != provided {
            return Err(FrostOpsError::InvalidFrostCiphersuite { stored, provided });
        }

        Ok(outcome)
    }

    pub fn seed(&self) -> Cow<'_, str> {
        // Not Expected to be `UNINITIALIZED` because length checks are performed on creating new and the seed must impl `ToString`
        let parsed = core::str::from_utf8(self.seed_bytes()).unwrap_or("UNINITIALIZED");

        Cow::Borrowed(parsed)
    }

    /// Useful when constructing the [String] format of this type
    pub fn seed_bytes(&self) -> &[u8] {
        // Should never panic because creating `Self` requires seed length 3 or greater
        &self.0[2..]
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn encode(&self) -> Vec<u8> {
        bitcode::encode(self)
    }

    pub fn decode(bytes: &[u8]) -> FrostOpsResult<Self> {
        bitcode::decode(bytes).or(Err(FrostOpsError::InvalidFrostCredentialSeed))
    }
}

impl fmt::Debug for FrostCredentialSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FrostCredentialSeed")
            .field(&faster_hex::hex_string_upper(&self.0))
            .finish()
    }
}

impl AsRef<[u8]> for FrostCredentialSeed {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Encode, Decode)]
pub enum FrostCredentialType {
    Anonymous,
    #[cfg(feature = "email")]
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

#[cfg(feature = "frost_ops")]
impl From<FrostCredentialType> for u8 {
    fn from(identifier_type: FrostCredentialType) -> Self {
        match identifier_type {
            FrostCredentialType::Anonymous => 0,
            #[cfg(feature = "email")]
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
            #[cfg(feature = "email")]
            1 => Self::Email,
            2 => Self::Username,
            _ => Self::Uninitialized,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Default, Encode, Decode)]
pub enum FrostCiphersuite {
    #[default]
    UNSPECIFIED = 0,
    FROST_ED25519_SHA512_V1 = 1,
}

impl FrostCiphersuite {
    pub const UNSPECIFIED_STR: &str = "FROST-UNSPECIFIED";
    pub const UNSPECIFIED_BYTES: &[u8] = Self::UNSPECIFIED_STR.as_bytes();

    pub const FROST_ED25519_SHA512_V1_STR: &str = "FROST-ED25519-SHA512-v1";
    pub const FROST_ED25519_SHA512_V1_BYTES: &[u8] = Self::FROST_ED25519_SHA512_V1_STR.as_bytes();

    pub const fn context_str(&self) -> &'static str {
        match self {
            Self::UNSPECIFIED => Self::UNSPECIFIED_STR,
            Self::FROST_ED25519_SHA512_V1 => Self::FROST_ED25519_SHA512_V1_STR,
        }
    }

    pub const fn from_context_str(context_str: &str) -> Self {
        match context_str.as_bytes() {
            Self::FROST_ED25519_SHA512_V1_BYTES => Self::FROST_ED25519_SHA512_V1,
            _ => Self::UNSPECIFIED,
        }
    }
}

impl From<&str> for FrostCiphersuite {
    fn from(context_str: &str) -> Self {
        Self::from_context_str(context_str)
    }
}

impl From<FrostCiphersuite> for &str {
    fn from(ciphersuite: FrostCiphersuite) -> Self {
        ciphersuite.context_str()
    }
}

impl From<u8> for FrostCiphersuite {
    fn from(identifier_byte: u8) -> Self {
        match identifier_byte {
            0 => Self::UNSPECIFIED,
            1 => Self::FROST_ED25519_SHA512_V1,
            _ => Self::UNSPECIFIED,
        }
    }
}

#[cfg(feature = "frost_ops")]
#[cfg(test)]
mod sanity_checks {
    use frost_core::Ciphersuite;
    use frost_ed25519::Ed25519Sha512;

    use crate::FrostCiphersuite;
    use crate::FrostCredentialSeed;
    use crate::FrostOpsError;

    pub type FrostEd25519 = frost_ed25519::Ed25519Sha512;

    #[test]
    fn invalid_seed() {
        use crate::FrostCredentialSeed;

        let anonymous =
            FrostCredentialSeed::new_with_username::<frost_ed25519::Ed25519Sha512>("ff");
        assert_eq!(
            Some(FrostOpsError::InvalidFrostCredentialSeed),
            anonymous.err()
        );

        let anonymous =
            FrostCredentialSeed::new_with_username::<frost_ed25519::Ed25519Sha512>("fff");
        assert_eq!(None, anonymous.err());
    }

    const FROST_ED25519_CONTEXT_STRING: &str = frost_ed25519::Ed25519Sha512::ID;
    const CURRENT_FROST_CIPHERSUITE: FrostCiphersuite =
        FrostCiphersuite::from_context_str(FROST_ED25519_CONTEXT_STRING);

    #[test]
    fn ed25519_test_ciphersuite_sanity() {
        {
            let anonymous =
                FrostCredentialSeed::new_anonymous::<frost_ed25519::Ed25519Sha512>().unwrap();
            let ciphersuite = anonymous.ciphersuite();
            assert_eq!(ciphersuite, CURRENT_FROST_CIPHERSUITE);
            assert!(anonymous.frost_identifier::<Ed25519Sha512>().is_ok());
        }

        {
            let username =
                FrostCredentialSeed::new_with_username::<frost_ed25519::Ed25519Sha512>("foobar")
                    .unwrap();
            let ciphersuite = username.ciphersuite();
            assert_eq!(ciphersuite, CURRENT_FROST_CIPHERSUITE);
            assert!(username.frost_identifier::<Ed25519Sha512>().is_ok());
        }

        {
            let email_cred = FrostCredentialSeed::new_with_email::<frost_ed25519::Ed25519Sha512>(
                "superuser@example.com",
            )
            .unwrap();
            let ciphersuite = email_cred.ciphersuite();
            assert_eq!(ciphersuite, CURRENT_FROST_CIPHERSUITE);
            assert!(email_cred.frost_identifier::<Ed25519Sha512>().is_ok());
        }
        {
            let email_cred = FrostCredentialSeed::new_with_email_strict::<
                frost_ed25519::Ed25519Sha512,
            >("superuser", "example.com")
            .unwrap();
            let ciphersuite = email_cred.ciphersuite();
            assert_eq!(ciphersuite, CURRENT_FROST_CIPHERSUITE);
            assert!(email_cred.frost_identifier::<Ed25519Sha512>().is_ok());
        }
    }

    #[test]
    fn ed25519_anonymous_identifier_creation() {
        use crate::FrostCredentialType;

        let anonymous =
            FrostCredentialSeed::new_anonymous::<frost_ed25519::Ed25519Sha512>().unwrap();
        assert_eq!(anonymous.credential_type(), FrostCredentialType::Anonymous);
        assert!(!anonymous.seed().is_empty());
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

        let email_cred =
            FrostCredentialSeed::new_with_email::<frost_ed25519::Ed25519Sha512>(email_address)
                .unwrap();
        assert_eq!(email_cred.credential_type(), FrostCredentialType::Email);
        assert_eq!(
            email_cred,
            FrostCredentialSeed::new_with_email::<frost_ed25519::Ed25519Sha512>(email_address)
                .unwrap()
        );
        let encoded = email_cred.encode();
        let decoded = FrostCredentialSeed::decode(&encoded).unwrap();

        assert_eq!(email_cred.credential_type(), decoded.credential_type());
        assert_eq!(
            email_cred.frost_identifier::<FrostEd25519>(),
            decoded.frost_identifier()
        );

        assert!(
            FrostCredentialSeed::new_with_email::<frost_ed25519::Ed25519Sha512>(
                "+00-imaginary-number"
            )
            .is_err()
        );
        assert!(
            FrostCredentialSeed::new_with_email::<frost_ed25519::Ed25519Sha512>("localhost")
                .is_err()
        );
    }

    #[test]
    fn ed25519_username_identifier_creation() {
        use crate::FrostCredentialType;

        let phone_number = "+00-imaginary-number";

        let phone_number_cred =
            FrostCredentialSeed::new_with_username::<frost_ed25519::Ed25519Sha512>(phone_number)
                .unwrap();
        assert_eq!(
            phone_number_cred.credential_type(),
            FrostCredentialType::Username
        );
        assert_eq!(
            phone_number_cred,
            FrostCredentialSeed::new_with_username::<frost_ed25519::Ed25519Sha512>(phone_number)
                .unwrap()
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
