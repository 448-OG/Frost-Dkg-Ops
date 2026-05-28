use core::fmt;
use std::borrow::Cow;

use bitcode::{Decode, Encode};
use frost_core::Ciphersuite;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "email")]
use email_address::{EmailAddress, Options as EmailOptions};

use crate::{FrostOpsError, FrostOpsResult, RandomBytes};

/// The `seed` can reconstruct the frost_identifier and is useful in keeping
/// the bytes sent over a network small instead of sending the FROST Identifier
/// together with the seed.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop)]
pub struct FrostCredentialSeed(Vec<u8>);

impl FrostCredentialSeed {
    pub fn new(
        credential_type: FrostCredentialType,
        seed: impl AsRef<[u8]> + ToString,
    ) -> FrostOpsResult<Self> {
        let seed = seed.as_ref();

        if seed.len() < 3 || credential_type == FrostCredentialType::Uninitialized {
            return Err(FrostOpsError::InvalidFrostCredentialSeed);
        }

        let mut seed_outcome = vec![credential_type as u8];

        seed_outcome.extend_from_slice(seed);

        Ok(Self(seed_outcome))
    }

    pub fn new_anonymous() -> FrostOpsResult<Self> {
        let bytes = RandomBytes::<32>::generate();
        let seed = faster_hex::hex_string_upper(bytes?.expose().as_slice());

        Self::new(FrostCredentialType::Anonymous, seed)
    }

    #[cfg(feature = "email")]
    pub fn new_with_email(email_address: &str) -> FrostOpsResult<Self> {
        let email_address = email_address.trim();

        let options = EmailOptions::default().with_required_tld();
        EmailAddress::parse_with_options(email_address, options)
            .or(Err(FrostOpsError::InvalidEmailAddress))?;

        Self::new(FrostCredentialType::Email, email_address)
    }

    #[cfg(feature = "email")]
    pub fn new_with_email_strict(username: &str, sld_tld: &str) -> FrostOpsResult<Self> {
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

        Self::new(FrostCredentialType::Email, email_address)
    }

    /// Can be a username or even a phone number (as long as the phone number is a String)
    pub fn new_with_username(username: &str) -> FrostOpsResult<Self> {
        let username = username.trim();

        Self::new(FrostCredentialType::Username, username)
    }

    pub fn credential_type(&self) -> FrostCredentialType {
        self.0
            .first()
            .cloned()
            .unwrap_or(FrostCredentialType::Uninitialized as u8)
            .into()
    }

    pub fn frost_identifier<C: Ciphersuite>(&self) -> FrostOpsResult<frost_core::Identifier<C>> {
        Ok(frost_core::Identifier::derive(self.seed_bytes())?)
    }

    pub fn seed(&self) -> Cow<'_, str> {
        // Not Expected to be `UNINITIALIZED` because length checks are performed on creating new and the seed must impl `ToString`
        let parsed = core::str::from_utf8(self.seed_bytes()).unwrap_or("UNINITIALIZED");

        Cow::Borrowed(parsed)
    }

    /// Useful when constructing the [String] format of this type
    pub fn seed_bytes(&self) -> &[u8] {
        // Should never panic because creating `Self` requires seed length 3 or greater
        &self.0[1..]
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
