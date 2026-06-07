use core::fmt;

use bitcode::{Decode, Encode};

#[cfg(feature = "frost_ops")]
use {
    crate::FrostOpsResult,
    frost_core::{
        Ciphersuite, VerifyingKey,
        keys::{KeyPackage, PublicKeyPackage, VerifyingShare},
    },
};

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{FrostIdentifierBytes, FrostSigningShareBytes};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostKeyPackageBytes {
    identifier: FrostIdentifierBytes,
    signing_share: FrostSigningShareBytes,
    verifying_share: FrostVerifyingShareBytes,
    verifying_key: FrostVerifyingKeyBytes,
    minimum_signers: u16,
}

#[cfg(feature = "frost_ops")]
impl FrostKeyPackageBytes {
    pub fn encode<C: Ciphersuite>(key_package: &KeyPackage<C>) -> FrostOpsResult<Self> {
        let identifier_bytes = FrostIdentifierBytes::encode(key_package.identifier());
        let signing_share = FrostSigningShareBytes::encode::<C>(key_package.signing_share());
        let verifying_share = FrostVerifyingShareBytes::encode::<C>(key_package.verifying_share())?;
        let verifying_key = FrostVerifyingKeyBytes::encode::<C>(key_package.verifying_key())?;

        Ok(Self {
            identifier: identifier_bytes,
            signing_share,
            verifying_share,
            verifying_key,
            minimum_signers: *key_package.min_signers(),
        })
    }

    pub fn to_frost<C: Ciphersuite>(&self) -> FrostOpsResult<KeyPackage<C>> {
        let identifier = self.identifier.decode::<C>()?;
        let signing_share = self.signing_share.decode::<C>()?;
        let verifying_share = self.verifying_share.decode::<C>()?;
        let verifying_key = self.verifying_key.decode::<C>()?;

        Ok(KeyPackage::<C>::new(
            identifier,
            signing_share,
            verifying_share,
            verifying_key,
            self.minimum_signers,
        ))
    }

    pub fn verifying_key_base58<C: Ciphersuite>(&self) -> FrostOpsResult<String> {
        let vk = self.verifying_key.decode::<C>()?;

        Ok(bs58::encode(&vk.serialize()?).into_string())
    }
}

#[derive(Clone, Encode, Decode, Zeroize, ZeroizeOnDrop)]
pub struct FrostVerifyingShareBytes(Vec<u8>);

#[cfg(feature = "frost_ops")]
impl FrostVerifyingShareBytes {
    pub fn encode<C: Ciphersuite>(verifying_share: &VerifyingShare<C>) -> FrostOpsResult<Self> {
        Ok(Self(verifying_share.serialize()?))
    }

    pub fn decode<C: Ciphersuite>(&self) -> FrostOpsResult<VerifyingShare<C>> {
        Ok(VerifyingShare::<C>::deserialize(&self.0)?)
    }
}

impl PartialEq for FrostVerifyingShareBytes {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;

        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for FrostVerifyingShareBytes {}

impl fmt::Debug for FrostVerifyingShareBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FrostVerifyingShareBytes")
            .field(&faster_hex::hex_string_upper(&self.0))
            .finish()
    }
}

#[derive(Clone, Encode, Decode, Zeroize, ZeroizeOnDrop)]
pub struct FrostVerifyingKeyBytes(Vec<u8>);

#[cfg(feature = "frost_ops")]
impl FrostVerifyingKeyBytes {
    pub fn encode<C: Ciphersuite>(verifying_key: &VerifyingKey<C>) -> FrostOpsResult<Self> {
        Ok(Self(verifying_key.serialize()?))
    }

    pub fn decode<C: Ciphersuite>(&self) -> FrostOpsResult<VerifyingKey<C>> {
        Ok(VerifyingKey::<C>::deserialize(&self.0)?)
    }
}

impl PartialEq for FrostVerifyingKeyBytes {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;

        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for FrostVerifyingKeyBytes {}

impl fmt::Debug for FrostVerifyingKeyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FrostVerifyingKeyBytes")
            .field(&faster_hex::hex_string_upper(&self.0))
            .finish()
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop)]
pub struct FrostPublicKeyPackage(Vec<u8>);

#[cfg(feature = "frost_ops")]
impl FrostPublicKeyPackage {
    pub fn encode<C: Ciphersuite>(public_package: &PublicKeyPackage<C>) -> FrostOpsResult<Self> {
        Ok(Self(public_package.serialize()?))
    }

    pub fn to_frost<C: Ciphersuite>(&self) -> FrostOpsResult<PublicKeyPackage<C>> {
        Ok(PublicKeyPackage::<C>::deserialize(&self.0)?)
    }

    pub fn verifying_key_base58<C: Ciphersuite>(&self) -> FrostOpsResult<String> {
        let package = self.to_frost::<C>()?;
        let vk = package.verifying_key();

        Ok(bs58::encode(&vk.serialize()?).into_string())
    }
}

impl fmt::Debug for FrostPublicKeyPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            format_args!("FrostPublicKeyPackage({})", &blake3::hash(&self.0))
        )
    }
}

impl fmt::Display for FrostPublicKeyPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &blake3::hash(&self.0))
    }
}
