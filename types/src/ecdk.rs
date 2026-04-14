use bitcode::{Decode, Encode};
use ed25519_dalek::{
    Signature as ClientDeviceSignature, SigningKey as ClientDeviceSigningKey,
    VerifyingKey as ClientDeviceVerifyingKey,
};
use zeroize::Zeroize;

use crate::{FrostClientError, FrostOpsError, FrostOpsResult, RandomBytes};

#[derive(
    Debug, Clone, Copy, Hash, Default, PartialEq, Eq, PartialOrd, Ord, Zeroize, Encode, Decode,
)]
pub struct EphemeralClientDeviceVerifyingKey(pub [u8; 32]);

impl EphemeralClientDeviceVerifyingKey {
    pub fn from_bytes(&self) -> FrostOpsResult<ClientDeviceVerifyingKey> {
        ClientDeviceVerifyingKey::from_bytes(&self.0)
            .or(Err(FrostOpsError::InvalidEphemeralClientDeviceVerifyingKey))
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Zeroize, Encode, Decode)]
pub struct EphemeralClientDeviceSignature(pub [u8; 64]);

impl EphemeralClientDeviceSignature {
    pub fn from_bytes(&self) -> ClientDeviceSignature {
        ClientDeviceSignature::from_bytes(&self.0)
    }
}

impl Default for EphemeralClientDeviceSignature {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

#[derive(Clone, Zeroize, Encode, Decode)]
pub struct EphemeralClientDeviceKeypair {
    signing_key: [u8; 32],
    pub verifying_key: EphemeralClientDeviceVerifyingKey,
}

impl EphemeralClientDeviceKeypair {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_signing_key_bytes(signing_key_bytes: &[u8; 32]) -> Self {
        let signing_key = ClientDeviceSigningKey::from_bytes(signing_key_bytes);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key: signing_key.to_bytes(),
            verifying_key: EphemeralClientDeviceVerifyingKey(verifying_key.to_bytes()),
        }
    }

    pub fn signing_key(&self) -> ClientDeviceSigningKey {
        ClientDeviceSigningKey::from_bytes(&self.signing_key)
    }

    pub fn verifying_key_encodable(&self) -> EphemeralClientDeviceVerifyingKey {
        self.verifying_key
    }

    pub fn verifying_key(&self) -> ClientDeviceVerifyingKey {
        let signing_key = ClientDeviceSigningKey::from_bytes(&self.signing_key);

        signing_key.verifying_key()
    }

    pub fn sign(&self, payload: impl AsRef<[u8]>) -> FrostOpsResult<ClientDeviceSignature> {
        use ed25519_dalek::Signer;

        self.signing_key()
            .try_sign(payload.as_ref())
            .or(Err(FrostClientError::ClientDeviceSigningError.into()))
    }

    pub fn sign_and_return_encodable(
        &self,
        payload: impl AsRef<[u8]>,
    ) -> FrostOpsResult<EphemeralClientDeviceSignature> {
        self.sign(payload)
            .map(|value| EphemeralClientDeviceSignature(value.to_bytes()))
            .or(Err(FrostClientError::ClientDeviceSigningError.into()))
    }

    pub fn sign_and_return_encodable_and_verifying_key(
        &self,
        payload: impl AsRef<[u8]>,
    ) -> FrostOpsResult<(
        EphemeralClientDeviceVerifyingKey,
        EphemeralClientDeviceSignature,
    )> {
        self.sign(payload)
            .map(|value| {
                (
                    self.verifying_key_encodable(),
                    EphemeralClientDeviceSignature(value.to_bytes()),
                )
            })
            .or(Err(FrostClientError::ClientDeviceSigningError.into()))
    }

    pub fn sign_and_get_verifying_key(
        &self,
        payload: impl AsRef<[u8]>,
    ) -> FrostOpsResult<(ClientDeviceVerifyingKey, ClientDeviceSignature)> {
        use ed25519_dalek::Signer;

        self.signing_key()
            .try_sign(payload.as_ref())
            .map(|signature| (self.verifying_key(), signature))
            .or(Err(FrostClientError::ClientDeviceSigningError.into()))
    }
}

impl PartialEq for EphemeralClientDeviceKeypair {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;

        let signing_key_cmp: bool = self.signing_key.ct_eq(other.signing_key.as_slice()).into();

        signing_key_cmp && self.verifying_key == other.verifying_key
    }
}

impl Eq for EphemeralClientDeviceKeypair {}

impl Default for EphemeralClientDeviceKeypair {
    fn default() -> Self {
        let secret_key = RandomBytes::<32>::generate();

        Self::from_signing_key_bytes(secret_key.expose())
    }
}
