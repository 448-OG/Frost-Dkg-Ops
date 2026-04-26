use bitcode::{Decode, Encode};
use hpke_rs::hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs::{
    Hpke, HpkePrivateKey as ClientDeviceSecretKey, HpkePublicKey as ClientDeviceVerifyingKey, Mode,
};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use zeroize::Zeroize;

use crate::{FrostOpsError, FrostOpsResult};

#[derive(Debug, Clone, Hash, Default, PartialEq, Eq, PartialOrd, Ord, Zeroize, Encode, Decode)]
pub struct EphemeralClientDeviceVerifyingKey(pub Vec<u8>);

impl EphemeralClientDeviceVerifyingKey {
    pub fn new(hpke_verifying_key: ClientDeviceVerifyingKey) -> Self {
        Self(hpke_verifying_key.as_slice().to_vec())
    }

    pub fn from_bytes(self) -> ClientDeviceVerifyingKey {
        ClientDeviceVerifyingKey::new(self.0)
    }
}

/// Ephemeral Client Device Hybrid Encryption Outputs
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Zeroize, Encode, Decode)]
pub struct EphemeralClientDeviceHeOutputs {
    pub sender_static_verifying_key: EphemeralClientDeviceVerifyingKey,
    pub sender_ephemeral_public_key: EphemeralClientDeviceVerifyingKey,
    pub ciphertext: Vec<u8>,
}

impl EphemeralClientDeviceHeOutputs {
    pub fn new(sender_static_verifying_key: EphemeralClientDeviceVerifyingKey) -> Self {
        Self {
            sender_static_verifying_key,
            sender_ephemeral_public_key: EphemeralClientDeviceVerifyingKey::default(),
            ciphertext: Vec::default(),
        }
    }
    pub fn sender_ephemeral_public_key(&self) -> &[u8] {
        self.sender_ephemeral_public_key.0.as_slice()
    }

    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext.as_slice()
    }
}

#[derive(Clone, Zeroize, Encode, Decode)]
pub struct EphemeralClientDeviceKeypair {
    secret_key: Vec<u8>,
    pub verifying_key: EphemeralClientDeviceVerifyingKey,
}

impl EphemeralClientDeviceKeypair {
    pub const INFO: &str = "DHKEM25519-HKDFSHA256-CHACHA20POLY1305";
    pub const AAD: &str = "FROST-AEAD";
    pub const INFO_BYTES: &[u8] = Self::INFO.as_bytes();
    pub const AAD_BYTES: &[u8] = Self::AAD.as_bytes();

    pub fn new() -> FrostOpsResult<Self> {
        let mut hpke = Self::hpke();

        let (secret_key, verifying_key) = hpke.generate_key_pair()?.into_keys();
        let secret_key = bitcode::serialize(&secret_key)
            .or(Err(FrostOpsError::UnableToSerializeHpkeSecretKey))?;
        let verifying_key = EphemeralClientDeviceVerifyingKey::new(verifying_key);

        Ok(Self {
            secret_key,
            verifying_key,
        })
    }

    pub fn hpke() -> Hpke<HpkeRustCrypto> {
        Hpke::<HpkeRustCrypto>::new(
            Mode::Auth,
            KemAlgorithm::DhKem25519,
            KdfAlgorithm::HkdfSha256,
            AeadAlgorithm::ChaCha20Poly1305,
        )
    }

    pub fn into_secret_key(
        self,
    ) -> FrostOpsResult<(ClientDeviceSecretKey, EphemeralClientDeviceVerifyingKey)> {
        let secret_key = bitcode::deserialize::<ClientDeviceSecretKey>(&self.secret_key)
            .or(Err(FrostOpsError::UnableToDeserializeHpkeSecretKey))?;

        Ok((secret_key, self.verifying_key))
    }

    pub fn into_keys(self) -> FrostOpsResult<(ClientDeviceSecretKey, ClientDeviceVerifyingKey)> {
        let secret_key = bitcode::deserialize::<ClientDeviceSecretKey>(&self.secret_key)
            .or(Err(FrostOpsError::UnableToDeserializeHpkeSecretKey))?;

        let verifying_key = self.verifying_key.from_bytes();

        Ok((secret_key, verifying_key))
    }

    pub fn verifying_key_encodable(&self) -> EphemeralClientDeviceVerifyingKey {
        self.verifying_key.clone()
    }

    pub fn verifying_key(&self) -> ClientDeviceVerifyingKey {
        self.verifying_key_encodable().from_bytes()
    }

    pub fn generate_he_outputs(
        self,
        payload: impl AsRef<[u8]>,
        recipient_verifying_key: &ClientDeviceVerifyingKey,
    ) -> FrostOpsResult<EphemeralClientDeviceHeOutputs> {
        let mut hpke = Self::hpke();

        let (sender_secret, sender_static_verifying_key) = self.into_secret_key()?;

        let (ephemeral_public_key, mut sender_ctx) = hpke.setup_sender(
            recipient_verifying_key,
            Self::INFO_BYTES,
            None,
            None,
            Some(&sender_secret), // <-- sender static private
        )?;

        let ciphertext = sender_ctx.seal(Self::AAD_BYTES, payload.as_ref())?;

        Ok(EphemeralClientDeviceHeOutputs {
            sender_ephemeral_public_key: EphemeralClientDeviceVerifyingKey(ephemeral_public_key),
            sender_static_verifying_key,
            ciphertext,
        })
    }

    pub fn decode_he_outputs(
        self,
        outputs: EphemeralClientDeviceHeOutputs,
    ) -> FrostOpsResult<Vec<u8>> {
        let hpke = Self::hpke();

        let (secret_key, _) = self.into_secret_key()?;

        let mut receiver_ctx = hpke.setup_receiver(
            &outputs.sender_ephemeral_public_key.0,
            &secret_key,
            Self::INFO_BYTES,
            None,
            None,
            Some(&outputs.sender_static_verifying_key.from_bytes()), // <-- sender static public key
        )?;

        Ok(receiver_ctx.open(Self::AAD_BYTES, &outputs.ciphertext)?)
    }
}

impl PartialEq for EphemeralClientDeviceKeypair {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;

        let signing_key_cmp: bool = self.secret_key.ct_eq(other.secret_key.as_slice()).into();

        signing_key_cmp && self.verifying_key == other.verifying_key
    }
}

impl Eq for EphemeralClientDeviceKeypair {}
