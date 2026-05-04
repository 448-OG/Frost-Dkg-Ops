use core::fmt;

use bitcode::{Decode, Encode};
use hpke_rs::hpke_types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs::{
    Hpke, HpkePrivateKey as ClientDeviceSecretKey, HpkePublicKey as ClientDeviceVerifyingKey, Mode,
};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use zeroize::Zeroize;

use ed25519_dalek::{
    Signature as AsymmetricSignature, SigningKey as AsymmetricSigningKey,
    VerifyingKey as AsymmetricVerifyingKey,
};

use crate::{
    Blake3HashBytes, FrostMessageEnvelope, FrostOpsError, FrostOpsResult, RandomBytes, TransmitType,
};

#[derive(Clone, Hash, Default, PartialEq, Eq, PartialOrd, Ord, Zeroize, Encode, Decode)]
pub struct EphemeralClientDeviceVerifyingKey(pub Vec<u8>);

impl EphemeralClientDeviceVerifyingKey {
    pub fn new(hpke_verifying_key: ClientDeviceVerifyingKey) -> Self {
        Self(hpke_verifying_key.as_slice().to_vec())
    }

    pub fn from_bytes(self) -> ClientDeviceVerifyingKey {
        ClientDeviceVerifyingKey::new(self.0)
    }
}

impl fmt::Debug for EphemeralClientDeviceVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("EphemeralClientDeviceVerifyingKey")
            .field(&faster_hex::hex_string_upper(&self.0))
            .finish()
    }
}

#[derive(Clone, Hash, Default, PartialEq, Eq, PartialOrd, Ord, Zeroize, Encode, Decode)]
pub struct HeEphemeralVerifyingKey(pub Vec<u8>);

impl HeEphemeralVerifyingKey {
    pub fn new(hpke_verifying_key: ClientDeviceVerifyingKey) -> Self {
        Self(hpke_verifying_key.as_slice().to_vec())
    }

    pub fn from_bytes(self) -> ClientDeviceVerifyingKey {
        ClientDeviceVerifyingKey::new(self.0)
    }
}

impl fmt::Debug for HeEphemeralVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HeEphemeralVerifyingKey")
            .field(&faster_hex::hex_string_upper(&self.0))
            .finish()
    }
}

/// Ephemeral Client Device Hybrid Encryption Outputs
#[derive(Default, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Zeroize, Encode, Decode)]
pub struct EphemeralClientDeviceHeOutputs {
    pub sender_static_verifying_key: EphemeralClientDeviceVerifyingKey,
    pub sender_ephemeral_verifying_key: HeEphemeralVerifyingKey,
    pub ciphertext: Vec<u8>,
}

impl EphemeralClientDeviceHeOutputs {
    pub fn new(sender_static_verifying_key: EphemeralClientDeviceVerifyingKey) -> Self {
        Self {
            sender_static_verifying_key,
            sender_ephemeral_verifying_key: HeEphemeralVerifyingKey::default(),
            ciphertext: Vec::default(),
        }
    }
    pub fn sender_ephemeral_verifying_key(&self) -> &HeEphemeralVerifyingKey {
        &self.sender_ephemeral_verifying_key
    }

    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext.as_slice()
    }
}

impl fmt::Debug for EphemeralClientDeviceHeOutputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralClientDeviceHeOutputs")
            .field(
                "sender_static_verifying_key",
                &self.sender_static_verifying_key,
            )
            .field(
                "sender_ephemeral_verifying_key",
                &self.sender_ephemeral_verifying_key,
            )
            .field("ciphertext", &Blake3HashBytes::new(self.ciphertext()))
            .finish()
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
            sender_ephemeral_verifying_key: HeEphemeralVerifyingKey(ephemeral_public_key),
            sender_static_verifying_key,
            ciphertext,
        })
    }

    pub fn decode_he_outputs(self, envelope: FrostMessageEnvelope) -> FrostOpsResult<Vec<u8>> {
        if envelope.transmission_type() != TransmitType::Unicast {
            return Err(FrostOpsError::InvalidTransmission {
                expected: TransmitType::Unicast,
                current: envelope.transmission_type(),
            });
        }

        let hpke = Self::hpke();

        let (secret_key, _) = self.into_secret_key()?;

        let envelope_binding_hash = envelope.binding_hash().to_hash();

        let sender_ephemeral_verifying_key = envelope.sender_he_verifying_key();
        let sender_static_verifying_key = envelope.sender_static_verifying_key();

        let mut receiver_ctx = hpke.setup_receiver(
            &sender_ephemeral_verifying_key.0,
            &secret_key,
            Self::INFO_BYTES,
            None,
            None,
            Some(&sender_static_verifying_key.clone().from_bytes()), // <-- sender static public key
        )?;

        let decoded_payload =
            receiver_ctx.open(Self::AAD_BYTES, &envelope.he_outputs().ciphertext)?;
        let computed_from_decode = Blake3HashBytes::from_slice(&decoded_payload)?.to_hash();

        if envelope_binding_hash != computed_from_decode {
            return Err(FrostOpsError::BindingHashMismatch);
        }

        Ok(decoded_payload[32..].to_vec())
    }

    pub fn decode_empty_he_outputs(envelope: FrostMessageEnvelope) -> FrostOpsResult<Vec<u8>> {
        let envelope_binding_hash = envelope.binding_hash().to_hash();

        if !envelope.sender_he_verifying_key().0.is_empty()
            || envelope.sender_static_verifying_key().0.is_empty()
            || envelope.recipient_credential_seed().is_some()
        {
            return Err(FrostOpsError::InvalidPayloadForEmptyEnvelope);
        }

        let payload = envelope.he_outputs().ciphertext().to_vec();
        let computed_from_decode = Blake3HashBytes::from_slice(&payload)?.to_hash();

        if envelope_binding_hash != computed_from_decode {
            return Err(FrostOpsError::BindingHashMismatch);
        }

        Ok(payload[32..].to_vec())
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

impl fmt::Debug for EphemeralClientDeviceKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralClientDeviceKeypair")
            .field("secret_key", &"[REDACTED]")
            .field("verifying_key", &self.verifying_key)
            .finish()
    }
}

// This is used when you want multiple parties to verify data
// without incurring the cost of HPKE
//

#[derive(Clone, Zeroize, Encode, Decode)]
pub struct AsymmetricKeypairBytes {
    signing_key: [u8; 32],
    pub verifying_key: AsymmetricVerifyingKeyBytes,
}

impl AsymmetricKeypairBytes {
    pub fn new() -> FrostOpsResult<Self> {
        let secret_key = RandomBytes::<32>::generate()?;

        Ok(Self::from_signing_key_bytes(secret_key.expose()))
    }

    pub fn from_signing_key_bytes(signing_key_bytes: &[u8; 32]) -> Self {
        let signing_key = AsymmetricSigningKey::from_bytes(signing_key_bytes);
        let verifying_key = signing_key.verifying_key();

        Self {
            signing_key: signing_key.to_bytes(),
            verifying_key: AsymmetricVerifyingKeyBytes(verifying_key.to_bytes()),
        }
    }

    pub fn signing_key(&self) -> AsymmetricSigningKey {
        AsymmetricSigningKey::from_bytes(&self.signing_key)
    }

    pub fn verifying_key_encodable(&self) -> AsymmetricVerifyingKeyBytes {
        self.verifying_key
    }

    pub fn verifying_key(&self) -> AsymmetricVerifyingKey {
        self.signing_key().verifying_key()
    }

    pub fn sign(&self, payload: impl AsRef<[u8]>) -> FrostOpsResult<AsymmetricSignature> {
        use ed25519_dalek::Signer;

        self.signing_key()
            .try_sign(payload.as_ref())
            .or(Err(FrostOpsError::UnableToSignPayload))
    }

    pub fn sign_and_return_encodable(
        &self,
        payload: impl AsRef<[u8]>,
    ) -> FrostOpsResult<AsymmetricSignatureBytes> {
        self.sign(payload)
            .map(|value| AsymmetricSignatureBytes(value.to_bytes()))
    }

    pub fn sign_and_return_encodable_and_verifying_key(
        &self,
        payload: impl AsRef<[u8]>,
    ) -> FrostOpsResult<(AsymmetricVerifyingKeyBytes, AsymmetricSignatureBytes)> {
        self.sign(payload).map(|value| {
            (
                self.verifying_key_encodable(),
                AsymmetricSignatureBytes(value.to_bytes()),
            )
        })
    }
}

impl fmt::Debug for AsymmetricKeypairBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsymmetricKeypairBytes")
            .field("signing_key", &"[REDACTED]")
            .field("verifying_key", &self.verifying_key)
            .finish()
    }
}

impl PartialEq for AsymmetricKeypairBytes {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;

        let signing_key_cmp: bool = self.signing_key.ct_eq(other.signing_key.as_slice()).into();

        signing_key_cmp && self.verifying_key == other.verifying_key
    }
}

impl Eq for AsymmetricKeypairBytes {}

#[derive(Clone, Copy, Hash, Default, PartialEq, Eq, PartialOrd, Ord, Zeroize, Encode, Decode)]
pub struct AsymmetricVerifyingKeyBytes(pub [u8; 32]);

impl AsymmetricVerifyingKeyBytes {
    pub fn from_bytes(&self) -> FrostOpsResult<AsymmetricVerifyingKey> {
        AsymmetricVerifyingKey::from_bytes(&self.0)
            .or(Err(FrostOpsError::InvalidAsymmetricVerifyingKeyBytes))
    }
}

impl fmt::Debug for AsymmetricVerifyingKeyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AsymmetricVerifyingKeyBytes")
            .field(&faster_hex::hex_string_upper(&self.0))
            .finish()
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Zeroize, Encode, Decode)]
pub struct AsymmetricSignatureBytes(pub [u8; 64]);

impl AsymmetricSignatureBytes {
    pub fn from_bytes(&self) -> AsymmetricSignature {
        AsymmetricSignature::from_bytes(&self.0)
    }
}

impl Default for AsymmetricSignatureBytes {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl fmt::Debug for AsymmetricSignatureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AsymmetricSignatureBytes")
            .field(&faster_hex::hex_string_upper(&self.0))
            .finish()
    }
}
