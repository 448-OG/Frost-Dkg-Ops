use bitcode::{Decode, Encode};

use crate::{
    Blake3HashBytes, EphemeralClientDeviceHeOutputs, EphemeralClientDeviceKeypair,
    EphemeralClientDeviceVerifyingKey, FrostCredentialSeed, FrostOpsResult,
    HeEphemeralVerifyingKey, Tai64NTimestamp, TransmitType,
};

// Message meant for the participants in a permissioned network
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub struct FrostMessageEnvelope {
    timestamp: Tai64NTimestamp,
    transmission_type: TransmitType,
    sld_tld: String,
    sender_credential_seed: FrostCredentialSeed,
    recipient_credential_seed: Option<FrostCredentialSeed>,
    binding_hash: Blake3HashBytes,
    /// In round1 DKG the `payload` is not encrypted since it is a broadcast
    he_outputs: EphemeralClientDeviceHeOutputs,
}

impl FrostMessageEnvelope {
    pub fn new(
        sender_credential_seed: FrostCredentialSeed,
        transmission_type: TransmitType,
    ) -> Self {
        let timestamp = Tai64NTimestamp::now();
        Self {
            timestamp,
            transmission_type,
            sld_tld: "example.com".to_string(),
            sender_credential_seed,
            recipient_credential_seed: Option::default(),
            binding_hash: Blake3HashBytes::default(),
            he_outputs: EphemeralClientDeviceHeOutputs::default(),
        }
    }

    pub fn new_broadcast(sender_credential_seed: FrostCredentialSeed) -> Self {
        Self::new(sender_credential_seed, TransmitType::Broadcast)
    }

    pub fn new_narrow_cast(sender_credential_seed: FrostCredentialSeed) -> Self {
        Self::new(sender_credential_seed, TransmitType::NarrowCast)
    }

    pub fn new_unicast(sender_credential_seed: FrostCredentialSeed) -> Self {
        Self::new(sender_credential_seed, TransmitType::Unicast)
    }

    pub fn set_sld_tld(mut self, sld_tld: &str) -> Self {
        self.sld_tld = sld_tld.to_string();

        self
    }

    pub fn set_recipient_credential_seed(mut self, credential_seed: FrostCredentialSeed) -> Self {
        self.recipient_credential_seed.replace(credential_seed);

        self
    }

    pub fn generate_he_outputs(
        mut self,
        ecdk: EphemeralClientDeviceKeypair,
        recipient_ecdvk: EphemeralClientDeviceVerifyingKey,
        payload: &impl Encode,
    ) -> FrostOpsResult<Self> {
        let payload = bitcode::encode(payload);
        self.binding_hash = self.compute_binding_hash(&payload);

        let mut payload_packed = self.binding_hash.to_bytes().to_vec();
        payload_packed.extend_from_slice(&payload);

        let outputs = ecdk.generate_he_outputs(payload_packed, &recipient_ecdvk.from_bytes())?;

        self.he_outputs = outputs;

        Ok(self)
    }

    pub fn generate_empty_he_outputs(
        mut self,
        ecdvk: EphemeralClientDeviceVerifyingKey,
        payload: &impl Encode,
    ) -> FrostOpsResult<Self> {
        let payload = bitcode::encode(payload);
        self.binding_hash = self.compute_binding_hash(&payload);

        let mut payload_packed = self.binding_hash.to_bytes().to_vec();
        payload_packed.extend_from_slice(&payload);

        self.he_outputs = EphemeralClientDeviceHeOutputs {
            sender_static_verifying_key: ecdvk,
            sender_ephemeral_verifying_key: HeEphemeralVerifyingKey::default(),
            ciphertext: payload_packed,
        };

        Ok(self)
    }

    /// Allows the target participants to ensure that the entire message was meant
    /// for the organization with the intended timestamp.
    /// ### Packing
    /// timestamp || Transmission Type (as u8) || organization || sender_credential_seed || recipient_credential_seed || payload (the decrypted payload in the recipient)
    pub fn compute_binding_hash(&self, payload: &[u8]) -> Blake3HashBytes {
        let mut binding_hash = blake3::Hasher::new();
        binding_hash.update(self.timestamp.as_slice());
        binding_hash.update(&[self.transmission_type as u8]);
        binding_hash.update(self.sld_tld.as_bytes());
        binding_hash.update(self.sender_credential_seed.as_bytes());

        if let Some(exists) = self.recipient_credential_seed.as_ref() {
            binding_hash.update(exists.as_bytes());
        }

        binding_hash.update(payload);

        Blake3HashBytes::pre_hashed(binding_hash.finalize())
    }

    pub fn decode_he_outputs(self, ecdk: EphemeralClientDeviceKeypair) -> FrostOpsResult<Vec<u8>> {
        ecdk.decode_he_outputs(self)
    }

    pub fn decode_empty_he_outputs(self) -> FrostOpsResult<Vec<u8>> {
        EphemeralClientDeviceKeypair::decode_empty_he_outputs(self)
    }

    pub fn timestamp(&self) -> Tai64NTimestamp {
        self.timestamp
    }

    pub fn transmission_type(&self) -> TransmitType {
        self.transmission_type
    }

    pub fn sld_tld(&self) -> &str {
        self.sld_tld.as_str()
    }

    pub fn sender_credential_seed(&self) -> &FrostCredentialSeed {
        &self.sender_credential_seed
    }

    pub fn recipient_credential_seed(&self) -> Option<&FrostCredentialSeed> {
        self.recipient_credential_seed.as_ref()
    }

    pub fn binding_hash(&self) -> Blake3HashBytes {
        self.binding_hash
    }

    /// In round1 DKG the `payload` is not encrypted since it is a broadcast
    pub fn he_outputs(self) -> EphemeralClientDeviceHeOutputs {
        self.he_outputs
    }

    pub fn sender_he_verifying_key(&self) -> &HeEphemeralVerifyingKey {
        &self.he_outputs.sender_ephemeral_verifying_key
    }

    pub fn sender_static_verifying_key(&self) -> &EphemeralClientDeviceVerifyingKey {
        &self.he_outputs.sender_static_verifying_key
    }

    pub fn ciphertext(&self) -> &[u8] {
        self.he_outputs.ciphertext()
    }
}
