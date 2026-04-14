use bitcode::{Decode, Encode};

use crate::{
    EphemeralClientDeviceKeypair, EphemeralClientDeviceSignature,
    EphemeralClientDeviceVerifyingKey, FrostClientError, FrostCredentialSeed, FrostOpsResult,
    Round1PackageBytes, Tai64NTimestamp, TransmitType,
};

// Message meant for the participants in a permissioned network
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub struct FrostMessageEnvelope {
    pub timestamp: Tai64NTimestamp,
    pub transmission_type: TransmitType,
    pub organization: String,
    pub sender_seed: FrostCredentialSeed,
    pub recipient_seed: Option<FrostCredentialSeed>,
    pub payload: FrostEnvelopePayload,
    pub ecdvk: EphemeralClientDeviceVerifyingKey,
    pub ecds: EphemeralClientDeviceSignature,
}

impl FrostMessageEnvelope {
    pub fn sign(mut self, ecdk: &EphemeralClientDeviceKeypair) -> FrostOpsResult<Self> {
        let packed = self.pack_for_signing();

        let (ecdvk, ecds) = ecdk.sign_and_return_encodable_and_verifying_key(packed)?;

        self.ecdvk = ecdvk;
        self.ecds = ecds;

        Ok(self)
    }

    pub fn pack_for_signing(&self) -> Vec<u8> {
        let mut message = Vec::<u8>::default();

        message.insert(0, self.transmission_type as u8);
        message.extend_from_slice(self.organization.as_bytes());
        message.extend_from_slice(self.sender_seed.as_bytes());
        if let Some(exists) = self.recipient_seed.as_ref() {
            message.extend_from_slice(exists.as_bytes());
        }
        message.extend_from_slice(&self.payload.encode());

        message
    }

    pub fn verify_ecds(&self) -> FrostOpsResult<bool> {
        let message = self.pack_for_signing();

        let verifying_key = self.ecdvk.from_bytes()?;
        let signature = self.ecds.from_bytes();

        Ok(verifying_key
            .verify_strict(message.as_ref(), &signature)
            .is_ok())
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub enum FrostEnvelopePayload {
    DkgRound1(Round1PackageBytes),
    /// These must be encrypted for each recipient
    DkgRound2Encrypted,
}

impl FrostEnvelopePayload {
    pub fn encode(&self) -> Vec<u8> {
        bitcode::encode(self)
    }

    pub fn decode(bytes: &[u8]) -> FrostOpsResult<Self> {
        bitcode::decode::<Self>(bytes).or(Err(FrostClientError::DecodeFrostEnvelopePayload.into()))
    }
}
