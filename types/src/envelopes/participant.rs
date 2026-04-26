use bitcode::{Decode, Encode};

use crate::{
    EphemeralClientDeviceHeOutputs, EphemeralClientDeviceKeypair,
    EphemeralClientDeviceVerifyingKey, FrostCredentialSeed, FrostOpsResult, Tai64NTimestamp,
    TransmitType,
};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
#[repr(u8)]
pub enum ParticipantOperation {
    /// Registers a participant locally for Key Agreement
    /// and automatically adds round1 data
    DkgRound1 = 0,
    DkgRound2 = 1,
    Ignore = 2,
}

impl From<u8> for ParticipantOperation {
    fn from(discriminant: u8) -> Self {
        match discriminant {
            0 => Self::DkgRound1,
            1 => Self::DkgRound2,
            _ => Self::Ignore,
        }
    }
}

// Message meant for the participants in a permissioned network
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub struct FrostMessageEnvelope {
    pub timestamp: Tai64NTimestamp,
    pub transmission_type: TransmitType,
    pub organization: String,
    pub sender_seed: FrostCredentialSeed,
    pub recipient_seed: Option<FrostCredentialSeed>,
    pub payload: Vec<u8>,
    /// In round1 DKG the `payload` is not encrypted since it is a broadcast
    pub he_outputs: EphemeralClientDeviceHeOutputs,
}

impl FrostMessageEnvelope {
    pub fn generate_he_outputs(
        mut self,
        ecdk: EphemeralClientDeviceKeypair,
        recipient_ecdvk: EphemeralClientDeviceVerifyingKey,
    ) -> FrostOpsResult<Self> {
        let packed = self.pack_for_dh_outputs();

        let outputs = ecdk.generate_he_outputs(packed, &recipient_ecdvk.from_bytes())?;

        self.he_outputs = outputs;

        Ok(self)
    }

    pub fn pack_for_dh_outputs(&self) -> Vec<u8> {
        let mut message = Vec::<u8>::default();

        message.extend_from_slice(self.organization.as_bytes());
        message.extend_from_slice(self.sender_seed.as_bytes());
        if let Some(exists) = self.recipient_seed.as_ref() {
            message.extend_from_slice(exists.as_bytes());
        }
        message.extend_from_slice(&self.payload);

        message
    }

    pub fn decode_he_outputs(self, ecdk: EphemeralClientDeviceKeypair) -> FrostOpsResult<Vec<u8>> {
        ecdk.decode_he_outputs(self.he_outputs)
    }
}
