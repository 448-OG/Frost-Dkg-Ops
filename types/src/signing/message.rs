use bitcode::{Decode, Encode};
use frost_core::Ciphersuite;
use zeroize::Zeroize;

use crate::{Blake3HashBytes, FrostIdentifierBytes, FrostOpsResult, FrostProtocolError};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize)]
pub struct FrostMessagePackage {
    message: String,
    hash: Blake3HashBytes,
    minimum_signers: u16,
    maximum_signers: u16,
    state: FrostMessageSigningState,
    participants: Vec<FrostIdentifierBytes>,
}

impl FrostMessagePackage {
    pub fn new(message: &str) -> FrostOpsResult<Self> {
        if message.len() > 1024 * 1024 {
            return Err(FrostProtocolError::MessageTooBig.into());
        }

        let hash = Blake3HashBytes::new(message);

        Ok(Self {
            message: message.to_string(),
            hash,
            ..Default::default()
        })
    }

    pub fn set_minimum_signers(&mut self, minimum_signers: u16) -> FrostOpsResult<&mut Self> {
        if minimum_signers < 2 {
            return Err(FrostProtocolError::MinimumSignersMustBe2OrMore.into());
        }

        self.minimum_signers = minimum_signers;

        Ok(self)
    }

    pub fn set_maximum_signers(&mut self, maximum_signers: u16) -> FrostOpsResult<&mut Self> {
        if maximum_signers < self.minimum_signers {
            return Err(FrostProtocolError::MinimumSignersMoreThanMaximumSigners.into());
        }

        self.maximum_signers = maximum_signers;

        Ok(self)
    }

    /// The participants field is always checked for duplicates then sorted
    pub fn add_participant<C: frost_core::Ciphersuite>(
        &mut self,
        participant: &frost_core::Identifier<C>,
    ) -> &mut Self {
        self.participants
            .push(FrostIdentifierBytes::encode(participant));

        self.participants.dedup();
        self.participants.sort();

        self
    }

    pub fn message(&self) -> &str {
        self.message.as_str()
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash.to_bytes()
    }

    pub fn to_blake3_hash(&self) -> blake3::Hash {
        self.hash.to_hash()
    }

    pub fn minimum_signers(&self) -> u16 {
        self.minimum_signers
    }

    pub fn maximum_signers(&self) -> u16 {
        self.maximum_signers
    }

    pub fn state(&self) -> FrostMessageSigningState {
        self.state
    }

    pub fn participants(&self) -> &[FrostIdentifierBytes] {
        self.participants.as_slice()
    }

    pub fn is_valid_participant(&self, participant: &FrostIdentifierBytes) -> bool {
        self.participants
            .iter()
            .any(|participant_stored| participant_stored == participant)
    }

    pub fn participants_decoded<C: Ciphersuite>(
        &self,
    ) -> FrostOpsResult<Vec<frost_core::Identifier<C>>> {
        self.participants
            .iter()
            .map(|participant| participant.decode())
            .collect()
    }
}

impl Default for FrostMessagePackage {
    fn default() -> Self {
        Self {
            message: "Hello World!".to_string(),
            hash: Blake3HashBytes::default(),
            minimum_signers: 2,
            maximum_signers: 2,
            state: FrostMessageSigningState::default(),
            participants: Vec::default(),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash, Encode, Decode)]
pub enum FrostMessageSigningState {
    #[default]
    Signal,
    Finalized,
}

impl Zeroize for FrostMessageSigningState {
    fn zeroize(&mut self) {
        *self = Self::default()
    }
}
