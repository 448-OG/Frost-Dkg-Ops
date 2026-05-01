use bitcode::{Decode, Encode};

use crate::FrostCredentialSeed;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Encode, Decode)]
pub enum FrostDkgState {
    InitCredentials,
    QueryMinMax,
    Round1,
    Round2,
    Part3,
    Finalized,
}

impl FrostDkgState {
    pub fn transition(&self) -> Self {
        match self {
            Self::InitCredentials => Self::QueryMinMax,
            Self::QueryMinMax => Self::Round1,
            Self::Round1 => Self::Round2,
            Self::Round2 => Self::Part3,
            Self::Part3 => Self::Finalized,
            Self::Finalized => Self::Finalized,
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Encode, Decode)]
pub struct MinMaxParticipants {
    pub min: u16,
    pub max: u16,
}

impl Default for MinMaxParticipants {
    fn default() -> Self {
        Self { min: 2, max: 2 }
    }
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode)]
pub struct DkgParticipants(pub Vec<FrostCredentialSeed>);

impl DkgParticipants {
    pub fn is_valid_participant(&self, credential_seed: &FrostCredentialSeed) -> bool {
        self.0.iter().any(|stored| stored == credential_seed)
    }
}
