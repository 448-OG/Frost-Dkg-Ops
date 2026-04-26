use bitcode::{Decode, Encode};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Encode, Decode)]
pub enum FrostDkgState {
    InitCredentials,
    QueryMinMax,
    Round1,
    Round2,
    Finalized,
}

impl FrostDkgState {
    pub fn transition(&self) -> Self {
        match self {
            Self::InitCredentials => Self::QueryMinMax,
            Self::QueryMinMax => Self::Round1,
            Self::Round1 => Self::Round2,
            Self::Round2 => Self::Finalized,
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
