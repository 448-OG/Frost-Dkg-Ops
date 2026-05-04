use bitcode::{Decode, Encode};

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub enum RelayOperation {
    RegisterToRelay,
    #[default]
    Route,
}

// A message sent by a participant and meant for the relay server
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub struct FrostRelayMessageEnvelope<T> {
    pub sld_tld_checked: String,
    pub payload: T,
}
