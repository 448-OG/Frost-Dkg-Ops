use core::fmt;
use std::ops::Deref;

use bitcode::{Decode, Encode};
use blake3::Hasher;
use file_format::FileFormat;
use tai64::Tai64N;
use zeroize::Zeroize;

use crate::{
    AsymmetricKeypairBytes, AsymmetricSignatureBytes, Blake3HashBytes, FrostCredentialSeed,
    FrostOpsError, FrostOpsResult, FrostProtocolError, FrostSignatureBytes,
    FrostSignatureShareBytes, FrostSigningCommitmentsBytes, FrostSigningNoncesBytes,
    FrostSigningPackageBytes, SignalAcknowledgement, SldTld, Tai64NTimestamp,
};

pub type FrostEventHash = Blake3HashBytes;

pub const FROST_SIGNING_KEY_LEN: usize = blake3::OUT_LEN + tai64::Tai64N::BYTE_SIZE;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Encode, Decode)]
pub struct FrostSigningEventKey(pub [u8; FROST_SIGNING_KEY_LEN]);

impl fmt::Debug for FrostSigningEventKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FrostSigningEventKey")
            .field(&faster_hex::hex_string_upper(self.0.as_slice()))
            .finish()
    }
}

impl Default for FrostSigningEventKey {
    fn default() -> Self {
        Self([0u8; FROST_SIGNING_KEY_LEN])
    }
}

impl AsRef<[u8]> for FrostSigningEventKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Deref for FrostSigningEventKey {
    type Target = [u8; FROST_SIGNING_KEY_LEN];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<FrostSigningEventKey> for [u8; FROST_SIGNING_KEY_LEN] {
    fn from(value: FrostSigningEventKey) -> Self {
        value.0
    }
}

impl From<[u8; FROST_SIGNING_KEY_LEN]> for FrostSigningEventKey {
    fn from(val: [u8; FROST_SIGNING_KEY_LEN]) -> Self {
        FrostSigningEventKey(val)
    }
}

pub const EVENT_MAX_MESSAGE_SIZE: usize = 5 * (1024 * 1024);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Encode, Decode, Zeroize)]
pub enum FrostSigningMessageOrigin {
    Relay,
    Participant(u16),
}

impl FrostSigningMessageOrigin {
    /// if participant then `0u8.to_le_bytes` + `participant_index_usize.to_le_bytes()`
    pub fn hash_preimage(&self) -> Vec<u8> {
        let mut outcome = Vec::<u8>::default();

        match self {
            Self::Relay => outcome.push(0),
            Self::Participant(index) => {
                outcome.push(1);
                outcome.extend_from_slice(&index.to_le_bytes());
            }
        }

        outcome
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode)]
pub struct FrostSigningMessageMetadata {
    // When the media was created
    timestamp: Tai64NTimestamp,
    size: usize,
    media_type: String,
    contents_hash: Blake3HashBytes,
}

impl FrostSigningMessageMetadata {
    /// TODO: Add chunked hashing when protocol moves to supporting larger file sizes
    pub fn new(message: impl AsRef<[u8]> + Encode + Decode<'static>) -> FrostOpsResult<Self> {
        let message = message.as_ref();

        let media_type = FileFormat::from_bytes(message).media_type().to_string();
        let size = message.len();
        if size > EVENT_MAX_MESSAGE_SIZE {
            return Err(FrostProtocolError::MessageTooBig.into());
        }

        let contents_hash = Blake3HashBytes::new(message);

        Ok(Self {
            timestamp: Tai64NTimestamp::now(),
            size,
            media_type,
            contents_hash,
        })
    }

    pub fn timestamp(&self) -> Tai64NTimestamp {
        self.timestamp
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn media_type(&self) -> &str {
        self.media_type.as_str()
    }

    pub fn encode(&self) -> Vec<u8> {
        bitcode::encode(self)
    }

    /// The blake3 hash of the entire contents of the message
    pub fn contents_hash(&self) -> Blake3HashBytes {
        self.contents_hash
    }

    pub fn decode(bytes: &[u8]) -> FrostOpsResult<Self> {
        bitcode::decode(bytes).or(Err(
            FrostOpsError::UnableToDecodeFrostSigningMessageMetadata,
        ))
    }

    /// timestamp.as_bytes() || size.to_le_bytes() || media_type.as_bytes() || Blake3 file contents hash
    pub fn hash(&self) -> Blake3HashBytes {
        let mut hasher = blake3::Hasher::new();
        hasher
            .update(self.timestamp.as_slice())
            .update(&self.size.to_le_bytes())
            .update(self.media_type().as_bytes())
            .update(self.contents_hash.as_bytes());

        Blake3HashBytes::pre_hashed(hasher.finalize())
    }
}

impl Default for FrostSigningMessageMetadata {
    fn default() -> Self {
        Self {
            timestamp: Tai64NTimestamp::now(),
            size: b"Hello World".len(),
            media_type: "application/text".to_string(),
            contents_hash: Blake3HashBytes::default(),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode)]
pub struct FrostMessageSigners(pub Vec<FrostCredentialSeed>);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode)]
pub struct FrostSigningEventInfo {
    pub sld_tld: SldTld,
    pub event: FrostSigningEvent,
    pub commitments: Option<FrostSigningCommitmentsBytes>,
    pub nonces: Option<FrostSigningNoncesBytes>,
    pub signature_share: Option<FrostSignatureShareBytes>,
    pub signing_package: Option<FrostSigningPackageBytes>,
    pub signature: Option<FrostSignatureBytes>,
    pub latest_timestamp: Tai64NTimestamp,
    pub valid_signers: Vec<FrostCredentialSeed>,
}

impl FrostSigningEventInfo {
    pub fn to_storage_key(&self) -> [u8; Tai64N::BYTE_SIZE + blake3::OUT_LEN] {
        let mut buffer = [0u8; Tai64N::BYTE_SIZE + blake3::OUT_LEN];
        buffer[..blake3::OUT_LEN].copy_from_slice(self.sld_tld.to_storage_key().as_bytes());
        buffer[blake3::OUT_LEN..].copy_from_slice(self.event.get_timestamp().as_bytes());

        buffer
    }
}

// Not that the threshold is fetched from the internal `KeyPackage` for credibility and correctness
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode)]
pub struct FrostSigningEvent {
    // When the signal was created
    timestamp: Tai64NTimestamp,
    state: FrostSigningEventState,
    origin: FrostSigningMessageOrigin,
    metadata: FrostSigningMessageMetadata,
    accepted: Vec<SignalAcknowledgement>,
    rejected: Vec<SignalAcknowledgement>,
    signers: FrostMessageSigners,
    event_hash: FrostEventHash,
    compiled_at: Tai64NTimestamp,
    sld_tld: SldTld,
}

impl FrostSigningEvent {
    /// Signers are always checked for duplicates and sorted
    /// since the `accepted` and `rejected` fields index the user to fetch
    /// the user credential. Sorting also ensures the outcome of the hash is the
    /// same for all signers
    pub fn new(mut signers: FrostMessageSigners, sld_tld: SldTld) -> FrostOpsResult<Self> {
        signers.0.dedup();
        signers.0.sort();

        let new_self = Self {
            timestamp: Tai64NTimestamp::now(),
            metadata: FrostSigningMessageMetadata::default(),
            state: FrostSigningEventState::Signal,
            origin: FrostSigningMessageOrigin::Relay,
            accepted: Vec::default(),
            rejected: Vec::default(),
            signers,
            event_hash: FrostEventHash::default(),
            compiled_at: Tai64NTimestamp::new_epoch(),
            sld_tld,
        };

        Ok(new_self.set_event_hash())
    }

    /// Events are stored by their keys for ordering
    pub fn to_storage_key(&self) -> FrostSigningEventKey {
        let mut buffer = [0u8; FROST_SIGNING_KEY_LEN];
        let sld_tld_hash = self.sld_tld.to_storage_key();

        buffer[..32].copy_from_slice(sld_tld_hash.as_bytes());
        buffer[32..].copy_from_slice(self.timestamp.as_bytes());

        buffer.into()
    }

    pub fn add_metadata(
        mut self,
        message: impl AsRef<[u8]> + Encode + Decode<'static>,
    ) -> FrostOpsResult<Self> {
        self.metadata = FrostSigningMessageMetadata::new(message)?;

        Ok(self)
    }

    pub fn add_signer(mut self, signers: FrostCredentialSeed) -> Self {
        self.signers.0.push(signers);
        self.signers.0.dedup();
        self.signers.0.sort();

        self
    }

    pub fn signers(&self) -> &FrostMessageSigners {
        &self.signers
    }

    pub fn is_valid_signer(&self, signer: &FrostCredentialSeed) -> bool {
        self.signers
            .0
            .iter()
            .any(|stored_signer| stored_signer == signer)
    }

    /// Used by signers to validate that the messages and signers
    /// forwarded by the relay to each is the same.
    ///
    /// signal timestamp.as_bytes() || metadata.hash() || origin.hash_preimage() ||
    /// || signers (sorted credential type+seed)
    pub fn event_hash(&self) -> FrostEventHash {
        let mut hasher = blake3::Hasher::new();
        hasher
            .update(self.timestamp.as_bytes())
            .update(self.metadata.hash().as_bytes())
            .update(&self.origin.hash_preimage());
        self.signers.0.iter().for_each(|credential| {
            hasher.update(credential.as_bytes());
        });

        FrostEventHash::pre_hashed(hasher.finalize())
    }

    pub fn set_event_hash(mut self) -> Self {
        let hash = self.event_hash();

        self.event_hash = hash;

        self
    }

    pub fn add_accepted(&mut self, received_ack: SignalAcknowledgement) -> &mut Self {
        self.accepted.push(received_ack);

        self
    }

    pub fn add_rejected(&mut self, received_ack: SignalAcknowledgement) -> &mut Self {
        self.rejected.push(received_ack);

        self
    }

    /// This is the timestamp that the relay server compiled all decision.
    pub fn set_compiled_at(&mut self, timestamp: Tai64NTimestamp) -> &mut Self {
        self.compiled_at = timestamp;

        self
    }

    pub fn get_timestamp(&self) -> Tai64NTimestamp {
        self.timestamp
    }

    /// Note that if timestamp is Unix epoch then the
    /// it should be treated that the server never compiled the acks
    pub fn compiled_at(&self) -> Tai64NTimestamp {
        self.compiled_at
    }

    pub fn get_origin(&self) -> FrostSigningMessageOrigin {
        self.origin
    }

    pub fn metadata(&self) -> &FrostSigningMessageMetadata {
        &self.metadata
    }

    pub fn accepted(&self) -> &[SignalAcknowledgement] {
        self.accepted.as_slice()
    }

    pub fn rejected(&self) -> &[SignalAcknowledgement] {
        self.rejected.as_slice()
    }

    pub fn get_state(&self) -> FrostSigningEventState {
        self.state
    }

    pub fn modify_state(&mut self, state: FrostSigningEventState) -> &mut Self {
        self.state = state;

        self
    }
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash, Encode, Decode)]
pub enum FrostSigningEventState {
    #[default]
    Signal,
    Rejected,
    Round2,
    Aggregate,
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode)]
pub struct ReceivedEventAcks {
    pub compiled_at: Tai64NTimestamp,
    pub state: FrostSigningEventState,
    pub sld_tld: Blake3HashBytes,
    pub store_key: FrostSigningEventKey,
    pub acks: Vec<SignalAcknowledgement>,
}

impl ReceivedEventAcks {
    pub fn sort_and_dedup(&mut self) -> &mut Self {
        self.acks.dedup();
        self.acks.sort();

        self
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode)]
pub struct TransmitFrostRound2 {
    pub credential: FrostCredentialSeed,
    pub timestamp: Tai64NTimestamp,
    pub signature_share: FrostSignatureShareBytes,
    pub event_hash: FrostEventHash,
    pub binding_hash: Blake3HashBytes,
    pub binding_signature: AsymmetricSignatureBytes,
}

impl TransmitFrostRound2 {
    pub fn binding_hash(&self) -> Blake3HashBytes {
        let mut hasher = Hasher::new();

        hasher
            .update(self.credential.as_bytes())
            .update(self.timestamp.as_slice())
            .update(&bitcode::encode(&self.signature_share))
            .update(self.event_hash.as_bytes());

        Blake3HashBytes::pre_hashed(hasher.finalize())
    }

    pub fn set_binding_hash(mut self) -> Self {
        self.binding_hash = self.binding_hash();

        self
    }

    pub fn sign(mut self, akp: AsymmetricKeypairBytes) -> FrostOpsResult<Self> {
        let signature = akp.sign_and_return_encodable(self.binding_hash.as_bytes())?;

        self.binding_signature = signature;

        Ok(self)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode)]
pub struct FinalizedSigningEvent {
    pub sld_tld_hash: Blake3HashBytes,
    pub timestamp: Tai64NTimestamp,
    pub event_hash: FrostEventHash,
    pub credential: FrostCredentialSeed,
    pub binding_hash: Blake3HashBytes,
    pub binding_signature: AsymmetricSignatureBytes,
}

// TODO Generating the binding hash and signing is a common operation therefore use a trait to simplify this
impl FinalizedSigningEvent {
    pub fn binding_hash(&self) -> Blake3HashBytes {
        let mut hasher = blake3::Hasher::new();

        hasher
            .update(self.sld_tld_hash.as_bytes())
            .update(self.timestamp.as_slice())
            .update(self.event_hash.as_bytes())
            .update(self.credential.as_bytes());

        Blake3HashBytes::pre_hashed(hasher.finalize())
    }

    pub fn set_binding_hash(mut self) -> Self {
        self.binding_hash = self.binding_hash();

        self
    }

    pub fn sign(mut self, akp: AsymmetricKeypairBytes) -> FrostOpsResult<Self> {
        let signature = akp.sign_and_return_encodable(self.binding_hash.as_bytes())?;

        self.binding_signature = signature;

        Ok(self)
    }
}
