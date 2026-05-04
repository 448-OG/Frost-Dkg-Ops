// use bitcode::{Decode, Encode};
// use file_format::FileFormat;
// use zeroize::Zeroize;

// use crate::{
//     Blake3HashBytes, FrostCredentialSeed, FrostOpsError, FrostOpsResult, FrostProtocolError,
//     FrostSigningCommitmentsBytes, Tai64NTimestamp,
// };

// pub type FrostMessageHash = Blake3HashBytes;

// #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize)]
// pub enum FrostSigningMessageOrigin {
//     Participant(u16),
//     Relay,
// }

// #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode)]
// pub struct FrostSigningMessageMetadata {
//     timestamp: Tai64NTimestamp,
//     size: usize,
//     mime: String,
// }

// impl FrostSigningMessageMetadata {
//     pub fn new(message: impl AsRef<[u8]> + Encode + Decode<'static>) -> FrostOpsResult<Self> {
//         let message = message.as_ref();

//         let mime = FileFormat::from_bytes(message).media_type().to_string();
//         let size = message.len();
//         if size > 1024 * 1024 {
//             return Err(FrostProtocolError::MessageTooBig.into());
//         }

//         Ok(Self {
//             timestamp: Tai64NTimestamp::now(),
//             size,
//             mime,
//         })
//     }

//     pub fn timestamp(&self) -> Tai64NTimestamp {
//         self.timestamp
//     }

//     pub fn size(&self) -> usize {
//         self.size
//     }

//     pub fn mime(&self) -> &str {
//         self.mime.as_str()
//     }

//     pub fn encode(&self) -> Vec<u8> {
//         bitcode::encode(self)
//     }

//     pub fn decode(bytes: &[u8]) -> FrostOpsResult<Self> {
//         bitcode::decode(bytes).or(Err(
//             FrostOpsError::UnableToDecodeFrostSigningMessageMetadata,
//         ))
//     }
// }

// impl Default for FrostSigningMessageMetadata {
//     fn default() -> Self {
//         Self {
//             timestamp: Tai64NTimestamp::now(),
//             size: b"Hello World".len(),
//             mime: "application/text".to_string(),
//         }
//     }
// }

// #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode)]
// pub struct FrostSigningEvent {
//     threshold: u16,
//     state: FrostSigningEventState,
//     origin: FrostSigningMessageOrigin,
//     metadata: FrostSigningMessageMetadata,
//     accepted: Vec<SignerDecision>,
//     rejected: Vec<SignerDecision>,
//     signers: Vec<FrostCredentialSeed>,
// }

// impl FrostSigningEvent {
//     /// Signers are always checked for duplicates and sorted
//     /// since the `accepted` and `rejected` fields index the user to fetch
//     /// the user credential
//     pub fn new(mut signers: Vec<FrostCredentialSeed>) -> FrostOpsResult<Self> {
//         signers.dedup();
//         signers.sort();

//         let new_self = Self {
//             threshold: 2,
//             metadata: FrostSigningMessageMetadata::default(),
//             state: FrostSigningEventState::Signal,
//             origin: FrostSigningMessageOrigin::Relay,
//             accepted: Vec::default(),
//             rejected: Vec::default(),
//             signers,
//             hash: FrostMessageHash::default(),
//         };

//         Ok(new_self)
//     }

//     pub fn add_message(
//         mut self,
//         message: impl AsRef<[u8]> + Encode + Decode<'static>,
//     ) -> FrostOpsResult<Self> {
//         self.metadata = FrostSigningMessageMetadata::new(message)?;

//         Ok(self)
//     }

//     pub fn add_signer(mut self, signers: FrostCredentialSeed) -> Self {
//         self.signers.push(signers);
//         self.signers.dedup();
//         self.signers.sort();

//         self
//     }

//     pub fn signers(&self) -> &[FrostCredentialSeed] {
//         self.signers.as_slice()
//     }

//     pub fn is_valid_signer(&self, signer: &FrostCredentialSeed) -> bool {
//         self.signers
//             .iter()
//             .any(|stored_signer| stored_signer == signer)
//     }

//     pub fn check_signer_capacity(&self) -> FrostOpsResult<&Self> {
//         if self.signers.len() < 2 {
//             return Err(FrostProtocolError::MinimumSignersMustBe2OrMore.into());
//         }

//         Ok(self)
//     }

//     pub fn validate(&self) -> FrostOpsResult<&Self> {
//         self.check_signer_capacity()?;

//         Ok(self)
//     }

//     /// Used by signers to validate that the messages and signers
//     /// forwarded by the relay to each is the same.
//     /// origin || metadata || signers
//     pub fn message_hash(&self) {

//         //     state: FrostSigningEventState,
//         // origin: FrostSigningMessageOrigin,
//         // metadata: FrostSigningMessageMetadata,
//         // accepted: Vec<SignerDecision>,
//         // rejected: Vec<(u16, Tai64NTimestamp, Mess)>,
//         // signers: Vec<FrostCredentialSeed>,
//     }

//     pub fn hash(&self) -> FrostMessageHash {
//         self.hash
//     }
// }

// #[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode)]
// pub struct SignerDecision {
//     signer_index: usize,
//     timestamp: Tai64NTimestamp,
//     note: Option<String>,
// }

// impl SignerDecision {
//     pub fn new(
//         my_credential_seed: &FrostCredentialSeed,
//         signers: &[FrostCredentialSeed],
//     ) -> FrostOpsResult<Self> {
//         let signer_index =
//             signers
//                 .binary_search(my_credential_seed)
//                 .or(Err(FrostOpsError::SignerNotFound(
//                     my_credential_seed.seed().to_string(),
//                 )))?;

//         Ok(Self {
//             signer_index,
//             timestamp: Tai64NTimestamp::now(),
//             note: Option::default(),
//         })
//     }

//     pub fn add_note(mut self, note: &str) -> Self {
//         self.note.replace(note.to_string());
//         self.timestamp = Tai64NTimestamp::now();

//         self
//     }

//     pub fn signer_index(&self) -> usize {
//         self.signer_index
//     }

//     pub fn timestamp(&self) -> Tai64NTimestamp {
//         self.timestamp
//     }

//     pub fn note(&self) -> Option<&String> {
//         self.note.as_ref()
//     }

//     /// metadata hash || Signer Index (to_le_bytes()) || TAI64N timestamp bytes || Note if exists (as bytes)
//     pub fn hash(&self, metadata_hash: Blake3HashBytes) -> Blake3HashBytes {
//         let mut hasher = blake3::Hasher::new();

//         hasher.update(metadata_hash.as_bytes());
//         hasher.update(self.signer_index.to_le_bytes().as_slice());
//         hasher.update(self.timestamp().as_slice());
//         if let Some(note) = self.note() {
//             hasher.update(note.as_bytes());
//         }

//         Blake3HashBytes::pre_hashed(hasher.finalize())
//     }
// }

// #[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash, Encode, Decode)]
// pub enum FrostSigningEventState {
//     #[default]
//     Signal,
//     Processing,
//     Accepted,
//     Rejected,
//     Round1,
//     Round2,
//     Aggregate,
// }
