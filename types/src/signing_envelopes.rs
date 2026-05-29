use bitcode::{Decode, Encode};

use crate::{
    AsymmetricKeypairBytes, AsymmetricSignatureBytes, Blake3HashBytes, FrostCredentialSeed,
    FrostEventHash, FrostOpsResult, FrostSigningCommitmentsBytes, FrostSigningEventKey, SldTld,
    Tai64NTimestamp, TransmitFrostRound2,
};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode)]
pub struct SignalAcknowledgement {
    // Timestamp the sender sent the message
    timestamp: Tai64NTimestamp,
    // This must be the hash derived using the method in SLD-TLD type
    // for efficiency in case the organization has bytes exceeding
    // 32 bytes
    sld_tld_hash: Blake3HashBytes,
    // Even though the signer seed can be found in the index of the event
    // in case a server was malicious and didn't include this participant's seed
    // this would fail hence duplication here is necessary
    signer: FrostCredentialSeed,
    // Accepted is `Some(round1 signing Commitments)`, declined is `Option::None`
    accepted: Option<FrostSigningCommitmentsBytes>,
    // The message hash of the `FrostSigningEvent` that is being acknowledged
    event_hash: FrostEventHash,
    notes: Vec<String>,
    binding_hash: Blake3HashBytes,
    signature: AsymmetricSignatureBytes,
}

impl SignalAcknowledgement {
    pub fn new(signer: FrostCredentialSeed) -> Self {
        Self {
            timestamp: Tai64NTimestamp::now(),
            sld_tld_hash: SldTld::default().to_storage_key(),
            signer,
            accepted: Option::default(),
            event_hash: FrostEventHash::default(),
            notes: Vec::default(),
            binding_hash: Blake3HashBytes::default(),
            signature: AsymmetricSignatureBytes::default(),
        }
    }

    pub fn add_note(mut self, note: &str) -> Self {
        self.notes.push(note.to_string());

        self
    }

    pub fn add_notes(mut self, notes: &[String]) -> Self {
        self.notes.extend_from_slice(notes);

        self
    }

    pub fn set_accepted(mut self, commitments: FrostSigningCommitmentsBytes) -> Self {
        self.accepted.replace(commitments);

        self
    }

    /// The default value is false, this method just makes sure the value is Option::None
    pub fn set_rejected(mut self) -> Self {
        self.accepted.take();

        self
    }

    pub fn set_event_hash(mut self, event_hash: FrostEventHash) -> Self {
        self.event_hash = event_hash;

        self
    }

    pub fn set_sld_tld(mut self, sld_tld: Blake3HashBytes) -> Self {
        self.sld_tld_hash = sld_tld;

        self
    }

    pub fn event_hash(&self) -> FrostEventHash {
        self.event_hash
    }

    pub fn signer(&self) -> &FrostCredentialSeed {
        &self.signer
    }

    pub fn sld_tld_hash(&self) -> Blake3HashBytes {
        self.sld_tld_hash
    }

    pub fn signature(&self) -> AsymmetricSignatureBytes {
        self.signature
    }

    pub fn timestamp(&self) -> Tai64NTimestamp {
        self.timestamp
    }

    pub fn binding_hash(&self) -> Blake3HashBytes {
        self.binding_hash
    }

    pub fn accepted(&self) -> Option<&FrostSigningCommitmentsBytes> {
        self.accepted.as_ref()
    }

    pub fn notes(&self) -> &[String] {
        self.notes.as_slice()
    }

    pub fn notes_tale(self) -> Vec<String> {
        self.notes
    }

    /// ```text
    /// TaiTimestamp.as_bytes || SLD-TLD hash.as_bytes() || signer.as_bytes() ||
    /// if accepted.is_some() encode value as bytes || event_hash.as_bytes() ||
    /// notes.iter().for_each(note.as_bytes)
    /// ```
    pub fn hash(&self) -> Blake3HashBytes {
        let mut hasher = blake3::Hasher::new();

        hasher.update(self.timestamp().as_bytes());
        hasher.update(self.sld_tld_hash.as_bytes());
        hasher.update(self.signer.as_bytes());
        if let Some(value) = self.accepted.as_ref() {
            hasher.update(&value.encode());
        }
        hasher.update(self.event_hash.as_bytes());
        self.notes().iter().for_each(|note| {
            hasher.update(note.as_bytes());
        });

        Blake3HashBytes::pre_hashed(hasher.finalize())
    }

    /// Signs the binding hash
    pub fn build(mut self, apk: AsymmetricKeypairBytes) -> FrostOpsResult<Self> {
        self.timestamp = Tai64NTimestamp::now(); // Update timestamp
        self.binding_hash = self.hash();

        let signature = apk.sign_and_return_encodable(self.binding_hash)?;
        self.signature = signature;

        Ok(self)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode)]
pub struct ReceivedSignatureShares {
    pub compiled_at: Tai64NTimestamp,
    pub event_key: FrostSigningEventKey,
    pub shares: Vec<TransmitFrostRound2>,
}
