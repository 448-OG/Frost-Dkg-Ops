use bitcode::{Decode, Encode};

use crate::FrostDkgState;
use crate::FrostSigningEventState;
use crate::TransmitType;

pub type FrostOpsResult<T> = Result<T, FrostOpsError>;

#[derive(Debug, PartialEq, thiserror::Error, Clone, Encode, Decode)]
pub enum FrostOpsError {
    #[error("Skip adding an event because it was never received as a signal in the first place")]
    SkipFrostSigningEvent,
    #[error(
        "Unable to generate randomness from the OS. This error is fatal and computing should not continue until this is fixed!"
    )]
    BadRandomness,
    #[error("The SLD-TLD has not been set")]
    SldTldNotFound,
    #[error(
        "The organization domain is not a valid domain. It must be contain only the second level domain and top level domain"
    )]
    InvalidSldTld,
    #[error(
        "The username, email, random hex or identifier to use as the FROST Credential seed is invalid. It must be at least 3 characters long"
    )]
    InvalidFrostCredentialSeed,
    #[error(
        "The received envelope was meant for the current recipient and processing it has been rejected"
    )]
    InvalidRecipient,
    #[error("The email address is invalid")]
    InvalidEmailAddress,
    #[error(
        "The server requires the email address to belong to the organization but the username `{0}` is a full email address instead of just the username"
    )]
    InvalidUsernameForStrictEmailConfig(String),
    #[error(
        "The server requires the email address to belong to the organization but the username was okay but SLD/TLD or both was incorrect: `{0}`"
    )]
    InvalidDomainSldTldForEmail(String),
    #[error("The FROST credential details have not been set")]
    FrostCredentialNotSet,
    #[error("The Ephemeral Client Device Keypair has not been set")]
    EcdkNotFound,
    #[error(
        "The number of envelopes received from the relay exceeds the maximum number of participants in the channel"
    )]
    InvalidNumOfParticipants,
    #[error("The participant is not part of the group")]
    InvalidParticipant,
    #[error("FROST error: {0}")]
    FrostProtocol(FrostProtocolError),
    #[cfg(feature = "client_storage")]
    #[error("FROST error: {0}")]
    Storage(FrostClientStorageError),
    #[error("Unable to serialize HPKE secret key")]
    UnableToSerializeHpkeSecretKey,
    #[error("Unable to deserialize HPKE secret key")]
    UnableToDeserializeHpkeSecretKey,
    #[error("The ephemeral device static verifying key is invalid")]
    InvalidEphemeralDeviceStaticVerifyingKey,
    #[error("The ephemeral device HPKE ephemeral verifying key is missing")]
    MissingEphemeralHeVerifyingKey,
    #[error("Invalid Tai64N bytes")]
    Tai64NTimestampBytes,
    #[error(
        "The relay transmitted a payload that is not round1 DKG yet only Round1 DKG payloads are accepted by the query"
    )]
    InvalidFrostEnvelopePayloadForRound1,
    #[error("Minimum and Maximum participants not set!")]
    MinMaxNotSet,
    #[error("The relay sent too many Round1 packages. Aborting adding received round1 packages")]
    RelayRound1TooManyPackages,
    #[error("{0}")]
    EphemeralDeviceKeys(InnerHpkeError),
    #[error("Unable to decode `FrostEnvelopePayload` from bytes.")]
    DecodeFrostEnvelopePayload,
    #[error(
        "The current state is invalid; expected state is `{expected:?}` but current state is `{current:?}`"
    )]
    InvalidClientState {
        current: FrostDkgState,
        expected: FrostDkgState,
    },
    #[error("The binding hash is not 32 bytes long")]
    BindingHashNot32Bytes,
    #[error("The hash that the server sent is not equal to the hash of the decrypted payload")]
    BindingHashMismatch,
    #[error("Invalid transmission type! Expected `{expected:?} but got `{current:?}`")]
    InvalidTransmission {
        expected: TransmitType,
        current: TransmitType,
    },
    #[error(
        "The payload expected for a HPKE requires only the sender static key be valid and every other field should be empty"
    )]
    InvalidPayloadForEmptyEnvelope,
    #[error("The round1 package bytes received are invalid!")]
    InvalidRound1PackageBytes,
    #[error("The round2 package bytes to decode invalid!")]
    InvalidRound2PackageBytes,
    #[error("Unable to map the frost_core::Identifier to a FrostCredentialSeed. Culprit: `{0}`")]
    UnableToGetTheIdentifierMapping(String),
    #[error(
        "The FROST message to sign metadata is corrupted. Unable to decode bytes to `FrostSigningMessageMetadata`."
    )]
    UnableToDecodeFrostSigningMessageMetadata,
    #[error(
        "The `FrostCredentialSeed` for participant `{0}` was not found in the list of signers, you need to add the `FrostCredentialSeed` when signaling to participants to sign a message"
    )]
    SignerNotFound(String),
    #[error("Unable to sign the payload")]
    UnableToSignPayload,
    #[error("Unable to convert the bytes into the `AsymmetricVerifyingKey`")]
    InvalidAsymmetricVerifyingKeyBytes,
    #[error("The number of signers must be 2 or more")]
    InvalidNumOfSigners,
    #[error(
        "The number of signers is greater than the number of registered participants in finalized DKG state"
    )]
    SignersAreMoreThanMaximumFinalizedDkgParticipants,
    #[error("{0}'s verifying key is corrupted. The storage is probably corrupted!")]
    AsymmetricVerifyingKeyBytesNotFound(String),
    #[error(
        "The current state is `{current_state:?}` while expected state is `{expected_state:?}`"
    )]
    InvalidSigningState {
        current_state: FrostSigningEventState,
        expected_state: FrostSigningEventState,
    },
    #[error(
        "The received round2 shares compiled_at timestamp must be later than the signal operation timestamps"
    )]
    InvalidRound2SigningTimestamp,
    #[error("The threshold is `{threshold}` but the valid signers are only `{num_of_signers}`")]
    InvalidThresholdEncounteredInRound2 { threshold: u16, num_of_signers: u16 },
    #[error(
        "Too many participants received. Protocol maximum is `{max}` but number of participants are `{current}`"
    )]
    TooManyParticipants { max: u16, current: usize },
    #[error(
        "Too many signers. Protocol maximum is `{max}` but number of participants are `{num_of_signers}`"
    )]
    TooManySigners { max: usize, num_of_signers: usize },
    #[error(
        "Insufficient signers. Protocol threshold is `{threshold}` but number of participants are `{num_of_signers}`"
    )]
    InsufficientSigners {
        threshold: u16,
        num_of_signers: usize,
    },
    #[error("FROST Signing nonces were required but none were found in storage")]
    FrostSigningNoncesNotFound,
    #[error("FROST Signing package was required but not found in storage")]
    FrostSigningPackageNotFound,
}

#[derive(Debug, PartialEq, thiserror::Error, Clone, Encode, Decode)]
pub enum InnerHpkeError {
    /// Error opening an HPKE ciphertext.
    #[error("Error opening an HPKE ciphertext.")]
    OpenError,

    /// Invalid configuration or arguments.
    #[error("Invalid configuration or arguments.")]
    InvalidConfig,

    /// Invalid input.
    #[error("Invalid input.")]
    InvalidInput,

    /// Unknown HPKE mode.
    #[error("Unknown HPKE mode.")]
    UnknownMode,

    /// Inconsistent PSK input.
    #[error("Inconsistent PSK input.")]
    InconsistentPsk,

    /// PSK input is required but missing.
    #[error("PSK input is required but missing.")]
    MissingPsk,

    /// PSK input is provided but not needed.
    #[error("PSK input is provided but not needed.")]
    UnnecessaryPsk,

    /// PSK input is too short (needs to be at least 32 bytes).
    #[error("PSK input is too short (needs to be at least 32 bytes).")]
    InsecurePsk,

    /// An error in the crypto library occurred.
    #[error("An error in the crypto library occurred. Error: {0}")]
    CryptoError(String),

    /// The message limit for this AEAD, key, and nonce.
    #[error("The message limit for this AEAD, key, and nonce.")]
    MessageLimitReached,

    /// Unable to collect enough randomness.
    #[error("Unable to collect enough randomness.")]
    InsufficientRandomness,
}

impl From<hpke_rs::HpkeError> for FrostOpsError {
    fn from(value: hpke_rs::HpkeError) -> Self {
        let error = match value {
            hpke_rs::HpkeError::OpenError => InnerHpkeError::OpenError,
            hpke_rs::HpkeError::InvalidConfig => InnerHpkeError::InvalidConfig,
            hpke_rs::HpkeError::InvalidInput => InnerHpkeError::InvalidInput,
            hpke_rs::HpkeError::UnknownMode => InnerHpkeError::UnknownMode,
            hpke_rs::HpkeError::InconsistentPsk => InnerHpkeError::InconsistentPsk,
            hpke_rs::HpkeError::MissingPsk => InnerHpkeError::MissingPsk,
            hpke_rs::HpkeError::UnnecessaryPsk => InnerHpkeError::UnnecessaryPsk,
            hpke_rs::HpkeError::InsecurePsk => InnerHpkeError::InsecurePsk,
            hpke_rs::HpkeError::CryptoError(inner_value) => {
                InnerHpkeError::CryptoError(inner_value)
            }
            hpke_rs::HpkeError::MessageLimitReached => InnerHpkeError::MessageLimitReached,
            hpke_rs::HpkeError::InsufficientRandomness => InnerHpkeError::InsufficientRandomness,
        };

        Self::EphemeralDeviceKeys(error)
    }
}

impl From<tai64::Error> for FrostOpsError {
    fn from(_: tai64::Error) -> Self {
        Self::Tai64NTimestampBytes
    }
}

#[cfg(feature = "client_storage")]
#[derive(Debug, PartialEq, Eq, thiserror::Error, Clone, Encode, Decode)]
pub enum FrostClientStorageError {
    #[error("Tried to insert a key that already exists")]
    KeyAlreadyExists,
    #[error("Tried to update a value but it's key was not found in the store")]
    KeyToUpdateNotFound,
    #[error("The Database is already open. Cannot acquire lock.")]
    DatabaseAlreadyOpen,
    #[error(
        "This savepoint is invalid or cannot be created. Savepoints become invalid when an older savepoint is restored after it was created, and savepoints cannot be created if the transaction is “dirty” (any tables have been opened)"
    )]
    InvalidSavepoint,
    #[error("`redb::RepairSession::abort` was called.")]
    RepairAborted,
    #[error("A persistent savepoint was modified")]
    PersistentSavepointModified,
    #[error("A persistent savepoint exists")]
    PersistentSavepointExists,
    #[error("An Ephemeral savepoint exists")]
    EphemeralSavepointExists,
    #[error("A transaction is still in-progress")]
    TransactionInProgress,
    #[error("The Database is corrupted. Error: `{0}`!")]
    Corrupted(String),
    #[error("The database file is in an old file format `{0}` and must be manually upgraded")]
    UpgradeRequired(u8),
    #[error("The value being inserted exceeds the maximum of 3GiB. Error: `{0}`!")]
    ValueTooLarge(usize),
    #[error("Table types didn’t match. Table: `{table}` - key: `{key}` - value: `{value}`!")]
    TableTypeMismatch {
        table: String,
        key: String,
        value: String,
    },
    #[error("The table is a multimap table. Error: `{0}`!")]
    TableIsMultimap(String),
    #[error("The table is not a multimap table. Error: `{0}`!")]
    TableIsNotMultimap(String),
    #[error("name: `{name}` - alignment: `{alignment}` - width: `{width:?}`")]
    TypeDefinitionChanged {
        name: String,
        alignment: usize,
        width: Option<usize>,
    },
    #[error("Table name does not match any table in database. Error: `{0}`!")]
    TableDoesNotExist(String),
    #[error("Table name already exists in the database. Error: `{0}`!")]
    TableExists(String),
    #[error("`{0}` - `{1}`")]
    TableAlreadyOpen(String, String),
    #[error("I/O error: `{}`", format!("{:?}", .0))]
    Io(CustomErrorKind),
    #[error("Database is already closed")]
    DatabaseClosed,
    #[error("A previous IO error occurred. The database must be closed and re-opened")]
    PreviousIo,
    #[error("Lock poisoned. Error: `{0}`!")]
    LockPoisoned(String),
    #[error("The transaction is still referenced by a table or other object")]
    ReadTransactionStillInUse,
    #[error("`non_exhaustive` reached!`")]
    Fatal,
}

#[cfg(feature = "client_storage")]
impl From<redb::Error> for FrostOpsError {
    fn from(value: redb::Error) -> Self {
        Self::Storage(value.into())
    }
}

#[cfg(feature = "client_storage")]
impl From<redb::TableError> for FrostOpsError {
    fn from(value: redb::TableError) -> Self {
        let value: redb::Error = value.into();
        Self::Storage(value.into())
    }
}

#[cfg(feature = "client_storage")]
impl From<redb::TransactionError> for FrostOpsError {
    fn from(value: redb::TransactionError) -> Self {
        let value: redb::Error = value.into();
        Self::Storage(value.into())
    }
}

#[cfg(feature = "client_storage")]
impl From<redb::StorageError> for FrostOpsError {
    fn from(value: redb::StorageError) -> Self {
        let value: redb::Error = value.into();
        Self::Storage(value.into())
    }
}

#[cfg(feature = "client_storage")]
impl From<redb::CommitError> for FrostOpsError {
    fn from(value: redb::CommitError) -> Self {
        let value: redb::Error = value.into();
        Self::Storage(value.into())
    }
}

#[cfg(feature = "client_storage")]
impl From<redb::Error> for FrostClientStorageError {
    fn from(value: redb::Error) -> Self {
        match value {
            redb::Error::DatabaseAlreadyOpen => Self::DatabaseAlreadyOpen,
            redb::Error::InvalidSavepoint => Self::InvalidSavepoint,
            redb::Error::RepairAborted => Self::RepairAborted,
            redb::Error::PersistentSavepointModified => Self::PersistentSavepointModified,
            redb::Error::PersistentSavepointExists => Self::PersistentSavepointExists,
            redb::Error::EphemeralSavepointExists => Self::EphemeralSavepointExists,
            redb::Error::TransactionInProgress => Self::TransactionInProgress,
            redb::Error::Corrupted(value) => Self::Corrupted(value),
            redb::Error::UpgradeRequired(value) => Self::UpgradeRequired(value),
            redb::Error::ValueTooLarge(value) => Self::ValueTooLarge(value),
            redb::Error::TableTypeMismatch { table, key, value } => Self::TableTypeMismatch {
                table,
                key: key.name().to_string(),
                value: value.name().to_string(),
            },
            redb::Error::TableIsMultimap(value) => Self::TableIsMultimap(value),
            redb::Error::TableIsNotMultimap(value) => Self::TableIsNotMultimap(value),
            redb::Error::TypeDefinitionChanged {
                name,
                alignment,
                width,
            } => Self::TypeDefinitionChanged {
                name: name.name().to_string(),
                alignment,
                width,
            },
            redb::Error::TableDoesNotExist(value) => Self::TableDoesNotExist(value),
            redb::Error::TableExists(value) => Self::TableExists(value),
            redb::Error::TableAlreadyOpen(value1, value2) => {
                Self::TableAlreadyOpen(value1, value2.to_string())
            }
            redb::Error::Io(value) => {
                let value: CustomErrorKind = value.kind().into();

                Self::Io(value)
            }
            redb::Error::DatabaseClosed => Self::DatabaseClosed,
            redb::Error::PreviousIo => Self::PreviousIo,
            redb::Error::LockPoisoned(value) => Self::LockPoisoned(value.to_string()),
            redb::Error::ReadTransactionStillInUse(_) => Self::ReadTransactionStillInUse,
            _ => Self::Fatal,
        }
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error, Clone, Encode, Decode)]
pub enum FrostProtocolError {
    #[error("Unable to decode the  `FrostCredential` from bytes")]
    UnableToDecodeFrostCredential,
    /// min_signers is invalid
    #[error("min_signers must be at least 2 and not larger than max_signers")]
    InvalidMinSigners,
    /// max_signers is invalid
    #[error("max_signers must be at least 2")]
    InvalidMaxSigners,
    /// max_signers is invalid
    #[error("coefficients must have min_signers-1 elements")]
    InvalidCoefficients,
    /// This identifier is unserializable.
    #[error("Malformed identifier is unserializable.")]
    MalformedIdentifier,
    /// This identifier is duplicated.
    #[error("Duplicated identifier.")]
    DuplicatedIdentifier,
    /// This identifier does not belong to a participant in the signing process.
    #[error("Unknown identifier.")]
    UnknownIdentifier,
    /// Incorrect number of identifiers.
    #[error("Incorrect number of identifiers.")]
    IncorrectNumberOfIdentifiers,
    /// The encoding of a signing key was malformed.
    #[error("Malformed signing key encoding.")]
    MalformedSigningKey,
    /// The encoding of a verifying key was malformed.
    #[error("Malformed verifying key encoding.")]
    MalformedVerifyingKey,
    /// The encoding of a signature was malformed.
    #[error("Malformed signature encoding.")]
    MalformedSignature,
    /// Signature verification failed.
    #[error("Invalid signature.")]
    InvalidSignature,
    /// Duplicated shares provided
    #[error("Duplicated shares provided.")]
    DuplicatedShares,
    /// Incorrect number of shares.
    #[error("Incorrect number of shares.")]
    IncorrectNumberOfShares,
    /// Commitment equals the identity
    #[error("Commitment equals the identity.")]
    IdentityCommitment,
    /// The participant's commitment is missing from the Signing Package
    #[error("The Signing Package must contain the participant's Commitment.")]
    MissingCommitment,
    /// The participant's commitment is incorrect
    #[error("The participant's commitment is incorrect.")]
    IncorrectCommitment,
    /// Incorrect number of commitments.
    #[error("Incorrect number of commitments.")]
    IncorrectNumberOfCommitments,
    /// Signature share verification failed.
    #[error("Invalid signature share. Culprits: {as_hexes:?}", as_hexes = .0.iter().map(|value| faster_hex::hex_string_upper(value)))]
    InvalidSignatureShare(Vec<Vec<u8>>),
    /// Secret share verification failed.
    /// The identifier of the signer whose secret share validation failed, if possible to identify.
    #[error("Invalid secret share. {} {as_hexes:?}", if !.0.is_empty() {" Culprits:"}else {""}, as_hexes =faster_hex::hex_string_upper(.0))]
    InvalidSecretShare(Vec<u8>),
    /// Round 1 package not found for Round 2 participant.
    #[error("Round 1 package not found for Round 2 participant.")]
    PackageNotFound,
    /// Incorrect number of packages.
    #[error("Incorrect number of packages.")]
    IncorrectNumberOfPackages,
    /// The incorrect package was specified.
    #[error("The incorrect package was specified.")]
    IncorrectPackage,
    /// The ciphersuite does not support DKG.
    #[error("The ciphersuite does not support DKG.")]
    DKGNotSupported,
    /// The proof of knowledge is not valid.
    #[error("The proof of knowledge is not valid. {}", faster_hex::hex_string_upper(.0))]
    InvalidProofOfKnowledge(Vec<u8>),
    /// Error in scalar Field.
    #[error("Error in scalar Field.")]
    FieldError(#[from] InnerFrostCoreFieldError),
    /// Error in elliptic curve Group.
    #[error("Error in elliptic curve Group.")]
    GroupError(#[from] InnerFrostCoreGroupError),
    /// Error in coefficient commitment deserialization.
    #[error("Invalid coefficient")]
    InvalidCoefficient,
    /// The ciphersuite does not support deriving identifiers from strings.
    #[error("The ciphersuite does not support deriving identifiers from strings.")]
    IdentifierDerivationNotSupported,
    /// Error serializing value.
    #[error("Error serializing value.")]
    SerializationError,
    /// Error deserializing value.
    #[error("Error deserializing value.")]
    DeserializationError,
    #[error("`non_exhaustive` was triggered. This is a critical bug!")]
    UnknownFrostError,
    #[error("Unable to Serialize Round 1 DKG Secret Package")]
    UnableToSerializedRound1DkgSecret,
    #[error("Unable to Deserialize Round 1 DKG Secret Package")]
    UnableToDeserializedRound1DkgSecret,
    #[error("The message is too big. Message limit is 1MiB to optimize for mobile networks")]
    MessageTooBig,
    #[error("The minimum signers supported is 2")]
    MinimumSignersMustBe2OrMore,
    #[error(
        "Round1 public package has not been set, cannot create round2 package without round1 public package"
    )]
    MissingRound1Package,
    #[error(
        "Round1 secret package has not been set, cannot create round2 package without round1 secret package"
    )]
    MissingRound1SecretPackage,
    #[error(
        "Unable to find the mapping of Frost Identifier to the HashMap of Credential Seeds. Culprit: {}",
        faster_hex::hex_string_upper(&.0)
    )]
    IdentifierToCredentialSeedMapping(Vec<u8>),
}

impl From<frost_core::FieldError> for FrostProtocolError {
    fn from(value: frost_core::FieldError) -> Self {
        let value = match value {
            frost_core::FieldError::MalformedScalar => InnerFrostCoreFieldError::MalformedScalar,
            frost_core::FieldError::InvalidZeroScalar => {
                InnerFrostCoreFieldError::InvalidZeroScalar
            }
            _ => InnerFrostCoreFieldError::InExhaustiveReached,
        };

        Self::FieldError(value)
    }
}

/// An error related to a scalar Field.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Copy, Clone, Eq, PartialEq, Encode, Decode)]
pub enum InnerFrostCoreFieldError {
    /// The encoding of a group scalar was malformed.
    #[error("Malformed scalar encoding.")]
    MalformedScalar,
    /// This scalar MUST NOT be zero.
    #[error("Invalid for this scalar to be zero.")]
    InvalidZeroScalar,
    #[error("InExhaustiveReached error reached for InnerFrostCoreFieldError")]
    InExhaustiveReached,
}

/// An error related to a Group (usually an elliptic curve or constructed from one) or one of its Elements.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Copy, Clone, Eq, PartialEq, Encode, Decode)]
pub enum InnerFrostCoreGroupError {
    /// The encoding of a group element was malformed.
    #[error("Malformed group element encoding.")]
    MalformedElement,
    /// This element MUST NOT be the identity.
    #[error("Invalid for this element to be the identity.")]
    InvalidIdentityElement,
    /// This element MUST have (large) prime order.
    #[error("Invalid for this element to not have large prime order.")]
    InvalidNonPrimeOrderElement,
    #[error("InExhaustiveReached error reached for InnerFrostCoreGroupError")]
    InExhaustiveReached,
}

impl From<frost_core::GroupError> for FrostProtocolError {
    fn from(value: frost_core::GroupError) -> Self {
        let value = match value {
            frost_core::GroupError::MalformedElement => InnerFrostCoreGroupError::MalformedElement,
            frost_core::GroupError::InvalidIdentityElement => {
                InnerFrostCoreGroupError::InvalidIdentityElement
            }
            frost_core::GroupError::InvalidNonPrimeOrderElement => {
                InnerFrostCoreGroupError::InvalidNonPrimeOrderElement
            }
            _ => InnerFrostCoreGroupError::InExhaustiveReached,
        };

        Self::GroupError(value)
    }
}

impl From<FrostProtocolError> for FrostOpsError {
    fn from(error: FrostProtocolError) -> Self {
        Self::FrostProtocol(error)
    }
}

impl<C: frost_core::Ciphersuite> From<frost_core::Error<C>> for FrostOpsError {
    fn from(value: frost_core::Error<C>) -> Self {
        Self::FrostProtocol(value.into())
    }
}

impl<C: frost_core::Ciphersuite> From<frost_core::Error<C>> for FrostProtocolError {
    fn from(value: frost_core::Error<C>) -> Self {
        use frost_core::Error as FrostError;

        match value {
            FrostError::InvalidMinSigners => Self::InvalidMinSigners,
            FrostError::InvalidMaxSigners => Self::InvalidMaxSigners,
            FrostError::InvalidCoefficients => Self::InvalidCoefficients,
            FrostError::MalformedIdentifier => Self::MalformedIdentifier,
            FrostError::DuplicatedIdentifier => Self::DuplicatedIdentifier,
            FrostError::UnknownIdentifier => Self::UnknownIdentifier,
            FrostError::IncorrectNumberOfIdentifiers => Self::IncorrectNumberOfIdentifiers,
            FrostError::MalformedSigningKey => Self::MalformedSigningKey,
            FrostError::MalformedVerifyingKey => Self::MalformedVerifyingKey,
            FrostError::MalformedSignature => Self::MalformedSignature,
            FrostError::InvalidSignature => Self::InvalidSignature,
            FrostError::DuplicatedShares => Self::DuplicatedShares,
            FrostError::IncorrectNumberOfShares => Self::IncorrectNumberOfShares,
            FrostError::IdentityCommitment => Self::IdentityCommitment,
            FrostError::MissingCommitment => Self::MissingCommitment,
            FrostError::IncorrectCommitment => Self::IncorrectCommitment,
            FrostError::IncorrectNumberOfCommitments => Self::IncorrectNumberOfCommitments,
            FrostError::InvalidSignatureShare { culprits } => Self::InvalidSignatureShare(
                culprits
                    .into_iter()
                    .map(|culprit| culprit.serialize())
                    .collect(),
            ),
            FrostError::InvalidSecretShare { culprit } => Self::InvalidSecretShare(
                culprit
                    .map(|culprit_exists| culprit_exists.serialize())
                    .unwrap_or_default(),
            ),
            FrostError::PackageNotFound => Self::PackageNotFound,
            FrostError::IncorrectNumberOfPackages => Self::IncorrectNumberOfPackages,
            FrostError::IncorrectPackage => Self::IncorrectPackage,
            FrostError::DKGNotSupported => Self::DKGNotSupported,
            FrostError::InvalidProofOfKnowledge { culprit } => {
                Self::InvalidProofOfKnowledge(culprit.serialize())
            }
            FrostError::FieldError(value) => value.into(),
            FrostError::GroupError(value) => value.into(),
            FrostError::InvalidCoefficient => Self::InvalidCoefficient,
            FrostError::IdentifierDerivationNotSupported => Self::IdentifierDerivationNotSupported,
            FrostError::SerializationError => Self::SerializationError,
            FrostError::DeserializationError => Self::DeserializationError,
            _ => Self::UnknownFrostError,
        }
    }
}

#[derive(Debug, Eq, Default, PartialEq, PartialOrd, Clone, Copy, Hash, Encode, Decode)]
pub enum CustomErrorKind {
    /// An entity was not found, often a file.
    NotFound,
    /// The operation lacked the necessary privileges to complete.
    PermissionDenied,
    /// The connection was refused by the remote server.
    ConnectionRefused,
    /// The connection was reset by the remote server.
    ConnectionReset,
    /// The remote host is not reachable.
    HostUnreachable,
    /// The network containing the remote host is not reachable.
    NetworkUnreachable,
    /// The connection was aborted (terminated) by the remote server.
    ConnectionAborted,
    /// The network operation failed because it was not connected yet.
    NotConnected,
    /// A socket address could not be bound because the address is already in use elsewhere.
    AddrInUse,
    /// A nonexistent interface was requested or the requested address was not local.
    AddrNotAvailable,
    /// The system's networking is down.
    NetworkDown,
    /// The operation failed because a pipe was closed.
    BrokenPipe,
    /// An entity already exists, often a file.
    AlreadyExists,
    /// The operation needs to block to complete, but the blocking operation was
    /// requested to not occur.
    WouldBlock,
    /// A filesystem object is, unexpectedly, not a directory.
    ///
    /// For example, a filesystem path was specified where one of the intermediate directory
    /// components was, in fact, a plain file.
    NotADirectory,
    /// The filesystem object is, unexpectedly, a directory.
    ///
    /// A directory was specified when a non-directory was expected.
    IsADirectory,
    /// A non-empty directory was specified where an empty directory was expected.
    DirectoryNotEmpty,
    /// The filesystem or storage medium is read-only, but a write operation was attempted.
    ReadOnlyFilesystem,
    /// Stale network file handle.
    ///
    /// With some network filesystems, notably NFS, an open file (or directory) can be invalidated
    /// by problems with the network or server.
    StaleNetworkFileHandle,
    /// A parameter was incorrect.
    InvalidInput,
    /// Data not valid for the operation were encountered.
    ///
    /// Unlike [`InvalidInput`], this typically means that the operation
    /// parameters were valid, however the error was caused by malformed
    /// input data.
    ///
    /// For example, a function that reads a file into a string will error with
    /// `InvalidData` if the file's contents are not valid UTF-8.
    ///
    /// [`InvalidInput`]: ErrorKind::InvalidInput
    InvalidData,
    /// The I/O operation's timeout expired, causing it to be canceled.
    TimedOut,
    /// An error returned when an operation could not be completed because a
    /// call to [`write`] returned [`Ok(0)`].
    ///
    /// This typically means that an operation could only succeed if it wrote a
    /// particular number of bytes but only a smaller number of bytes could be
    /// written.
    ///
    /// [`write`]: crate::io::Write::write
    /// [`Ok(0)`]: Ok
    WriteZero,
    /// The underlying storage (typically, a filesystem) is full.
    ///
    /// This does not include out of quota errors.
    StorageFull,
    /// Seek on unseekable file.
    ///
    /// Seeking was attempted on an open file handle which is not suitable for seeking - for
    /// example, on Unix, a named pipe opened with `File::open`.
    NotSeekable,
    /// Filesystem quota or some other kind of quota was exceeded.
    QuotaExceeded,
    /// File larger than allowed or supported.
    ///
    /// This might arise from a hard limit of the underlying filesystem or file access API, or from
    /// an administratively imposed resource limitation.  Simple disk full, and out of quota, have
    /// their own errors.
    FileTooLarge,
    /// Resource is busy.
    ResourceBusy,
    /// Executable file is busy.
    ///
    /// An attempt was made to write to a file which is also in use as a running program.  (Not all
    /// operating systems detect this situation.)
    ExecutableFileBusy,
    /// Deadlock (avoided).
    ///
    /// A file locking operation would result in deadlock.  This situation is typically detected, if
    /// at all, on a best-effort basis.
    Deadlock,
    /// Cross-device or cross-filesystem (hard) link or rename.
    CrossesDevices,
    /// Too many (hard) links to the same filesystem object.
    ///
    /// The filesystem does not support making so many hardlinks to the same file.
    TooManyLinks,
    /// A filename was invalid.
    ///
    /// This error can also occur if a length limit for a name was exceeded.
    InvalidFilename,
    /// Program argument list too long.
    ///
    /// When trying to run an external program, a system or process limit on the size of the
    /// arguments would have been exceeded.
    ArgumentListTooLong,
    /// This operation was interrupted.
    ///
    /// Interrupted operations can typically be retried.
    Interrupted,

    /// This operation is unsupported on this platform.
    ///
    /// This means that the operation can never succeed.
    Unsupported,

    // ErrorKinds which are primarily categorisations for OS error
    // codes should be added above.
    //
    /// An error returned when an operation could not be completed because an
    /// "end of file" was reached prematurely.
    ///
    /// This typically means that an operation could only succeed if it read a
    /// particular number of bytes but only a smaller number of bytes could be
    /// read.
    UnexpectedEof,

    /// An operation could not be completed, because it failed
    /// to allocate enough memory.
    OutOfMemory,

    // "Unusual" error kinds which do not correspond simply to (sets
    // of) OS error codes, should be added just above this comment.
    // `Other` and `Uncategorized` should remain at the end:
    //
    /// A custom error that does not fall under any other I/O error kind.
    ///
    /// This can be used to construct your own [`Error`]s that do not match any
    /// [`ErrorKind`].
    ///
    /// This [`ErrorKind`] is not used by the standard library.
    ///
    /// Errors from the standard library that do not fall under any of the I/O
    /// error kinds cannot be `match`ed on, and will only match a wildcard (`_`) pattern.
    /// New [`ErrorKind`]s might be added in the future for some of those.
    Other,
    /// `InExhaustiveReached` reached, maybe std::io::ErrorKind has new variants
    #[default]
    InExhaustiveReached,
}

impl From<std::io::ErrorKind> for CustomErrorKind {
    fn from(value: std::io::ErrorKind) -> Self {
        use std::io::ErrorKind as StdVariant;

        match value {
            StdVariant::NotFound => Self::NotFound,
            StdVariant::PermissionDenied => Self::PermissionDenied,
            StdVariant::ConnectionRefused => Self::ConnectionRefused,
            StdVariant::ConnectionReset => Self::ConnectionReset,
            StdVariant::HostUnreachable => Self::HostUnreachable,
            StdVariant::NetworkUnreachable => Self::NetworkUnreachable,
            StdVariant::ConnectionAborted => Self::ConnectionAborted,
            StdVariant::NotConnected => Self::NotConnected,
            StdVariant::AddrInUse => Self::AddrInUse,
            StdVariant::AddrNotAvailable => Self::AddrNotAvailable,
            StdVariant::NetworkDown => Self::NetworkDown,
            StdVariant::BrokenPipe => Self::BrokenPipe,
            StdVariant::AlreadyExists => Self::AlreadyExists,
            StdVariant::WouldBlock => Self::WouldBlock,
            StdVariant::NotADirectory => Self::NotADirectory,
            StdVariant::IsADirectory => Self::IsADirectory,
            StdVariant::DirectoryNotEmpty => Self::DirectoryNotEmpty,
            StdVariant::ReadOnlyFilesystem => Self::ReadOnlyFilesystem,
            StdVariant::StaleNetworkFileHandle => Self::StaleNetworkFileHandle,
            StdVariant::InvalidInput => Self::InvalidInput,
            StdVariant::InvalidData => Self::InvalidData,
            StdVariant::TimedOut => Self::TimedOut,
            StdVariant::WriteZero => Self::WriteZero,
            StdVariant::StorageFull => Self::StorageFull,
            StdVariant::NotSeekable => Self::NotSeekable,
            StdVariant::QuotaExceeded => Self::QuotaExceeded,
            StdVariant::FileTooLarge => Self::FileTooLarge,
            StdVariant::ResourceBusy => Self::ResourceBusy,
            StdVariant::ExecutableFileBusy => Self::ExecutableFileBusy,
            StdVariant::Deadlock => Self::Deadlock,
            StdVariant::CrossesDevices => Self::CrossesDevices,
            StdVariant::TooManyLinks => Self::TooManyLinks,
            StdVariant::InvalidFilename => Self::InvalidFilename,
            StdVariant::ArgumentListTooLong => Self::ArgumentListTooLong,
            StdVariant::Interrupted => Self::Interrupted,
            StdVariant::Unsupported => Self::Unsupported,
            StdVariant::UnexpectedEof => Self::UnexpectedEof,
            StdVariant::OutOfMemory => Self::OutOfMemory,
            StdVariant::Other => Self::Other,
            _ => Self::InExhaustiveReached,
        }
    }
}
