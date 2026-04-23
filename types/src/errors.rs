#[cfg(feature = "client")]
use crate::FrostDkgState;
use crate::TransmitType;

pub type FrostOpsResult<T> = Result<T, FrostOpsError>;

#[derive(Debug, PartialEq, Eq, thiserror::Error, Clone)]
pub enum FrostOpsError {
    #[error(
        "The username, email, random hex or identifier to use as the FROST Credential seed is invalid. It must be at least 3 characters long"
    )]
    InvalidFrostCredentialSeed,
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
    #[error("The organization's domain has not been set")]
    SldTlDNotSet,
    #[error("The FROST credential details have not been set")]
    FrostCredentialNotSet,
    #[error("The Ephemeral Client Device Keypair has not been set")]
    EcdkNotFound,
    #[error("FROST error: {0}")]
    FrostProtocol(FrostProtocolError),
    #[error("{0}")]
    Client(FrostClientError),
    #[cfg(feature = "client_storage")]
    #[error("FROST error: {0}")]
    Storage(FrostClientStorageError),
    #[error("The Ephemeral Client Device Verifying Key is invalid")]
    InvalidEphemeralClientDeviceVerifyingKey,
    #[error("Invalid Tai64N bytes")]
    Tai64NTimestampBytes,
    #[error(
        "A relay Round1 DKG envelope transmit type is invalid: `{0:?}`. Round1 DKG only accepts broadcasts."
    )]
    RelayRound1IsCorrupted(TransmitType),
    #[error(
        "The relay transmitted a payload that is not round1 DKG yet only Round1 DKG payloads are accepted by the query"
    )]
    InvalidFrostEnvelopePayloadForRound1,
    #[error("Minimum and Maximum participants not set!")]
    MinMaxNotSet,
    #[error("The relay sent too many Round1 packages. Aborting adding received round1 packages")]
    RelayRound1TooManyPackages,
}

#[cfg(feature = "client")]
#[derive(Debug, PartialEq, Eq, thiserror::Error, Clone)]
pub enum FrostClientError {
    #[error("Unable to sign the payload using the Ed25519 Client Device Signing Key")]
    ClientDeviceSigningError,
    #[error("Unable to decode `FrostEnvelopePayload` from bytes.")]
    DecodeFrostEnvelopePayload,
    #[error(
        "The current state is invalid; expected state is `{expected:?}` but current state is `{current:?}`"
    )]
    InvalidClientState {
        current: FrostDkgState,
        expected: FrostDkgState,
    },

    #[error(
        "The current state is invalid; expected state to have reached `{expected:?}` but current state is `{current:?}`"
    )]
    InvalidReachClientState {
        current: FrostDkgState,
        expected: FrostDkgState,
    },
}

impl From<tai64::Error> for FrostOpsError {
    fn from(_: tai64::Error) -> Self {
        Self::Tai64NTimestampBytes
    }
}

impl From<FrostClientError> for FrostOpsError {
    fn from(error: FrostClientError) -> Self {
        Self::Client(error)
    }
}

#[cfg(feature = "client_storage")]
#[derive(Debug, PartialEq, Eq, thiserror::Error, Clone)]
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
    #[error("I/O error: `{0}`")]
    Io(std::io::ErrorKind),
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
            redb::Error::Io(value) => Self::Io(value.kind()),
            redb::Error::DatabaseClosed => Self::DatabaseClosed,
            redb::Error::PreviousIo => Self::PreviousIo,
            redb::Error::LockPoisoned(value) => Self::LockPoisoned(value.to_string()),
            redb::Error::ReadTransactionStillInUse(_) => Self::ReadTransactionStillInUse,
            _ => Self::Fatal,
        }
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error, Clone)]
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
    FieldError(#[from] frost_core::FieldError),
    /// Error in elliptic curve Group.
    #[error("Error in elliptic curve Group.")]
    GroupError(#[from] frost_core::GroupError),
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
    #[error("The maximum signers must be more or equal to minimum signers")]
    MinimumSignersMoreThanMaximumSigners,
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
            FrostError::FieldError(value) => Self::FieldError(value),
            FrostError::GroupError(value) => Self::GroupError(value),
            FrostError::InvalidCoefficient => Self::InvalidCoefficient,
            FrostError::IdentifierDerivationNotSupported => Self::IdentifierDerivationNotSupported,
            FrostError::SerializationError => Self::SerializationError,
            FrostError::DeserializationError => Self::DeserializationError,
            _ => Self::UnknownFrostError,
        }
    }
}
