pub type FrostOpsResult<T> = Result<T, FrostOpsError>;

#[derive(Debug, PartialEq, Eq, thiserror::Error, Clone)]
pub enum FrostOpsError {
    #[error("The email address is invalid")]
    InvalidEmailAddress,
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
}

impl<C: frost_core::Ciphersuite> From<frost_core::Error<C>> for FrostOpsError {
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
