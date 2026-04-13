use bitcode::{Decode, Encode};

use crate::{Blake3HashBytes, Round1PackageBytes, Round1SecretBytes};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode)]
pub struct FrostDkgInfo {
    minimum_signers: u16,
    maximum_signers: u16,
    state: FrostDkgState,
    message: Blake3HashBytes,
}

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode)]
pub enum FrostDkgState {
    #[default]
    Uninitialized,
    Round1Data {
        secret: Round1SecretBytes,
        public: Round1PackageBytes,
    },
}
