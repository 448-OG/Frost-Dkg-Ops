use bitcode::{Decode, Encode};
use frost_core::Ciphersuite;
use frost_dkg_types::{
    EphemeralClientDeviceKeypair, EphemeralClientDeviceVerifyingKey, FrostCredential,
    FrostCredentialSeed, FrostDkgState, FrostOpsResult, MinMaxParticipants, Tai64NTimestamp,
    round1::{Round1PackageBytes, Round1SecretBytes},
};

pub trait FrostDkgStorage<C: Ciphersuite>: Sized {
    fn init() -> impl Future<Output = FrostOpsResult<Self>>;

    fn get_organization_sld_tld(&self) -> impl Future<Output = FrostOpsResult<String>>;

    fn set_ecdk(
        &self,
        keypair: &EphemeralClientDeviceKeypair,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn get_edcs(&self) -> impl Future<Output = FrostOpsResult<EphemeralClientDeviceKeypair>>;

    fn get_ecdk(
        &self,
    ) -> impl Future<Output = FrostOpsResult<Option<EphemeralClientDeviceKeypair>>>;

    fn get_edcvk(&self) -> impl Future<Output = FrostOpsResult<EphemeralClientDeviceVerifyingKey>>;

    fn get_credential(&self) -> impl Future<Output = FrostOpsResult<Option<FrostCredential<C>>>>;

    fn set_credential(
        &self,
        credential: &FrostCredential<C>,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn get_state(&self) -> impl Future<Output = FrostOpsResult<FrostDkgState>>;

    fn set_state(&self, state: FrostDkgState) -> impl Future<Output = FrostOpsResult<()>>;

    fn get_dkg_min_max_participants(
        &self,
    ) -> impl Future<Output = FrostOpsResult<MinMaxParticipants>>;

    fn set_dkg_min_max_participants(
        &self,
        min_max_participants: MinMaxParticipants,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn get_participants(&self) -> impl Future<Output = FrostOpsResult<Vec<FrostCredentialSeed>>>;

    fn set_round1_packages(
        &self,
        secret: Round1SecretBytes,
        public: Round1PackageBytes,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn get_round1_package(
        &self,
    ) -> impl Future<Output = FrostOpsResult<Option<Round1PackageBytes>>>;

    fn set_received_round1_package(
        &self,
        envelope: FrostRound1ReceivedPackage,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn set_received_round1_packages(
        &self,
        round1_packages: Vec<FrostRound1ReceivedPackage>,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn get_received_round1_packages(
        &self,
    ) -> impl Future<Output = FrostOpsResult<Vec<FrostRound1ReceivedPackage>>>;
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub struct FrostRound1ReceivedPackage {
    pub timestamp: Tai64NTimestamp,
    pub organization: String,
    pub sender_seed: FrostCredentialSeed,
    pub ecdvk: EphemeralClientDeviceVerifyingKey,
    pub payload: Round1PackageBytes,
}
