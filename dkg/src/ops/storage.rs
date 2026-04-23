use frost_core::Ciphersuite;
use frost_dkg_types::{
    EphemeralClientDeviceKeypair, EphemeralClientDeviceVerifyingKey, FrostCredential,
    FrostDkgState, FrostMessageEnvelope, FrostOpsResult, MinMaxParticipants,
    round1::{Round1PackageBytes, Round1SecretBytes},
};

pub trait FrostDkgStorage<C: Ciphersuite>: Sized {
    fn init() -> impl Future<Output = FrostOpsResult<Self>>;

    fn set_organization_sld_tld(&self, sld_tld: &str) -> impl Future<Output = FrostOpsResult<()>>;

    fn get_organization_sld_tld(&self) -> impl Future<Output = FrostOpsResult<Option<String>>>;

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
        envelope: FrostMessageEnvelope,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn set_received_round1_packages(
        &self,
        envelopes: Vec<FrostMessageEnvelope>,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn get_received_round1_packages(
        &self,
    ) -> impl Future<Output = FrostOpsResult<Vec<FrostMessageEnvelope>>>;
}
