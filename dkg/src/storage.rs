use frost_core::Ciphersuite;
use frost_dkg_types::{
    AsymmetricKeypairBytes, AsymmetricVerifyingKeyBytes, EphemeralClientDeviceKeypair,
    EphemeralClientDeviceVerifyingKey, FinalizedParticipants, FrostCredentialSeed, FrostDkgState,
    FrostOpsResult, FrostRelayMessageEnvelope, FrostRoundPackage, MinMaxParticipants,
    Round1Participants, SldTld,
    finalized::{FrostKeyPackageBytes, FrostPublicKeyPackage},
    round1, round2,
};

pub trait FrostDkgStorage<C: Ciphersuite>: Sized {
    fn init() -> impl Future<Output = FrostOpsResult<Self>>;

    fn set_sld_tld(&self, sld_tld: SldTld) -> impl Future<Output = FrostOpsResult<()>>;

    fn get_all_sld_tlds(&self) -> impl Future<Output = FrostOpsResult<Vec<SldTld>>>;

    fn get_state(&self, sld_tld: &SldTld) -> impl Future<Output = FrostOpsResult<FrostDkgState>>;

    fn get_state_and_register_envelope(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<
        Output = FrostOpsResult<(
            FrostDkgState,
            FrostRelayMessageEnvelope<FrostCredentialSeed>,
        )>,
    >;

    fn set_state(
        &self,
        sld_tld: &SldTld,
        state: FrostDkgState,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn get_asymmetric_keypair(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<Output = FrostOpsResult<AsymmetricKeypairBytes>>;

    fn get_asymmetric_verifying_key(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<Output = FrostOpsResult<AsymmetricVerifyingKeyBytes>>;

    fn get_credential(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<Output = FrostOpsResult<Option<FrostCredentialSeed>>>;

    fn set_credential(
        &self,
        sld_tld: &SldTld,
        credential: FrostCredentialSeed,
        new_state: FrostDkgState,
        avkp: AsymmetricKeypairBytes,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn set_dkg_min_max_participants(
        &self,
        sld_tld: &SldTld,
        min_max: MinMaxParticipants,
        state: FrostDkgState,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn get_dkg_min_max_participants(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<Output = FrostOpsResult<Option<MinMaxParticipants>>>;

    fn get_participants(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<Output = FrostOpsResult<FinalizedParticipants>>;

    fn set_ecdk(
        &self,
        sld_tld: &SldTld,
        keypair: EphemeralClientDeviceKeypair,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn get_ecdk(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<Output = FrostOpsResult<Option<EphemeralClientDeviceKeypair>>>;

    fn set_received_round1_packages(
        &self,
        sld_tld: &SldTld,
        state: FrostDkgState,
        round1_packages: Vec<FrostRoundPackage<round1::Round1PackageBytes>>,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn set_round1_package(
        &self,
        sld_tld: &SldTld,
        round1_secret: round1::Round1SecretBytes,
        round1_package: round1::Round1PackageBytes,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    #[allow(clippy::type_complexity)]
    fn get_requirements_to_validate_a_broadcast(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<
        Output = FrostOpsResult<(
            FrostDkgState,
            Vec<FrostRoundPackage<round1::Round1PackageBytes>>,
            EphemeralClientDeviceKeypair,
            FrostCredentialSeed,
            MinMaxParticipants,
        )>,
    >;

    #[allow(clippy::type_complexity)]
    fn get_requirements_to_create_round2(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<
        Output = FrostOpsResult<(
            FrostDkgState,
            Vec<FrostRoundPackage<round1::Round1PackageBytes>>,
            EphemeralClientDeviceKeypair,
            AsymmetricVerifyingKeyBytes,
            round1::Round1SecretBytes,
            FrostCredentialSeed,
        )>,
    >;

    #[allow(clippy::type_complexity)]
    fn get_requirements_to_verify_round2(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<
        Output = FrostOpsResult<(
            FrostDkgState,
            FrostCredentialSeed,
            Vec<FrostRoundPackage<round2::Round2PackageBytes>>,
            EphemeralClientDeviceKeypair,
            Round1Participants,
            MinMaxParticipants,
        )>,
    >;

    fn get_round1_package(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<
        Output = FrostOpsResult<(
            Option<round1::Round1PackageBytes>,
            EphemeralClientDeviceVerifyingKey,
            FrostCredentialSeed,
            MinMaxParticipants,
        )>,
    >;

    fn set_round2_packages(
        &self,
        sld_tld: &SldTld,
        round2_secret: round2::Round2SecretBytes,
        round2_packages: Vec<FrostRoundPackage<round2::Round2PackageBytes>>,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn set_received_round2_packages(
        &self,
        sld_tld: &SldTld,
        state: FrostDkgState,
        round2_packages: Vec<FrostRoundPackage<round2::Round2PackageBytes>>,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn get_round2_packages(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<Output = FrostOpsResult<Vec<FrostRoundPackage<round2::Round2PackageBytes>>>>;

    #[allow(clippy::type_complexity)]
    fn get_requirements_to_perform_part3(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<
        Output = FrostOpsResult<(
            FrostDkgState,
            round2::Round2SecretBytes,
            Vec<FrostRoundPackage<round1::Round1PackageBytes>>,
            Vec<FrostRoundPackage<round2::Round2PackageBytes>>,
        )>,
    >;

    fn set_part3_packages(
        &self,
        sld_tld: &SldTld,
        state: FrostDkgState,
        key_package: FrostKeyPackageBytes,
        public_package: FrostPublicKeyPackage,
        participants: FinalizedParticipants,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn get_finalized_packages(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<Output = FrostOpsResult<(FrostKeyPackageBytes, FrostPublicKeyPackage)>>;

    fn get_finalized_key_package(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<Output = FrostOpsResult<FrostKeyPackageBytes>>;

    fn get_finalized_public_package(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<Output = FrostOpsResult<FrostPublicKeyPackage>>;
}
