use frost_core::Ciphersuite;
use frost_dkg_types::{
    FrostCredentialSeed, FrostMessageEnvelope, FrostOpsResult, FrostRelayMessageEnvelope,
    MinMaxParticipants, SldTld,
};

pub trait FrostAuthenticatedChannel<C: Ciphersuite>: Sized {
    fn init() -> impl Future<Output = FrostOpsResult<Self>>;

    fn is_active_domain(&self, sld_tld: &SldTld) -> impl Future<Output = FrostOpsResult<bool>>;

    /// Registers user querying the endpoint while also querying
    /// the number of participants at the same time to save network trips
    fn fetch_min_max_participants(
        &self,
        envelope: FrostRelayMessageEnvelope<FrostCredentialSeed>,
    ) -> impl Future<Output = FrostOpsResult<MinMaxParticipants>>;

    fn fetch_round1_broadcasts(
        &self,
        sld_tld: &SldTld,
    ) -> impl Future<Output = FrostOpsResult<Vec<FrostMessageEnvelope>>>;

    fn transmit_round1_broadcast(
        &self,
        sld_tld: &SldTld,
        envelope: FrostMessageEnvelope,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn transmit_round2_unicast(
        &self,
        sld_tld: &SldTld,
        envelopes: Vec<FrostMessageEnvelope>,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn fetch_round2_uni_casts(
        &self,
        sld_tld: &SldTld,
        credential_seed: &FrostCredentialSeed,
    ) -> impl Future<Output = FrostOpsResult<Vec<FrostMessageEnvelope>>>;
}
