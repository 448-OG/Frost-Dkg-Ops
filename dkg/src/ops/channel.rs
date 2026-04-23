use frost_core::Ciphersuite;
use frost_dkg_types::{FrostMessageEnvelope, FrostOpsResult, MinMaxParticipants};

pub trait FrostAuthenticatedChannel<C: Ciphersuite>: Sized {
    fn init() -> impl Future<Output = FrostOpsResult<Self>>;

    fn fetch_min_max_participants(
        &self,
    ) -> impl Future<Output = FrostOpsResult<MinMaxParticipants>>;

    fn get_dkg_round1_packages(
        &self,
    ) -> impl Future<Output = FrostOpsResult<Vec<FrostMessageEnvelope>>>;
}
