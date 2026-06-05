use frost_dkg_types::{
    FinalizedSigningEvent, FrostCredentialSeed, FrostEventHash, FrostMessageEnvelope,
    FrostOpsResult, FrostRelayMessageEnvelope, FrostSigningEvent, MinMaxParticipants,
    SignalAcknowledgement, SldTld, TransmitFrostRound2,
};

pub trait FrostAuthenticatedChannel: Sized {
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

    fn signal_ack(&self, ack: SignalAcknowledgement) -> impl Future<Output = FrostOpsResult<()>>;

    fn update_signing_event(
        &self,
        sld_tld: SldTld,
        payload: TransmitFrostRound2,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn receive_round2_signature_shares(
        &self,
        event_hash: FrostEventHash,
        shares: Vec<TransmitFrostRound2>,
    ) -> impl Future<Output = FrostOpsResult<()>>;

    fn finalized_signing_event(
        &self,
        sld_tld: &SldTld,
        finalized: FinalizedSigningEvent,
    ) -> impl Future<Output = FrostOpsResult<()>>;
}
