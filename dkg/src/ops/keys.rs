use std::marker::PhantomData;

use frost_core::Ciphersuite;

use frost_dkg_types::{
    EphemeralClientDeviceKeypair, EphemeralClientDeviceSignature,
    EphemeralClientDeviceVerifyingKey, FrostClientError, FrostCredential, FrostDkgState,
    FrostEnvelopePayload, FrostMessageEnvelope, FrostOpsError, FrostOpsResult, MinMaxParticipants,
    Tai64NTimestamp, TransmitType, round1,
};
use zeroize::Zeroize;

use crate::{FrostAuthenticatedChannel, FrostDkgStorage};

pub struct DkgStateHandler<C: Ciphersuite, S: FrostDkgStorage<C>, N: FrostAuthenticatedChannel<C>> {
    storage: S,
    channel: N,
    foo: PhantomData<C>,
}

impl<C: Ciphersuite, S: FrostDkgStorage<C>, N: FrostAuthenticatedChannel<C>>
    DkgStateHandler<C, S, N>
{
    pub async fn init() -> FrostOpsResult<Self> {
        let storage = S::init().await?;

        let channel = N::init().await?;

        Ok(Self {
            storage,
            channel,
            foo: PhantomData,
        })
    }

    pub async fn init_credential(&self, credential: &FrostCredential<C>) -> FrostOpsResult<()> {
        self.storage.set_credential(credential).await
    }

    pub async fn generate_ecdk(&self) -> FrostOpsResult<()> {
        self.storage
            .set_ecdk(&EphemeralClientDeviceKeypair::new())
            .await
    }

    pub async fn init_dkg_min_max_participants(&self) -> FrostOpsResult<MinMaxParticipants> {
        let current_state = self.storage.get_state().await?;

        if !matches!(current_state, FrostDkgState::QueryMinMax) {
            return Err(FrostClientError::InvalidClientState {
                current: current_state,
                expected: FrostDkgState::QueryMinMax,
            }
            .into());
        }

        let fetched_min_max = self.channel.fetch_min_max_participants().await?;

        self.storage
            .set_dkg_min_max_participants(fetched_min_max)
            .await?;

        Ok(fetched_min_max)
    }

    pub async fn round1_broadcast_package(&self) -> FrostOpsResult<FrostMessageEnvelope> {
        let state = self.storage.get_state().await?;

        let credential = self
            .storage
            .get_credential()
            .await?
            .ok_or(FrostOpsError::FrostCredentialNotSet)?;
        let sender_seed = credential.seed().clone();
        let min_max = self.storage.get_dkg_min_max_participants().await?;

        let package = if let Some(exists) = self.storage.get_round1_package().await? {
            exists
        } else {
            if !matches!(state, FrostDkgState::Round1) {
                return Err(FrostClientError::InvalidReachClientState {
                    current: state,
                    expected: FrostDkgState::Round1,
                }
                .into());
            }

            let (secret, public) = frost_core::keys::dkg::part1(
                credential.frost_identifier(),
                min_max.max,
                min_max.min,
                rand::rngs::OsRng,
            )?;

            let mut secret = round1::Round1SecretBytes::serialize(&secret)?;
            secret.zeroize();
            let public = round1::Round1PackageBytes::encode(&public)?;

            self.storage
                .set_round1_packages(secret, public.clone())
                .await?;

            public
        };

        let organization = self
            .storage
            .get_organization_sld_tld()
            .await?
            .ok_or(FrostOpsError::SldTlDNotSet)?;

        let transmission_type = TransmitType::Broadcast;

        let payload = FrostEnvelopePayload::DkgRound1(package);

        let ecdk = self.storage.get_edcs().await?;

        let signed = FrostMessageEnvelope {
            timestamp: Tai64NTimestamp::now(),
            transmission_type,
            organization,
            sender_seed,
            recipient_seed: None,
            payload,
            ecdvk: EphemeralClientDeviceVerifyingKey::default(),
            ecds: EphemeralClientDeviceSignature::default(),
        }
        .sign(&ecdk)?;

        Ok(signed)
    }

    /// Returns `*FrostDkgState, Vec<Unverified packages>)`
    pub async fn receive_round1_packages(
        &self,
        round1_packages: Vec<FrostMessageEnvelope>,
    ) -> FrostOpsResult<(FrostDkgState, Vec<FrostMessageEnvelope>)> {
        let current_state = self.storage.get_state().await?;

        if current_state != FrostDkgState::Round1 {
            return Err(FrostClientError::InvalidClientState {
                current: current_state,
                expected: FrostDkgState::Round1,
            }
            .into());
        }

        let min_max = self.storage.get_dkg_min_max_participants().await?;

        let current_participants = self.storage.get_received_round1_packages().await?;

        let my_credential_seed = self
            .storage
            .get_credential()
            .await?
            .ok_or(FrostOpsError::FrostCredentialNotSet)?;

        let mut verified = Vec::<FrostMessageEnvelope>::new();
        let mut unverified = Vec::<FrostMessageEnvelope>::new();

        for package in round1_packages {
            if &package.sender_seed == my_credential_seed.seed() {
                continue;
            }

            if current_participants.iter().any(|exists| exists == &package) {
                continue;
            }

            match package.payload {
                FrostEnvelopePayload::DkgRound1(_) => {
                    if package.transmission_type != TransmitType::Broadcast {
                        return Err(FrostOpsError::RelayRound1IsCorrupted(
                            package.transmission_type,
                        ));
                    } else if !package.verify_ecds()? {
                        unverified.push(package);
                    } else {
                        verified.push(package);
                    }
                }

                _ => return Err(FrostOpsError::InvalidFrostEnvelopePayloadForRound1),
            }
        }

        let current_len = verified.len() + current_participants.len() + 1;
        if current_len > min_max.max as usize {
            return Err(FrostOpsError::RelayRound1TooManyPackages);
        }

        self.storage.set_received_round1_packages(verified).await?;

        if current_len == min_max.max as usize {
            let new_state = current_state.transition();

            self.storage.set_state(new_state).await?;

            Ok((new_state, unverified))
        } else {
            Ok((current_state, unverified))
        }
    }

    pub async fn transition<T: AsRef<[u8]>>(&self) -> FrostOpsResult<FrostDkgState> {
        let current_state = self.storage.get_state().await?;

        let new_state = current_state.transition();

        self.storage.set_state(new_state).await?;

        Ok(new_state)
    }
}

#[cfg(test)]
mod sanity_checks {
    use std::{collections::HashMap, marker::PhantomData};

    use async_dup::Arc;
    use async_lock::RwLock;
    use bitcode::Decode;
    use frost_core::Ciphersuite;
    use frost_dkg_types::{
        EphemeralClientDeviceKeypair, EphemeralClientDeviceSignature,
        EphemeralClientDeviceVerifyingKey, FrostClientError, FrostCredential, FrostCredentialSeed,
        FrostDkgState, FrostEnvelopePayload, FrostMessageEnvelope, FrostOpsError, FrostOpsResult,
        FrostRelayMessageEnvelope, MinMaxParticipants, round1,
    };

    use crate::{DkgStateHandler, FrostAuthenticatedChannel, FrostDkgStorage};

    type FrostCredentialEd25519 = FrostCredential<frost_ed25519::Ed25519Sha512>;

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
    pub struct FrostCredentialStoredInRelay {
        organization: String,
        seed: FrostCredentialSeed,
        ecdvk: EphemeralClientDeviceVerifyingKey,
        ecds: EphemeralClientDeviceSignature, //can be transmitted to other participants for verification
    }

    #[test]
    fn register_credential() {
        smol::block_on(async move {
            let sld_tld = "example.com";

            let party1_id = "foo";
            let party2_id = "bar";
            let party3_id = "maa";

            let party1 = DkgStateHandler::<
                frost_ed25519::Ed25519Sha512,
                Arc<RwLock<ClientStorage<frost_ed25519::Ed25519Sha512>>>,
                RelayMemNetwork<frost_ed25519::Ed25519Sha512>,
            >::init()
            .await
            .unwrap();

            let party2 = DkgStateHandler::<
                frost_ed25519::Ed25519Sha512,
                Arc<RwLock<ClientStorage<frost_ed25519::Ed25519Sha512>>>,
                RelayMemNetwork<frost_ed25519::Ed25519Sha512>,
            >::init()
            .await
            .unwrap();

            let party3 = DkgStateHandler::<
                frost_ed25519::Ed25519Sha512,
                Arc<RwLock<ClientStorage<frost_ed25519::Ed25519Sha512>>>,
                RelayMemNetwork<frost_ed25519::Ed25519Sha512>,
            >::init()
            .await
            .unwrap();

            {
                //set SLD-TLD domain
                party1
                    .storage
                    .set_organization_sld_tld(sld_tld)
                    .await
                    .unwrap();
                party2
                    .storage
                    .set_organization_sld_tld(sld_tld)
                    .await
                    .unwrap();
                party3
                    .storage
                    .set_organization_sld_tld(sld_tld)
                    .await
                    .unwrap();
            }

            let party1_credential =
                FrostCredentialEd25519::new_with_email_strict(party1_id, sld_tld).unwrap();
            let party2_credential =
                FrostCredentialEd25519::new_with_email_strict(party2_id, sld_tld).unwrap();
            let party3_credential =
                FrostCredentialEd25519::new_with_email_strict(party3_id, sld_tld).unwrap();

            {
                assert!(
                    party1_credential != party2_credential
                        && party1_credential != party3_credential
                );
                assert!(
                    party2_credential != party1_credential
                        && party2_credential != party3_credential
                );
                assert!(
                    party3_credential != party1_credential
                        && party3_credential != party2_credential
                );
            }

            {
                let state = party1.storage.get_state().await.unwrap();
                // Init identifier
                if state != FrostDkgState::InitCredentials {
                    panic!("Expected `FrostDkgState::InitCredentials` state");
                }

                party1.init_credential(&party1_credential).await.unwrap();
                party2.init_credential(&party2_credential).await.unwrap();
                party3.init_credential(&party3_credential).await.unwrap();

                party1.generate_ecdk().await.unwrap();
                party2.generate_ecdk().await.unwrap();
                party3.generate_ecdk().await.unwrap();
            }

            let party1_ecdk = party1.storage.get_ecdk().await.unwrap().unwrap();
            let party2_ecdk = party2.storage.get_ecdk().await.unwrap().unwrap();
            let party3_ecdk = party3.storage.get_ecdk().await.unwrap().unwrap();

            {
                assert!(party1_ecdk != party2_ecdk && party1_ecdk != party3_ecdk);
                assert!(party2_ecdk != party1_ecdk && party2_ecdk != party3_ecdk);
                assert!(party3_ecdk != party1_ecdk && party3_ecdk != party2_ecdk);
            }

            let party1_seed = party1
                .storage
                .get_credential()
                .await
                .unwrap()
                .unwrap()
                .seed()
                .clone();

            let party2_seed = party2
                .storage
                .get_credential()
                .await
                .unwrap()
                .unwrap()
                .seed()
                .clone();

            let party3_seed = party3
                .storage
                .get_credential()
                .await
                .unwrap()
                .unwrap()
                .seed()
                .clone();

            let party1_envelope = FrostRelayMessageEnvelope {
                organization: sld_tld.to_string(),
                payload: party1_seed.encode(),
                ecdvk: EphemeralClientDeviceVerifyingKey::default(),
                ecds: EphemeralClientDeviceSignature::default(),
            }
            .sign(&party1_ecdk)
            .unwrap();

            let party2_envelope = FrostRelayMessageEnvelope {
                organization: sld_tld.to_string(),
                payload: party2_seed.encode(),
                ecdvk: EphemeralClientDeviceVerifyingKey::default(),
                ecds: EphemeralClientDeviceSignature::default(),
            }
            .sign(&party2_ecdk)
            .unwrap();

            let party3_envelope = FrostRelayMessageEnvelope {
                organization: sld_tld.to_string(),
                payload: party3_seed.encode(),
                ecdvk: EphemeralClientDeviceVerifyingKey::default(),
                ecds: EphemeralClientDeviceSignature::default(),
            }
            .sign(&party3_ecdk)
            .unwrap();

            let mut remote_server_storage = RemoteServerStorage::new();

            {
                // Register and Query Min Max
                let min_max_1 = remote_server_storage.register_user(party1_envelope);
                let min_max_2 = remote_server_storage.register_user(party2_envelope);
                let min_max_3 = remote_server_storage.register_user(party3_envelope);

                assert!(remote_server_storage.is_valid_participant(&party1_seed));
                assert!(remote_server_storage.is_valid_participant(&party2_seed));
                assert!(remote_server_storage.is_valid_participant(&party3_seed));

                assert!(min_max_1 == min_max_2 && min_max_1 == min_max_3);
                assert_eq!(min_max_1, MinMaxParticipants { min: 2, max: 3 });

                party1
                    .storage
                    .set_dkg_min_max_participants(min_max_1)
                    .await
                    .unwrap();
                party2
                    .storage
                    .set_dkg_min_max_participants(min_max_2)
                    .await
                    .unwrap();
                party3
                    .storage
                    .set_dkg_min_max_participants(min_max_3)
                    .await
                    .unwrap();
            }

            {
                // Send Round1 Broadcast
                let one = party1.round1_broadcast_package().await.unwrap();
                let two = party2.round1_broadcast_package().await.unwrap();
                let three = party3.round1_broadcast_package().await.unwrap();

                assert!(one != two && one != three);
                assert!(two != one && two != three);
                assert!(three != one && three != two);
            }

            {
                // Transmit round1
                let party1_round1_broadcast = party1.round1_broadcast_package().await.unwrap();
                let party2_round1_broadcast = party2.round1_broadcast_package().await.unwrap();
                let party3_round1_broadcast = party3.round1_broadcast_package().await.unwrap();

                remote_server_storage.receive_transmission(party1_round1_broadcast);
                remote_server_storage.receive_transmission(party2_round1_broadcast);
                remote_server_storage.receive_transmission(party3_round1_broadcast);
            }

            {
                // Fetch Round1 Data Simulation
                let party1_fetch = remote_server_storage.get_round1_packages();
                let party2_fetch = remote_server_storage.get_round1_packages();
                let party3_fetch = remote_server_storage.get_round1_packages();

                let (state1, unverified1) =
                    party1.receive_round1_packages(party1_fetch).await.unwrap();
                let (state2, unverified2) =
                    party2.receive_round1_packages(party2_fetch).await.unwrap();
                let (state3, unverified3) =
                    party3.receive_round1_packages(party3_fetch).await.unwrap();

                assert!(unverified1.is_empty());
                assert!(unverified2.is_empty());
                assert!(unverified3.is_empty());

                assert_eq!(state1, FrostDkgState::Round2);
                assert_eq!(state2, FrostDkgState::Round2);
                assert_eq!(state3, FrostDkgState::Round2);
            }
        })
    }

    struct ClientStorage<C: Ciphersuite> {
        min_max: Option<MinMaxParticipants>,
        org_info: Option<String>,
        state: FrostDkgState,
        credential: Option<FrostCredential<C>>,
        ecdk: Option<EphemeralClientDeviceKeypair>,
        round1_secret: Option<round1::Round1SecretBytes>,
        round1_package: Option<round1::Round1PackageBytes>,
        received_round1_packages: HashMap<FrostCredentialSeed, FrostMessageEnvelope>,
    }

    impl<C: Ciphersuite> FrostDkgStorage<C> for Arc<RwLock<ClientStorage<C>>> {
        async fn init() -> FrostOpsResult<Self> {
            let init = ClientStorage {
                min_max: Option::default(),
                org_info: Option::default(),
                state: FrostDkgState::Uninitialized,
                credential: Option::default(),
                ecdk: Option::default(),
                round1_secret: Option::default(),
                round1_package: Option::default(),
                received_round1_packages: HashMap::default(),
            };

            Ok(Arc::new(RwLock::new(init)))
        }

        async fn get_organization_sld_tld(
            &self,
        ) -> frost_dkg_types::FrostOpsResult<Option<String>> {
            Ok(self.read().await.org_info.clone())
        }

        async fn set_organization_sld_tld(
            &self,
            sld_tld: &str,
        ) -> frost_dkg_types::FrostOpsResult<()> {
            let state = self.get_state().await?;

            if state != FrostDkgState::Uninitialized {
                return Err(FrostClientError::InvalidClientState {
                    current: state,
                    expected: FrostDkgState::Uninitialized,
                }
                .into());
            }

            self.write().await.org_info.replace(sld_tld.to_string());

            let new_state = state.transition();

            self.set_state(new_state).await?; //TODO: Use same tx

            Ok(())
        }

        async fn get_dkg_min_max_participants(&self) -> FrostOpsResult<MinMaxParticipants> {
            self.read().await.min_max.ok_or(FrostOpsError::MinMaxNotSet)
        }

        async fn set_dkg_min_max_participants(
            &self,
            min_max_participants: MinMaxParticipants,
        ) -> FrostOpsResult<()> {
            let state = self.get_state().await?;

            if !matches!(state, FrostDkgState::QueryMinMax) {
                return Err(FrostClientError::InvalidClientState {
                    current: state,
                    expected: FrostDkgState::QueryMinMax,
                }
                .into());
            }

            let mut writer = self.write().await;
            writer.min_max.replace(min_max_participants);

            writer.state = state.transition();

            Ok(())
        }

        async fn get_credential(
            &self,
        ) -> frost_dkg_types::FrostOpsResult<Option<FrostCredential<C>>> {
            Ok(self.read().await.credential.clone())
        }

        async fn set_credential(
            &self,
            credential: &FrostCredential<C>,
        ) -> frost_dkg_types::FrostOpsResult<()> {
            let state = self.get_state().await?;

            if !matches!(state, FrostDkgState::InitCredentials) {
                return Err(FrostClientError::InvalidClientState {
                    current: state,
                    expected: FrostDkgState::InitCredentials,
                }
                .into());
            }

            self.write().await.credential.replace(credential.clone());

            let new_state = state.transition();

            self.set_state(new_state).await?; //TODO: Use same tx

            Ok(())
        }

        async fn get_state(&self) -> frost_dkg_types::FrostOpsResult<FrostDkgState> {
            Ok(self.read().await.state)
        }

        async fn set_state(&self, state: FrostDkgState) -> frost_dkg_types::FrostOpsResult<()> {
            self.write().await.state = state;

            Ok(())
        }

        async fn set_ecdk(&self, keypair: &EphemeralClientDeviceKeypair) -> FrostOpsResult<()> {
            self.write().await.ecdk.replace(keypair.clone());

            Ok(())
        }

        async fn get_ecdk(&self) -> FrostOpsResult<Option<EphemeralClientDeviceKeypair>> {
            Ok(self.read().await.ecdk.clone())
        }

        async fn get_edcvk(
            &self,
        ) -> frost_dkg_types::FrostOpsResult<EphemeralClientDeviceVerifyingKey> {
            Ok(self
                .read()
                .await
                .ecdk
                .as_ref()
                .ok_or(FrostOpsError::EcdkNotFound)?
                .verifying_key_encodable())
        }

        async fn get_edcs(&self) -> FrostOpsResult<EphemeralClientDeviceKeypair> {
            self.read()
                .await
                .ecdk
                .clone()
                .ok_or(FrostOpsError::EcdkNotFound)
        }

        async fn set_round1_packages(
            &self,
            secret: round1::Round1SecretBytes,
            public: round1::Round1PackageBytes,
        ) -> FrostOpsResult<()> {
            self.write().await.round1_secret.replace(secret);
            self.write().await.round1_package.replace(public);

            Ok(())
        }

        async fn get_round1_package(
            &self,
        ) -> FrostOpsResult<Option<frost_dkg_types::round1::Round1PackageBytes>> {
            Ok(self.read().await.round1_package.clone())
        }

        async fn set_received_round1_package(
            &self,
            envelope: FrostMessageEnvelope,
        ) -> FrostOpsResult<()> {
            let credential_seed = envelope.sender_seed.clone();

            self.write()
                .await
                .received_round1_packages
                .insert(credential_seed, envelope);

            Ok(())
        }

        async fn set_received_round1_packages(
            &self,
            envelopes: Vec<FrostMessageEnvelope>,
        ) -> FrostOpsResult<()> {
            for envelope in envelopes {
                let credential_seed = envelope.sender_seed.clone();

                self.write()
                    .await
                    .received_round1_packages
                    .insert(credential_seed, envelope);
            }

            Ok(())
        }

        async fn get_received_round1_packages(&self) -> FrostOpsResult<Vec<FrostMessageEnvelope>> {
            Ok(self
                .read()
                .await
                .received_round1_packages
                .values()
                .cloned()
                .collect())
        }
    }

    struct RelayMemNetwork<C: Ciphersuite>(PhantomData<C>);

    impl<C: Ciphersuite> FrostAuthenticatedChannel<C> for RelayMemNetwork<C> {
        async fn init() -> FrostOpsResult<Self> {
            Ok(Self(PhantomData))
        }

        async fn fetch_min_max_participants(&self) -> FrostOpsResult<MinMaxParticipants> {
            Ok(MinMaxParticipants { min: 2, max: 3 })
        }

        async fn get_dkg_round1_packages(&self) -> FrostOpsResult<Vec<FrostMessageEnvelope>> {
            todo!()
        }
    }

    #[derive(Debug, Default)]
    struct RemoteServerStorage {
        organization: String,
        min_max: MinMaxParticipants,
        credential_seeds: HashMap<FrostCredentialSeed, FrostCredentialStoredInRelay>,
        round1_dkg: HashMap<FrostCredentialSeed, FrostMessageEnvelope>,
    }

    impl RemoteServerStorage {
        fn new() -> Self {
            Self {
                organization: "example.com".to_string(),
                min_max: MinMaxParticipants { min: 2, max: 3 },
                ..Default::default()
            }
        }

        fn register_user(
            &mut self,
            data: FrostRelayMessageEnvelope<impl Decode<'static> + AsRef<[u8]>>,
        ) -> MinMaxParticipants {
            let organization = "example.com";

            if data.organization != organization {
                panic!("Invalid organization");
            }

            if data.verify_ecds().unwrap() {
                panic!("Invalid Ephemeral Client Device Signature")
            }

            let seed = bitcode::decode::<FrostCredentialSeed>(data.payload.as_ref())
                .expect("Unable to decode `FrostCredentialSeed`");
            let to_storage_data = FrostCredentialStoredInRelay {
                organization: data.organization,
                seed: seed.clone(),
                ecdvk: data.ecdvk,
                ecds: data.ecds,
            };

            self.credential_seeds.insert(seed, to_storage_data);

            self.min_max
        }

        fn is_valid_participant(&self, participant: &FrostCredentialSeed) -> bool {
            self.credential_seeds.contains_key(participant)
        }

        fn receive_transmission(&mut self, data: FrostMessageEnvelope) -> &mut Self {
            if data.organization != self.organization {
                panic!("Invalid organization");
            }

            if !data.verify_ecds().unwrap() {
                panic!("Invalid Ephemeral Client Device Signature")
            }

            match data.payload {
                FrostEnvelopePayload::DkgRound1(_) => {
                    self.process_round1(data.sender_seed.clone(), data)
                }
                _ => todo!(),
            }
        }

        fn process_round1(
            &mut self,
            sender_seed: FrostCredentialSeed,
            data: FrostMessageEnvelope,
        ) -> &mut Self {
            self.round1_dkg.insert(sender_seed, data);

            self
        }

        fn get_round1_packages(&self) -> Vec<FrostMessageEnvelope> {
            self.round1_dkg.values().cloned().collect()
        }
    }
}
