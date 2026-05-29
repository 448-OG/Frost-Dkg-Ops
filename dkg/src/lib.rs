mod keys;
pub use keys::*;

mod storage;
pub use storage::*;

mod channel;
pub use channel::*;

mod signing;
pub use signing::*;

#[cfg(test)]
mod sanity_checks {
    use std::{
        collections::{BTreeMap, HashMap, HashSet, VecDeque},
        sync::LazyLock,
    };

    use async_dup::Arc;
    use async_lock::{Mutex, RwLock};
    use frost_dkg_types::{
        AsymmetricKeypairBytes, AsymmetricVerifyingKeyBytes, Blake3HashBytes,
        EphemeralClientDeviceKeypair, FinalizedParticipants, FrostCredentialSeed, FrostDkgState,
        FrostMessageEnvelope, FrostOpsError, FrostOpsResult, FrostRelayMessageEnvelope,
        FrostRoundPackage, FrostSigningEventInfo, FrostSigningEventKey, MinMaxParticipants,
        Round1Participants, SldTld, Tai64NTimestamp,
        finalized::{FrostKeyPackageBytes, FrostPublicKeyPackage},
        round1::{self, Round1PackageBytes},
        round2,
    };
    use frost_ed25519::Ed25519Sha512;

    use crate::{DkgStateHandler, FrostAuthenticatedChannel, FrostDkgStorage};

    type FrostEd25519DkgHandler =
        DkgStateHandler<frost_ed25519::Ed25519Sha512, Arc<RwLock<ClientStorage>>, RelayMemNetwork>;

    static REMOTE_SERVER: LazyLock<Mutex<RemoteServer>> = LazyLock::new(|| {
        let sld_tld = SldTld::new("example.com").unwrap();

        Mutex::new(RemoteServer::new(sld_tld.checked()))
    });

    #[test]
    fn module() {
        smol::block_on(async move {
            REMOTE_SERVER
                .lock()
                .await
                .set_min_max(MinMaxParticipants { min: 2, max: 3 });

            let party1 = FrostEd25519DkgHandler::init().await.unwrap();
            let party2 = FrostEd25519DkgHandler::init().await.unwrap();
            let party3 = FrostEd25519DkgHandler::init().await.unwrap();

            let sld_tld = SldTld::new(&REMOTE_SERVER.lock().await.organization).unwrap();

            {
                // Init SLD-TLD
                party1.set_new_sld_tld(sld_tld.unchecked()).await.unwrap();
                party2.set_new_sld_tld(sld_tld.unchecked()).await.unwrap();
                party3.set_new_sld_tld(sld_tld.unchecked()).await.unwrap();
            }

            let mut state = party1.get_state(&sld_tld).await.unwrap();

            {
                if state != FrostDkgState::InitCredentials {
                    panic!("Expected `FrostDkgState::InitCredentials` state");
                }

                let party1_id = "foo";
                let party2_id = "bar";
                let party3_id = "maa";

                let party1_credential =
                    FrostCredentialSeed::new_with_email_strict::<Ed25519Sha512>(
                        party1_id,
                        sld_tld.checked(),
                    )
                    .unwrap();
                let party2_credential =
                    FrostCredentialSeed::new_with_email_strict::<Ed25519Sha512>(
                        party2_id,
                        sld_tld.checked(),
                    )
                    .unwrap();
                let party3_credential =
                    FrostCredentialSeed::new_with_email_strict::<Ed25519Sha512>(
                        party3_id,
                        sld_tld.checked(),
                    )
                    .unwrap();

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

                party1
                    .set_credential(&sld_tld, party1_credential)
                    .await
                    .unwrap();

                party2
                    .set_credential(&sld_tld, party2_credential)
                    .await
                    .unwrap();

                party3
                    .set_credential(&sld_tld, party3_credential)
                    .await
                    .unwrap();
            }

            {
                // Fetch min max participants
                let party1_min_max = party1.set_dkg_participants(&sld_tld).await.unwrap();
                let party2_min_max = party2.set_dkg_participants(&sld_tld).await.unwrap();
                let party3_min_max = party3.set_dkg_participants(&sld_tld).await.unwrap();

                assert!(party1_min_max == FrostDkgState::Round1);
                assert!(party1_min_max == party2_min_max && party1_min_max == party3_min_max);
            }

            {
                // Perform round 1 broadcast
                party1.round1_dkg_broadcast(&sld_tld).await.unwrap();
                party2.round1_dkg_broadcast(&sld_tld).await.unwrap();
                party3.round1_dkg_broadcast(&sld_tld).await.unwrap();

                let (party1_inner_state, party1_round1_invalid_packages) =
                    party1.receive_round1_dkg_broadcast(&sld_tld).await.unwrap();
                let (party2_inner_state, party2_round1_invalid_packages) =
                    party2.receive_round1_dkg_broadcast(&sld_tld).await.unwrap();
                let (party3_inner_state, party3_round1_invalid_packages) =
                    party3.receive_round1_dkg_broadcast(&sld_tld).await.unwrap();

                assert!(party1_round1_invalid_packages.is_empty());
                assert!(party2_round1_invalid_packages.is_empty());
                assert!(party3_round1_invalid_packages.is_empty());
                assert_eq!(
                    party1_inner_state == party2_inner_state,
                    party1_inner_state == party3_inner_state
                );

                state = party1_inner_state;
            }

            if state != FrostDkgState::Round2 {
                panic!("Expected Round 2")
            }

            {
                // Perform round2 narrowcast
                party1.round2_dkg_unicast(&sld_tld).await.unwrap();
                party2.round2_dkg_unicast(&sld_tld).await.unwrap();
                party3.round2_dkg_unicast(&sld_tld).await.unwrap();

                let (party1_receive_round2, party1_invalid) =
                    party1.receive_round2_unicast(&sld_tld).await.unwrap();
                let (party2_receive_round2, party2_invalid) =
                    party2.receive_round2_unicast(&sld_tld).await.unwrap();
                let (party3_receive_round2, party3_invalid) =
                    party3.receive_round2_unicast(&sld_tld).await.unwrap();

                assert!(party1_receive_round2 == FrostDkgState::Part3);
                assert!(party2_receive_round2 == FrostDkgState::Part3);
                assert!(party3_receive_round2 == FrostDkgState::Part3);

                assert!(party1_invalid.is_empty());
                assert!(party2_invalid.is_empty());
                assert!(party3_invalid.is_empty());
            }

            {
                // Finalize DKG
                let party1_finalized = party1.finalize(&sld_tld).await.unwrap();
                let party2_finalized = party2.finalize(&sld_tld).await.unwrap();
                let party3_finalized = party3.finalize(&sld_tld).await.unwrap();

                assert!(party1_finalized == FrostDkgState::Finalized);
                assert!(party2_finalized == FrostDkgState::Finalized);
                assert!(party3_finalized == FrostDkgState::Finalized);
            }

            // Check validity
            let (party1_key_package, party1_public_package) =
                party1.get_finalized_packages(&sld_tld).await.unwrap();
            let (party2_key_package, party2_public_package) =
                party2.get_finalized_packages(&sld_tld).await.unwrap();
            let (party3_key_package, party3_public_package) =
                party3.get_finalized_packages(&sld_tld).await.unwrap();

            {
                assert_ne!(party1_key_package, party2_key_package);
                assert_ne!(party1_key_package, party3_key_package);
                assert_ne!(party2_key_package, party1_key_package);
                assert_ne!(party2_key_package, party3_key_package);
                assert_ne!(party3_key_package, party2_key_package);
                assert_ne!(party3_key_package, party1_key_package);

                assert_eq!(party1_public_package, party2_public_package);
                assert_eq!(party1_public_package, party3_public_package);
                assert_eq!(party2_public_package, party3_public_package);

                let party1_base58_private = party1_key_package
                    .verifying_key_base58::<frost_ed25519::Ed25519Sha512>()
                    .unwrap();
                let party2_base58_private = party2_key_package
                    .verifying_key_base58::<frost_ed25519::Ed25519Sha512>()
                    .unwrap();
                let party3_base58_private = party3_key_package
                    .verifying_key_base58::<frost_ed25519::Ed25519Sha512>()
                    .unwrap();
                assert_eq!(
                    party1_base58_private == party2_base58_private,
                    party1_base58_private == party3_base58_private
                );

                let party1_base58_public = party1_public_package
                    .verifying_key_base58::<frost_ed25519::Ed25519Sha512>()
                    .unwrap();
                let party2_base58_public = party2_public_package
                    .verifying_key_base58::<frost_ed25519::Ed25519Sha512>()
                    .unwrap();
                let party3_base58_public = party3_public_package
                    .verifying_key_base58::<frost_ed25519::Ed25519Sha512>()
                    .unwrap();

                assert_eq!(
                    party1_base58_public == party2_base58_public,
                    party1_base58_public == party3_base58_public
                );

                assert_eq!(party1_base58_private, party1_base58_public);
                assert_eq!(party2_base58_private, party2_base58_public);
                assert_eq!(party3_base58_private, party3_base58_public);
            }

            {
                // Test asymmetric keypair signing ops
                let party1_akp = party1.get_signing_keypair(&sld_tld).await.unwrap();
                let party2_akp = party2.get_signing_keypair(&sld_tld).await.unwrap();
                let party3_akp = party3.get_signing_keypair(&sld_tld).await.unwrap();

                assert!(party1_akp.signing_key() != party2_akp.signing_key());
                assert!(party1_akp.signing_key() != party3_akp.signing_key());
                assert!(party2_akp.signing_key() != party1_akp.signing_key());
                assert!(party2_akp.signing_key() != party3_akp.signing_key());
                assert!(party3_akp.signing_key() != party1_akp.signing_key());
                assert!(party3_akp.signing_key() != party2_akp.signing_key());

                for value in party1.get_participants(&sld_tld).await.unwrap().0 {
                    assert!(
                        value.1 == party2_akp.verifying_key_encodable()
                            || value.1 == party3_akp.verifying_key_encodable()
                    );

                    assert!(
                        value.0 == party2.credential_seed(&sld_tld).await.unwrap().unwrap()
                            || value.0 == party3.credential_seed(&sld_tld).await.unwrap().unwrap()
                    );

                    assert!(
                        value.0 != party1.credential_seed(&sld_tld).await.unwrap().unwrap()
                            && value.1 != party1_akp.verifying_key_encodable()
                    );
                }

                for value in party2.get_participants(&sld_tld).await.unwrap().0 {
                    assert!(
                        value.1 == party1_akp.verifying_key_encodable()
                            || value.1 == party3_akp.verifying_key_encodable()
                    );

                    assert!(
                        value.0 == party1.credential_seed(&sld_tld).await.unwrap().unwrap()
                            || value.0 == party3.credential_seed(&sld_tld).await.unwrap().unwrap()
                    );

                    assert!(
                        value.0 != party2.credential_seed(&sld_tld).await.unwrap().unwrap()
                            && value.1 != party2_akp.verifying_key_encodable()
                    );
                }

                for value in party3.get_participants(&sld_tld).await.unwrap().0 {
                    assert!(
                        value.1 == party1_akp.verifying_key_encodable()
                            || value.1 == party2_akp.verifying_key_encodable()
                    );

                    assert!(
                        value.0 == party1.credential_seed(&sld_tld).await.unwrap().unwrap()
                            || value.0 == party2.credential_seed(&sld_tld).await.unwrap().unwrap()
                    );

                    assert!(
                        value.0 != party3.credential_seed(&sld_tld).await.unwrap().unwrap()
                            && value.1 != party3_akp.verifying_key_encodable()
                    );
                }
            }
        })
    }

    #[derive(Debug, Clone)]
    struct ParticipantInfo {
        sld_tld: SldTld,
        min_max: Option<MinMaxParticipants>,
        ecdk: EphemeralClientDeviceKeypair,
        avpk: AsymmetricKeypairBytes,
        credential: Option<FrostCredentialSeed>,
        state: FrostDkgState,
        participants: FinalizedParticipants,
        round1_secret: Option<round1::Round1SecretBytes>,
        round1_package: Option<round1::Round1PackageBytes>,
        round2_secret: Option<round2::Round2SecretBytes>,
        round2_packages: Vec<FrostRoundPackage<round2::Round2PackageBytes>>,
        finalized_key_package: Option<FrostKeyPackageBytes>,
        finalized_public_package: Option<FrostPublicKeyPackage>,
    }

    struct ClientStorage {
        participant_info: HashMap<Blake3HashBytes, ParticipantInfo>,
        received_round1_packages: BTreeMap<Vec<u8>, FrostRoundPackage<round1::Round1PackageBytes>>,
        // Received from each participant using encrypted authenticated channel
        received_round2_packages: Vec<FrostRoundPackage<round2::Round2PackageBytes>>,
        events: BTreeMap<[u8; 44], FrostSigningEventInfo>,
    }

    impl FrostDkgStorage for Arc<RwLock<ClientStorage>> {
        // TODO test when state already initialized
        async fn init() -> FrostOpsResult<Self> {
            let init = ClientStorage {
                participant_info: HashMap::default(),
                received_round1_packages: BTreeMap::default(),
                received_round2_packages: Vec::default(),
                events: BTreeMap::default(),
            };

            Ok(Arc::new(RwLock::new(init)))
        }

        async fn set_sld_tld(&self, sld_tld: frost_dkg_types::SldTld) -> FrostOpsResult<()> {
            self.write()
                .await
                .participant_info
                .entry(sld_tld.to_storage_key())
                .or_insert(ParticipantInfo {
                    sld_tld,
                    min_max: Option::default(),
                    credential: Option::default(),
                    avpk: AsymmetricKeypairBytes::new()?,
                    ecdk: EphemeralClientDeviceKeypair::new()?,
                    state: FrostDkgState::InitCredentials,
                    participants: FinalizedParticipants(Vec::default()),
                    round1_secret: Option::default(),
                    round1_package: Option::default(),
                    round2_secret: Option::default(),
                    round2_packages: Vec::default(),
                    finalized_key_package: Option::default(),
                    finalized_public_package: Option::default(),
                });

            Ok(())
        }

        async fn get_all_sld_tlds(&self) -> FrostOpsResult<Vec<SldTld>> {
            Ok(self
                .read()
                .await
                .participant_info
                .values()
                .map(|value| value.sld_tld.clone())
                .collect())
        }

        async fn set_state(&self, sld_tld: &SldTld, state: FrostDkgState) -> FrostOpsResult<()> {
            self.write()
                .await
                .participant_info
                .get_mut(&sld_tld.to_storage_key())
                .map(|value| value.state = state)
                .ok_or(FrostOpsError::SldTldNotFound)?;

            Ok(())
        }

        async fn get_state(&self, sld_tld: &SldTld) -> FrostOpsResult<FrostDkgState> {
            self.read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| value.state)
                .ok_or(FrostOpsError::SldTldNotFound)
        }

        async fn set_credential(
            &self,
            sld_tld: &SldTld,
            credential: FrostCredentialSeed,
            new_state: FrostDkgState,
            avkp: AsymmetricKeypairBytes,
        ) -> FrostOpsResult<()> {
            self.write()
                .await
                .participant_info
                .get_mut(&sld_tld.to_storage_key())
                .map(|value| {
                    value.credential.replace(credential);
                    value.state = new_state;
                    value.avpk = avkp;
                })
                .ok_or(FrostOpsError::SldTldNotFound)?;

            Ok(())
        }

        async fn get_credential(
            &self,
            sld_tld: &SldTld,
        ) -> FrostOpsResult<Option<FrostCredentialSeed>> {
            self.read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| value.credential.clone())
                .ok_or(FrostOpsError::SldTldNotFound)
        }

        async fn get_state_and_register_envelope(
            &self,
            sld_tld: &SldTld,
        ) -> FrostOpsResult<(
            FrostDkgState,
            FrostRelayMessageEnvelope<FrostCredentialSeed>,
        )> {
            self.read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| {
                    let state = value.state;
                    let envelope = FrostRelayMessageEnvelope {
                        sld_tld_checked: sld_tld.checked().to_string(),
                        payload: value
                            .credential
                            .clone()
                            .ok_or(FrostOpsError::FrostCredentialNotSet)?,
                    };

                    Ok::<_, FrostOpsError>((state, envelope))
                })
                .transpose()?
                .ok_or(FrostOpsError::SldTldNotFound)
        }

        async fn get_dkg_min_max_participants(
            &self,
            sld_tld: &frost_dkg_types::SldTld,
        ) -> FrostOpsResult<Option<MinMaxParticipants>> {
            Ok(self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .and_then(|value| value.min_max))
        }

        async fn set_dkg_min_max_participants(
            &self,
            sld_tld: &SldTld,
            min_max: MinMaxParticipants,
            state: FrostDkgState,
        ) -> FrostOpsResult<()> {
            self.write()
                .await
                .participant_info
                .get_mut(&sld_tld.to_storage_key())
                .map(|value| {
                    value.min_max.replace(min_max);
                    value.state = state;
                })
                .ok_or(FrostOpsError::SldTldNotFound)?;

            Ok(())
        }

        async fn set_ecdk(
            &self,
            sld_tld: &SldTld,
            keypair: EphemeralClientDeviceKeypair,
        ) -> FrostOpsResult<()> {
            self.write()
                .await
                .participant_info
                .get_mut(&sld_tld.to_storage_key())
                .map(|value| value.ecdk = keypair)
                .ok_or(FrostOpsError::SldTldNotFound)?;

            Ok(())
        }

        async fn get_ecdk(
            &self,
            sld_tld: &SldTld,
        ) -> FrostOpsResult<Option<EphemeralClientDeviceKeypair>> {
            Ok(self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| value.ecdk.clone()))
        }

        async fn get_round1_package(
            &self,
            sld_tld: &SldTld,
        ) -> FrostOpsResult<(
            Option<round1::Round1PackageBytes>,
            frost_dkg_types::EphemeralClientDeviceVerifyingKey,
            FrostCredentialSeed,
            MinMaxParticipants,
        )> {
            self.read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| {
                    let round1_package = value.round1_package.clone();
                    let ecdvk = value.ecdk.clone().verifying_key;
                    let credential = value.credential.clone().unwrap();
                    let min_max = value.min_max.unwrap();

                    (round1_package, ecdvk, credential, min_max)
                })
                .ok_or(FrostOpsError::SldTldNotFound)
        }

        async fn set_round1_package(
            &self,
            sld_tld: &SldTld,
            round1_secret: round1::Round1SecretBytes,
            round1_package: round1::Round1PackageBytes,
        ) -> FrostOpsResult<()> {
            self.write()
                .await
                .participant_info
                .get_mut(&sld_tld.to_storage_key())
                .map(|value| {
                    value.round1_secret.replace(round1_secret);
                    value.round1_package.replace(round1_package);
                })
                .ok_or(FrostOpsError::SldTldNotFound)?;

            Ok(())
        }

        async fn get_participants(
            &self,
            sld_tld: &SldTld,
        ) -> FrostOpsResult<FinalizedParticipants> {
            Ok(self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| value.participants.clone())
                .unwrap())
        }

        async fn get_requirements_to_validate_a_broadcast(
            &self,
            sld_tld: &SldTld,
        ) -> FrostOpsResult<(
            FrostDkgState,
            Vec<FrostRoundPackage<round1::Round1PackageBytes>>,
            EphemeralClientDeviceKeypair,
            FrostCredentialSeed,
            MinMaxParticipants,
        )> {
            let (state, ecdk, credential, min_max) = self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| {
                    let state = value.state;
                    let ecdk = value.ecdk.clone();
                    let credential = value.credential.clone().unwrap();
                    let min_max = value.min_max.unwrap();

                    (state, ecdk, credential, min_max)
                })
                .ok_or(FrostOpsError::SldTldNotFound)?;

            let mut round1_received_packages =
                Vec::<FrostRoundPackage<round1::Round1PackageBytes>>::default();

            let prefix = sld_tld.to_storage_key().as_bytes().to_vec();
            for (key, value) in self
                .read()
                .await
                .received_round1_packages
                .range(prefix.clone()..)
            {
                if !key.starts_with(&prefix) {
                    break;
                }

                round1_received_packages.push(value.clone());
            }

            Ok((state, round1_received_packages, ecdk, credential, min_max))
        }

        async fn set_received_round1_packages(
            &self,
            sld_tld: &SldTld,
            state: FrostDkgState,
            round1_packages: Vec<FrostRoundPackage<round1::Round1PackageBytes>>,
        ) -> FrostOpsResult<()> {
            let mut writer = self.write().await;

            for package in round1_packages {
                writer
                    .received_round1_packages
                    .insert(package.to_storage_key(sld_tld), package);
            }

            writer
                .participant_info
                .get_mut(&sld_tld.to_storage_key())
                .map(|value| value.state = state)
                .ok_or(FrostOpsError::SldTldNotFound)
        }

        async fn get_requirements_to_create_round2(
            &self,
            sld_tld: &SldTld,
        ) -> FrostOpsResult<(
            FrostDkgState,
            Vec<FrostRoundPackage<round1::Round1PackageBytes>>,
            EphemeralClientDeviceKeypair,
            AsymmetricVerifyingKeyBytes,
            round1::Round1SecretBytes,
            FrostCredentialSeed,
        )> {
            let (state, ecdk, avk, credential) = self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| {
                    let state = value.state;
                    let ecdk = value.ecdk.clone();
                    let credential = value.credential.clone().unwrap();
                    let avk = value.avpk.verifying_key_encodable();

                    (state, ecdk, avk, credential)
                })
                .ok_or(FrostOpsError::SldTldNotFound)?;

            let mut round1_received_packages =
                Vec::<FrostRoundPackage<round1::Round1PackageBytes>>::default();

            let prefix = sld_tld.to_storage_key().as_bytes().to_vec();
            for (key, value) in self
                .read()
                .await
                .received_round1_packages
                .range(prefix.clone()..)
            {
                if !key.starts_with(&prefix) {
                    break;
                }

                round1_received_packages.push(value.clone());
            }
            let round1_secret = self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .unwrap()
                .round1_secret
                .clone()
                .unwrap();

            Ok((
                state,
                round1_received_packages,
                ecdk,
                avk,
                round1_secret,
                credential,
            ))
        }

        async fn set_round2_packages(
            &self,
            sld_tld: &SldTld,
            round2_secret: frost_dkg_types::round2::Round2SecretBytes,
            round2_packages: Vec<FrostRoundPackage<frost_dkg_types::round2::Round2PackageBytes>>,
        ) -> FrostOpsResult<()> {
            let mut writer = self.write().await;
            writer
                .participant_info
                .get_mut(&sld_tld.to_storage_key())
                .map(|value| {
                    value.round2_packages = round2_packages;
                    value.round2_secret.replace(round2_secret);
                })
                .unwrap();

            Ok(())
        }

        async fn get_round2_packages(
            &self,
            sld_tld: &SldTld,
        ) -> FrostOpsResult<Vec<FrostRoundPackage<round2::Round2PackageBytes>>> {
            Ok(self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| value.round2_packages.clone())
                .unwrap())
        }

        async fn set_received_round2_packages(
            &self,
            sld_tld: &SldTld,
            state: FrostDkgState,
            round2_packages: Vec<FrostRoundPackage<round2::Round2PackageBytes>>,
        ) -> FrostOpsResult<()> {
            let mut writer = self.write().await;
            writer
                .participant_info
                .get_mut(&sld_tld.to_storage_key())
                .map(|value| {
                    value.state = state;
                })
                .unwrap();

            writer.received_round2_packages = round2_packages;

            Ok(())
        }

        async fn get_requirements_to_verify_round2(
            &self,
            sld_tld: &SldTld,
        ) -> FrostOpsResult<(
            FrostDkgState,
            FrostCredentialSeed,
            Vec<FrostRoundPackage<round2::Round2PackageBytes>>,
            EphemeralClientDeviceKeypair,
            Round1Participants,
            MinMaxParticipants,
        )> {
            let (state, credential_seed, ecdk, min_max) = self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| {
                    let state = value.state;
                    let credential_seed = value.credential.as_ref().unwrap().clone();
                    let ecdk = value.ecdk.clone();
                    let min_max = value.min_max.unwrap();

                    (state, credential_seed, ecdk, min_max)
                })
                .unwrap();

            let participants = self
                .read()
                .await
                .received_round1_packages
                .values()
                .map(|value| value.credential_seed.clone())
                .collect::<Vec<FrostCredentialSeed>>();

            let round2_packages = self.read().await.received_round2_packages.clone();

            Ok((
                state,
                credential_seed,
                round2_packages,
                ecdk,
                Round1Participants(participants),
                min_max,
            ))
        }

        async fn get_requirements_to_perform_part3(
            &self,
            sld_tld: &SldTld,
        ) -> FrostOpsResult<(
            FrostDkgState,
            round2::Round2SecretBytes,
            Vec<FrostRoundPackage<round1::Round1PackageBytes>>,
            Vec<FrostRoundPackage<round2::Round2PackageBytes>>,
            FrostCredentialSeed,
            AsymmetricKeypairBytes,
            MinMaxParticipants,
        )> {
            let (state, round2_secret, credential, akp, min_max) = self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| {
                    let state = value.state;
                    let round2_secret = value.round2_secret.clone().unwrap();
                    let min_max = value.min_max.unwrap();
                    let akp = value.avpk.clone();
                    let credential = value.credential.clone().unwrap();

                    (state, round2_secret, credential, akp, min_max)
                })
                .unwrap();

            let round1_packages = self
                .read()
                .await
                .received_round1_packages
                .values()
                .cloned()
                .collect::<Vec<FrostRoundPackage<Round1PackageBytes>>>();

            let round2_packages = self.read().await.received_round2_packages.clone();

            Ok((
                state,
                round2_secret,
                round1_packages,
                round2_packages,
                credential,
                akp,
                min_max,
            ))
        }

        async fn set_part3_packages(
            &self,
            sld_tld: &SldTld,
            state: FrostDkgState,
            key_package: frost_dkg_types::finalized::FrostKeyPackageBytes,
            public_package: frost_dkg_types::finalized::FrostPublicKeyPackage,
            participants: FinalizedParticipants,
        ) -> FrostOpsResult<()> {
            let mut writer = self.write().await;
            writer
                .participant_info
                .get_mut(&sld_tld.to_storage_key())
                .map(|value| {
                    value.state = state;
                    value.finalized_key_package.replace(key_package);
                    value.finalized_public_package.replace(public_package);
                    value.participants = participants;
                })
                .unwrap();

            Ok(())
        }

        async fn get_finalized_packages(
            &self,
            sld_tld: &SldTld,
        ) -> FrostOpsResult<(FrostKeyPackageBytes, FrostPublicKeyPackage)> {
            Ok(self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| {
                    (
                        value.finalized_key_package.clone().unwrap(),
                        value.finalized_public_package.clone().unwrap(),
                    )
                })
                .unwrap())
        }
        async fn get_finalized_key_package(
            &self,
            sld_tld: &SldTld,
        ) -> FrostOpsResult<FrostKeyPackageBytes> {
            Ok(self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .and_then(|value| value.finalized_key_package.clone())
                .unwrap())
        }

        async fn get_finalized_public_package(
            &self,
            sld_tld: &SldTld,
        ) -> FrostOpsResult<FrostPublicKeyPackage> {
            Ok(self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .and_then(|value| value.finalized_public_package.clone())
                .unwrap())
        }

        async fn get_asymmetric_keypair(
            &self,
            sld_tld: &SldTld,
        ) -> FrostOpsResult<AsymmetricKeypairBytes> {
            Ok(self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| value.avpk.clone())
                .unwrap())
        }

        async fn get_asymmetric_verifying_key(
            &self,
            sld_tld: &SldTld,
        ) -> FrostOpsResult<AsymmetricVerifyingKeyBytes> {
            Ok(self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| value.avpk.verifying_key_encodable())
                .unwrap())
        }

        async fn check_if_signing_event_exists(
            &self,
            sld_tld: Blake3HashBytes,
            event_info: &frost_dkg_types::FrostSigningEvent,
        ) -> FrostOpsResult<(bool, FrostKeyPackageBytes)> {
            let key_package = self
                .read()
                .await
                .participant_info
                .get(&sld_tld)
                .map(|value| value.finalized_key_package.clone())
                .flatten()
                .unwrap();

            let event_exists = self
                .read()
                .await
                .events
                .get(event_info.to_storage_key().as_slice())
                .is_some();

            Ok((event_exists, key_package))
        }

        async fn get_requirements_to_verify_signature_shares(
            &self,
            sld_tld_hash: &Blake3HashBytes,
            event_key: FrostSigningEventKey,
        ) -> FrostOpsResult<(
            FrostCredentialSeed,
            FrostSigningEventInfo,
            FrostKeyPackageBytes,
            FrostPublicKeyPackage,
            FinalizedParticipants,
            AsymmetricKeypairBytes,
        )> {
            let (my_credential, key_package, public_package, finalized_participants, akp) = self
                .read()
                .await
                .participant_info
                .get(sld_tld_hash)
                .map(|value| {
                    let my_credential = value.credential.clone().unwrap();
                    let key_package = value.finalized_key_package.clone().unwrap();
                    let public_package = value.finalized_public_package.clone().unwrap();
                    let finalized_participants = value.participants.clone();
                    let akp = value.avpk.clone();

                    (
                        my_credential,
                        key_package,
                        public_package,
                        finalized_participants,
                        akp,
                    )
                })
                .unwrap();

            let stored_event = self
                .read()
                .await
                .events
                .get(event_key.as_slice())
                .cloned()
                .unwrap();

            Ok((
                my_credential,
                stored_event,
                key_package,
                public_package,
                finalized_participants,
                akp,
            ))
        }

        async fn get_requirements_to_validate_a_received_signal(
            &self,
            sld_tld_hash: Blake3HashBytes,
            event_key: FrostSigningEventKey,
        ) -> FrostOpsResult<(
            FrostDkgState,
            FrostCredentialSeed,
            FinalizedParticipants,
            Option<FrostSigningEventInfo>,
            MinMaxParticipants,
            AsymmetricKeypairBytes,
        )> {
            let (dkg_state, my_credential, finalized_participants, min_max, akp) = self
                .read()
                .await
                .participant_info
                .get(&sld_tld_hash)
                .map(|value| {
                    let dkg_state = value.state;
                    let my_credential = value.credential.clone().unwrap();
                    let min_max = value.min_max.unwrap();
                    let finalized_participants = value.participants.clone();
                    let akp = value.avpk.clone();

                    (
                        dkg_state,
                        my_credential,
                        finalized_participants,
                        min_max,
                        akp,
                    )
                })
                .unwrap();

            let stored_event = self.read().await.events.get(event_key.as_slice()).cloned();

            Ok((
                dkg_state,
                my_credential,
                finalized_participants,
                stored_event,
                min_max,
                akp,
            ))
        }

        async fn get_requirements_to_verify_event(
            &self,
            sld_tld_hash: &Blake3HashBytes,
            event_key: FrostSigningEventKey,
        ) -> FrostOpsResult<(
            FrostCredentialSeed,
            FrostSigningEventInfo,
            FinalizedParticipants,
            FrostKeyPackageBytes,
            AsymmetricKeypairBytes,
            SldTld,
        )> {
            let (my_credential, finalized_participants, key_package, akp, sld_tld) = self
                .read()
                .await
                .participant_info
                .get(&sld_tld_hash)
                .map(|value| {
                    let my_credential = value.credential.clone().unwrap();
                    let key_package = value.finalized_key_package.clone().unwrap();
                    let finalized_participants = value.participants.clone();
                    let akp = value.avpk.clone();
                    let sld_tld = value.sld_tld.clone();

                    (
                        my_credential,
                        finalized_participants,
                        key_package,
                        akp,
                        sld_tld,
                    )
                })
                .unwrap();

            let stored_event = self
                .read()
                .await
                .events
                .get(event_key.as_slice())
                .cloned()
                .unwrap();

            Ok((
                my_credential,
                stored_event,
                finalized_participants,
                key_package,
                akp,
                sld_tld,
            ))
        }

        async fn set_signing_event(&self, event_info: FrostSigningEventInfo) -> FrostOpsResult<()> {
            self.write()
                .await
                .events
                .insert(event_info.to_storage_key(), event_info);

            Ok(())
        }
    }

    struct RelayMemNetwork(SldTld);

    impl FrostAuthenticatedChannel for RelayMemNetwork {
        async fn init() -> FrostOpsResult<Self> {
            Ok(Self(SldTld::new("example.com").unwrap()))
        }

        async fn fetch_min_max_participants(
            &self,
            envelope: FrostRelayMessageEnvelope<FrostCredentialSeed>,
        ) -> FrostOpsResult<MinMaxParticipants> {
            assert!(self.0.checked() == envelope.sld_tld_checked);

            let mut remote_lock = REMOTE_SERVER.lock().await;

            remote_lock.participants.push(envelope.payload);

            Ok(remote_lock.min_max)
        }

        async fn is_active_domain(
            &self,
            _sld_tld: &frost_dkg_types::SldTld,
        ) -> FrostOpsResult<bool> {
            Ok(true)
        }

        async fn transmit_round1_broadcast(
            &self,
            _sld_tld: &SldTld,
            envelope: FrostMessageEnvelope,
        ) -> FrostOpsResult<()> {
            REMOTE_SERVER
                .lock()
                .await
                .receive_round1_dkg_broadcast(envelope);

            Ok(())
        }

        async fn fetch_round1_broadcasts(
            &self,
            _sld_tld: &SldTld,
        ) -> FrostOpsResult<Vec<FrostMessageEnvelope>> {
            Ok(REMOTE_SERVER
                .lock()
                .await
                .round1_dkg_messages
                .iter()
                .cloned()
                .collect())
        }

        async fn transmit_round2_unicast(
            &self,
            _sld_tld: &SldTld,
            envelopes: Vec<FrostMessageEnvelope>,
        ) -> FrostOpsResult<()> {
            REMOTE_SERVER
                .lock()
                .await
                .receive_round2_dkg_unicast(envelopes);

            Ok(())
        }

        async fn fetch_round2_uni_casts(
            &self,
            _sld_tld: &SldTld,
            credential_seed: &FrostCredentialSeed,
        ) -> FrostOpsResult<Vec<FrostMessageEnvelope>> {
            Ok(REMOTE_SERVER
                .lock()
                .await
                .round2_dkg_messages
                .get(credential_seed)
                .cloned()
                .unwrap())
        }

        async fn signal_ack(
            &self,
            ack: frost_dkg_types::SignalAcknowledgement,
        ) -> FrostOpsResult<()> {
            todo!()
        }

        async fn finalized_signing_event(
            &self,
            sld_tld: &SldTld,
            finalized: frost_dkg_types::FinalizedSigningEvent,
        ) -> FrostOpsResult<()> {
            todo!()
        }

        async fn receive_round2_signature_shares(
            &self,
            event_hash: frost_dkg_types::FrostEventHash,
            shares: Vec<frost_dkg_types::TransmitFrostRound2>,
        ) -> FrostOpsResult<()> {
            todo!()
        }

        async fn update_signing_event(
            &self,
            sld_tld: SldTld,
            payload: frost_dkg_types::TransmitFrostRound2,
        ) -> FrostOpsResult<()> {
            todo!()
        }
    }

    #[derive(Debug, Default)]
    struct RemoteServer {
        organization: String,
        min_max: MinMaxParticipants,
        participants: Vec<FrostCredentialSeed>,
        round1_dkg_messages: HashSet<FrostMessageEnvelope>,
        round2_dkg_messages: HashMap<FrostCredentialSeed, Vec<FrostMessageEnvelope>>,
        messages: BTreeMap<FrostSigningEventKey, FrostSigningEventInfo>,
    }

    impl RemoteServer {
        fn new(organization: &str) -> Self {
            Self {
                organization: organization.to_string(),
                min_max: MinMaxParticipants { min: 2, max: 3 },
                ..Default::default()
            }
        }

        fn set_min_max(&mut self, min_max: MinMaxParticipants) -> &mut Self {
            self.min_max = min_max;

            self
        }

        fn is_valid_participant(&self, participant: &FrostCredentialSeed) -> bool {
            self.participants.iter().any(|stored| stored == participant)
        }

        fn transmission_checks(&mut self, data: &FrostMessageEnvelope) {
            if data.sld_tld() != self.organization {
                panic!("Invalid organization");
            }

            if !self.is_valid_participant(data.sender_credential_seed()) {
                panic!("Invalid sender participant");
            }

            if let Some(participant) = data.recipient_credential_seed().as_ref()
                && !self.is_valid_participant(participant)
            {
                panic!("Recipient is an invalid participant");
            }
        }

        fn receive_round1_dkg_broadcast(&mut self, data: FrostMessageEnvelope) {
            self.transmission_checks(&data);
            // In real world add to queue
            self.round1_dkg_messages.insert(data);
        }

        fn receive_round2_dkg_unicast(&mut self, envelopes: Vec<FrostMessageEnvelope>) {
            for data in envelopes {
                self.round2_dkg_messages
                    .entry(data.recipient_credential_seed().unwrap().clone())
                    .and_modify(|v| {
                        v.push(data.clone());
                        v.dedup();
                    })
                    .or_insert(vec![data]);
            }
        }
    }
}
