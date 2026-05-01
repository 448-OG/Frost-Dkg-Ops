use std::{
    collections::{BTreeMap, HashMap},
    marker::PhantomData,
};

use frost_core::Ciphersuite;

use frost_dkg_types::{
    DkgParticipants, EphemeralClientDeviceVerifyingKey, FrostCredential, FrostCredentialSeed,
    FrostDkgState, FrostMessageEnvelope, FrostOpsError, FrostOpsResult, FrostRoundPackage, SldTld,
    Tai64NTimestamp, TransmitType,
    finalized::{FrostKeyPackageBytes, FrostPublicKeyPackage},
    round1, round2,
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

    pub async fn set_new_sld_tld(&self, sld_tld: &str) -> FrostOpsResult<()> {
        let domain = SldTld::new(sld_tld)?;

        self.channel.is_active_domain(&domain).await?;

        self.storage.set_sld_tld(domain).await?;

        Ok(())
    }

    pub async fn set_credential(
        &self,
        sld_tld: &SldTld,
        credential: FrostCredential<C>,
    ) -> FrostOpsResult<FrostDkgState> {
        let current = self.storage.get_state(sld_tld).await?;
        let expected = FrostDkgState::InitCredentials;

        if current != expected {
            return Err(FrostOpsError::InvalidClientState { current, expected });
        }

        let new_state = current.transition();

        self.storage
            .set_credential(sld_tld, credential, new_state)
            .await?;

        Ok(new_state)
    }

    pub async fn set_dkg_participants(&self, sld_tld: &SldTld) -> FrostOpsResult<FrostDkgState> {
        let (current, envelope) = self
            .storage
            .get_state_and_register_envelope(sld_tld)
            .await?;
        let expected = FrostDkgState::QueryMinMax;

        if current != expected {
            return Err(FrostOpsError::InvalidClientState { current, expected });
        }

        let min_max = self.channel.fetch_min_max_participants(envelope).await?;

        let new_state = current.transition();

        self.storage
            .set_dkg_min_max_participants(sld_tld, min_max, new_state)
            .await?;

        Ok(new_state)
    }

    pub async fn round1_dkg_broadcast(&self, sld_tld: &SldTld) -> FrostOpsResult<()> {
        let (round1_package_queried, ecdvk, credential, min_max) =
            self.storage.get_round1_package(sld_tld).await?;

        let envelope: FrostMessageEnvelope = if let Some(package) = round1_package_queried {
            FrostMessageEnvelope::new_broadcast(credential.seed_take())
                .set_sld_tld(sld_tld.checked())
                .generate_empty_he_outputs(ecdvk, &package)?
        } else {
            let (round1_secret, round1_package) = frost_core::keys::dkg::part1(
                credential.frost_identifier(),
                min_max.max,
                min_max.min,
                rand::rngs::OsRng,
            )?;

            let encode_secret = round1::Round1SecretBytes::new(round1_secret)?;
            let round1_package = round1::Round1PackageBytes::parse(&round1_package)?;

            self.storage
                .set_round1_package(sld_tld, encode_secret, round1_package.clone())
                .await?;

            FrostMessageEnvelope::new_broadcast(credential.seed_take())
                .set_sld_tld(sld_tld.checked())
                .generate_empty_he_outputs(ecdvk, &round1_package)?
        };

        self.channel
            .transmit_round1_broadcast(sld_tld, envelope)
            .await
    }

    /// Ignores a [FrostMessageEnvelope] if the credential seed or static verifying key are
    /// the same as those of the current user
    pub async fn receive_round1_dkg_broadcast(
        &self,
        sld_tld: &SldTld,
    ) -> FrostOpsResult<(FrostDkgState, Vec<(FrostMessageEnvelope, FrostOpsError)>)> {
        let (
            mut current_state,
            mut fetched_received_round1_packages,
            my_ecdk,
            my_frost_credential,
            min_max,
        ) = self
            .storage
            .get_requirements_to_validate_a_broadcast(sld_tld)
            .await?;
        let expected_state = FrostDkgState::Round1;

        if current_state != expected_state {
            return Err(FrostOpsError::InvalidClientState {
                current: current_state,
                expected: expected_state,
            });
        }

        let my_ecdvk = my_ecdk.clone().verifying_key_encodable();

        let round1 = self.channel.fetch_round1_broadcasts(sld_tld).await?;

        let mut invalid = Vec::<(FrostMessageEnvelope, FrostOpsError)>::default();

        for envelope in round1 {
            if envelope.sld_tld() != sld_tld.checked() {
                invalid.push((envelope.clone(), FrostOpsError::InvalidSldTld));

                continue;
            }

            if envelope.sender_credential_seed().as_bytes().is_empty() {
                invalid.push((envelope.clone(), FrostOpsError::InvalidFrostCredentialSeed));
                continue;
            }

            if envelope.sender_credential_seed() == my_frost_credential.seed() {
                continue;
            }

            if envelope.sender_static_verifying_key().0.is_empty() {
                invalid.push((
                    envelope.clone(),
                    FrostOpsError::InvalidEphemeralDeviceStaticVerifyingKey,
                ));

                continue;
            }

            if envelope.sender_static_verifying_key() == &my_ecdvk {
                continue;
            }

            if envelope.transmission_type() != TransmitType::Broadcast {
                invalid.push((
                    envelope.clone(),
                    FrostOpsError::InvalidTransmission {
                        current: envelope.transmission_type(),
                        expected: TransmitType::Broadcast,
                    },
                ));

                continue;
            }

            if !envelope.sender_he_verifying_key().0.is_empty() {
                invalid.push((
                    envelope.clone(),
                    FrostOpsError::MissingEphemeralHeVerifyingKey,
                ));

                continue;
            }

            let decoded_payload = match envelope.clone().decode_empty_he_outputs() {
                Err(error) => {
                    invalid.push((envelope.clone(), error));

                    continue;
                }
                Ok(value) => value,
            };

            let decoded_broadcast = match round1::Round1PackageBytes::decode(&decoded_payload) {
                Ok(value) => value,
                Err(error) => {
                    invalid.push((envelope.clone(), error));

                    continue;
                }
            };

            fetched_received_round1_packages.push(FrostRoundPackage {
                timestamp: envelope.timestamp(),
                credential_seed: envelope.sender_credential_seed().clone(),
                ecdvk: envelope.sender_static_verifying_key().clone(),
                payload: decoded_broadcast,
            });
        }

        fetched_received_round1_packages.dedup();

        // `+1` because I am also a participant
        let parsed_packages_len = fetched_received_round1_packages.len() + 1;

        if parsed_packages_len > min_max.max as usize {
            return Err(FrostOpsError::InvalidNumOfParticipants);
        }

        if parsed_packages_len == min_max.max as usize {
            current_state = current_state.transition();
        }

        self.storage
            .set_received_round1_packages(sld_tld, current_state, fetched_received_round1_packages)
            .await?;

        Ok((current_state, invalid))
    }

    pub async fn round2_dkg_unicast(&self, sld_tld: &SldTld) -> FrostOpsResult<()> {
        let (
            current_state,
            fetched_received_round1_packages,
            my_ecdk,
            round1_secret,
            my_credential_seed,
        ) = self
            .storage
            .get_requirements_to_create_round2(sld_tld)
            .await?;
        let expected_state = FrostDkgState::Round2;

        if current_state != expected_state {
            return Err(FrostOpsError::InvalidClientState {
                current: current_state,
                expected: expected_state,
            });
        }

        self.prepare_and_store_round2_dkg_packages(
            sld_tld,
            round1_secret,
            fetched_received_round1_packages,
        )
        .await?;

        let get_round2_packages = self.storage.get_round2_packages(sld_tld).await?;

        let envelopes = get_round2_packages
            .into_iter()
            .map(|value| {
                FrostMessageEnvelope::new_unicast(my_credential_seed.clone())
                    .set_sld_tld(sld_tld.checked())
                    .set_recipient_credential_seed(value.credential_seed)
                    .generate_he_outputs(my_ecdk.clone(), value.ecdvk, &value.payload)
            })
            .collect::<FrostOpsResult<Vec<FrostMessageEnvelope>>>()?;

        self.channel
            .transmit_round2_unicast(sld_tld, envelopes)
            .await
    }

    async fn prepare_and_store_round2_dkg_packages(
        &self,
        sld_tld: &SldTld,
        round1_secret: round1::Round1SecretBytes,
        fetched_received_round1_packages: Vec<FrostRoundPackage<round1::Round1PackageBytes>>,
    ) -> FrostOpsResult<()> {
        let mut prepare_round1_received_packages = BTreeMap::<
            frost_core::Identifier<C>,
            frost_core::keys::dkg::round1::Package<C>,
        >::default();

        let mut identifier_mapping = HashMap::<
            frost_core::Identifier<C>,
            (FrostCredentialSeed, EphemeralClientDeviceVerifyingKey),
        >::default();

        fetched_received_round1_packages
            .iter()
            .try_for_each(|package| {
                let identifier = package.credential_seed.frost_identifier::<C>()?;
                identifier_mapping.insert(
                    identifier,
                    (package.credential_seed.clone(), package.ecdvk.clone()),
                );

                let round1_package = package.payload.to_frost_package::<C>()?;

                prepare_round1_received_packages.insert(identifier, round1_package);

                Ok::<_, FrostOpsError>(())
            })?;

        let round1_secret = round1_secret.deserialize::<C>()?;

        let (mut part2_secret, part2_packages) =
            frost_core::keys::dkg::part2::<C>(round1_secret, &prepare_round1_received_packages)?;

        let part2_secret_bytes = round2::Round2SecretBytes::serialize(&part2_secret)?;
        part2_secret.zeroize();

        let part2_prepared_packages = part2_packages
            .into_iter()
            .map(|(identifier, package)| {
                let payload = round2::Round2PackageBytes::parse(&package)?;

                let timestamp = Tai64NTimestamp::now();

                let (credential_seed, ecdvk) = identifier_mapping
                    .get(&identifier)
                    .ok_or(FrostOpsError::UnableToGetTheIdentifierMapping(
                        faster_hex::hex_string_upper(identifier.serialize().as_slice()),
                    ))?
                    .clone();

                let package_with_info = FrostRoundPackage {
                    timestamp,
                    credential_seed,
                    ecdvk,
                    payload,
                };

                Ok::<_, FrostOpsError>(package_with_info)
            })
            .collect::<FrostOpsResult<Vec<FrostRoundPackage<round2::Round2PackageBytes>>>>()?;

        self.storage
            .set_round2_packages(sld_tld, part2_secret_bytes, part2_prepared_packages)
            .await?;

        Ok(())
    }

    pub async fn receive_round2_unicast(
        &self,
        sld_tld: &SldTld,
    ) -> FrostOpsResult<(FrostDkgState, Vec<(FrostMessageEnvelope, FrostOpsError)>)> {
        let (
            mut current_state,
            my_credential_seed,
            mut stored_received_round2_packages,
            my_ecdk,
            round1_participants,
            min_max,
        ) = self
            .storage
            .get_requirements_to_verify_round2(sld_tld)
            .await?;
        let expected_state = FrostDkgState::Round2;

        if current_state != expected_state {
            return Err(FrostOpsError::InvalidClientState {
                current: current_state,
                expected: expected_state,
            });
        }

        let round2_envelopes = self
            .channel
            .fetch_round2_uni_casts(sld_tld, &my_credential_seed)
            .await?;

        let mut invalid_envelopes = Vec::<(FrostMessageEnvelope, FrostOpsError)>::default();

        for envelope in round2_envelopes {
            if let Some(recipient_exists) = envelope.recipient_credential_seed()
                && recipient_exists != &my_credential_seed
            {
                invalid_envelopes.push((envelope.clone(), FrostOpsError::InvalidRecipient));

                continue;
            }

            if !round1_participants.is_valid_participant(envelope.sender_credential_seed()) {
                invalid_envelopes.push((envelope.clone(), FrostOpsError::InvalidParticipant));

                continue;
            }

            if envelope.sld_tld() != sld_tld.checked() {
                invalid_envelopes.push((envelope.clone(), FrostOpsError::InvalidSldTld));

                continue;
            }

            let decrypted = match envelope.clone().decode_he_outputs(my_ecdk.clone()) {
                Ok(value) => value,
                Err(error) => {
                    invalid_envelopes.push((envelope.clone(), error));

                    continue;
                }
            };

            let payload = match round2::Round2PackageBytes::decode(&decrypted) {
                Ok(value) => value,
                Err(error) => {
                    invalid_envelopes.push((envelope.clone(), error));

                    continue;
                }
            };

            let prepared = FrostRoundPackage {
                timestamp: envelope.timestamp(),
                credential_seed: envelope.sender_credential_seed().clone(),
                ecdvk: envelope.sender_static_verifying_key().clone(),
                payload,
            };

            stored_received_round2_packages.push(prepared);
        }

        stored_received_round2_packages.dedup();

        let num_participants = stored_received_round2_packages.len() + 1;

        if num_participants > min_max.max as usize {
            return Err(FrostOpsError::InvalidNumOfParticipants);
        }

        if num_participants == min_max.max as usize {
            current_state = current_state.transition();
        }

        self.storage
            .set_received_round2_packages(sld_tld, current_state, stored_received_round2_packages)
            .await?;

        Ok((current_state, invalid_envelopes))
    }

    pub async fn finalize(&self, sld_tld: &SldTld) -> FrostOpsResult<FrostDkgState> {
        let (mut current_state, round2_secret, round1_received_packages, round2_received_packages) =
            self.storage
                .get_requirements_to_perform_part3(sld_tld)
                .await?;

        let expected_state = FrostDkgState::Part3;

        if current_state != expected_state {
            return Err(FrostOpsError::InvalidClientState {
                current: current_state,
                expected: expected_state,
            });
        }

        let mut prepared_round1_public_packages = BTreeMap::<
            frost_core::Identifier<C>,
            frost_core::keys::dkg::round1::Package<C>,
        >::default();

        let mut prepared_round2_public_packages = BTreeMap::<
            frost_core::Identifier<C>,
            frost_core::keys::dkg::round2::Package<C>,
        >::default();

        let mut final_participants = Vec::<FrostCredentialSeed>::default();

        round1_received_packages.into_iter().try_for_each(|value| {
            let identifier = value.credential_seed.frost_identifier::<C>()?;
            let package = value.payload.to_frost_package::<C>()?;

            prepared_round1_public_packages.insert(identifier, package);

            final_participants.push(value.credential_seed);

            Ok::<_, FrostOpsError>(())
        })?;

        round2_received_packages.into_iter().try_for_each(|value| {
            let identifier = value.credential_seed.frost_identifier::<C>()?;
            let package = value.payload.to_frost_package::<C>()?;

            prepared_round2_public_packages.insert(identifier, package);

            Ok::<_, FrostOpsError>(())
        })?;

        let round2_secret_package = round2_secret.deserialize::<C>()?;

        let (mut key_package, public_package) = frost_core::keys::dkg::part3(
            &round2_secret_package,
            &prepared_round1_public_packages,
            &prepared_round2_public_packages,
        )?;

        let key_package_bytes = FrostKeyPackageBytes::encode(&key_package)?;
        key_package.zeroize();
        let public_package_bytes = FrostPublicKeyPackage::encode(&public_package)?;

        current_state = current_state.transition();

        self.storage
            .set_part3_packages(
                sld_tld,
                current_state,
                key_package_bytes,
                public_package_bytes,
                DkgParticipants(final_participants),
            )
            .await?;

        Ok(current_state)
    }

    pub async fn get_participants(&self, sld_tld: &SldTld) -> FrostOpsResult<DkgParticipants> {
        self.storage.get_participants(sld_tld).await
    }

    pub async fn get_finalized_packages(
        &self,
        sld_tld: &SldTld,
    ) -> FrostOpsResult<(FrostKeyPackageBytes, FrostPublicKeyPackage)> {
        self.storage.get_finalized_packages(sld_tld).await
    }

    pub async fn get_finalized_key_package(
        &self,
        sld_tld: &SldTld,
    ) -> FrostOpsResult<FrostKeyPackageBytes> {
        self.storage.get_finalized_key_package(sld_tld).await
    }

    pub async fn get_finalized_public_package(
        &self,
        sld_tld: &SldTld,
    ) -> FrostOpsResult<FrostPublicKeyPackage> {
        self.storage.get_finalized_public_package(sld_tld).await
    }
}

#[cfg(test)]
mod sanity_checks {
    use std::{
        collections::{BTreeMap, HashMap, HashSet},
        marker::PhantomData,
        sync::LazyLock,
    };

    use async_dup::Arc;
    use async_lock::{Mutex, RwLock};
    use frost_core::Ciphersuite;
    use frost_dkg_types::{
        Blake3HashBytes, DkgParticipants, EphemeralClientDeviceKeypair, FrostCredential,
        FrostCredentialSeed, FrostDkgState, FrostMessageEnvelope, FrostOpsError, FrostOpsResult,
        FrostRelayMessageEnvelope, FrostRoundPackage, MinMaxParticipants, SldTld,
        finalized::{FrostKeyPackageBytes, FrostPublicKeyPackage},
        round1::{self, Round1PackageBytes},
        round2,
    };

    use crate::{DkgStateHandler, FrostAuthenticatedChannel, FrostDkgStorage};

    type FrostEd25519DkgHandler = DkgStateHandler<
        frost_ed25519::Ed25519Sha512,
        Arc<RwLock<ClientStorage<frost_ed25519::Ed25519Sha512>>>,
        RelayMemNetwork<frost_ed25519::Ed25519Sha512>,
    >;

    type FrostCredentialEd25519 = FrostCredential<frost_ed25519::Ed25519Sha512>;

    static REMOTE_SERVER: LazyLock<Mutex<RemoteServer>> = LazyLock::new(|| {
        let sld_tld = SldTld::new("example.com").unwrap();

        Mutex::new(RemoteServer::new(sld_tld.checked()))
    });

    #[test]
    fn register_credential() {
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

            let mut state = party1.storage.get_state(&sld_tld).await.unwrap();

            {
                if state != FrostDkgState::InitCredentials {
                    panic!("Expected `FrostDkgState::InitCredentials` state");
                }

                let party1_id = "foo";
                let party2_id = "bar";
                let party3_id = "maa";

                let party1_credential =
                    FrostCredentialEd25519::new_with_email_strict(party1_id, sld_tld.checked())
                        .unwrap();
                let party2_credential =
                    FrostCredentialEd25519::new_with_email_strict(party2_id, sld_tld.checked())
                        .unwrap();
                let party3_credential =
                    FrostCredentialEd25519::new_with_email_strict(party3_id, sld_tld.checked())
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
        })
    }

    #[derive(Debug, Clone)]
    struct ParticipantInfo<C: Ciphersuite> {
        sld_tld: SldTld,
        min_max: Option<MinMaxParticipants>,
        ecdk: EphemeralClientDeviceKeypair,
        credential: Option<FrostCredential<C>>,
        state: FrostDkgState,
        participants: DkgParticipants,
        round1_secret: Option<round1::Round1SecretBytes>,
        round1_package: Option<round1::Round1PackageBytes>,
        round2_secret: Option<round2::Round2SecretBytes>,
        round2_packages: Vec<FrostRoundPackage<round2::Round2PackageBytes>>,
        finalized_key_package: Option<FrostKeyPackageBytes>,
        finalized_public_package: Option<FrostPublicKeyPackage>,
    }

    struct ClientStorage<C: Ciphersuite> {
        participant_info: HashMap<Blake3HashBytes, ParticipantInfo<C>>,
        received_round1_packages: BTreeMap<Vec<u8>, FrostRoundPackage<round1::Round1PackageBytes>>,
        // Received from each participant using encrypted authenticated channel
        received_round2_packages: Vec<FrostRoundPackage<round2::Round2PackageBytes>>,
    }

    impl<C: Ciphersuite> FrostDkgStorage<C> for Arc<RwLock<ClientStorage<C>>> {
        // TODO test when state already initialized
        async fn init() -> FrostOpsResult<Self> {
            let init = ClientStorage {
                participant_info: HashMap::default(),
                received_round1_packages: BTreeMap::default(),
                received_round2_packages: Vec::default(),
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
                    ecdk: EphemeralClientDeviceKeypair::new()?,
                    state: FrostDkgState::InitCredentials,
                    participants: DkgParticipants(Vec::default()),
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
            credential: FrostCredential<C>,
            new_state: FrostDkgState,
        ) -> FrostOpsResult<()> {
            self.write()
                .await
                .participant_info
                .get_mut(&sld_tld.to_storage_key())
                .map(|value| {
                    value.credential.replace(credential);
                    value.state = new_state;
                })
                .ok_or(FrostOpsError::SldTldNotFound)?;

            Ok(())
        }

        async fn get_credential(
            &self,
            sld_tld: &SldTld,
        ) -> FrostOpsResult<Option<FrostCredential<C>>> {
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
                            .ok_or(FrostOpsError::FrostCredentialNotSet)?
                            .seed_take(),
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
            FrostCredential<C>,
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

        async fn get_participants(&self, sld_tld: &SldTld) -> FrostOpsResult<DkgParticipants> {
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
            FrostCredential<C>,
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
            round1::Round1SecretBytes,
            FrostCredentialSeed,
        )> {
            let (state, ecdk, credential) = self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| {
                    let state = value.state;
                    let ecdk = value.ecdk.clone();
                    let credential = value.credential.clone().unwrap();

                    (state, ecdk, credential)
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
                round1_secret,
                credential.seed_take(),
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
            frost_dkg_types::DkgParticipants,
            MinMaxParticipants,
        )> {
            let (state, credential_seed, ecdk, min_max) = self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| {
                    let state = value.state;
                    let credential_seed = value.credential.as_ref().unwrap().seed().clone();
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
                DkgParticipants(participants),
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
        )> {
            let (state, round2_secret) = self
                .read()
                .await
                .participant_info
                .get(&sld_tld.to_storage_key())
                .map(|value| {
                    let state = value.state;
                    let round2_secret = value.round2_secret.clone().unwrap();

                    (state, round2_secret)
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

            Ok((state, round2_secret, round1_packages, round2_packages))
        }

        async fn set_part3_packages(
            &self,
            sld_tld: &SldTld,
            state: FrostDkgState,
            key_package: frost_dkg_types::finalized::FrostKeyPackageBytes,
            public_package: frost_dkg_types::finalized::FrostPublicKeyPackage,
            participants: DkgParticipants,
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
    }

    struct RelayMemNetwork<C: Ciphersuite>(SldTld, PhantomData<C>);

    impl<C: Ciphersuite> FrostAuthenticatedChannel<C> for RelayMemNetwork<C> {
        async fn init() -> FrostOpsResult<Self> {
            Ok(Self(SldTld::new("example.com").unwrap(), PhantomData))
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
    }

    #[derive(Debug, Default)]
    struct RemoteServer {
        organization: String,
        min_max: MinMaxParticipants,
        participants: Vec<FrostCredentialSeed>,
        round1_dkg_messages: HashSet<FrostMessageEnvelope>,
        round2_dkg_messages: HashMap<FrostCredentialSeed, Vec<FrostMessageEnvelope>>,
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
