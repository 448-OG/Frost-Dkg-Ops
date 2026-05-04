use std::{
    collections::{BTreeMap, HashMap},
    marker::PhantomData,
};

use frost_core::Ciphersuite;

use frost_dkg_types::{
    AsymmetricKeypairBytes, AsymmetricVerifyingKeyBytes, EphemeralClientDeviceVerifyingKey,
    FinalizedParticipants, FrostCredentialSeed, FrostDkgState, FrostMessageEnvelope, FrostOpsError,
    FrostOpsResult, FrostRoundPackage, SldTld, Tai64NTimestamp, TransmitType,
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

    pub async fn get_state(&self, sld_tld: &SldTld) -> FrostOpsResult<FrostDkgState> {
        self.storage.get_state(sld_tld).await
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
        credential: FrostCredentialSeed,
    ) -> FrostOpsResult<FrostDkgState> {
        let current = self.storage.get_state(sld_tld).await?;
        let expected = FrostDkgState::InitCredentials;

        if current != expected {
            return Err(FrostOpsError::InvalidClientState { current, expected });
        }

        let new_state = current.transition();
        let avk = AsymmetricKeypairBytes::new()?;

        self.storage
            .set_credential(sld_tld, credential, new_state, avk)
            .await?;

        Ok(new_state)
    }

    pub async fn credential_seed(
        &self,
        sld_tld: &SldTld,
    ) -> FrostOpsResult<Option<FrostCredentialSeed>> {
        self.storage.get_credential(sld_tld).await
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
            FrostMessageEnvelope::new_broadcast(credential)
                .set_sld_tld(sld_tld.checked())
                .generate_empty_he_outputs(ecdvk, &package)?
        } else {
            let (round1_secret, round1_package) = frost_core::keys::dkg::part1(
                credential.frost_identifier::<C>()?,
                min_max.max,
                min_max.min,
                rand::rngs::OsRng,
            )?;

            let encode_secret = round1::Round1SecretBytes::new(round1_secret)?;
            let round1_package = round1::Round1PackageBytes::parse(&round1_package)?;

            self.storage
                .set_round1_package(sld_tld, encode_secret, round1_package.clone())
                .await?;

            FrostMessageEnvelope::new_broadcast(credential)
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

            if envelope.sender_credential_seed() == &my_frost_credential {
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
            avk,
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
            avk,
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
        avk: AsymmetricVerifyingKeyBytes,
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
                let payload = round2::Round2PackageBytes::parse(&package, avk)?;

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

        let mut final_participants =
            Vec::<(FrostCredentialSeed, AsymmetricVerifyingKeyBytes)>::default();

        round1_received_packages.into_iter().try_for_each(|value| {
            let identifier = value.credential_seed.frost_identifier::<C>()?;
            let package = value.payload.to_frost_package::<C>()?;

            prepared_round1_public_packages.insert(identifier, package);

            Ok::<_, FrostOpsError>(())
        })?;

        round2_received_packages.into_iter().try_for_each(|value| {
            let identifier = value.credential_seed.frost_identifier::<C>()?;
            let package = value.payload.to_frost_package::<C>()?;

            prepared_round2_public_packages.insert(identifier, package);

            final_participants.push((value.credential_seed, value.payload.avk));

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
                FinalizedParticipants(final_participants),
            )
            .await?;

        Ok(current_state)
    }

    pub async fn get_participants(
        &self,
        sld_tld: &SldTld,
    ) -> FrostOpsResult<FinalizedParticipants> {
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

    pub async fn get_signing_keypair(
        &self,
        sld_tld: &SldTld,
    ) -> FrostOpsResult<AsymmetricKeypairBytes> {
        self.storage.get_asymmetric_keypair(sld_tld).await
    }

    pub async fn get_asymmetric_verifying_key(
        &self,
        sld_tld: &SldTld,
    ) -> FrostOpsResult<AsymmetricVerifyingKeyBytes> {
        self.storage.get_asymmetric_verifying_key(sld_tld).await
    }
}
