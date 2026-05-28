use std::collections::BTreeMap;

use file_format::FileFormat;
use frost_core::Ciphersuite;
use frost_dkg_types::{
    AsymmetricSignatureBytes, Blake3HashBytes, EVENT_MAX_MESSAGE_SIZE, FinalizedParticipants,
    FinalizedSigningEvent, FrostCredentialSeed, FrostDkgState, FrostMessageSigners, FrostOpsError,
    FrostOpsResult, FrostSignatureBytes, FrostSignatureShareBytes, FrostSigningCommitmentsBytes,
    FrostSigningEvent, FrostSigningEventInfo, FrostSigningEventState, FrostSigningMessageOrigin,
    FrostSigningNoncesBytes, ReceivedEventAcks, ReceivedSignatureShares, SignalAcknowledgement,
    SldTld, Tai64NTimestamp, TransmitFrostRound2,
};
use zeroize::Zeroize;

use crate::{DkgStateHandler, FrostAuthenticatedChannel, FrostDkgStorage};

impl<C: Ciphersuite, KV: FrostDkgStorage, N: FrostAuthenticatedChannel> DkgStateHandler<C, KV, N> {
    pub async fn receive_signing_event(
        &self,
        sld_tld: SldTld,
        signal: FrostSigningEvent,
    ) -> FrostOpsResult<()> {
        let (exists, key_package) = self
            .storage()
            .check_if_signing_event_exists(sld_tld.to_storage_key(), &signal)
            .await?;

        if exists {
            return Ok(());
        }

        // Due to the nature of mobile networks collecting errors is a priority
        // rather than sending one error and then encountering another error then
        // sending it over the network in another round.
        let mut errors = Vec::<String>::new();

        if signal.get_state() != FrostSigningEventState::Signal {
            errors.push(format!(
                "The message signing event has an invalid state. Expected: `{:?}` but found `{:?}`",
                FrostSigningEventState::Signal,
                signal.get_state()
            ));
        }

        if signal.metadata().size() > EVENT_MAX_MESSAGE_SIZE {
            errors.push("The message size exceeds 1MiB".to_string());
        }

        if FileFormat::from_media_type(signal.metadata().media_type()).is_empty() {
            errors.push("The message metadata of the signing event is invalid".to_string());
        }

        let (current_dkg_state, my_credential, participants, last_signed_event, min_max, akp) =
            self.storage()
                .get_requirements_to_validate_a_received_signal(
                    sld_tld.to_storage_key(),
                    signal.to_storage_key(),
                )
                .await?;

        let expected_state = FrostDkgState::Finalized;

        if let Some(last_signed_event) = last_signed_event.as_ref()
            && signal.get_timestamp().parse()? < last_signed_event.event.get_timestamp().parse()?
        {
            let note =
                "This event is invalid because it's time is earlier than the last event I signed";

            let ack = SignalAcknowledgement::new(my_credential)
                .set_sld_tld(sld_tld.to_storage_key())
                .set_rejected()
                .set_event_hash(signal.event_hash())
                .add_note(note)
                .build(akp)?;

            return self.channel().signal_ack(ack).await;
        }

        if current_dkg_state != expected_state {
            return Err(FrostOpsError::InvalidClientState {
                current: current_dkg_state,
                expected: expected_state,
            });
        }

        let mut key_package = key_package.to_frost::<C>()?;
        let threshold = *key_package.min_signers();

        if threshold as usize > participants.0.len().saturating_add(1) {
            errors.push("The threshold is abnormal".to_string());
        }

        if threshold < min_max.min {
            errors.push(
                "The minimum signers selected are below the threshold agreed upon".to_string(),
            );
        }

        if !signal.accepted().is_empty() || !signal.rejected().is_empty() {
            errors.push("This event contains accepted or rejected messages yet I have not acknowledged that anything".to_string());
        }

        let current_event_hash = signal.event_hash();
        if signal.event_hash() != current_event_hash {
            errors.push("The hash of the event to sign is invalid".to_string());
        }

        let invalid_signers = self.check_signers(&participants, signal.signers());

        match signal.get_origin() {
            FrostSigningMessageOrigin::Relay => (),
            FrostSigningMessageOrigin::Participant(index) => {
                if let Some(origin_seed) = signal.signers().0.get(index as usize) {
                    let is_valid_origin = self.check_origin(&participants, origin_seed);

                    if !is_valid_origin {
                        errors.push("The origin of the event is not a valid signer".to_string());
                    }
                } else {
                    errors.push("The origin of the event is an invalid participant".to_string());
                }
            }
        };

        if !invalid_signers.is_empty() {
            let culprits_format = invalid_signers
                .iter()
                .map(|value| value.seed().to_string() + ", ")
                .collect::<String>();

            errors.push("The following are not valid signers: ".to_string() + &culprits_format);
        }

        let (mut nonces, commitments) =
            frost_core::round1::commit(key_package.signing_share(), &mut rand::rngs::OsRng);
        let nonces_bytes = FrostSigningNoncesBytes::parse(&nonces)?;
        let commitments_bytes = FrostSigningCommitmentsBytes::parse(&commitments)?;
        key_package.zeroize();
        nonces.zeroize();

        let ack = if errors.is_empty() {
            SignalAcknowledgement::new(my_credential)
                .set_sld_tld(sld_tld.to_storage_key())
                .set_accepted(commitments_bytes.clone())
                .set_event_hash(signal.event_hash())
                .add_note("I accept this message and it's contents")
                .build(akp)?
        } else {
            SignalAcknowledgement::new(my_credential)
                .set_sld_tld(sld_tld.to_storage_key())
                .set_rejected()
                .set_event_hash(signal.event_hash())
                .add_notes(&errors)
                .build(akp)?
        };

        let mut event_info = FrostSigningEventInfo {
            sld_tld: sld_tld.clone(),
            event: signal,
            commitments: Option::default(),
            nonces: Option::default(),
            signature_share: Option::default(),
            signing_package: Option::default(),
            signature: Option::default(),
            latest_timestamp: Tai64NTimestamp::now(),
            valid_signers: Vec::default(),
        };

        if ack.accepted().is_some() {
            event_info.commitments.replace(commitments_bytes);
            event_info.nonces.replace(nonces_bytes);
        }

        self.storage().set_signing_event(event_info).await?;

        self.channel().signal_ack(ack).await
    }

    // returns `(FrostSigningEvent, Vec of errors)`
    pub async fn receive_signal_acks(
        &self,
        mut received_ack: ReceivedEventAcks,
    ) -> FrostOpsResult<(FrostSigningEvent, Vec<String>)> {
        fn validate_data<C: Ciphersuite>(
            stored_event: &FrostSigningEvent,
            ack: &SignalAcknowledgement,
            errors: &mut Vec<String>,
            participants: &FinalizedParticipants,
            commitments_map: &mut BTreeMap<
                frost_core::Identifier<C>,
                frost_core::round1::SigningCommitments<C>,
            >,
        ) -> FrostOpsResult<bool> {
            if stored_event.event_hash() != ack.event_hash() {
                errors.push(format!(
                    "Event hash in acknowledgement does not match event hash for signal event. Culprit is `{}`",
                    ack.signer().seed()
                ));
            }

            if stored_event.get_timestamp() > ack.timestamp() {
                errors.push(format!(
                    "Acknowledgement cannot be earlier than when the message was created. Culprit is `{}`",
                    ack.signer().seed()
                ));
            }

            let computed_hash = ack.hash();

            if computed_hash != ack.binding_hash() {
                errors.push(format!(
                    "Binding hash error. Culprit is `{}`",
                    ack.signer().seed()
                ));
            }

            if let Some(commitment) = ack.accepted() {
                match commitment.to_frost::<C>() {
                    Ok(value) => {
                        let key = ack.signer().frost_identifier::<C>()?;
                        commitments_map.insert(key, value);
                    }
                    Err(error) => {
                        errors.push(format!(
                            "Invalid signing commitment. Culprit is `{}`. Error details: `{error}`!",
                            ack.signer().seed()
                        ));
                    }
                }
            }

            let avk = participants
                .get_asymmetric_verifying_key(ack.signer())
                .ok_or(FrostOpsError::AsymmetricVerifyingKeyBytesNotFound(
                    ack.signer().seed().to_string(),
                ))?;

            let avk = avk.from_bytes()?;
            let signature = ack.signature().from_bytes();

            Ok(avk
                .verify_strict(computed_hash.as_bytes(), &signature)
                .is_ok())
        }

        let (my_credential_seed, mut stored_event, participants, key_package, akp, sld_tld) = self
            .storage()
            .get_requirements_to_verify_event(&received_ack.sld_tld, received_ack.store_key)
            .await?;

        // Ignore an invalid event since this is not supposed to happen if the server is setup correctly
        // In future log this for user notifications.

        // Remove any duplicates received from relay
        received_ack.sort_and_dedup();

        let mut errors = Vec::<String>::default();

        if stored_event.event.get_state() != FrostSigningEventState::Signal {
            return Err(FrostOpsError::InvalidSigningState {
                current_state: stored_event.event.get_state(),
                expected_state: FrostSigningEventState::Signal,
            });
        }

        if received_ack.compiled_at.parse()? < stored_event.event.get_timestamp().parse()? {
            errors.push(
                    "The relay server sent an invalid timestamp when it compiled all the acknowledgements for the signers".to_string()
                );
        }

        let mut commitments_map = BTreeMap::<
            frost_core::Identifier<C>,
            frost_core::round1::SigningCommitments<C>,
        >::default();

        received_ack.acks.into_iter().try_for_each(|ack| {
            if validate_data(
                &stored_event.event,
                &ack,
                &mut errors,
                &participants,
                &mut commitments_map,
            )? {
                if ack.accepted().is_some() {
                    stored_event.event.add_accepted(ack.clone());
                } else {
                    stored_event.event.add_rejected(ack.clone());
                }
            } else {
                errors.push(format!(
                    "Invalid signature for acknowledgement. Culprit is `{}`",
                    ack.signer().seed()
                ));
            }

            Ok::<_, FrostOpsError>(())
        })?;

        let mut key_package = key_package.to_frost::<C>()?;
        let threshold = *key_package.min_signers();

        if stored_event.event.accepted().len() >= threshold as usize {
            stored_event
                .event
                .modify_state(FrostSigningEventState::Round2);
        }

        if stored_event.event.rejected().len() >= threshold as usize {
            stored_event
                .event
                .modify_state(FrostSigningEventState::Rejected);
        }

        stored_event.event.set_compiled_at(received_ack.compiled_at);

        if stored_event.event.get_state() == FrostSigningEventState::Round2 {
            let signing_package = frost_core::SigningPackage::new(
                commitments_map,
                stored_event.event.event_hash().as_bytes(),
            );
            let mut signer_nonces = stored_event
                .nonces
                .as_ref()
                .ok_or(FrostOpsError::FrostSigningNoncesNotFound)?
                .to_frost::<C>()?;
            let signature_share =
                frost_core::round2::sign(&signing_package, &signer_nonces, &key_package)?;

            signer_nonces.zeroize();
            key_package.zeroize();

            let signature_share_bytes = FrostSignatureShareBytes::encode(signature_share);

            stored_event.signature_share.replace(signature_share_bytes);
        }

        stored_event.latest_timestamp = Tai64NTimestamp::now();

        let return_event = stored_event.event.clone();
        let event_hash = stored_event.event.event_hash();

        let mut signature_share_bytes = stored_event.signature_share.clone();

        self.storage()
            .set_signing_event(stored_event.clone())
            .await?;

        if let Some(signature_share_bytes) = signature_share_bytes.take() {
            self.channel()
                .update_signing_event(
                    sld_tld,
                    TransmitFrostRound2 {
                        credential: my_credential_seed,
                        timestamp: Tai64NTimestamp::now(),
                        signature_share: signature_share_bytes,
                        event_hash,
                        binding_hash: Blake3HashBytes::default(),
                        binding_signature: AsymmetricSignatureBytes::default(),
                    }
                    .set_binding_hash()
                    .sign(akp)?,
                )
                .await?;
        }

        Ok((return_event, errors))
    }

    pub async fn process_round2_signature_shares(
        &self,
        sld_tld: SldTld,
        received_shares: ReceivedSignatureShares,
    ) -> FrostOpsResult<()> {
        let (
            my_credential_seed,
            mut stored_event,
            key_package,
            group_public_package,
            participants,
            akp,
        ) = self
            .storage()
            .get_requirements_to_verify_signature_shares(
                &sld_tld.to_storage_key(),
                received_shares.event_key,
            )
            .await?;

        let signers_len = received_shares.shares.len();

        if signers_len > participants.0.len() {
            return Err(FrostOpsError::TooManySigners {
                max: participants.0.len(),
                num_of_signers: signers_len,
            });
        }

        let expected_state = FrostSigningEventState::Round2;
        let current_state = stored_event.event.get_state();
        if current_state != expected_state {
            return Err(FrostOpsError::InvalidSigningState {
                current_state,
                expected_state,
            });
        }

        if received_shares.compiled_at < stored_event.event.get_timestamp()
            || received_shares.compiled_at < stored_event.latest_timestamp
        {
            return Err(FrostOpsError::InvalidRound2SigningTimestamp); //TODO handle in client
        }

        let mut errors = Vec::<String>::default();

        let mut valid_shares =
            BTreeMap::<frost_core::Identifier<C>, frost_core::round2::SignatureShare<C>>::default();

        for share in received_shares.shares {
            if share.timestamp < stored_event.event.get_timestamp()
                || share.timestamp < stored_event.latest_timestamp
                || share.timestamp > received_shares.compiled_at
            {
                errors.push(format!(
                    "The timestamp for the received signature share must be later than the signal timestamp, internal latest round1 timestamp and less than the compiled_at timestamp for received shares. Culprit is `{}`",
                    share.credential.seed()
                ));

                continue;
            }

            // Ignore checking if this is a valid participant since that is already checked when
            // receiving the signal
            let is_valid_signer = stored_event
                .event
                .accepted()
                .iter()
                .any(|value| value.signer() == &share.credential);

            if !is_valid_signer {
                errors.push(format!(
                    "This signer is part of round2 but it was never registered as a signer when signaling this event. Culprit is `{}`",
                    share.credential.seed()
                ));

                continue;
            }

            let avk = participants
                .get_asymmetric_verifying_key(&share.credential)
                .ok_or(FrostOpsError::FrostCredentialNotSet)?;

            let binding_signature = share.binding_signature.from_bytes();

            if avk
                .from_bytes()?
                .verify_strict(share.binding_hash.as_bytes(), &binding_signature)
                .is_err()
            {
                errors.push(format!(
                    "Invalid binding signature. Culprit is `{}`",
                    share.credential.seed()
                ));

                continue;
            } else {
                let identifier = share.credential.frost_identifier()?;
                let share = share.signature_share.to_frost::<C>()?;

                valid_shares.insert(identifier, share);
            }
        }

        let mut key_package = key_package.to_frost::<C>()?;
        let threshold = *key_package.min_signers();

        if (threshold as usize) < valid_shares.len() {
            return Err(FrostOpsError::InsufficientSigners {
                threshold,
                num_of_signers: valid_shares.len(),
            });
        }

        let signing_package = stored_event
            .signing_package
            .as_ref()
            .ok_or(FrostOpsError::FrostSigningPackageNotFound)?
            .to_frost::<C>()?;
        let pubkey_package = group_public_package.to_frost::<C>()?;

        let group_signature =
            frost_core::aggregate(&signing_package, &valid_shares, &pubkey_package)?;
        let group_signature = FrostSignatureBytes::encode(&group_signature)?;

        key_package.zeroize();

        stored_event.signature.replace(group_signature);
        stored_event.latest_timestamp = Tai64NTimestamp::now();
        stored_event
            .event
            .modify_state(FrostSigningEventState::Aggregate);

        let event_hash = stored_event.event.event_hash();

        self.storage().set_signing_event(stored_event).await?;

        self.channel()
            .finalized_signing_event(
                &sld_tld,
                FinalizedSigningEvent {
                    sld_tld_hash: sld_tld.to_storage_key(),
                    timestamp: Tai64NTimestamp::now(),
                    event_hash,
                    credential: my_credential_seed,
                    binding_hash: Blake3HashBytes::default(),
                    binding_signature: AsymmetricSignatureBytes::default(),
                }
                .set_binding_hash()
                .sign(akp)?,
            )
            .await
    }

    pub fn check_signers(
        &self,
        participants: &FinalizedParticipants,
        signers: &FrostMessageSigners,
    ) -> Vec<FrostCredentialSeed> {
        let mut invalid_signers = Vec::<FrostCredentialSeed>::default();

        for signer in signers.0.as_slice() {
            if !participants.is_valid_participant(signer) {
                invalid_signers.push(signer.clone());
            }
        }

        invalid_signers
    }

    pub fn check_origin(
        &self,
        participants: &FinalizedParticipants,
        origin: &FrostCredentialSeed,
    ) -> bool {
        participants.is_valid_participant(origin)
    }
}
