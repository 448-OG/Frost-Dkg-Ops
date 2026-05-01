mod client;
pub use client::*;

mod test_utils;

#[cfg(test)]
mod sanity_checks {
    #[test]
    fn types_sanity() {
        use std::collections::BTreeMap;

        use frost_ed25519::{
            self as frost,
            keys::dkg::{round1, round2},
            round1::SigningCommitments,
        };

        use frost_dkg_types::FrostMessagePackage;

        let rng = rand::rngs::OsRng;

        let max_signers = 2;
        let min_signers = 2;

        let party1 = "foo@example.com";
        let party2 = "bar@example.com";

        let party1_identifier = frost_ed25519::Identifier::derive(party1.as_bytes()).unwrap();
        let party2_identifier = frost_ed25519::Identifier::derive(party2.as_bytes()).unwrap();

        let (party1_round1_secret_package, party1_round1_package) =
            frost::keys::dkg::part1(party1_identifier, max_signers, min_signers, rng).unwrap();
        let (party2_round1_secret_package, party2_round1_package) =
            frost::keys::dkg::part1(party2_identifier, max_signers, min_signers, rng).unwrap();

        // Receive party2 transmit party1
        let mut party1_round1_received_packages =
            BTreeMap::<frost_ed25519::Identifier, round1::Package>::default();
        let mut party2_round1_received_packages =
            BTreeMap::<frost_ed25519::Identifier, round1::Package>::default();

        party1_round1_received_packages.insert(party2_identifier, party2_round1_package);
        party2_round1_received_packages.insert(party1_identifier, party1_round1_package);

        let (party1_round2_secret_package, party1_round2_packages) =
            frost_ed25519::keys::dkg::part2(
                party1_round1_secret_package,
                &party1_round1_received_packages,
            )
            .unwrap();

        let (party2_round2_secret_package, party2_round2_packages) =
            frost_ed25519::keys::dkg::part2(
                party2_round1_secret_package,
                &party2_round1_received_packages,
            )
            .unwrap();

        let mut party1_round2_received_packages =
            BTreeMap::<frost_ed25519::Identifier, round2::Package>::default();
        let mut party2_round2_received_packages =
            BTreeMap::<frost_ed25519::Identifier, round2::Package>::default();

        party1_round2_received_packages.insert(
            party2_identifier,
            party2_round2_packages
                .get(&party1_identifier)
                .cloned()
                .unwrap(),
        );

        party2_round2_received_packages.insert(
            party1_identifier,
            party1_round2_packages
                .get(&party2_identifier)
                .cloned()
                .unwrap(),
        );

        let (party1_key_package, party1_public_package) = frost_ed25519::keys::dkg::part3(
            &party1_round2_secret_package,
            &party1_round1_received_packages,
            &party1_round2_received_packages,
        )
        .unwrap();
        let (party2_key_package, party2_public_package) = frost_ed25519::keys::dkg::part3(
            &party2_round2_secret_package,
            &party2_round1_received_packages,
            &party2_round2_received_packages,
        )
        .unwrap();

        let public_package = party1_public_package;
        assert_eq!(public_package, party2_public_package);

        let message = "Hello World! I am using FROST signatures";
        let message_package = FrostMessagePackage::new(message).unwrap();

        let (party1_signing_round1_nonces, party1_signing_round1_commitments) =
            frost::round1::commit(party1_key_package.signing_share(), &mut rand::rngs::OsRng);
        let (party2_signing_round1_nonces, party2_signing_round1_commitments) =
            frost::round1::commit(party2_key_package.signing_share(), &mut rand::rngs::OsRng);
        {
            use frost_dkg_types::{FrostSigningCommitmentsBytes, FrostSigningNoncesBytes};

            let party1_signing_round1_nonces_bytes =
                FrostSigningNoncesBytes::encode(&party1_signing_round1_nonces).unwrap();
            let decoded_party1_signing_round1_nonces = party1_signing_round1_nonces_bytes
                .decode::<frost_ed25519::Ed25519Sha512>()
                .unwrap();
            assert_eq!(
                party1_signing_round1_nonces,
                decoded_party1_signing_round1_nonces
            );

            let party1_signing_round1_commitments_bytes =
                FrostSigningCommitmentsBytes::encode(&party1_signing_round1_commitments).unwrap();
            let decoded_party1_signing_round1_commitments = party1_signing_round1_commitments_bytes
                .decode::<frost_ed25519::Ed25519Sha512>()
                .unwrap();
            assert_eq!(
                party1_signing_round1_commitments,
                decoded_party1_signing_round1_commitments
            );
        }
        let mut commitments_map =
            BTreeMap::<frost_ed25519::Identifier, SigningCommitments>::default();
        commitments_map.insert(party1_identifier, party1_signing_round1_commitments);
        commitments_map.insert(party2_identifier, party2_signing_round1_commitments);

        let signing_package = frost::SigningPackage::new(commitments_map, &message_package.hash());
        let party1_signature_share = frost::round2::sign(
            &signing_package,
            &party1_signing_round1_nonces,
            &party1_key_package,
        )
        .unwrap();
        let party2_signature_share = frost::round2::sign(
            &signing_package,
            &party2_signing_round1_nonces,
            &party2_key_package,
        )
        .unwrap();
        {
            use frost_dkg_types::FrostSigningPackageBytes;

            let signing_package_bytes = FrostSigningPackageBytes::encode(&signing_package).unwrap();
            let decoded_signing_package = signing_package_bytes
                .decode::<frost_ed25519::Ed25519Sha512>()
                .unwrap();
            assert_eq!(signing_package, decoded_signing_package);
        }
        let mut signature_shares =
            BTreeMap::<frost_ed25519::Identifier, frost_ed25519::round2::SignatureShare>::default();
        signature_shares.insert(party1_identifier, party1_signature_share);
        signature_shares.insert(party2_identifier, party2_signature_share);

        let group_signature =
            frost::aggregate(&signing_package, &signature_shares, &public_package).unwrap();
        {
            use frost_dkg_types::FrostSignatureBytes;

            let group_signature_bytes = FrostSignatureBytes::encode(&group_signature).unwrap();
            let decoded_group_signature = group_signature_bytes
                .decode::<frost_ed25519::Ed25519Sha512>()
                .unwrap();
            assert_eq!(group_signature, decoded_group_signature);
        }

        assert!(
            public_package
                .verifying_key()
                .verify(&message_package.hash(), &group_signature)
                .is_ok()
        );
    }
}
