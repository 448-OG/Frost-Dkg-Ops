use bitcode::{Decode, Encode};
use frost_core::{
    Ciphersuite, VerifyingKey,
    keys::{KeyPackage, VerifyingShare},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{FrostIdentifierBytes, FrostOpsResult, FrostSigningShareBytes};

pub struct FrostKeyPackageBytes {
    identifier: FrostIdentifierBytes,
    signing_share: FrostSigningShareBytes,
    verifying_share: FrostVerifyingShareBytes,
    verifying_key: FrostVerifyingKeyBytes,
    minimum_signers: u16,
}

impl FrostKeyPackageBytes {
    pub fn encode<C: Ciphersuite>(key_package: &KeyPackage<C>) -> FrostOpsResult<Self> {
        let identifier_bytes = FrostIdentifierBytes::encode(key_package.identifier());
        let signing_share = FrostSigningShareBytes::encode::<C>(key_package.signing_share());
        let verifying_share = FrostVerifyingShareBytes::encode::<C>(key_package.verifying_share())?;
        let verifying_key = FrostVerifyingKeyBytes::encode::<C>(key_package.verifying_key())?;

        Ok(Self {
            identifier: identifier_bytes,
            signing_share,
            verifying_share,
            verifying_key,
            minimum_signers: *key_package.min_signers(),
        })
    }

    pub fn decode<C: Ciphersuite>(&self) -> FrostOpsResult<KeyPackage<C>> {
        let identifier = self.identifier.decode::<C>()?;
        let signing_share = self.signing_share.decode::<C>()?;
        let verifying_share = self.verifying_share.decode::<C>()?;
        let verifying_key = self.verifying_key.decode::<C>()?;

        Ok(KeyPackage::<C>::new(
            identifier,
            signing_share,
            verifying_share,
            verifying_key,
            self.minimum_signers,
        ))
    }
}

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct FrostVerifyingShareBytes(Vec<u8>);

impl FrostVerifyingShareBytes {
    pub fn encode<C: Ciphersuite>(verifying_share: &VerifyingShare<C>) -> FrostOpsResult<Self> {
        Ok(Self(verifying_share.serialize()?))
    }

    pub fn decode<C: Ciphersuite>(&self) -> FrostOpsResult<VerifyingShare<C>> {
        Ok(VerifyingShare::<C>::deserialize(&self.0)?)
    }
}

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Encode, Decode, Zeroize, ZeroizeOnDrop,
)]
pub struct FrostVerifyingKeyBytes(Vec<u8>);

impl FrostVerifyingKeyBytes {
    pub fn encode<C: Ciphersuite>(verifying_key: &VerifyingKey<C>) -> FrostOpsResult<Self> {
        Ok(Self(verifying_key.serialize()?))
    }

    pub fn decode<C: Ciphersuite>(&self) -> FrostOpsResult<VerifyingKey<C>> {
        Ok(VerifyingKey::<C>::deserialize(&self.0)?)
    }
}

#[cfg(test)]
mod sanity_checks {
    #[test]
    #[cfg(feature = "ed25519")]
    fn types_sanity() {
        use std::collections::BTreeMap;

        use frost_ed25519::{
            self as frost,
            keys::dkg::{round1, round2},
        };

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
        let (_party2_key_package, _party2_public_package) = frost_ed25519::keys::dkg::part3(
            &party2_round2_secret_package,
            &party2_round1_received_packages,
            &party2_round2_received_packages,
        )
        .unwrap();

        {
            // Test round2 outputs

            use crate::{FrostKeyPackageBytes, FrostPublicKeyPackage};
            let key_package_bytes = FrostKeyPackageBytes::encode(&party1_key_package).unwrap();
            let public_package_bytes =
                FrostPublicKeyPackage::encode(&party1_public_package).unwrap();

            let decoded_key_package_bytes = key_package_bytes
                .decode::<frost_ed25519::Ed25519Sha512>()
                .unwrap();
            let decoded_public_package_bytes = public_package_bytes
                .decode::<frost_ed25519::Ed25519Sha512>()
                .unwrap();

            assert_eq!(&party1_key_package, &decoded_key_package_bytes);
            assert_eq!(&party1_public_package, &decoded_public_package_bytes);
        }
    }
}
