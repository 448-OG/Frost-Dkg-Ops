use std::collections::BTreeMap;

use bitcode::{Decode, Encode};
use frost_core::{Ciphersuite, Identifier, keys::dkg::round2};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{FrostIdentifierBytes, FrostOpsError, FrostOpsResult};

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Zeroize, Hash, ZeroizeOnDrop,
)]
pub struct Round2SecretBytes(Vec<u8>);

impl Round2SecretBytes {
    pub fn serialize<C: Ciphersuite>(
        round2_secret: &round2::SecretPackage<C>,
    ) -> FrostOpsResult<Self> {
        Ok(Self(bitcode::serialize(&round2_secret).or(Err(
            FrostOpsError::UnableToSerializedRound1DkgSecret,
        ))?))
    }

    pub fn deserialize<C: Ciphersuite>(&self) -> FrostOpsResult<round2::SecretPackage<C>> {
        bitcode::deserialize(&self.0).or(Err(FrostOpsError::UnableToDeserializedRound1DkgSecret))
    }
}

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash, Zeroize, ZeroizeOnDrop,
)]
pub struct Round2PackageBytes(Vec<(FrostIdentifierBytes, Vec<u8>)>);

impl Round2PackageBytes {
    pub fn encode<C: Ciphersuite>(
        round2_public_package: &BTreeMap<Identifier<C>, round2::Package<C>>,
    ) -> FrostOpsResult<Self> {
        let mut encoded = Vec::<(FrostIdentifierBytes, Vec<u8>)>::default();

        round2_public_package.iter().try_for_each(|(key, value)| {
            encoded.push((FrostIdentifierBytes::encode::<C>(key), value.serialize()?));

            Ok::<_, FrostOpsError>(())
        })?;

        Ok(Self(encoded))
    }

    pub fn decode<C: Ciphersuite>(
        &self,
    ) -> FrostOpsResult<BTreeMap<Identifier<C>, round2::Package<C>>> {
        let mut decoded = BTreeMap::<Identifier<C>, round2::Package<C>>::default();

        self.0.iter().try_for_each(|(key, value)| {
            let key = key.decode::<C>()?;
            let value = round2::Package::<C>::deserialize(value)?;

            decoded.insert(key, value);

            Ok::<_, FrostOpsError>(())
        })?;

        Ok(decoded)
    }
}

#[cfg(test)]
mod sanity_checks {
    #[test]
    #[cfg(feature = "ed25519")]
    fn types_sanity() {
        use std::collections::BTreeMap;

        use frost_ed25519::{self as frost, keys::dkg::round1};

        let rng = rand::rngs::OsRng;

        let max_signers = 2;
        let min_signers = 2;

        let party1 = "foo@example.com";
        let party2 = "bar@example.com";

        let party1_identifier = frost_ed25519::Identifier::derive(party1.as_bytes()).unwrap();
        let party2_identifier = frost_ed25519::Identifier::derive(party2.as_bytes()).unwrap();

        let (party1_round1_secret_package, _) =
            frost::keys::dkg::part1(party1_identifier, max_signers, min_signers, rng).unwrap();
        let (_, party2_round1_package) =
            frost::keys::dkg::part1(party2_identifier, max_signers, min_signers, rng).unwrap();

        let mut party1_round1_packages =
            BTreeMap::<frost_ed25519::Identifier, round1::Package>::default();
        party1_round1_packages.insert(party2_identifier, party2_round1_package);

        let (party1_round2_secret_package, party1_round2_packages) =
            frost_ed25519::keys::dkg::part2(party1_round1_secret_package, &party1_round1_packages)
                .unwrap();

        {
            // Round2

            use crate::{Round2PackageBytes, Round2SecretBytes};

            let party1_round2_secret_bytes =
                Round2SecretBytes::serialize(&party1_round2_secret_package).unwrap();
            let party1_round2_public_package_bytes =
                Round2PackageBytes::encode(&party1_round2_packages).unwrap();

            let party1_round2_decoded_secret =
                Round2SecretBytes::deserialize(&party1_round2_secret_bytes).unwrap();
            assert_eq!(&party1_round2_secret_package, &party1_round2_decoded_secret);
            let party1_round2_decoded_public_package =
                Round2PackageBytes::decode::<frost_ed25519::Ed25519Sha512>(
                    &party1_round2_public_package_bytes,
                )
                .unwrap();
            assert_eq!(
                &party1_round2_packages,
                &party1_round2_decoded_public_package
            );
        }
    }
}
