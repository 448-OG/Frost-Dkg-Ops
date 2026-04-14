use bitcode::{Decode, Encode};

use crate::{
    EphemeralClientDeviceKeypair, EphemeralClientDeviceSignature,
    EphemeralClientDeviceVerifyingKey, FrostOpsResult,
};

// A message sent by a participant and meant for the relay server
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub struct FrostRelayMessageEnvelope<T: AsRef<[u8]>> {
    pub organization: String,
    pub payload: T,
    pub ecdvk: EphemeralClientDeviceVerifyingKey,
    pub ecds: EphemeralClientDeviceSignature,
}

impl<T: AsRef<[u8]>> FrostRelayMessageEnvelope<T> {
    pub fn sign(mut self, ecdk: &EphemeralClientDeviceKeypair) -> FrostOpsResult<Self> {
        let packed = self.pack_for_signing();

        let (ecdvk, ecds) = ecdk.sign_and_return_encodable_and_verifying_key(packed)?;

        self.ecdvk = ecdvk;
        self.ecds = ecds;

        Ok(self)
    }

    pub fn pack_for_signing(&self) -> Vec<u8> {
        let mut message = Vec::<u8>::default();

        message.extend_from_slice(self.organization.as_bytes());
        message.extend_from_slice(self.payload.as_ref());

        message
    }

    pub fn verify_ecds(&self) -> FrostOpsResult<bool> {
        let message = self.pack_for_signing();

        let verifying_key = self.ecdvk.from_bytes()?;
        let signature = self.ecds.from_bytes();

        Ok(verifying_key
            .verify_strict(message.as_ref(), &signature)
            .is_err())
    }
}

#[cfg(test)]
mod sanity_checks {
    use bitcode::Decode;

    use crate::{
        EphemeralClientDeviceSignature, EphemeralClientDeviceVerifyingKey, FrostCredential,
        FrostCredentialSeed,
    };

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
        use std::collections::HashMap;

        use crate::{EphemeralClientDeviceKeypair, FrostCredentialSeed, FrostRelayMessageEnvelope};

        let party1 = "foo@example.com";
        let party2 = "bar@example.com";
        let party3 = "maa@example.com";

        let party1_ecdk = EphemeralClientDeviceKeypair::new();
        let party2_ecdk = EphemeralClientDeviceKeypair::new();
        let party3_ecdk = EphemeralClientDeviceKeypair::new();

        let party1_credential_local = FrostCredentialEd25519::new_with_email(party1).unwrap();
        let party2_credential_local = FrostCredentialEd25519::new_with_email(party2).unwrap();
        let party3_credential_local = FrostCredentialEd25519::new_with_email(party3).unwrap();

        {
            //test credentials are not the same
            assert!(
                party1_credential_local != party2_credential_local
                    || party1_credential_local != party3_credential_local
            );
            assert!(
                party2_credential_local != party1_credential_local
                    || party2_credential_local != party3_credential_local
            );
            assert!(
                party3_credential_local != party1_credential_local
                    || party3_credential_local != party2_credential_local
            );
        }

        let organization = "example.com";

        let party1_envelope = FrostRelayMessageEnvelope {
            organization: organization.to_string(),
            payload: party1_credential_local.seed().encode(),
            ecdvk: party1_ecdk.verifying_key_encodable(),
            ecds: {
                let mut signed_payload_bytes = Vec::<u8>::default();
                signed_payload_bytes.extend_from_slice(organization.as_bytes());
                signed_payload_bytes.extend_from_slice(party1_credential_local.seed().as_bytes());

                party1_ecdk
                    .sign_and_return_encodable(&signed_payload_bytes)
                    .unwrap()
            },
        };

        let party2_envelope = FrostRelayMessageEnvelope {
            organization: organization.to_string(),
            payload: party2_credential_local.seed().encode(),
            ecdvk: party2_ecdk.verifying_key_encodable(),
            ecds: {
                let mut signed_payload_bytes = Vec::<u8>::default();
                signed_payload_bytes.extend_from_slice(organization.as_bytes());
                signed_payload_bytes.extend_from_slice(party2_credential_local.seed().as_bytes());

                party2_ecdk
                    .sign_and_return_encodable(&signed_payload_bytes)
                    .unwrap()
            },
        };

        let party3_envelope = FrostRelayMessageEnvelope {
            organization: organization.to_string(),
            payload: party3_credential_local.seed().encode(),
            ecdvk: party3_ecdk.verifying_key_encodable(),
            ecds: {
                let mut signed_payload_bytes = Vec::<u8>::default();
                signed_payload_bytes.extend_from_slice(organization.as_bytes());
                signed_payload_bytes.extend_from_slice(party3_credential_local.seed().as_bytes());

                party3_ecdk
                    .sign_and_return_encodable(&signed_payload_bytes)
                    .unwrap()
            },
        };

        {
            let mut remote_server_storage =
                HashMap::<FrostCredentialSeed, FrostCredentialStoredInRelay>::default();

            fn register_user(
                storage: &mut HashMap<FrostCredentialSeed, FrostCredentialStoredInRelay>,
                data: FrostRelayMessageEnvelope<impl Decode<'static> + AsRef<[u8]>>,
            ) {
                let organization = "example.com";

                if data.organization != organization {
                    panic!("Invalid organization");
                }

                let seed = bitcode::decode::<FrostCredentialSeed>(data.payload.as_ref())
                    .expect("Unable to decode `FrostCredentialSeed`");
                let to_storage_data = FrostCredentialStoredInRelay {
                    organization: data.organization,
                    seed: seed.clone(),
                    ecdvk: data.ecdvk,
                    ecds: data.ecds,
                };

                storage.insert(seed, to_storage_data);
            }

            register_user(&mut remote_server_storage, party1_envelope);
            register_user(&mut remote_server_storage, party2_envelope);
            register_user(&mut remote_server_storage, party3_envelope);

            assert!(remote_server_storage.contains_key(party1_credential_local.seed()));
            assert!(remote_server_storage.contains_key(party2_credential_local.seed()));
            assert!(remote_server_storage.contains_key(party3_credential_local.seed()));
        }
    }
}
