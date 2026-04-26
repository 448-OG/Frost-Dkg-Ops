use bitcode::{Decode, Encode};

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub enum RelayOperation {
    RegisterToRelay,
    #[default]
    Route,
}

// A message sent by a participant and meant for the relay server
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub struct FrostRelayMessageEnvelope<T: AsRef<[u8]>> {
    pub organization: String,
    pub payload: T,
}

#[cfg(test)]
mod sanity_checks {
    use bitcode::Decode;

    use crate::{FrostCredential, FrostCredentialSeed};

    type FrostCredentialEd25519 = FrostCredential<frost_ed25519::Ed25519Sha512>;

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
    pub struct FrostCredentialStoredInRelay {
        organization: String,
        seed: FrostCredentialSeed,
    }

    #[test]
    fn register_credential() {
        use std::collections::HashMap;

        use crate::{FrostCredentialSeed, FrostRelayMessageEnvelope};

        let party1 = "foo@example.com";
        let party2 = "bar@example.com";
        let party3 = "maa@example.com";

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
        };

        let party2_envelope = FrostRelayMessageEnvelope {
            organization: organization.to_string(),
            payload: party2_credential_local.seed().encode(),
        };

        let party3_envelope = FrostRelayMessageEnvelope {
            organization: organization.to_string(),
            payload: party3_credential_local.seed().encode(),
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
