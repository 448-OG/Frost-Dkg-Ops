use frost_core::Ciphersuite;
use frost_dkg_types::{FrostCredentialSeed, FrostOpsResult};
use redb::TableDefinition;

use crate::FrostStorage;

// `FrostCredentialEncoded`
impl FrostStorage {
    const FROST_CREDENTIALS: TableDefinition<'static, &[u8], Vec<u8>> =
        TableDefinition::new("FrostCredentials");

    pub async fn set_credential(
        &self,
        org_domain: &str,
        credential: &FrostCredentialSeed,
    ) -> FrostOpsResult<()> {
        let credential_bytes = credential.encode();

        self.insert_if_not_exist(Self::FROST_CREDENTIALS, org_domain, credential_bytes)
            .await
    }

    pub async fn get_credential<C: Ciphersuite>(
        &self,
        org_domain: &str,
    ) -> FrostOpsResult<Option<FrostCredentialSeed>> {
        self.get_credential_bytes(org_domain)
            .await?
            .map(|credential_bytes| FrostCredentialSeed::decode(&credential_bytes))
            .transpose()
    }

    pub async fn get_credential_bytes(&self, org_domain: &str) -> FrostOpsResult<Option<Vec<u8>>> {
        self.get(Self::FROST_CREDENTIALS, org_domain).await
    }
}

#[cfg(test)]
mod sanity_checks {
    use frost_dkg_types::FrostCredentialSeed;

    use crate::test_utils::db_ops::frost_credentials_db_path;

    #[test]
    fn types_sanity() {
        use crate::FrostStorage;

        smol::block_on(async move {
            use frost_dkg_types::{FrostClientStorageError, FrostOpsError};

            let org_domain = "example.com";
            let party1 = "foo@example.com";

            let party1_credential = FrostCredentialSeed::new_with_email(party1).unwrap();

            let db_path = frost_credentials_db_path();

            let storage = FrostStorage::init(db_path.as_str().into()).unwrap();

            storage
                .set_credential(org_domain, &party1_credential)
                .await
                .unwrap();

            assert_eq!(
                Some(FrostOpsError::Storage(
                    FrostClientStorageError::KeyAlreadyExists
                )),
                storage
                    .set_credential(org_domain, &party1_credential)
                    .await
                    .err()
            );

            let get_credential = storage
                .get_credential::<frost_ed25519::Ed25519Sha512>(org_domain)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(get_credential, party1_credential);

            assert!(
                storage
                    .get_credential::<frost_ed25519::Ed25519Sha512>("foo_var")
                    .await
                    .unwrap()
                    .is_none()
            );
        })
    }
}
