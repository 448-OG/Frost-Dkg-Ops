#[cfg(test)]
pub mod db_ops {
    use std::{fs::DirBuilder, io::ErrorKind};

    pub fn frost_credentials_db_path() -> String {
        let dir_path = workspace_dir_path();

        if let Err(error) = DirBuilder::new().create(&dir_path) {
            if error.kind() == ErrorKind::AlreadyExists {
                std::fs::remove_dir_all(&dir_path).unwrap();

                frost_credentials_db_path();
            } else {
                panic!("{:?}", error.kind());
            }
        }

        dir_path + "/FrostCredentials"
    }

    pub fn workspace_dir_path() -> String {
        let mut dir_path = std::env!("CARGO_WORKSPACE_DIR").to_string();
        dir_path.push_str("/target/Storage");

        dir_path
    }
}
