pub struct Config {
    rust_log: String,

    listen_addr: String,

    db_addr: String,
    db_proto: String,
    db_user: String,
    db_pass: String,

    encryption_provider: String,
    hashing_provider: String,
    keyderivation_provider: String,
    envelope_provider: String,

    filesystem_provider: String,

    gcp_project_id: String,
    gcp_keyring_location: String,
    gcp_keyring_name: String,
    gcp_key_name: String,
}

impl Config {
    pub fn default() -> Self {
        Self {
            rust_log: Self::env_or("RUST_LOG", "pandorica=debug"),

            listen_addr: Self::env_or("LISTEN_ADDR", "127.0.0.1:5000"),

            db_addr: Self::env_or("DB_ADDR", "127.0.0.1:8000"),
            db_proto: Self::env_or("DB_PROTO", "ws"),
            db_user: Self::env_or("DB_USER", "root"),
            db_pass: Self::env_or("DB_PASS", "root"),

            encryption_provider: Self::env_or("ENCRYPTION_PROVIDER", "chacha20poly1305"),
            hashing_provider: Self::env_or("HASHING_PROVIDER", "argon2id"),
            keyderivation_provider: Self::env_or("KEYDERIVATION_PROVIDER", "scrypt"),
            envelope_provider: Self::env_or("ENVELOPE_PROVIDER", "gcp"),

            filesystem_provider: Self::env_or("FILESYSTEM_PROVIDER", "memory"),

            gcp_project_id: Self::env_expect_gcp("GCP_PROJECT_ID"),
            gcp_keyring_location: Self::env_expect_gcp("GCP_KEYRING_LOCATION"),
            gcp_keyring_name: Self::env_expect_gcp("GCP_KEYRING_NAME"),
            gcp_key_name: Self::env_expect_gcp("GCP_KEY_NAME"),
        }
    }

    pub fn rust_log(&self) -> &str {
        &self.rust_log
    }

    pub fn listen_addr(&self) -> &str {
        &self.listen_addr
    }

    pub fn db_addr(&self) -> &str {
        &self.db_addr
    }

    pub fn db_proto(&self) -> &str {
        &self.db_proto
    }

    pub fn db_user(&self) -> &str {
        &self.db_user
    }

    pub fn db_pass(&self) -> &str {
        &self.db_pass
    }

    pub fn encryption_provider(&self) -> &str {
        &self.encryption_provider
    }

    pub fn hashing_provider(&self) -> &str {
        &self.hashing_provider
    }

    pub fn keyderivation_provider(&self) -> &str {
        &self.keyderivation_provider
    }

    pub fn envelope_provider(&self) -> &str {
        &self.envelope_provider
    }

    pub fn filesystem_provider(&self) -> &str {
        &self.filesystem_provider
    }

    pub fn gcp_project_id(&self) -> &str {
        &self.gcp_project_id
    }

    pub fn gcp_keyring_location(&self) -> &str {
        &self.gcp_keyring_location
    }

    pub fn gcp_keyring_name(&self) -> &str {
        &self.gcp_keyring_name
    }

    pub fn gcp_key_name(&self) -> &str {
        &self.gcp_key_name
    }

    fn env_or(key: &str, default: &str) -> String {
        std::env::var(key).unwrap_or(default.to_string())
    }

    fn env_expect(key: &str) -> String {
        std::env::var(key).unwrap_or_else(|_| panic!("{} is not set", key))
    }

    fn env_expect_if<F>(key: &str, condition: F) -> String
    where
        F: FnOnce() -> bool,
    {
        if condition() {
            Self::env_expect(key)
        } else {
            Default::default()
        }
    }

    fn env_expect_gcp(key: &str) -> String {
        Self::env_expect_if(key, || Self::env_or("ENVELOPE_PROVIDER", "gcp") == "gcp")
    }
}
