pub struct Config {
    pub rust_log: String,

    pub listen_addr: String,

    pub db_addr: String,
    pub db_proto: String,
    pub db_user: String,
    pub db_pass: String,

    pub encryption_provider: String,
    pub hashing_provider: String,
    pub keyderivation_provider: String,
    pub envelope_provider: String,

    pub filesystem_provider: String,

    pub gcp_project_id: String,
    pub gcp_keyring_location: String,
    pub gcp_keyring_name: String,
    pub gcp_key_name: String,
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

    fn env_expect_aws(key: &str) -> String {
        Self::env_expect_if(key, || Self::env_or("ENVELOPE_PROVIDER", "gcp") == "aws")
    }
}
