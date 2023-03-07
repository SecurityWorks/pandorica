use serde::{Deserialize, Serialize};
use singleton::{Singleton, SingletonInit};
use std::borrow::Cow;
use std::fs::OpenOptions;
use std::io::Write;

#[derive(Serialize, Deserialize, Singleton)]
#[singleton(sync = false)]
pub struct Config {
    pub log_level: Cow<'static, str>,
    pub listen_addr: Cow<'static, str>,
    pub db: DbConfig,
    pub crypto: CryptoConfig,
    pub fs: FsConfig,
    pub gcp: Option<GcpConfig>,
}

#[derive(Serialize, Deserialize)]
pub struct DbConfig {
    pub addr: Cow<'static, str>,
    pub proto: Cow<'static, str>,
    pub user: Cow<'static, str>,
    pub pass: Cow<'static, str>,
}

#[derive(Serialize, Deserialize)]
pub struct CryptoConfig {
    pub hsm_provider: Cow<'static, str>,
}

#[derive(Serialize, Deserialize)]
pub struct FsConfig {
    pub provider: Cow<'static, str>,
}

#[derive(Serialize, Deserialize)]
pub struct GcpConfig {
    pub project_id: Cow<'static, str>,
    pub location: Cow<'static, str>,
    pub key_ring: Cow<'static, str>,
    pub key: Cow<'static, str>,
}

impl SingletonInit<Config> for Config {
    fn init() -> Config {
        let config_file = OpenOptions::new().read(true).open(
            std::env::current_dir()
                .unwrap()
                .as_path()
                .join("config.toml"),
        );
        if config_file.is_err() {
            eprintln!("{:?}", config_file.err().unwrap());
            let default_config = Config::default();
            let mut config_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(
                    std::env::current_dir()
                        .unwrap()
                        .as_path()
                        .join("config.toml"),
                )
                .unwrap();
            config_file
                .write_all(toml::to_string_pretty(&default_config).unwrap().as_bytes())
                .unwrap();
            config_file.flush().unwrap();
        }

        config::Config::builder()
            .add_source(config::File::with_name("config"))
            .add_source(config::Environment::with_prefix("PANDORICA"))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_level: "info".into(),
            listen_addr: "127.0.0.1:5000".into(),
            db: DbConfig {
                addr: "127.0.0.1:8000".into(),
                proto: "ws".into(),
                user: "root".into(),
                pass: "root".into(),
            },
            crypto: CryptoConfig {
                hsm_provider: "gcp".into(),
            },
            fs: FsConfig {
                provider: "memory".into(),
            },
            gcp: None,
        }
    }
}
