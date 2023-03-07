use serde::{Deserialize, Serialize};
use singleton::{Singleton, SingletonInit};
use std::borrow::Cow;
use std::fs::OpenOptions;
use std::io::Write;

#[derive(Serialize, Deserialize, Singleton)]
#[singleton(sync = false)]
pub struct Settings {
    pub log_level: Cow<'static, str>,
    pub listen_addr: Cow<'static, str>,
    pub db: DatabaseSettings,
    pub crypto: CryptoSettings,
    pub fs: FilesystemSettings,
    pub gcp: Option<GoogleCloudPlatformSettings>,
}

#[derive(Serialize, Deserialize)]
pub struct DatabaseSettings {
    pub addr: Cow<'static, str>,
    pub proto: Cow<'static, str>,
    pub user: Cow<'static, str>,
    pub pass: Cow<'static, str>,
}

#[derive(Serialize, Deserialize)]
pub struct CryptoSettings {
    pub hsm_provider: Cow<'static, str>,
}

#[derive(Serialize, Deserialize)]
pub struct FilesystemSettings {
    pub provider: Cow<'static, str>,
}

#[derive(Serialize, Deserialize)]
pub struct GoogleCloudPlatformSettings {
    pub project_id: Cow<'static, str>,
    pub location: Cow<'static, str>,
    pub key_ring: Cow<'static, str>,
    pub key: Cow<'static, str>,
}

impl SingletonInit<Settings> for Settings {
    fn init() -> Settings {
        let config_file = OpenOptions::new().read(true).open(
            std::env::current_dir()
                .unwrap()
                .as_path()
                .join("config.toml"),
        );
        if config_file.is_err() {
            eprintln!("{:?}", config_file.err().unwrap());
            let default_config = Settings::default();
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

impl Default for Settings {
    fn default() -> Self {
        Self {
            log_level: "info".into(),
            listen_addr: "127.0.0.1:5000".into(),
            db: DatabaseSettings {
                addr: "127.0.0.1:8000".into(),
                proto: "ws".into(),
                user: "root".into(),
                pass: "root".into(),
            },
            crypto: CryptoSettings {
                hsm_provider: "gcp".into(),
            },
            fs: FilesystemSettings {
                provider: "memory".into(),
            },
            gcp: None,
        }
    }
}
