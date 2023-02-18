#![forbid(unsafe_code)]

extern crate core;

use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Config;
use crate::crypto::{CryptoProvider, KeyProvider};
use crate::fs::FileSystem;
use crate::handlers::auth::AuthService;
use crate::knox_auth::auth_service_server::AuthServiceServer;
use once_cell::sync::Lazy;
use surrealdb::engine::remote::ws::{Client, Ws, Wss};
use surrealdb::opt::auth::Root;
use surrealdb::Surreal;
use tokio::sync::Mutex;
use tonic::transport::Server;
use tracing_subscriber::fmt::format::FmtSpan;

mod config;
mod crypto;
mod fs;
mod handlers;
mod models;
mod shared;

const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("knox_descriptor");

tonic::include_proto!("knox_proto");

static CONFIG: Lazy<Config> = Lazy::new(Config::default);
static DB: Surreal<Client> = Surreal::init();
static CRYPTO: Lazy<CryptoProvider> = Lazy::new(setup_cryptoproviders);
static FS: Lazy<FileSystem> = Lazy::new(setup_filesystem);
static KEY_PROVIDER: Lazy<Arc<Mutex<KeyProvider>>> =
    Lazy::new(|| Arc::new(Mutex::new(KeyProvider::default())));

static RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
});

fn main() -> shared::Result<()> {
    let _ = CRYPTO.encryption(); // Force initialization of the encryption provider
    RUNTIME.block_on(async_main())
}

async fn async_main() -> shared::Result<()> {
    // Configure the default `tracing` subscriber
    // The `fmt` subscriber from the `tracing-subscriber` crate logs `tracing`
    // events to stdout.
    tracing_subscriber::fmt()
        .with_env_filter(CONFIG.rust_log.clone())
        .with_span_events(FmtSpan::CLOSE)
        .init();

    // Setup database
    let result = match CONFIG.db_proto.as_str() {
        "ws" => DB.connect::<Ws>(CONFIG.db_addr.clone()).await,
        "wss" => DB.connect::<Wss>(CONFIG.db_addr.clone()).await,
        val => {
            throw_error!("Unknown database protocol: {}", val);
        }
    };
    if result.is_err() {
        throw_error!(
            "An error occurred during database initialization: {:?}",
            result.err().unwrap()
        );
    }

    let result = DB
        .signin(Root {
            username: CONFIG.db_user.as_str(),
            password: CONFIG.db_pass.as_str(),
        })
        .await;
    if result.is_err() {
        throw_error!(
            "An error occurred during database authentication: {:?}",
            result.err().unwrap()
        );
    }

    let result = DB.use_ns("pandorica").use_db("pandorica").await;
    if result.is_err() {
        throw_error!(
            "An error occurred during database setup: {:?}",
            result.err().unwrap()
        );
    }

    // Initialize the key provider
    {
        let mut guard = KEY_PROVIDER.lock().await;

        guard
            .init()
            .await
            .unwrap_or_else(|e| throw_error!("Error initializing key provider: {:?}", e));
    }

    // Setup the services
    let auth_service = AuthService::default();

    // Setup reflection
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build()?;

    let addr: SocketAddr = match CONFIG.listen_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            throw_error!("Failed to parse LISTEN_ADDR: {}", e.to_string());
        }
    };

    Server::builder()
        .add_service(reflection_service)
        .add_service(AuthServiceServer::new(auth_service))
        .serve(addr)
        .await?;

    Ok(())
}

fn setup_cryptoproviders() -> CryptoProvider {
    RUNTIME.block_on(async {
        CryptoProvider::new(
            CONFIG.encryption_provider.clone(),
            CONFIG.hashing_provider.clone(),
            CONFIG.keyderivation_provider.clone(),
            CONFIG.envelope_provider.clone(),
        )
        .await
        .unwrap_or_else(|e| throw_error!("Failed to initialize crypto providers: {:?}", e))
    })
}

fn setup_filesystem() -> FileSystem {
    FileSystem::new(CONFIG.filesystem_provider.clone())
}
