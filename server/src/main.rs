#![forbid(unsafe_code)]

use ::shared::config::Config;
use ::shared::error::EmptyResult;
use singleton::{sync::Singleton, unsync::Singleton as UnsyncSingleton};
use std::net::SocketAddr;
use surrealdb::engine::remote::ws::{Client, Ws, Wss};
use surrealdb::opt::auth::Root;
use surrealdb::Surreal;
use tonic::transport::Server;
use tracing_subscriber::fmt::format::FmtSpan;

use crate::crypto::KeyProvider;
use crate::handlers::auth::AuthService;
use crate::knox_auth::auth_service_server::AuthServiceServer;

mod crypto;
mod fs;
mod handlers;
mod models;
mod repos;
mod validators;

const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("knox_descriptor");

tonic::include_proto!("knox_proto");

static DB: Surreal<Client> = Surreal::init();

#[tokio::main]
async fn main() -> EmptyResult {
    tracing_subscriber::fmt()
        .with_env_filter(format!("pandorica={}", Config::get().log_level))
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let result = match Config::get().db.proto.as_ref() {
        "ws" => {
            DB.connect::<Ws>(Config::get().db.addr.clone().into_owned())
                .await
        }
        "wss" => {
            DB.connect::<Wss>(Config::get().db.addr.clone().into_owned())
                .await
        }
        val => {
            panic!("Unknown database protocol: {}", val);
        }
    };
    if result.is_err() {
        panic!(
            "An error occurred during database initialization: {:?}",
            result.err().unwrap()
        );
    }

    let result = DB
        .signin(Root {
            username: &Config::get().db.user,
            password: &Config::get().db.pass,
        })
        .await;
    if result.is_err() {
        panic!(
            "An error occurred during database authentication: {:?}",
            result.err().unwrap()
        );
    }

    let result = DB.use_ns("pandorica").use_db("pandorica").await;
    if result.is_err() {
        panic!(
            "An error occurred during database setup: {:?}",
            result.err().unwrap()
        );
    }

    // Initialize the key provider
    {
        let mut guard = KeyProvider::lock().await;

        guard
            .init_cloud()
            .await
            .unwrap_or_else(|e| panic!("Error initializing key provider: {:?}", e));
    }

    // Setup the services
    let auth_service = AuthService::default();

    // Setup reflection
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build()?;

    let addr: SocketAddr = match Config::get().listen_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            panic!("Failed to parse LISTEN_ADDR: {}", e);
        }
    };

    Server::builder()
        .add_service(reflection_service)
        .add_service(AuthServiceServer::new(auth_service))
        .serve(addr)
        .await?;

    Ok(())
}
