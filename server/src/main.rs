#![forbid(unsafe_code)]

use crate::config::Settings;
use ::crypto::hsm::HsmProvider;
use ::shared::error::EmptyResult;
use protobuf::pandorica_auth::auth_service_server::AuthServiceServer;
use protobuf::pandorica_user::user_service_server::UserServiceServer;
use protobuf::FILE_DESCRIPTOR_SET;
use singleton::{sync::Singleton, unsync::Singleton as UnsyncSingleton};
use std::net::SocketAddr;
use surrealdb::engine::remote::ws::{Client, Ws, Wss};
use surrealdb::opt::auth::Root;
use surrealdb::Surreal;
use tonic::transport::Server;
use tracing_subscriber::fmt::format::FmtSpan;

use crate::handlers::auth::AuthService;
use crate::handlers::user::UserService;
use crate::kms::KeyManagementSystem;

mod config;
mod fs;
mod handlers;
mod helpers;
mod kms;
mod models;
mod repos;
mod validators;

static DB: Surreal<Client> = Surreal::init();

#[tokio::main]
async fn main() -> EmptyResult {
    tracing_subscriber::fmt()
        .with_env_filter(format!("pandorica={}", Settings::get().log_level))
        .with_span_events(FmtSpan::CLOSE)
        .init();

    let result = match Settings::get().db.proto.as_ref() {
        "ws" => {
            DB.connect::<Ws>(Settings::get().db.addr.clone().into_owned())
                .await
        }
        "wss" => {
            DB.connect::<Wss>(Settings::get().db.addr.clone().into_owned())
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
            username: &Settings::get().db.user,
            password: &Settings::get().db.pass,
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

    {
        let mut hsm = HsmProvider::lock().await;
        hsm.init_provider(&Settings::get().hsm).await?;
    }
    {
        let mut kms = KeyManagementSystem::lock().await;
        kms.init_kms().await?;
    }

    // Setup the services
    let auth_service = AuthService::default();
    let user_service = UserService::default();

    // Setup reflection
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build()?;

    let addr: SocketAddr = match Settings::get().listen_addr.parse() {
        Ok(a) => a,
        Err(e) => {
            panic!("Failed to parse LISTEN_ADDR: {}", e);
        }
    };

    Server::builder()
        .add_service(reflection_service)
        .add_service(AuthServiceServer::new(auth_service))
        .add_service(UserServiceServer::new(user_service))
        .serve(addr)
        .await?;

    Ok(())
}
