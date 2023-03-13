use protobuf::{pandorica_auth, pandorica_user};
use shared::error::{EmptyResult, OperationResult};
use tonic::transport::Channel;
use tonic::Request;

pub async fn login(
    url: String,
    username: String,
    password: String,
) -> OperationResult<pandorica_auth::AuthResponse> {
    let channel = Channel::from_shared(url)?.connect().await?;

    let mut client = pandorica_auth::auth_service_client::AuthServiceClient::new(channel);

    let request = Request::new(pandorica_auth::LoginRequest { username, password });

    let response = client.login(request).await?;

    Ok(response.into_inner())
}

pub async fn logout(url: String, session_id: &str) -> EmptyResult {
    let channel = Channel::from_shared(url)?.connect().await?;

    let mut client = pandorica_auth::auth_service_client::AuthServiceClient::with_interceptor(
        channel,
        move |mut req: Request<()>| {
            req.metadata_mut()
                .insert("session_id", session_id.parse().unwrap());
            Ok(req)
        },
    );

    let request = Request::new(pandorica_auth::LogoutRequest {});

    let _ = client.logout(request).await;

    Ok(())
}

pub async fn me(url: String, session_id: &str) -> OperationResult<pandorica_user::MeResponse> {
    let channel = Channel::from_shared(url)?.connect().await?;

    let mut client = pandorica_user::user_service_client::UserServiceClient::with_interceptor(
        channel,
        move |mut req: Request<()>| {
            req.metadata_mut()
                .insert("session_id", session_id.parse().unwrap());
            Ok(req)
        },
    );

    let request = Request::new(pandorica_user::MeRequest {});

    let response = client.me(request).await?;

    Ok(response.into_inner())
}
