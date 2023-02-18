use bytes::Buf;
use futures::{Stream, StreamExt};
use warp::Filter;

pub fn upload() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path!("upload")
        .and(warp::post())
        .and(warp::header::exact(
            "Content-Type",
            "application/octet-stream",
        ))
        .and(warp::body::stream())
        .and_then(upload_handler)
}

async fn upload_handler(
    body: impl Stream<Item = Result<impl Buf, warp::Error>> + StreamExt,
) -> Result<impl warp::Reply, warp::Rejection> {
    let mut stream = Box::pin(body);

    while let Some(item) = stream.next().await {
        let mut in_data = item.unwrap();
        let data = in_data.copy_to_bytes(in_data.remaining());
        tracing::debug!("Received {} bytes", data.len());
        tracing::debug!("{:?}", data.to_ascii_lowercase())
    }

    Ok(warp::reply())
}
