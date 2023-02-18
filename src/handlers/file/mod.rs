use crate::handlers::file::upload::upload;
use warp::Filter;

mod upload;

pub fn file() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path("file").and(upload())
}
