pub mod sync;
pub mod unsync;

pub use async_trait::async_trait;
pub use once_cell::sync::OnceCell;
pub use singleton_derive::Singleton;
pub use tokio::sync::Mutex;

pub trait SingletonInit<T: 'static + Send + Sync + ?Sized = Self> {
    fn init() -> T;
}
