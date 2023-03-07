use crate::SingletonInit;
use async_trait::async_trait;
use std::ops::{Deref, DerefMut};
use tokio::sync::{Mutex, MutexGuard};

#[async_trait]
pub trait Singleton<T: 'static + SingletonInit + Send + Sync + ?Sized = Self> {
    fn get() -> &'static Mutex<T>;

    async fn lock<'a>() -> SingletonGuard<'a, T>;
}

pub struct SingletonGuard<'a, T: 'static + SingletonInit + Send + Sync + ?Sized> {
    pub inner: MutexGuard<'a, T>,
}

impl<'a, T: 'static + SingletonInit + Send + Sync + ?Sized> Deref for SingletonGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, T: 'static + SingletonInit + Send + Sync + ?Sized> DerefMut for SingletonGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
