use crate::SingletonInit;

pub trait Singleton<T: 'static + SingletonInit + Send + Sync + ?Sized = Self> {
    fn get() -> &'static T;
}
