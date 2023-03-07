use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

pub trait IntoKey {
    fn get_key(&self) -> String;
}

impl<T: IntoKey + Serialize> IntoKey for Vec<T> {
    fn get_key(&self) -> String {
        self.iter().map(|e| e.get_key()).collect()
    }
}

impl<T: IntoKey + Serialize> IntoKey for Box<T> {
    fn get_key(&self) -> String {
        self.as_ref().get_key()
    }
}

#[derive(Deserialize, Clone)]
#[serde(untagged)]
pub enum Foreign<T: IntoKey + Serialize> {
    Value(T),
    Key(String),
    None,
}

impl<T: IntoKey + Serialize> Foreign<T> {
    pub fn value(&self) -> Option<&T> {
        match self {
            Foreign::None => None,
            Foreign::Key(_) => None,
            Foreign::Value(inner) => Some(inner),
        }
    }

    pub fn value_mut(&mut self) -> Option<&mut T> {
        match self {
            Foreign::None => None,
            Foreign::Key(_) => None,
            Foreign::Value(inner) => Some(inner),
        }
    }

    pub fn key(&self) -> Option<&str> {
        match self {
            Foreign::None => None,
            Foreign::Key(inner) => Some(inner),
            Foreign::Value(_) => None,
        }
    }
}

impl<T: IntoKey + Serialize> Default for Foreign<T> {
    fn default() -> Self {
        Foreign::None
    }
}

impl<T: IntoKey + Serialize> From<T> for Foreign<T> {
    fn from(value: T) -> Self {
        Foreign::Value(value)
    }
}

impl<T: IntoKey + Serialize> Deref for Foreign<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            Foreign::None => panic!("Cannot deref Foreign::None"),
            Foreign::Key(_) => panic!("Cannot deref Foreign::Key"),
            Foreign::Value(inner) => inner,
        }
    }
}

impl<T: IntoKey + Serialize> DerefMut for Foreign<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Foreign::None => panic!("Cannot deref Foreign::None"),
            Foreign::Key(_) => panic!("Cannot deref Foreign::Key"),
            Foreign::Value(inner) => inner,
        }
    }
}

impl<T: IntoKey + Serialize> Serialize for Foreign<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Foreign::None => serializer.serialize_none(),
            Foreign::Key(inner) => serializer.serialize_str(inner),
            Foreign::Value(inner) => serializer.serialize_str(inner.get_key().as_str()),
        }
    }
}
