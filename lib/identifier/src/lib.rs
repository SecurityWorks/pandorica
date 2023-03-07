use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(untagged)]
pub enum Identifier {
    Some(String),
    None,
}

impl Identifier {
    pub fn new() -> Self {
        Self::Some(uuid7::uuid7().to_string())
    }

    pub fn is_some(&self) -> bool {
        match self {
            Self::Some(_) => true,
            Self::None => false,
        }
    }

    pub fn is_none(&self) -> bool {
        match self {
            Self::Some(_) => false,
            Self::None => true,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Some(s) => s,
            Self::None => panic!("Cannot as_str Identifier::None"),
        }
    }

    pub fn as_string(&self) -> String {
        match self {
            Self::Some(s) => s.clone(),
            Self::None => panic!("Cannot as_string Identifier::None"),
        }
    }

    pub fn full_identifier(&self) -> &str {
        match self {
            Self::Some(s) => s,
            Self::None => panic!("Cannot full_identifier Identifier::None"),
        }
    }

    pub fn partial_identifier(&self) -> &str {
        match self {
            Self::Some(s) => s.split(':').last().unwrap(),
            Self::None => panic!("Cannot partial_identifier Identifier::None"),
        }
    }
}

impl Default for Identifier {
    fn default() -> Self {
        Self::None
    }
}

impl Deref for Identifier {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Some(s) => s,
            Self::None => panic!("Cannot deref Identifier::None"),
        }
    }
}

impl DerefMut for Identifier {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Some(s) => s,
            Self::None => panic!("Cannot deref_mut Identifier::None"),
        }
    }
}

impl Serialize for Identifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Some(s) => serializer.serialize_str(s),
            Self::None => serializer.serialize_none(),
        }
    }
}
