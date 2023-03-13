use chrono::{DateTime, Local, NaiveDateTime, Utc};
use std::fmt::{Display, Formatter};

pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub added_on: DateTime<Local>,
    pub last_seen_on: DateTime<Local>,
    pub is_active: bool,
}

impl Display for User {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "User {}\n    Username: {}\n    Email: {}\n    Added On: {}\n    Last Seen On: {}\n    Is Active: {}",
            self.id,
            self.username,
            self.email,
            self.added_on,
            self.last_seen_on,
            self.is_active
        )
    }
}

impl From<protobuf::pandorica_common::User> for User {
    fn from(value: protobuf::pandorica_common::User) -> Self {
        Self {
            id: value.id,
            username: value.username,
            email: value.email.unwrap_or("<no email>".into()),
            added_on: NaiveDateTime::from_timestamp_micros(value.added_on)
                .unwrap()
                .and_local_timezone(Utc)
                .unwrap()
                .with_timezone(&Local),
            last_seen_on: NaiveDateTime::from_timestamp_micros(value.last_seen_on)
                .unwrap()
                .and_local_timezone(Utc)
                .unwrap()
                .with_timezone(&Local),
            is_active: value.is_active,
        }
    }
}

pub struct Session {
    pub id: String,
    pub user_id: String,
    pub added_on: DateTime<Local>,
    pub last_used_on: DateTime<Local>,
    pub expires_on: DateTime<Local>,
}

impl Display for Session {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Session {}\n    User ID: {}\n    Added On: {}\n    Last Used On: {}\n    Expires On: {}",
            self.id,
            self.user_id,
            self.added_on,
            self.last_used_on,
            self.expires_on
        )
    }
}

impl From<protobuf::pandorica_common::Session> for Session {
    fn from(value: protobuf::pandorica_common::Session) -> Self {
        Self {
            id: value.id,
            user_id: value.user_id.unwrap_or("<no user>".into()),
            added_on: NaiveDateTime::from_timestamp_micros(value.added_on)
                .unwrap()
                .and_local_timezone(Utc)
                .unwrap()
                .with_timezone(&Local),
            last_used_on: NaiveDateTime::from_timestamp_micros(value.last_used_on)
                .unwrap()
                .and_local_timezone(Utc)
                .unwrap()
                .with_timezone(&Local),
            expires_on: NaiveDateTime::from_timestamp_micros(value.expires_on)
                .unwrap()
                .and_local_timezone(Utc)
                .unwrap()
                .with_timezone(&Local),
        }
    }
}
