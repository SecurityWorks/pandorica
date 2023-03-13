use once_cell::sync::Lazy;
use owo_colors::{OwoColorize, Stream, Style};

pub fn stdout(text: &str, style: &Lazy<Style>) -> String {
    format!(
        "{}",
        text.if_supports_color(Stream::Stdout, |s| s.style((*style).to_owned()))
    )
}

pub fn stderr(text: &str, style: &Lazy<Style>) -> String {
    format!(
        "{}",
        text.if_supports_color(Stream::Stderr, |s| s.style((*style).to_owned()))
    )
}
