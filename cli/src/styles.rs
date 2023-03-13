use once_cell::sync::Lazy;
use owo_colors::Style;

pub static BOLD_WHITE: Lazy<Style> = Lazy::new(|| Style::new().bold().bright_white());
pub static BOLD_GRAY: Lazy<Style> = Lazy::new(|| Style::new().bold().white());
pub static BOLD_GREEN: Lazy<Style> = Lazy::new(|| Style::new().bold().bright_green());
pub static BOLD_RED: Lazy<Style> = Lazy::new(|| Style::new().bold().bright_red());
