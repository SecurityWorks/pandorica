use rustyline::config::Configurer;
use rustyline::highlight::Highlighter;
use rustyline::hint::{Hint, Hinter};
use rustyline::history::History;
use rustyline::{ColorMode, Completer, Editor, Helper, Validator};
use std::borrow::Cow;
use std::borrow::Cow::{Borrowed, Owned};
use std::collections::HashSet;

#[derive(Completer, Helper, Validator, Clone)]
pub struct CliHelper {
    pub masking: bool,
    pub commands: HashSet<Command>,
}

impl CliHelper {
    pub fn new() -> Self {
        let mut commands = HashSet::new();

        commands.insert(Command::new(
            "help",
            "help",
            "help",
            "Show this help message",
        ));
        commands.insert(Command::new(
            "login",
            "login [username] [password]",
            "login ",
            "Login to the server",
        ));
        commands.insert(Command::new(
            "logout",
            "logout",
            "logout",
            "Logout from the server",
        ));
        commands.insert(Command::new(
            "register",
            "register",
            "register",
            "Register a new account",
        ));
        commands.insert(Command::new("me", "me", "me", "Show your profile"));
        commands.insert(Command::new("exit", "exit", "exit", "Exit the CLI"));

        Self {
            masking: false,
            commands,
        }
    }

    pub fn begin_masking<H: History>(editor: &mut Editor<CliHelper, H>) {
        editor.helper_mut().unwrap().masking = true;
        editor.set_color_mode(ColorMode::Forced);
        editor.set_auto_add_history(false);
    }

    pub fn end_masking<H: History>(editor: &mut Editor<CliHelper, H>) {
        editor.helper_mut().unwrap().masking = false;
        editor.set_color_mode(ColorMode::Enabled);
        editor.set_auto_add_history(true);
    }
}

impl Highlighter for CliHelper {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        use unicode_width::UnicodeWidthStr;
        if self.masking {
            Owned("*".repeat(line.width()))
        } else if line.starts_with("login") && line.split(' ').count() == 3 {
            let mut parts = line.split(' ');
            let mut output = String::new();
            output.push_str(parts.next().unwrap());
            output.push(' ');
            output.push_str(parts.next().unwrap());
            output.push(' ');
            output.push_str(&"*".repeat(parts.next().unwrap().width()));
            Owned(output)
        } else {
            Borrowed(line)
        }
    }

    fn highlight_char(&self, line: &str, _pos: usize) -> bool {
        self.masking || (line.starts_with("login ") && line.split(' ').count() == 3)
    }
}

impl Hinter for CliHelper {
    type Hint = Command;

    fn hint(&self, line: &str, pos: usize, _ctx: &rustyline::Context<'_>) -> Option<Self::Hint> {
        if line.is_empty() || pos < line.len() {
            return None;
        }

        self.commands
            .iter()
            .filter_map(|command| {
                if command.display.starts_with(line) {
                    Some(command.suffix(pos))
                } else {
                    None
                }
            })
            .next()
    }
}

#[derive(Hash, Debug, PartialEq, Eq, Clone)]
pub struct Command {
    pub name: String,
    pub display: String,
    pub complete_up_to: usize,
    pub description: String,
}

impl Command {
    pub fn new(name: &str, display: &str, complete_up_to: &str, description: &str) -> Self {
        Self {
            name: name.into(),
            display: display.into(),
            complete_up_to: complete_up_to.len(),
            description: description.into(),
        }
    }

    pub fn suffix(&self, strip_chars: usize) -> Self {
        Self {
            name: self.name.clone(),
            display: self.display[strip_chars..].into(),
            complete_up_to: self.complete_up_to.saturating_sub(strip_chars),
            description: self.description.clone(),
        }
    }
}

impl Hint for Command {
    fn display(&self) -> &str {
        &self.display
    }

    fn completion(&self) -> Option<&str> {
        if self.complete_up_to > 0 {
            Some(&self.display[..self.complete_up_to])
        } else {
            None
        }
    }
}
