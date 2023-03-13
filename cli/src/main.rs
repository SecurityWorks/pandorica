mod client;
mod colorize;
mod commands;
mod helper;
mod models;
mod styles;

use clap::{Parser, ValueEnum};
use rustyline::error::ReadlineError;
use rustyline::{Editor, Result};

/// The Pandorica CLI is a command line interface for the Pandorica server.
/// It allows you to interact with the server from the command line.
#[derive(Parser, Debug)]
#[clap(name = "Pandorica CLI", version = "0.1.0", author = "Omnilium")]
struct Args {
    /// The host of the Pandorica server
    #[arg(short, long, default_value_t = String::from("http://localhost:5000"))]
    url: String,
    /// The username to use for authentication [Optional]
    #[arg(long)]
    username: Option<String>,
    /// The password to use for authentication [Optional]
    #[arg(long)]
    password: Option<String>,
    #[arg(long, value_enum, global = true, default_value_t = Color::Auto)]
    color: Color,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Color {
    Always,
    Auto,
    Never,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.color == Color::Always {
        owo_colors::set_override(true);
    } else if args.color == Color::Never {
        owo_colors::set_override(false);
    }

    let mut session_id: String = String::new();

    if let Some(username) = args.username {
        if let Some(password) = args.password {
            session_id = commands::login(args.url.clone(), username, password).await;
        }
    }

    println!(
        "{} {}{}\nExecute the {} command to see the available commands.",
        colorize::stdout("Pandorica CLI", &styles::BOLD_WHITE),
        colorize::stdout("v", &styles::BOLD_WHITE),
        colorize::stdout(env!("CARGO_PKG_VERSION"), &styles::BOLD_GREEN),
        colorize::stdout("help", &styles::BOLD_WHITE)
    );

    let helper = helper::CliHelper::new();
    let mut readline = Editor::new()?;
    readline.set_helper(Some(helper.clone()));

    let mut now: std::time::Instant;
    let mut elapsed = 0;

    loop {
        let prompt = if elapsed == 0 {
            String::from("> ")
        } else if elapsed > 1000 {
            format!("{}ms > ", elapsed / 1000)
        } else {
            format!("{}µs > ", elapsed)
        };
        let input =
            readline.readline(colorize::stdout(prompt.as_str(), &styles::BOLD_GRAY).as_str());
        now = std::time::Instant::now();
        match input {
            Ok(line) => {
                readline.add_history_entry(line.as_str())?;
                match line.split(' ').next().unwrap() {
                    "help" => commands::help(&helper),
                    "login" => {
                        let (username, password) = if line.split(' ').count() == 3 {
                            (
                                line.split(' ').nth(1).unwrap().to_string(),
                                line.split(' ').nth(2).unwrap().to_string(),
                            )
                        } else {
                            let username = readline.readline("Username: ")?;
                            helper::CliHelper::begin_masking(&mut readline);
                            let password = readline.readline("Password: ")?;
                            helper::CliHelper::end_masking(&mut readline);
                            (username, password)
                        };
                        session_id = String::from(
                            commands::login(args.url.clone(), username, password)
                                .await
                                .split(':')
                                .last()
                                .unwrap(),
                        );
                    }
                    "logout" => {
                        commands::logout(args.url.clone(), &session_id).await;
                        session_id = String::new();
                    }
                    "register" => commands::not_implemented(),
                    "exit" => break,
                    "me" => {
                        commands::me(args.url.clone(), &session_id).await;
                    }
                    &_ => commands::help(&helper),
                }
            }
            Err(ReadlineError::Interrupted) => {
                break;
            }
            Err(ReadlineError::Eof) => {
                break;
            }
            Err(err) => {
                eprintln!(
                    "{} {:#?}",
                    colorize::stderr("ERROR:", &styles::BOLD_RED),
                    err
                );
                break;
            }
        }
        elapsed = now.elapsed().as_micros();
    }

    Ok(())
}
