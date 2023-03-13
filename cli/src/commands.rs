use crate::helper::CliHelper;
use crate::models::{Session, User};

pub fn not_implemented() {
    eprintln!(
        "{}",
        crate::colorize::stderr(
            "ERROR: This command is not implemented yet.",
            &crate::styles::BOLD_RED
        )
    );
}

pub fn help(helper: &CliHelper) {
    use unicode_width::UnicodeWidthStr;
    println!("Commands:");

    helper.commands.iter().for_each(|command| {
        println!(
            "  {}{}{}",
            command.name,
            " ".repeat(16 - command.name.width()),
            command.description
        );
    });
}

pub async fn login(url: String, username: String, password: String) -> String {
    println!(
        "Logging in to {} with user {}...",
        crate::colorize::stdout(&url, &crate::styles::BOLD_GREEN),
        crate::colorize::stdout(&username, &crate::styles::BOLD_GREEN)
    );

    let result = crate::client::login(url, username, password).await;

    match result {
        Ok(response) => {
            println!(
                "{}",
                crate::colorize::stdout("Logged in successfully.", &crate::styles::BOLD_GREEN)
            );

            response.session.unwrap().id
        }
        Err(err) => {
            eprintln!(
                "{} {:#?}",
                crate::colorize::stderr("ERROR:", &crate::styles::BOLD_RED),
                err
            );

            String::new()
        }
    }
}

pub async fn logout(url: String, session_id: &str) {
    println!(
        "Logging out from {}...",
        crate::colorize::stdout(&url, &crate::styles::BOLD_GREEN)
    );

    let result = crate::client::logout(url, session_id).await;

    match result {
        Ok(_) => {
            println!(
                "{}",
                crate::colorize::stdout("Logged out successfully.", &crate::styles::BOLD_GREEN)
            );
        }
        Err(err) => {
            eprintln!(
                "{} {:#?}",
                crate::colorize::stderr("ERROR:", &crate::styles::BOLD_RED),
                err
            );
        }
    }
}

pub async fn me(url: String, session_id: &str) {
    if session_id.is_empty() {
        eprintln!(
            "{}",
            crate::colorize::stderr(
                "ERROR: You are not logged in. Please log in first.",
                &crate::styles::BOLD_RED
            )
        );

        return;
    }

    println!(
        "Getting information about the current user on {}...",
        crate::colorize::stdout(&url, &crate::styles::BOLD_GREEN)
    );

    let result = crate::client::me(url, session_id).await;

    match result {
        Ok(response) => {
            println!(
                "{}",
                crate::colorize::stdout(
                    "Got information successfully.",
                    &crate::styles::BOLD_GREEN
                )
            );

            let user: User = response.user.unwrap().into();
            let mut sessions: Vec<Session> = Vec::new();
            response.sessions.iter().for_each(|session| {
                sessions.push(session.clone().into());
            });

            println!("{}\n", user);
            sessions.iter().for_each(|session| {
                println!("{}\n", session);
            });
        }
        Err(err) => {
            eprintln!(
                "{} {:#?}",
                crate::colorize::stderr("ERROR:", &crate::styles::BOLD_RED),
                err
            );
        }
    }
}
