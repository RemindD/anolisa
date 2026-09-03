use std::env;
use std::process::ExitCode;

use asc_cli::{Cli, HELP, ParseOutcome};

fn main() -> ExitCode {
    match Cli::parse_from(env::args()) {
        Ok(ParseOutcome::Help) => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        Ok(ParseOutcome::Run(cli)) => match cli.execute() {
            Ok(data) => {
                if let Ok(output) = serde_json::to_string_pretty(&data) {
                    println!("{output}");
                    ExitCode::SUCCESS
                } else {
                    eprintln!("asc-cli: response serialization failed");
                    ExitCode::FAILURE
                }
            }
            Err(error) => {
                eprintln!("asc-cli: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("asc-cli: {error}\n\n{HELP}");
            ExitCode::from(2)
        }
    }
}
