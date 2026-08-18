//! Process entry point for the test-only `AgentSecCore` V2 policy service.

use std::env;
use std::error::Error;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use asc_pcp::{FileStateStore, HttpAgentSightClient};
use asc_policy_service::{PolicyService, serve};

const HELP: &str = "\
AgentSecCore V2 test policy service

Usage:
  asc-policy-service [OPTIONS]

Options:
  --listen <ADDRESS>                  Listen address [default: 127.0.0.1:7460]
  --agentsight-url <URL>              AgentSight origin [default: http://127.0.0.1:7396]
  --agentsight-token-file <PATH>      Optional AgentSight Bearer token file
  --state-file <PATH>                 Durable PCP JSON state [default: ./asc-policy-service-state.json]
  --reconcile-interval-seconds <N>    Background interval; 0 disables it [default: 5]
  --receipt-limit <N>                 Receipt page size, 1..1000 [default: 100]
  -h, --help                          Print help
";

#[derive(Debug)]
struct Config {
    listen: String,
    agentsight_url: String,
    agentsight_token_file: Option<PathBuf>,
    state_file: PathBuf,
    reconcile_interval: Duration,
    receipt_limit: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7460".to_owned(),
            agentsight_url: "http://127.0.0.1:7396".to_owned(),
            agentsight_token_file: None,
            state_file: PathBuf::from("asc-policy-service-state.json"),
            reconcile_interval: Duration::from_secs(5),
            receipt_limit: 100,
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum ConfigError {
    #[error("missing value for {0}")]
    MissingValue(String),
    #[error("invalid value for {option}: {value}")]
    InvalidValue { option: String, value: String },
    #[error("unknown argument: {0}")]
    UnknownArgument(String),
}

enum ParsedConfig {
    Run(Config),
    Help,
}

fn parse_config<I>(arguments: I) -> Result<ParsedConfig, ConfigError>
where
    I: IntoIterator<Item = String>,
{
    let mut config = Config::default();
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => return Ok(ParsedConfig::Help),
            "--listen" => config.listen = next_value(&mut arguments, &argument)?,
            "--agentsight-url" => {
                config.agentsight_url = next_value(&mut arguments, &argument)?;
            }
            "--agentsight-token-file" => {
                config.agentsight_token_file =
                    Some(PathBuf::from(next_value(&mut arguments, &argument)?));
            }
            "--state-file" => {
                config.state_file = PathBuf::from(next_value(&mut arguments, &argument)?);
            }
            "--reconcile-interval-seconds" => {
                let value = next_value(&mut arguments, &argument)?;
                let seconds = parse_number::<u64>(&argument, &value)?;
                config.reconcile_interval = Duration::from_secs(seconds);
            }
            "--receipt-limit" => {
                let value = next_value(&mut arguments, &argument)?;
                let limit = parse_number::<u16>(&argument, &value)?;
                if !(1..=1_000).contains(&limit) {
                    return Err(ConfigError::InvalidValue {
                        option: argument,
                        value,
                    });
                }
                config.receipt_limit = limit;
            }
            _ => return Err(ConfigError::UnknownArgument(argument)),
        }
    }
    Ok(ParsedConfig::Run(config))
}

fn next_value<I>(arguments: &mut I, option: &str) -> Result<String, ConfigError>
where
    I: Iterator<Item = String>,
{
    arguments
        .next()
        .ok_or_else(|| ConfigError::MissingValue(option.to_owned()))
}

fn parse_number<T>(option: &str, value: &str) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
{
    value.parse::<T>().map_err(|_| ConfigError::InvalidValue {
        option: option.to_owned(),
        value: value.to_owned(),
    })
}

fn run(config: &Config) -> Result<(), Box<dyn Error>> {
    let client = match &config.agentsight_token_file {
        Some(path) => HttpAgentSightClient::new_with_token_file(&config.agentsight_url, path)?,
        None => HttpAgentSightClient::new(&config.agentsight_url)?,
    };
    let store = FileStateStore::new(&config.state_file);
    let service = Arc::new(PolicyService::new(client, store)?);
    let listener = TcpListener::bind(&config.listen)?;
    let local_address = listener.local_addr()?;

    let reconcile_interval = config.reconcile_interval;
    let receipt_limit = config.receipt_limit;
    if !reconcile_interval.is_zero() {
        let maintenance_service = Arc::clone(&service);
        thread::spawn(move || {
            loop {
                thread::sleep(reconcile_interval);
                match maintenance_service.maintain_once(receipt_limit) {
                    Ok(report) if !report.errors.is_empty() => {
                        eprintln!(
                            "policy maintenance completed with errors: {:?}",
                            report.errors
                        );
                    }
                    Err(error) => eprintln!("policy maintenance failed: {error}"),
                    Ok(_) => {}
                }
            }
        });
    }

    eprintln!(
        "asc-policy-service listening on http://{local_address}; state={}; agentsight={}",
        config.state_file.display(),
        config.agentsight_url
    );
    serve(&listener, &service)?;
    Ok(())
}

fn main() -> ExitCode {
    match parse_config(env::args().skip(1)) {
        Ok(ParsedConfig::Help) => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        Ok(ParsedConfig::Run(config)) => match run(&config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("asc-policy-service failed: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}\n\n{HELP}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_maintenance_options() {
        let ParsedConfig::Run(config) = parse_config([
            "--listen".to_owned(),
            "127.0.0.1:17460".to_owned(),
            "--reconcile-interval-seconds".to_owned(),
            "0".to_owned(),
            "--agentsight-token-file".to_owned(),
            "/run/credentials/agentsight-token".to_owned(),
            "--receipt-limit".to_owned(),
            "500".to_owned(),
        ])
        .unwrap() else {
            panic!("expected run configuration");
        };
        assert_eq!(config.listen, "127.0.0.1:17460");
        assert!(config.reconcile_interval.is_zero());
        assert_eq!(
            config.agentsight_token_file,
            Some(PathBuf::from("/run/credentials/agentsight-token"))
        );
        assert_eq!(config.receipt_limit, 500);
    }
}
