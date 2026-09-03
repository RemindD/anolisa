use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::path::PathBuf;

use asc_agentsight_client::{DEFAULT_AGENTSIGHT_BASE_URL, DEFAULT_AGENTSIGHT_TOKEN_FILE};

use crate::BootstrapConfig;

const HELP: &str = "Usage: asc-daemon [serve] --socket <ABSOLUTE_PATH> [OPTIONS]\n\
\n\
Runs the AgentSecCore V2 Policy capability-validation POC.\n\
Options:\n\
  --agentsight-url <URL>          AgentSight API root\n\
  --agentsight-token-file <PATH>  AgentSight Bearer token file\n";

/// Parsed command-line configuration for the daemon process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cli {
    /// Bootstrap configuration selected by the explicit process invocation.
    pub bootstrap: BootstrapConfig,
    /// POC `AgentSight` client configuration.
    pub policy: PolicyPocConfig,
}

/// External endpoint configuration for the Policy POC worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPocConfig {
    /// `AgentSight` API root.
    pub agentsight_url: String,
    /// Bearer-token file read once during daemon startup.
    pub agentsight_token_file: PathBuf,
}

impl Default for PolicyPocConfig {
    fn default() -> Self {
        Self {
            agentsight_url: DEFAULT_AGENTSIGHT_BASE_URL.to_owned(),
            agentsight_token_file: PathBuf::from(DEFAULT_AGENTSIGHT_TOKEN_FILE),
        }
    }
}

/// Successful command-line parse outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    /// Run the foreground daemon service.
    Serve(Cli),
    /// Print help without starting the service.
    Help(&'static str),
}

impl Cli {
    /// Parses an argv sequence including the binary name.
    ///
    /// Both `asc-daemon --socket ...` and `asc-daemon serve --socket ...` are
    /// accepted so the foreground entrypoint can be exercised independently
    /// without selecting a packaging-owned default path.
    ///
    /// # Errors
    /// Returns a stable parse error for a missing value, unknown option, repeated
    /// socket, non-Unicode option, or absent socket path.
    pub fn parse_from<I, T>(arguments: I) -> Result<ParseOutcome, CliError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        let mut arguments = arguments.into_iter().map(Into::into);
        let _program = arguments.next();
        let mut socket_path = None;
        let mut agentsight_url = None;
        let mut agentsight_token_file = None;
        let mut command_seen = false;

        while let Some(argument) = arguments.next() {
            if argument == OsStr::new("--help") || argument == OsStr::new("-h") {
                return Ok(ParseOutcome::Help(HELP));
            }
            if argument == OsStr::new("serve") && !command_seen && socket_path.is_none() {
                command_seen = true;
                continue;
            }
            if argument == OsStr::new("--socket") {
                if socket_path.is_some() {
                    return Err(CliError::RepeatedSocket);
                }
                let value = arguments.next().ok_or(CliError::MissingSocketValue)?;
                if value.is_empty() {
                    return Err(CliError::MissingSocketValue);
                }
                socket_path = Some(PathBuf::from(value));
                continue;
            }
            if argument == OsStr::new("--agentsight-url") {
                if agentsight_url.is_some() {
                    return Err(CliError::RepeatedAgentSightUrl);
                }
                let value = arguments
                    .next()
                    .ok_or(CliError::MissingAgentSightUrlValue)?;
                if value.is_empty() {
                    return Err(CliError::MissingAgentSightUrlValue);
                }
                agentsight_url = Some(value.to_string_lossy().into_owned());
                continue;
            }
            if argument == OsStr::new("--agentsight-token-file") {
                if agentsight_token_file.is_some() {
                    return Err(CliError::RepeatedAgentSightTokenFile);
                }
                let value = arguments
                    .next()
                    .ok_or(CliError::MissingAgentSightTokenFileValue)?;
                if value.is_empty() {
                    return Err(CliError::MissingAgentSightTokenFileValue);
                }
                agentsight_token_file = Some(PathBuf::from(value));
                continue;
            }

            let mut rendered = String::new();
            write!(&mut rendered, "{}", argument.to_string_lossy())
                .expect("writing into a String cannot fail");
            return Err(CliError::UnknownArgument(rendered));
        }

        let socket_path = socket_path.ok_or(CliError::MissingSocket)?;
        if !socket_path.is_absolute() {
            return Err(CliError::RelativeSocket);
        }
        let defaults = PolicyPocConfig::default();
        Ok(ParseOutcome::Serve(Self {
            bootstrap: BootstrapConfig::new(socket_path),
            policy: PolicyPocConfig {
                agentsight_url: agentsight_url.unwrap_or(defaults.agentsight_url),
                agentsight_token_file: agentsight_token_file
                    .unwrap_or(defaults.agentsight_token_file),
            },
        }))
    }
}

/// Invalid daemon command-line input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CliError {
    /// A socket path is required until packaging freezes a system-owned default.
    #[error("--socket <ABSOLUTE_PATH> is required")]
    MissingSocket,
    /// `--socket` was not followed by a value.
    #[error("--socket requires a value")]
    MissingSocketValue,
    /// Supplying multiple socket paths is ambiguous.
    #[error("--socket may be specified only once")]
    RepeatedSocket,
    /// `--agentsight-url` was not followed by a value.
    #[error("--agentsight-url requires a value")]
    MissingAgentSightUrlValue,
    /// More than one `AgentSight` API root was supplied.
    #[error("--agentsight-url may be specified only once")]
    RepeatedAgentSightUrl,
    /// `--agentsight-token-file` was not followed by a value.
    #[error("--agentsight-token-file requires a value")]
    MissingAgentSightTokenFileValue,
    /// More than one `AgentSight` token file was supplied.
    #[error("--agentsight-token-file may be specified only once")]
    RepeatedAgentSightTokenFile,
    /// The service framework rejects relative daemon endpoints.
    #[error("--socket must be an absolute path")]
    RelativeSocket,
    /// The current independent bootstrap has no other process options.
    #[error("unknown argument: {0}")]
    UnknownArgument(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_subcommand_and_serve_select_the_same_foreground_process() {
        let direct = Cli::parse_from(["asc-daemon", "--socket", "/run/asc/daemon.sock"]);
        let explicit = Cli::parse_from(["asc-daemon", "serve", "--socket", "/run/asc/daemon.sock"]);

        assert_eq!(direct, explicit);
        assert!(matches!(direct, Ok(ParseOutcome::Serve(_))));
    }

    #[test]
    fn socket_is_explicit_absolute_and_unambiguous() {
        assert_eq!(
            Cli::parse_from(["asc-daemon"]),
            Err(CliError::MissingSocket)
        );
        assert_eq!(
            Cli::parse_from(["asc-daemon", "--socket", "daemon.sock"]),
            Err(CliError::RelativeSocket)
        );
        assert_eq!(
            Cli::parse_from([
                "asc-daemon",
                "--socket",
                "/run/one.sock",
                "--socket",
                "/run/two.sock",
            ]),
            Err(CliError::RepeatedSocket)
        );
    }

    #[test]
    fn parses_explicit_agentsight_endpoint_and_token_file() {
        let ParseOutcome::Serve(cli) = Cli::parse_from([
            "asc-daemon",
            "serve",
            "--socket",
            "/run/asc/daemon.sock",
            "--agentsight-url",
            "http://127.0.0.1:17396/api",
            "--agentsight-token-file",
            "/run/credentials/agentsight-token",
        ])
        .unwrap() else {
            panic!("expected daemon configuration")
        };
        assert_eq!(cli.policy.agentsight_url, "http://127.0.0.1:17396/api");
        assert_eq!(
            cli.policy.agentsight_token_file,
            PathBuf::from("/run/credentials/agentsight-token")
        );
    }
}
