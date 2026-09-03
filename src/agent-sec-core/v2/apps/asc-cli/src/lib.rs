//! Minimal daemon-only client for the Policy capability-validation POC.

#![forbid(unsafe_code)]

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use asc_daemon_protocol::{
    BINDING_CREATE_METHOD, BINDING_GET_METHOD, CreateBindingParams, CreatePolicyParams,
    CreateScopeParams, GetBindingParams, POLICY_CREATE_METHOD, RequestEnvelope, ResponseEnvelope,
    SCOPE_CREATE_METHOD,
};
use asc_foundation_types::{ResourceId, Revision};
use asc_policy_types::authoring::PolicyTemplate;
use asc_policy_types::scope::ScopeSelector;

const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Parsed POC CLI invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cli {
    /// Explicit daemon endpoint. The CLI never starts or bypasses the daemon.
    pub socket_path: PathBuf,
    command: Command,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    CreatePolicy { name: String, template: PathBuf },
    CreateScope { pid: u32 },
    CreateBinding(CreateBindingParams),
    GetBinding(GetBindingParams),
}

/// Result of parsing command-line input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseOutcome {
    /// Execute one daemon request.
    Run(Cli),
    /// Print static help.
    Help,
}

impl Cli {
    /// Parses one strict Policy POC command line.
    ///
    /// # Errors
    /// Returns a stable error for missing, repeated, or malformed options.
    pub fn parse_from<I, S>(arguments: I) -> Result<ParseOutcome, CliError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut arguments: Vec<String> = arguments.into_iter().map(Into::into).collect();
        if !arguments.is_empty() {
            arguments.remove(0);
        }
        if arguments
            .iter()
            .any(|value| matches!(value.as_str(), "-h" | "--help"))
        {
            return Ok(ParseOutcome::Help);
        }
        let socket_path =
            take_option(&mut arguments, "--socket")?.ok_or(CliError::MissingOption("--socket"))?;
        let socket_path = PathBuf::from(socket_path);
        if !socket_path.is_absolute() {
            return Err(CliError::RelativeSocket);
        }
        let command = parse_command(arguments)?;
        Ok(ParseOutcome::Run(Self {
            socket_path,
            command,
        }))
    }

    /// Sends the selected request through the configured UDS and returns its data.
    ///
    /// # Errors
    /// Returns local input/transport failures or a structured daemon failure.
    pub fn execute(&self) -> Result<serde_json::Value, CliError> {
        let request = self.request()?;
        let response = send_request(&self.socket_path, &request)?;
        if response.ok {
            Ok(response.data)
        } else {
            let error = response.error.unwrap_or(asc_daemon_protocol::ErrorBody {
                code: "protocol_error".to_owned(),
                message: "daemon returned an invalid failure response".to_owned(),
            });
            Err(CliError::Daemon {
                code: error.code,
                message: error.message,
            })
        }
    }

    fn request(&self) -> Result<RequestEnvelope, CliError> {
        match &self.command {
            Command::CreatePolicy { name, template } => {
                let bytes = fs::read(template).map_err(|_| CliError::TemplateUnavailable)?;
                let template = serde_json::from_slice::<PolicyTemplate>(&bytes)
                    .map_err(|_| CliError::InvalidTemplate)?;
                RequestEnvelope::from_params(
                    POLICY_CREATE_METHOD,
                    &CreatePolicyParams {
                        policy_name: name.clone(),
                        template,
                    },
                )
                .map_err(|_| CliError::Serialization)
            }
            Command::CreateScope { pid } => RequestEnvelope::from_params(
                SCOPE_CREATE_METHOD,
                &CreateScopeParams {
                    selector: ScopeSelector::Pid { pid: *pid },
                },
            )
            .map_err(|_| CliError::Serialization),
            Command::CreateBinding(params) => {
                RequestEnvelope::from_params(BINDING_CREATE_METHOD, params)
                    .map_err(|_| CliError::Serialization)
            }
            Command::GetBinding(params) => RequestEnvelope::from_params(BINDING_GET_METHOD, params)
                .map_err(|_| CliError::Serialization),
        }
    }
}

fn parse_command(mut arguments: Vec<String>) -> Result<Command, CliError> {
    if arguments.len() < 2 {
        return Err(CliError::MissingCommand);
    }
    let resource = arguments.remove(0);
    let operation = arguments.remove(0);
    let command = match (resource.as_str(), operation.as_str()) {
        ("policy", "create") => {
            let name = required_option(&mut arguments, "--name")?;
            let template = PathBuf::from(required_option(&mut arguments, "--file")?);
            Command::CreatePolicy { name, template }
        }
        ("scope", "create") => {
            let raw = required_option(&mut arguments, "--pid")?;
            let pid = raw
                .parse::<u32>()
                .ok()
                .filter(|pid| *pid > 0)
                .ok_or(CliError::InvalidOption("--pid"))?;
            Command::CreateScope { pid }
        }
        ("binding", "create") => Command::CreateBinding(CreateBindingParams {
            policy_id: resource_id(required_option(&mut arguments, "--policy-id")?)?,
            policy_revision: revision(&required_option(&mut arguments, "--policy-revision")?)?,
            scope_id: resource_id(required_option(&mut arguments, "--scope-id")?)?,
            scope_revision: revision(&required_option(&mut arguments, "--scope-revision")?)?,
        }),
        ("binding", "get") => Command::GetBinding(GetBindingParams {
            binding_id: resource_id(required_option(&mut arguments, "--binding-id")?)?,
        }),
        _ => return Err(CliError::UnknownCommand),
    };
    if let Some(argument) = arguments.first() {
        return Err(CliError::UnknownArgument(argument.clone()));
    }
    Ok(command)
}

fn required_option(arguments: &mut Vec<String>, option: &'static str) -> Result<String, CliError> {
    take_option(arguments, option)?.ok_or(CliError::MissingOption(option))
}

fn take_option(
    arguments: &mut Vec<String>,
    option: &'static str,
) -> Result<Option<String>, CliError> {
    let matches: Vec<_> = arguments
        .iter()
        .enumerate()
        .filter_map(|(index, value)| (value == option).then_some(index))
        .collect();
    match matches.as_slice() {
        [] => Ok(None),
        [index] => {
            if *index + 1 >= arguments.len() {
                return Err(CliError::MissingOptionValue(option));
            }
            arguments.remove(*index);
            Ok(Some(arguments.remove(*index)))
        }
        _ => Err(CliError::RepeatedOption(option)),
    }
}

fn resource_id(value: String) -> Result<ResourceId, CliError> {
    ResourceId::new(value).map_err(|_| CliError::InvalidIdentifier)
}

fn revision(value: &str) -> Result<Revision, CliError> {
    value
        .parse::<u32>()
        .map_err(|_| CliError::InvalidRevision)
        .and_then(|value| Revision::new(value).map_err(|_| CliError::InvalidRevision))
}

fn send_request(path: &Path, request: &RequestEnvelope) -> Result<ResponseEnvelope, CliError> {
    let mut stream = UnixStream::connect(path).map_err(|_| CliError::DaemonUnavailable)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| CliError::DaemonUnavailable)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|_| CliError::DaemonUnavailable)?;
    serde_json::to_writer(&mut stream, request).map_err(|_| CliError::Serialization)?;
    stream
        .write_all(b"\n")
        .map_err(|_| CliError::DaemonUnavailable)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_| CliError::DaemonUnavailable)?;

    let mut response = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut response)
        .map_err(|_| CliError::DaemonUnavailable)?;
    if response.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(CliError::ResponseTooLarge);
    }
    serde_json::from_slice(&response).map_err(|_| CliError::InvalidResponse)
}

/// Stable local CLI failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CliError {
    /// No Policy subcommand was provided.
    #[error("a command is required")]
    MissingCommand,
    /// An unsupported resource or operation was selected.
    #[error("unknown command")]
    UnknownCommand,
    /// A required option was absent.
    #[error("missing required option {0}")]
    MissingOption(&'static str),
    /// An option was not followed by a value.
    #[error("{0} requires a value")]
    MissingOptionValue(&'static str),
    /// An option was provided more than once.
    #[error("{0} may be specified only once")]
    RepeatedOption(&'static str),
    /// An option value is malformed.
    #[error("invalid value for {0}")]
    InvalidOption(&'static str),
    /// A trailing argument is unsupported.
    #[error("unknown argument: {0}")]
    UnknownArgument(String),
    /// The daemon socket must be explicit and absolute.
    #[error("--socket must be an absolute path")]
    RelativeSocket,
    /// A resource identity is invalid.
    #[error("invalid resource identifier")]
    InvalidIdentifier,
    /// A revision is not a positive `u32`.
    #[error("invalid revision")]
    InvalidRevision,
    /// The Policy template file could not be read.
    #[error("Policy template file is unavailable")]
    TemplateUnavailable,
    /// The Policy template file does not match the authoring schema.
    #[error("invalid Policy template JSON")]
    InvalidTemplate,
    /// The selected request could not be serialized.
    #[error("request serialization failed")]
    Serialization,
    /// The daemon socket or I/O path is unavailable.
    #[error("daemon unavailable")]
    DaemonUnavailable,
    /// The bounded response limit was exceeded.
    #[error("daemon response is too large")]
    ResponseTooLarge,
    /// The daemon response did not match the protocol envelope.
    #[error("invalid daemon response")]
    InvalidResponse,
    /// The daemon returned a structured method failure.
    #[error("daemon error {code}: {message}")]
    Daemon { code: String, message: String },
}

/// Static help for the POC CLI.
pub const HELP: &str = "\
AgentSecCore V2 Policy capability-validation CLI\n\n\
Usage:\n\
  asc-cli --socket <ABSOLUTE_PATH> policy create --name <NAME> --file <TEMPLATE_JSON>\n\
  asc-cli --socket <ABSOLUTE_PATH> scope create --pid <PID>\n\
  asc-cli --socket <ABSOLUTE_PATH> binding create --policy-id <ID> --policy-revision <N> --scope-id <ID> --scope-revision <N>\n\
  asc-cli --socket <ABSOLUTE_PATH> binding get --binding-id <ID>\n\n\
The CLI is daemon-only and has no local fallback.\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_template_is_reused_without_rewriting_its_json() {
        let template = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/pap/prevent-file-deletion.json");
        let outcome = Cli::parse_from([
            "asc-cli",
            "policy",
            "create",
            "--name",
            "protect files",
            "--file",
            template.to_str().unwrap(),
            "--socket",
            "/run/asc/daemon.sock",
        ])
        .unwrap();
        let ParseOutcome::Run(cli) = outcome else {
            panic!("expected executable CLI")
        };
        let request = cli.request().unwrap();
        let actual = serde_json::to_value(request).unwrap();
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/daemon/poc-policy-create.request.json"
        ))
        .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn rejects_relative_socket_zero_pid_and_unknown_arguments() {
        assert_eq!(
            Cli::parse_from([
                "asc-cli",
                "--socket",
                "daemon.sock",
                "scope",
                "create",
                "--pid",
                "1",
            ]),
            Err(CliError::RelativeSocket)
        );
        assert_eq!(
            Cli::parse_from([
                "asc-cli",
                "--socket",
                "/run/asc.sock",
                "scope",
                "create",
                "--pid",
                "0",
            ]),
            Err(CliError::InvalidOption("--pid"))
        );
    }
}
