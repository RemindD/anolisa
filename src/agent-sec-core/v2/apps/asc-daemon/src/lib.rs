//! Process bootstrap for the `AgentSecCore` V2 daemon.
//!
//! The service framework remains independent while this process composition
//! root can register the Policy capability-validation POC.

#![forbid(unsafe_code)]

mod bootstrap;
mod cli;
mod runtime;
mod signals;

pub use bootstrap::{
    BootstrapConfig, BootstrapError, default_service_config, serve, serve_policy_poc,
    serve_without_handlers,
};
pub use cli::{Cli, CliError, ParseOutcome, PolicyPocConfig};
pub use runtime::{RuntimeError, run_with_shutdown_timeout};
pub use signals::{ProcessSignals, SignalError};
