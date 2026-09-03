use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use asc_agentsight_client::AgentSightClient;
use asc_daemon::{Cli, ParseOutcome, ProcessSignals, run_with_shutdown_timeout, serve_policy_poc};
use asc_daemon_service::ShutdownToken;

const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

fn main() -> ExitCode {
    match run_with_shutdown_timeout(run(), RUNTIME_SHUTDOWN_TIMEOUT) {
        Ok(exit_code) => exit_code,
        Err(problem) => {
            report_error(&problem);
            ExitCode::FAILURE
        }
    }
}

async fn run() -> ExitCode {
    let outcome = match Cli::parse_from(std::env::args_os()) {
        Ok(outcome) => outcome,
        Err(problem) => {
            eprintln!("asc-daemon: {problem}");
            return ExitCode::from(2);
        }
    };
    let ParseOutcome::Serve(cli) = outcome else {
        let ParseOutcome::Help(help) = outcome else {
            unreachable!("all parse outcomes are covered")
        };
        print!("{help}");
        return ExitCode::SUCCESS;
    };

    let client = match AgentSightClient::new_with_token_file(
        &cli.policy.agentsight_url,
        &cli.policy.agentsight_token_file,
    ) {
        Ok(client) => Arc::new(client),
        Err(problem) => {
            report_error(&problem);
            return ExitCode::FAILURE;
        }
    };

    let signals = match ProcessSignals::install() {
        Ok(signals) => signals,
        Err(problem) => {
            eprintln!("asc-daemon: {problem}");
            return ExitCode::FAILURE;
        }
    };
    let shutdown = ShutdownToken::new();
    let signal_task = tokio::spawn(signals.request_shutdown(shutdown.clone()));
    let result = serve_policy_poc(cli.bootstrap, client, shutdown).await;
    signal_task.abort();

    match result {
        Ok(_) => ExitCode::SUCCESS,
        Err(problem) => {
            report_error(&problem);
            ExitCode::FAILURE
        }
    }
}

fn report_error(problem: &dyn std::error::Error) {
    eprintln!("asc-daemon: {problem}");
    let mut source = problem.source();
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }
}
