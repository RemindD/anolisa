//! Daemon protocol adapter for local-peer PAP requests.
//!
//! The crate decodes method-specific protocol values, accepts a
//! transport-owned peer identity, and delegates authorization and Policy
//! administration to `asc-daemon-core`. Authentication binding is deferred.

#![forbid(unsafe_code)]

mod handler;
mod pap_handler;

pub use handler::DaemonHandler;
