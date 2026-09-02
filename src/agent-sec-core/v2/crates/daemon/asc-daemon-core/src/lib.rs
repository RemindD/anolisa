//! Transport-independent daemon identity, authorization, and PAP orchestration.

#![forbid(unsafe_code)]

mod identity;
mod pap;

pub use identity::{PeerCredentials, Principal, PrincipalRole};
pub use pap::{PolicyAdministration, PolicyAdministrationError, ResourcePage};
