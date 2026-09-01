//! PAP request and response contracts for the future local daemon transport.
//!
//! This crate owns only the untrusted wire boundary. Stable Policy, Scope,
//! and prepared resource payloads are reused from `asc-policy-types`; PAP,
//! persistence, authorization, and request dispatch live in higher layers.
//! Its response contract uses method-specific results and structured errors;
//! command rendering and process exit codes remain client concerns.

#![forbid(unsafe_code)]

mod common;
mod envelope;
mod frame;
pub mod method;
mod pap;
mod response;

pub use common::{ListParams, ListResult, ResourceParams, RevisionParams};
pub use envelope::DaemonRequest;
pub use frame::MAX_FRAME_BYTES;
pub use pap::{
    CreateBindingParams, CreateBindingResult, CreatePolicyParams, CreatePolicyResult,
    CreateScopeParams, CreateScopeResult, DeleteBindingResult, DeletePolicyResult,
    DeleteScopeResult, GetBindingResult, GetPolicyResult, GetScopeResult, ListBindingsResult,
    ListPoliciesResult, ListScopesResult, UpdateBindingParams, UpdateBindingResult,
    UpdatePolicyParams, UpdatePolicyResult, UpdateScopeParams, UpdateScopeResult,
};
pub use response::{
    DaemonError, DaemonResponse, ErrorCode, ErrorResponse, RequestId, SuccessResponse, error_code,
};
