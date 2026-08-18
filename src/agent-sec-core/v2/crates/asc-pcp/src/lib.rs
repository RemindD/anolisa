//! Persistent single-process PCP control loop for `AgentSight` reconciliation.

#![forbid(unsafe_code)]

mod client;
mod controller;
mod store;

pub use client::{
    AgentSightClient, BINDINGS_PATH, ClientError, HttpAgentSightClient, POLICIES_PATH,
    RECEIPTS_PATH, STATE_PATH,
};
pub use controller::{Controller, ControllerError};
pub use store::{
    BindingOperationRecord, ControllerState, FileStateStore, MemoryStateStore,
    PolicyOperationRecord, PreparedPolicyRecord, StateStore, StoreError,
};
