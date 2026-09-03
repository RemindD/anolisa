//! Minimal in-process Policy runtime used by the capability-validation POC.
//!
//! This crate deliberately provides an in-memory Repository, one supported
//! Policy compiler path, and a bounded best-effort reconciliation queue. It is
//! not a durable outbox or a production reconciliation subsystem.

#![forbid(unsafe_code)]

mod compiler;
mod memory;
mod reconciler;

pub use compiler::PocPolicyCompiler;
pub use memory::InMemoryPapRepository;
pub use reconciler::{
    BindingDeploymentClient, EnqueueError, ReconcileEnqueuer, ReconcileWorker, reconciliation_queue,
};
