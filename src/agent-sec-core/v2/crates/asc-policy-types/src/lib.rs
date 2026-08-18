//! Stable domain and wire contracts for the `AgentSecCore` policy control plane.
//!
//! This crate intentionally contains data contracts only. Policy storage,
//! resolution, target compilation, and enforcement live in higher-level
//! crates. Rust types are canonical; serde JSON is the wire representation.

#![forbid(unsafe_code)]

pub mod binding;
pub mod error;
pub mod identifiers;
pub mod ir;
pub mod mapping;
pub mod policy;
pub mod profile;
pub mod protocol;
pub mod receipt;
pub mod reconcile;
pub mod resource;
pub mod scope;
pub mod state;

pub use error::{Validate, ValidationError};
