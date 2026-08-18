//! Durable single-process PCP controller state.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use asc_policy_engine::TemplateEnvelope;
use asc_policy_types::policy::PolicyEnvelope;
use asc_policy_types::receipt::Receipt;
use asc_policy_types::reconcile::{
    ReconcileBindingRequest, ReconcileBindingResponse, ReconcilePolicyRequest,
    ReconcilePolicyResponse,
};
use serde::{Deserialize, Serialize};

/// Stored product template and its deterministic Canonical IR result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedPolicyRecord {
    /// Original product-level intent.
    pub template: TemplateEnvelope,
    /// Lowered backend-independent policy.
    pub canonical_policy: PolicyEnvelope,
}

/// Durable idempotency record for one policy operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyOperationRecord {
    /// Exact desired request. Reusing the operation ID with another body is rejected.
    pub request: ReconcilePolicyRequest,
    /// Last authoritative `AgentSight` result, absent while uncertain.
    pub observed: Option<ReconcilePolicyResponse>,
}

/// Durable idempotency record for one binding operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BindingOperationRecord {
    /// Exact desired request. Reusing the operation ID with another body is rejected.
    pub request: ReconcileBindingRequest,
    /// Last authoritative `AgentSight` result, absent while uncertain.
    pub observed: Option<ReconcileBindingResponse>,
}

/// Complete single-process PCP state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ControllerState {
    /// Prepared policies keyed by `policyId:revision`.
    pub prepared_policies: BTreeMap<String, PreparedPolicyRecord>,
    /// Policy operations keyed by operation ID.
    pub policy_operations: BTreeMap<String, PolicyOperationRecord>,
    /// Binding operations keyed by operation ID.
    pub binding_operations: BTreeMap<String, BindingOperationRecord>,
    /// Deduplicated receipts keyed by receipt ID.
    pub receipts: BTreeMap<String, Receipt>,
    /// Last durably committed receipt cursor.
    pub receipt_cursor: Option<String>,
}

/// Persistence failure.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Filesystem I/O failed.
    #[error("state I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Stored JSON is outside the state contract.
    #[error("state JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    /// A process-local state lock was poisoned.
    #[error("state lock was poisoned")]
    Poisoned,
}

/// Pluggable durable state backend.
pub trait StateStore {
    /// Loads the last committed state.
    ///
    /// # Errors
    /// Returns an I/O, decoding, or local synchronization failure.
    fn load(&self) -> Result<ControllerState, StoreError>;
    /// Atomically replaces the committed state.
    ///
    /// # Errors
    /// Returns an I/O, encoding, or local synchronization failure.
    fn save(&self, state: &ControllerState) -> Result<(), StoreError>;
}

/// In-memory store for tests and ephemeral controllers.
#[derive(Debug, Default)]
pub struct MemoryStateStore {
    state: Mutex<ControllerState>,
}

impl StateStore for MemoryStateStore {
    fn load(&self) -> Result<ControllerState, StoreError> {
        self.state
            .lock()
            .map_err(|_| StoreError::Poisoned)
            .map(|state| state.clone())
    }

    fn save(&self, state: &ControllerState) -> Result<(), StoreError> {
        *self.state.lock().map_err(|_| StoreError::Poisoned)? = state.clone();
        Ok(())
    }
}

/// JSON file store using same-directory write, fsync, and atomic rename.
#[derive(Debug)]
pub struct FileStateStore {
    path: PathBuf,
    access: Mutex<()>,
}

impl FileStateStore {
    /// Creates a store at `path`. The file is created on first save.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            access: Mutex::new(()),
        }
    }

    fn temporary_path(&self) -> PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(".tmp");
        self.path.with_file_name(name)
    }
}

impl StateStore for FileStateStore {
    fn load(&self) -> Result<ControllerState, StoreError> {
        let _guard = self.access.lock().map_err(|_| StoreError::Poisoned)?;
        if !self.path.exists() {
            return Ok(ControllerState::default());
        }
        let bytes = fs::read(&self.path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn save(&self, state: &ControllerState) -> Result<(), StoreError> {
        let _guard = self.access.lock().map_err(|_| StoreError::Poisoned)?;
        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let temporary = self.temporary_path();
        write_state_file(&temporary, state)?;
        fs::rename(&temporary, &self.path)?;
        sync_parent(&self.path)?;
        Ok(())
    }
}

fn write_state_file(path: &Path, state: &ControllerState) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec_pretty(state)?;
    let mut file = File::create(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), StoreError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}
