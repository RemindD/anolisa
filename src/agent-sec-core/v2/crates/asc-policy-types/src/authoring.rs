//! Product-facing policy authoring contracts.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::{Validate, ValidationError};

/// Minimal phase-one product policy vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum PolicyTemplate {
    /// High-sensitivity files must not be read into Agent context.
    HighSensitivityReadDeny {
        /// Absolute file paths or bounded glob patterns selected by the user.
        files: Vec<String>,
    },
    /// Deny deletion operations targeting matched filesystem directory entries.
    ///
    /// This template does not cover rename, move, link, content mutation, or
    /// other namespace-mutation operations.
    PreventFileDeletion {
        /// Absolute file paths or bounded glob patterns selected by the user.
        files: Vec<String>,
    },
    /// Low-sensitivity data may be read but direct flow to untrusted endpoints is denied.
    LowSensitivityEgress {
        /// Low-sensitivity paths whose direct flow is tracked.
        files: Vec<String>,
        /// Destinations excluded from the deny rule.
        trusted_destinations: Vec<TrustedDestination>,
    },
}

impl Validate for PolicyTemplate {
    fn validate(&self) -> Result<(), ValidationError> {
        let Self::PreventFileDeletion { files } = self else {
            return Err(ValidationError::new(
                "kind",
                "only prevent_file_deletion is currently supported",
            ));
        };
        if files.is_empty() {
            return Err(ValidationError::new("files", "must not be empty"));
        }
        let mut seen = HashSet::with_capacity(files.len());
        for (index, path) in files.iter().enumerate() {
            let field = format!("files[{index}]");
            validate_file_pattern(path).map_err(|message| ValidationError::new(&field, message))?;
            if !seen.insert(path) {
                return Err(ValidationError::new(field, "duplicate matcher"));
            }
        }
        Ok(())
    }
}

fn validate_file_pattern(value: &str) -> Result<(), &'static str> {
    if !value.starts_with('/') || value.contains('\0') || value.contains('~') || value.contains('$')
    {
        return Err(
            "path must be absolute and contain no NUL, home expansion, or environment variables",
        );
    }
    if value.len() > 4_096 {
        return Err("path exceeds 4096 bytes");
    }
    if value.len() > 1 && value.ends_with('/') {
        return Err("path must not have a trailing separator");
    }
    if value.len() > 1 && value.contains("//") {
        return Err("path contains repeated separators");
    }
    if value
        .split('/')
        .any(|segment| matches!(segment, "." | ".."))
    {
        return Err("path contains a dot segment");
    }
    if value.contains(['*', '?']) {
        if value.contains(['[', ']', '{', '}', '\\']) {
            return Err("glob supports only *, ?, and whole-segment **");
        }
        if value
            .split('/')
            .any(|segment| segment.contains("**") && segment != "**")
        {
            return Err("** must occupy a complete path segment");
        }
    }
    Ok(())
}

/// Product-level trusted egress destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum TrustedDestination {
    /// Lowercase DNS name or `*.` suffix pattern.
    Host {
        /// Host pattern selected by the user.
        pattern: String,
        /// Destination ports selected by the user.
        ports: Vec<u16>,
    },
    /// Canonical IP network.
    Cidr {
        /// Canonical network and prefix.
        cidr: String,
        /// Destination ports selected by the user.
        ports: Vec<u16>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_templates_keep_normalization_and_glob_validation_at_admission() {
        for path in ["/", "/protected", "/workspace/**", "/a/*/b", "/file?.txt"] {
            PolicyTemplate::PreventFileDeletion {
                files: vec![path.into()],
            }
            .validate()
            .unwrap();
        }
        for path in [
            "",
            "relative",
            "/with\0nul",
            "/~/file",
            "/$HOME/file",
            "/trailing/",
            "/repeated//separator",
            "/dot/./segment",
            "/dot/../segment",
            "/a/**b",
            "/a/[bc]*",
            "/a/{bc}*",
            "/a/\\*",
        ] {
            let error = PolicyTemplate::PreventFileDeletion {
                files: vec!["/valid".into(), path.into()],
            }
            .validate()
            .unwrap_err();
            assert_eq!(error.path, "files[1]", "{path:?}");
        }
        assert!(
            PolicyTemplate::PreventFileDeletion {
                files: vec![format!("/{}", "a".repeat(4095))],
            }
            .validate()
            .is_ok()
        );
        assert!(
            PolicyTemplate::PreventFileDeletion {
                files: vec![format!("/{}", "a".repeat(4096))],
            }
            .validate()
            .is_err()
        );
    }
}
