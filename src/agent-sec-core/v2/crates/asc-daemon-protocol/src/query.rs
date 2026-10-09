//! Flat V1-compatible observability filters; ownership comes only from the authenticated socket peer.

use serde::{Deserialize, Serialize};

/// Parameters for the three bounded observability query methods.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ObservabilityQueryParams {
    /// Required by run and timeline queries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Required only by timeline queries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Inclusive ISO lower bound, interpreted as local time when naive as in V1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// Exclusive ISO upper bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    /// Inclusive epoch nanoseconds; mutually exclusive with since.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_ns: Option<u64>,
    /// Exclusive epoch nanoseconds; mutually exclusive with until.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_ns: Option<u64>,
    /// Page size, 1..=1000; defaults to 100, or 1000 for timeline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Nonnegative signed 64-bit offset, counted over observations for timeline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    /// Timeline-only toggle, default true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_security: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ownership_parameters_are_rejected_even_for_root() {
        for input in [
            json!({"uid":1000}),
            json!({"owner_uid":1000}),
            json!({"uid":null}),
        ] {
            assert!(serde_json::from_value::<ObservabilityQueryParams>(input).is_err());
        }
        assert_eq!(
            serde_json::to_value(ObservabilityQueryParams::default()).unwrap(),
            json!({})
        );
    }
}
