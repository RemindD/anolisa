use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// One daemon request with method-specific parameters.
///
/// TODO(daemon-transport-compat): before registering this PAP-only envelope on
/// the supported daemon socket, implement the V1 `trace_context`, `caller`,
/// `timeout_ms`, request-ID, and unknown-field behavior or introduce an approved
/// versioned boundary.
///
/// TODO(daemon-otel): add W3C `traceparent` and `tracestate` carriers only with
/// transport extraction and context attachment around application dispatch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DaemonRequest {
    /// Fixed allowlisted method name.
    #[serde(deserialize_with = "deserialize_method")]
    pub method: String,
    /// Method-specific object decoded after allowlist dispatch.
    #[serde(default = "empty_object", deserialize_with = "deserialize_params")]
    pub params: Value,
}

fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

fn deserialize_method<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let method = String::deserialize(deserializer)?;
    if method.trim().is_empty() {
        Err(D::Error::custom("method must be a non-empty string"))
    } else {
        Ok(method)
    }
}

fn deserialize_params<'de, D>(deserializer: D) -> Result<Value, D::Error>
where
    D: Deserializer<'de>,
{
    let params = Value::deserialize(deserializer)?;
    if params.is_object() {
        Ok(params)
    } else {
        Err(D::Error::custom("params must be a JSON object"))
    }
}
