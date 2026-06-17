"""Map SecurityEvent details into telemetry business fields."""

import json
import math
from datetime import datetime, timezone
from typing import Any


def now_iso() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def to_json_safe(value: Any) -> Any:
    """Return a JSON-safe representation of *value*."""
    return _make_json_safe(value)


def details_dict(value: Any) -> dict[str, Any]:
    """Return *value* when it is a dict, otherwise an empty dict."""
    if isinstance(value, dict):
        return value
    return {}


def value_or_none(value: Any) -> Any:
    """Return None for missing string fields encoded as empty strings."""
    if value == "":
        return None
    return value


def result_dict(details: dict[str, Any]) -> dict[str, Any]:
    """Return details.result when it is a dict, otherwise an empty dict."""
    result = details.get("result")
    if isinstance(result, dict):
        return result
    return {}


def request_value(details: dict[str, Any]) -> Any:
    """Return the JSON-safe request field or None when absent."""
    if "request" not in details:
        return None
    return to_json_safe(details.get("request"))


def error_value(details: dict[str, Any]) -> Any:
    """Return the explicit error value from event details."""
    if "error" not in details:
        return None
    return to_json_safe(details.get("error"))


def error_type_value(details: dict[str, Any]) -> Any:
    """Return the explicit error type from event details."""
    if "error_type" not in details:
        return None
    return to_json_safe(details.get("error_type"))


def result_value(result: dict[str, Any], key: str) -> Any:
    """Return a JSON-safe result field, or None when it is absent."""
    if key not in result:
        return None
    return to_json_safe(result.get(key))


def _is_json_scalar(value: Any) -> bool:
    """Return whether *value* can be represented as a JSON scalar."""
    return value is None or isinstance(value, (str, bool, int, float))


def _normalize_json_scalar(value: Any) -> Any:
    """Return the strict JSON representation of a scalar value."""
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _make_json_safe(value: Any) -> Any:
    """Convert arbitrary Python values into JSON-serializable values."""
    if _is_json_scalar(value):
        return _normalize_json_scalar(value)
    if isinstance(value, dict):
        return {str(key): _make_json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_make_json_safe(item) for item in value]
    if isinstance(value, set):
        return [_make_json_safe(item) for item in sorted(value, key=repr)]

    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _make_json_safe(model_dump())

    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError):
        return str(value)
    return value
