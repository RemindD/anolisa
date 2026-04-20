"""Global fixtures for unit tests — isolate all security-event I/O."""

import os

import pytest


@pytest.fixture(autouse=True, scope="session")
def _isolate_data_dir(tmp_path_factory):
    """Redirect all security-event I/O to a disposable temp directory.

    Prevents unit tests from polluting the production SQLite DB / JSONL log
    at ``~/.agent-sec-core/``.
    """
    data_dir = tmp_path_factory.mktemp("unit-test-data")
    os.environ["AGENT_SEC_DATA_DIR"] = str(data_dir)
    yield
    os.environ.pop("AGENT_SEC_DATA_DIR", None)
