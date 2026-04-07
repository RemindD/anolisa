"""Shared test infrastructure — add agent-sec-cli to sys.path."""

import os
import sys

_SCRIPTS_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "skill", "scripts"
)
sys.path.insert(0, os.path.abspath(_SCRIPTS_DIR))
