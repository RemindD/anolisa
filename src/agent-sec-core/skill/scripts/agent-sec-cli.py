#!/usr/bin/env python3
"""AgentSecCore unified CLI entry point.

Usage (invoked by LLM via run_shell_command):
  python3 agent-sec-cli.py harden --mode scan
  python3 agent-sec-cli.py harden --mode reinforce --config agentos_baseline
  python3 agent-sec-cli.py harden --mode dry-run
  python3 agent-sec-cli.py verify
  python3 agent-sec-cli.py verify --skill /path/to/skill
  python3 agent-sec-cli.py summary --hours 24 --format text
"""
import argparse
import sys
import os

# Ensure security_middleware is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from security_middleware import invoke


def main():
    parser = argparse.ArgumentParser(description="AgentSecCore unified CLI entry point")
    subparsers = parser.add_subparsers(dest="action", required=True)

    # harden subcommand
    harden_parser = subparsers.add_parser("harden", help="System security hardening")
    harden_parser.add_argument(
        "--mode", default="scan", choices=["scan", "reinforce", "dry-run"],
        help="Hardening mode (default: scan)",
    )
    harden_parser.add_argument(
        "--config", default="agentos_baseline",
        help="Hardening config baseline (default: agentos_baseline)",
    )

    # verify subcommand
    verify_parser = subparsers.add_parser("verify", help="Skill integrity verification")
    verify_parser.add_argument(
        "--skill", default=None,
        help="Path to specific skill for verification",
    )

    # summary subcommand
    summary_parser = subparsers.add_parser("summary", help="Security event summary")
    summary_parser.add_argument(
        "--hours", type=int, default=24,
        help="Summary time range in hours (default: 24)",
    )
    summary_parser.add_argument(
        "--format", default="text", choices=["text", "json"],
        help="Output format (default: text)",
    )

    args = parser.parse_args()

    # Build kwargs from subcommand-specific args only (exclude 'action')
    kwargs = {k: v for k, v in vars(args).items() if k != "action"}

    result = invoke(args.action, **kwargs)
    if result.stdout:
        print(result.stdout)
    if result.error:
        print(result.error, file=sys.stderr)
    sys.exit(result.exit_code)


if __name__ == "__main__":
    main()
