"""Asset-verify backend — delegates to the verifier.py script via direct import."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from security_middleware.result import ActionResult

# ---------------------------------------------------------------------------
# The ``asset-verify`` directory uses a hyphen, which is not a valid Python
# package name.  We add it to ``sys.path`` so we can import ``verifier``
# directly.
# ---------------------------------------------------------------------------
_ASSET_VERIFY_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "asset-verify")


class AssetVerifyBackend:
    """Verify skill integrity using the asset-verify/verifier.py module."""

    def execute(
        self,
        ctx,
        skill: str | None = None,
        **kwargs,
    ) -> ActionResult:
        """Run verification for a single skill or all configured directories.

        Args:
            ctx:   Request context (unused beyond tracing).
            skill: Optional path to a single skill directory to verify.
                   When *None*, all directories from ``config.conf`` are scanned.
        """
        try:
            verifier = self._import_verifier()
        except Exception as exc:
            return ActionResult(
                success=False,
                error=f"Failed to import verifier: {exc}",
                exit_code=1,
            )

        try:
            return self._run(verifier, skill)
        except Exception as exc:
            return ActionResult(
                success=False,
                error=f"Verification error: {exc}",
                exit_code=1,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _import_verifier():  # noqa: ANN205
        """Lazily import the verifier module from the asset-verify directory."""
        abs_dir = os.path.abspath(_ASSET_VERIFY_DIR)
        if abs_dir not in sys.path:
            sys.path.insert(0, abs_dir)

        # Import (or re-import) the verifier module.
        import importlib

        mod = importlib.import_module("verifier")
        return mod

    @staticmethod
    def _run(verifier, skill: str | None) -> ActionResult:
        """Execute the appropriate verification path."""

        trusted_keys = verifier.load_trusted_keys(verifier.DEFAULT_TRUSTED_KEYS_DIR)

        if skill is not None:
            # ---------- single skill ----------
            try:
                verifier.verify_skill(skill, trusted_keys)
                name = os.path.basename(skill)
                return ActionResult(
                    success=True,
                    stdout=f"[OK] {name}\n",
                    data={"passed": 1, "failed": 0},
                )
            except Exception as exc:
                name = os.path.basename(skill)
                return ActionResult(
                    success=False,
                    stdout=f"[ERROR] {name}\n  {exc}\n",
                    data={"passed": 0, "failed": 1},
                    exit_code=1,
                )

        # ---------- full scan ----------
        config = verifier.load_config(verifier.DEFAULT_CONFIG)

        all_passed: list[str] = []
        all_failed: list[dict] = []
        output_lines: list[str] = []

        for skills_dir in config.get("skills_dirs", []):
            results = verifier.verify_skills_dir(skills_dir, trusted_keys)
            for name in results["passed"]:
                all_passed.append(name)
                output_lines.append(f"[OK] {name}")
            for item in results["failed"]:
                all_failed.append(item)
                output_lines.append(f"[ERROR] {item['name']}")
                output_lines.append(f"  {item['error']}")

        output_lines.append("")
        output_lines.append("=" * 50)
        output_lines.append(f"PASSED: {len(all_passed)}")
        output_lines.append(f"FAILED: {len(all_failed)}")
        output_lines.append("=" * 50)
        status = "VERIFICATION PASSED" if not all_failed else "VERIFICATION FAILED"
        output_lines.append(status)

        has_failures = len(all_failed) > 0

        return ActionResult(
            success=(not has_failures),
            stdout="\n".join(output_lines) + "\n",
            data={"passed": len(all_passed), "failed": len(all_failed)},
            exit_code=1 if has_failures else 0,
        )
