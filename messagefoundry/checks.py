# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The ``messagefoundry check`` commit/CI gate — one callable for the git hook and the IDE.

``run_checks`` runs the project's checks against a config directory and reports a clear pass/fail,
reusing the in-process ``validate``/``dry_run`` paths (no re-shelling for the MessageFoundry-native
checks). Two checks are **required** (they can block a commit):

* ``validate`` — every config module loads and every ``inbound → router`` reference resolves.
* ``dryrun`` — *only when* a fixtures dir with ``*.hl7`` is given (searched recursively): each message
  routes through its inbound's Router/Handler(s) without erroring. A fixture under a
  ``<messages>/<inbound_name>/`` subdir is dry-run **only** against that feed (#11); a fixture not under
  such a subdir runs against **every** inbound. Absent fixtures → skipped (never blocks).

``ruff`` and ``mypy`` are **advisory**: run only when installed (``shutil.which``) and never block —
a non-developer author shouldn't be stopped by a lint nit. Exit-code policy lives in the CLI
(``__main__._check``): 0 iff no required check failed.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ["CheckResult", "CheckReport", "run_checks"]


@dataclass(frozen=True)
class CheckResult:
    """The outcome of one check."""

    name: str
    ok: bool
    required: bool
    skipped: bool = False
    detail: str = ""

    @property
    def blocking(self) -> bool:
        """A required check that ran and failed — the only thing that fails the gate."""
        return self.required and not self.ok and not self.skipped

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "required": self.required,
            "skipped": self.skipped,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class CheckReport:
    """All check outcomes for one run."""

    results: list[CheckResult]

    @property
    def ok(self) -> bool:
        """True unless a required check ran and failed."""
        return not any(r.blocking for r in self.results)

    def to_json(self) -> dict[str, Any]:
        return {"ok": self.ok, "checks": [r.to_json() for r in self.results]}


def run_checks(
    config_dir: str | Path,
    *,
    messages_dir: str | Path | None = None,
    run_lint: bool = True,
) -> CheckReport:
    """Run the gate against ``config_dir``; ``messages_dir`` enables the dry-run check when it has
    fixtures. Set ``run_lint=False`` to skip the advisory ruff/mypy pass."""
    results = [_check_validate(config_dir), _check_dryrun(config_dir, messages_dir)]
    if run_lint:
        results.append(_run_tool("ruff", ["ruff", "check", str(config_dir)]))
        results.append(_run_tool("mypy", ["mypy", str(config_dir)]))
    return CheckReport(results)


def _check_validate(config_dir: str | Path) -> CheckResult:
    from messagefoundry.config.wiring import validate_config

    errors = [d for d in validate_config(config_dir) if d.severity == "error"]
    if errors:
        detail = f"{len(errors)} problem(s): " + "; ".join(
            f"{d.file or '-'}: {d.message}" for d in errors[:5]
        )
        return CheckResult("validate", ok=False, required=True, detail=detail)
    return CheckResult("validate", ok=True, required=True, detail="no problems")


def _check_dryrun(config_dir: str | Path, messages_dir: str | Path | None) -> CheckResult:
    from messagefoundry.config.wiring import WiringError, load_config
    from messagefoundry.pipeline.dryrun import dry_run, read_message_sets
    from messagefoundry.store import MessageStatus

    if messages_dir is None:
        return CheckResult(
            "dryrun", ok=True, required=False, skipped=True, detail="no fixtures dir"
        )
    mpath = Path(messages_dir)
    if not mpath.exists():
        # An explicitly-given path that doesn't exist is a mistake (renamed/typo'd fixtures dir),
        # not "no fixtures" — fail the gate rather than silently skip the required check (low-20).
        return CheckResult(
            "dryrun", ok=False, required=True, detail=f"messages path not found: {mpath}"
        )
    if mpath.is_dir() and not any(mpath.glob("**/*.hl7")):
        # A real dir with no fixtures (searched recursively, since per-feed fixtures live in
        # <messages>/<inbound>/ subdirs) is the documented "absent fixtures -> skipped" case. A single
        # file (any extension) falls through and is dry-run like the `dryrun` CLI accepts (low-20).
        return CheckResult(
            "dryrun", ok=True, required=False, skipped=True, detail=f"no *.hl7 fixtures in {mpath}"
        )
    try:
        reg = load_config(config_dir)
    except WiringError as exc:
        # validate already reports (and blocks on) this — don't double-fail here.
        return CheckResult(
            "dryrun", ok=True, required=False, skipped=True, detail=f"config did not load: {exc}"
        )
    if not reg.inbound:
        return CheckResult(
            "dryrun", ok=True, required=False, skipped=True, detail="no inbound connections"
        )

    # Per-feed mapping (#11): a fixture under <messages>/<inbound_name>/ is dry-run only against that
    # feed; an unmapped fixture (top-level, or under a non-feed subdir) cross-products every inbound.
    inbound_names = list(reg.inbound)
    message_sets = read_message_sets(mpath, inbound_names)
    errors: list[str] = []
    total = 0
    pinned = 0
    for label, _path, raw, target in message_sets:
        targets = [target] if target is not None else inbound_names
        if target is not None:
            pinned += 1
        for ic_name in targets:
            total += 1
            result = dry_run(reg, raw, inbound=ic_name)
            if result.error or result.disposition is MessageStatus.ERROR:
                errors.append(f"{label} @ {ic_name}: {result.error or result.disposition.value}")
    if errors:
        detail = f"{len(errors)}/{total} run(s) errored: " + "; ".join(errors[:5])
        return CheckResult("dryrun", ok=False, required=True, detail=detail)
    pin_note = f", {pinned} feed-pinned" if pinned else ""
    detail = f"{total} run(s) clean across {len(message_sets)} message(s){pin_note}"
    return CheckResult("dryrun", ok=True, required=True, detail=detail)


def _run_tool(name: str, cmd: list[str]) -> CheckResult:
    """Advisory: run ``cmd`` only if its executable resolves; absent → skipped, never blocking."""
    if shutil.which(cmd[0]) is None:
        return CheckResult(name, ok=True, required=False, skipped=True, detail="not installed")
    try:
        # nosec: cmd[0] is a fixed tool name (ruff/mypy), no shell; args are repo paths (low-27).
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=120)  # nosec B603 B607
    except subprocess.TimeoutExpired:
        # A wedged advisory tool must not block a commit forever — degrade to a skip (low-21).
        return CheckResult(name, ok=True, required=False, skipped=True, detail="timed out (120s)")
    except OSError as exc:
        return CheckResult(
            name, ok=True, required=False, skipped=True, detail=f"could not run: {exc}"
        )
    if proc.returncode == 0:
        return CheckResult(name, ok=True, required=False, detail="passed")
    detail = (proc.stdout or proc.stderr).strip().replace("\n", " ")[:300] or "failed"
    return CheckResult(name, ok=False, required=False, detail=detail)
