# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Every shell ``run:`` block in ``.github/workflows/`` must parse as valid shell.

**Why this exists.** ``release.yml`` once shipped

    python -m pip install --quiet "packaging==$PKG_PIN\\"

— a stray backslash before the closing quote left the shell string unterminated, so the job would have
died at tag time. Nothing caught it, and that is the point:

* the **YAML parsed**, because a broken shell string is still a valid YAML scalar;
* the **pin guard** (``test_ci_venv_pinning.py``) passed, because it greps for pin *syntax* and the line
  does contain ``packaging==``;
* **no CI leg executed it** — the step is inside ``if [ "$GITHUB_REF_TYPE" = tag ]`` on a
  ``webconsole-*`` tag, and no pull request runs a tag-only release job.

So every existing gate was *structurally* incapable of seeing it, and the first execution would have been
a release. This test closes that class: it asks the shell itself whether each block is parseable, which is
a question none of the line-oriented guards can ask.

**Scope, stated honestly.** ``bash -n`` checks *syntax*, not behaviour — it catches unterminated strings,
unbalanced quotes, unclosed ``if``/``for``/``case``, and stray operators. It cannot catch a command that
parses and then does the wrong thing. That is a real limit, not an oversight: the failure this test exists
to prevent was purely syntactic.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))

#: ``${{ ... }}`` is an Actions expression substituted BEFORE the shell ever sees the script, and it is
#: not valid shell (``${{`` is a bad substitution). Replace it with a plain token so the check tests the
#: script's own syntax rather than re-discovering that Actions templating is not bash. Non-greedy so
#: adjacent expressions on one line stay separate.
_GHA_EXPR = re.compile(r"\$\{\{.*?\}\}", re.DOTALL)

#: Shells this test can check. A ``pwsh``/``powershell`` block is a different language; checking it would
#: need pwsh -NoProfile -Command, which is out of scope here (and those blocks are Windows-only).
_BASH_SHELLS = {"bash", "sh", None}


def _effective_shell(workflow: Any, job: Any, step: Any) -> str | None:
    """Resolve the shell for a step the way Actions does: step > job defaults > workflow defaults."""
    if "shell" in step:
        return str(step["shell"]).split()[0]
    for scope in (job, workflow):
        got = (scope.get("defaults") or {}).get("run", {}).get("shell")
        if got:
            return str(got).split()[0]
    return None  # Actions' own default: bash on Linux/macOS runners


def _runs_on_windows(job: Any) -> bool:
    return "windows" in str(job.get("runs-on", "")).lower()


def _shell_blocks() -> list[tuple[str, str, str, str]]:
    """Every checkable block as ``(workflow, job, step-name, script)``."""
    out: list[tuple[str, str, str, str]] = []
    for wf in WORKFLOWS:
        doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
        for job_id, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            for i, step in enumerate(job.get("steps") or []):
                if not isinstance(step, dict) or "run" not in step:
                    continue
                shell = _effective_shell(doc, job, step)
                # An unspecified shell on a Windows runner is pwsh, not bash — skip rather than
                # mis-check it. An EXPLICIT bash on Windows is still bash and is checked.
                if shell is None and _runs_on_windows(job):
                    continue
                if shell not in _BASH_SHELLS:
                    continue
                name = str(step.get("name") or f"step[{i}]")
                out.append((wf.name, str(job_id), name, str(step["run"])))
    return out


def test_the_workflow_set_is_not_empty() -> None:
    """Liveness: a glob that silently matches nothing would make every check below vacuous."""
    assert WORKFLOWS, f"no workflows found under {ROOT / '.github' / 'workflows'}"
    print(f"scanned workflows: {[w.name for w in WORKFLOWS]}")


def test_there_are_shell_blocks_to_check() -> None:
    """Liveness: prove the extractor actually finds blocks, so a pass means 'checked', not 'found none'."""
    blocks = _shell_blocks()
    print(
        f"checkable shell run: blocks = {len(blocks)} across {len({b[0] for b in blocks})} workflows"
    )
    assert len(blocks) >= 20, (
        f"only {len(blocks)} shell blocks found — the extractor is probably broken (shell resolution or "
        f"the steps walk), which would make the syntax check below pass without checking anything"
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available to syntax-check with")
def test_every_shell_run_block_parses(tmp_path: Path) -> None:
    """``bash -n`` every block. Reports ALL offenders, not just the first, so one run fixes them all."""
    bash = shutil.which("bash")
    assert bash is not None  # narrowed by the skipif; keeps mypy honest
    blocks = _shell_blocks()
    failures: list[str] = []
    for i, (wf, job, step, script) in enumerate(blocks):
        # Write to a FILE rather than piping via stdin. A script containing a heredoc (`<<'PYVER'`) makes
        # `bash -n` read the heredoc body from the same stream it is reading the script from, and it
        # blocks waiting for a terminator that never arrives — measured as a 30 s timeout, not a syntax
        # error. With a file argument, stdin is free and heredoc bodies are skipped unparsed, which is
        # exactly the behaviour wanted: an embedded Python block should be opaque to a shell check.
        probe = tmp_path / f"block{i}.sh"
        probe.write_text(_GHA_EXPR.sub("GHA_EXPR", script), encoding="utf-8")
        try:
            proc = subprocess.run(
                [bash, "-n", str(probe)], capture_output=True, text=True, timeout=30
            )
        except (
            subprocess.TimeoutExpired
        ):  # pragma: no cover - names the block instead of dying blind
            failures.append(
                f"{wf} :: job {job} :: {step}\n    bash -n TIMED OUT (unterminated heredoc?)"
            )
            continue
        if proc.returncode != 0:
            failures.append(f"{wf} :: job {job} :: {step}\n    {proc.stderr.strip()}")
    print(f"syntax-checked {len(blocks)} shell blocks; {len(failures)} failed")
    assert not failures, "shell `run:` blocks that do not parse:\n\n" + "\n\n".join(failures)
