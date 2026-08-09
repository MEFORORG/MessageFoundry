# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The engine's half of the vault ASVS gate's RUNTIME contract (ADR 0156).

The ASVS gate does not live here. It lives in the vault repo, and it makes three claims about
THIS tree:

  1. the evidence anchors recorded in the scorecard still resolve in the engine source;
  2. ``scripts/asvs/scorecard.py`` exists at exactly that path;
  3. that file RUNS -- as a bare script, on a bare interpreter, with nothing installed.

Claim 1 needs the private assessment record and can only ever be checked where that record is.
Claims 2 and 3 are properties of THIS tree alone, and until this module existed neither repo
checked either of them.

WHY THAT MATTERS, precisely. The vault runs the verifier twice, in two workflows, and NEITHER
installs anything:

  * ``asvs-scorecard.yml`` -- ``actions/setup-python`` then ``python scripts/asvs/scorecard.py``.
    Its own comment states the invariant and the reason: "No install step and no dependency: the
    verifier is stdlib-only (tomllib, json, re) precisely so this job cannot rot on a lockfile it
    does not own."
  * ``asvs-verifier-drift.yml`` -- its ``preflight`` job executes the INCOMING engine copy, as
    ``python ../engine/scripts/asvs/scorecard.py`` with the working directory set to the vault
    checkout. So ``sys.path[0]`` is ``.../scripts/asvs``: not the engine root, not the vault root.
    A first-party import has nothing to resolve against.

That invariant was asserted in a comment and enforced nowhere. The engine's own tests import the
module -- ``from scripts.asvs.scorecard import ...`` -- from a pytest session with the repo root on
``sys.path`` and the project's full extras installed. So the exact invocation the vault uses was
never exercised here, and an added ``import httpx`` would pass every check in this repo.

WHAT BREAKING IT COSTS, since a soft failure invites the reasoning that it does not matter. The
mirror job opens its pull request as a DRAFT when the incoming verifier does not run, and a draft
is never merged. So the vault keeps verifying the record with its OLD copy while reporting drift as
a warning -- which is the exact recurring condition (six hand-made mirror commits, the last of them
326 lines behind) that splitting the drift workflow out was built to end. The gate does not go red.
It goes stale, quietly, which is the failure mode this whole programme exists to remove.

The check therefore belongs HERE, in the repo that can cause the drift, on the trigger that already
fires for it: any pull request touching ``scripts/asvs/**`` is code by ci.yml's docs-only detector,
so the required ``test`` leg runs this module. No new workflow and no new required context.

Runnable on its own -- ``python tests/test_asvs_verifier_vault_contract.py`` -- which prints the full
inventory it scanned and exits non-zero on a violation. The inventory is printed rather than merely
counted so that a run which scanned nothing cannot be mistaken for a run which found nothing.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Hardcoded in BOTH vault workflows (as ``engine/scripts/asvs/scorecard.py`` and
# ``../engine/scripts/asvs/scorecard.py``). A rename here is a silent break there: the parity step
# resolves the missing file to the sentinel "MISSING" and warns rather than failing.
VERIFIER_REL = "scripts/asvs/scorecard.py"
VERIFIER = REPO_ROOT / VERIFIER_REL

# ``__main__`` is what a module names when it imports itself under direct execution; it is not a
# distribution and never needs installing. Nothing else is exempt -- notably not ``messagefoundry``,
# because the vault's preflight invocation puts only ``scripts/asvs`` on ``sys.path``.
_ALWAYS_AVAILABLE = frozenset({"__main__"})


def import_roots(source: str, filename: str) -> dict[str, list[int]]:
    """Top-level package name of every import in ``source``, mapped to the lines it appears on.

    ``ast.walk`` rather than a scan of module-level statements: the verifier defers two imports
    (``hashlib``, ``json``) into function bodies, and a deferred third-party import is exactly as
    fatal on a bare interpreter as a top-level one -- it just fails later, on the code path that
    matters, instead of at startup. A ``--help`` smoke test cannot see those; this can.
    """
    roots: dict[str, list[int]] = {}
    for node in ast.walk(ast.parse(source, filename=filename)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.setdefault(alias.name.split(".")[0], []).append(node.lineno)
        elif isinstance(node, ast.ImportFrom):
            # ``level > 0`` is a relative import: it resolves against the containing PACKAGE, and
            # scripts/asvs has no ``__init__.py``, so under the vault's script invocation there is
            # no package to resolve against. Record it under a name that can never be stdlib.
            if node.level:
                roots.setdefault(f"<relative import level {node.level}>", []).append(node.lineno)
            elif node.module:
                roots.setdefault(node.module.split(".")[0], []).append(node.lineno)
    return roots


def non_stdlib(roots: dict[str, list[int]]) -> dict[str, list[int]]:
    """The subset of ``roots`` a bare CPython could not import."""
    return {
        name: lines
        for name, lines in roots.items()
        if name not in sys.stdlib_module_names and name not in _ALWAYS_AVAILABLE
    }


def scan(rel: str = VERIFIER_REL) -> tuple[str, dict[str, list[int]], dict[str, list[int]]]:
    source = (REPO_ROOT / rel).read_text(encoding="utf-8")
    roots = import_roots(source, rel)
    return source, roots, non_stdlib(roots)


# EVERY tool this repo expects the assessment repo to MIRROR AND RUN, not just the verifier.
#
# The stdlib-only rule is a property of the arrangement, not of one file: the assessment repo runs
# these on a bare `setup-python` with no install step, so any third-party import is fatal there and
# invisible here. The rule was discovered on the verifier; it is stated once, over a list, because a
# fix that does not generalise is the one that comes back -- and the second entry arrived four days
# after the first.
MIRRORED_TOOLS = (
    VERIFIER_REL,
    # Not yet wired into a vault workflow. It is listed anyway, and deliberately: the cheap moment
    # to hold a tool to the mirror contract is BEFORE it acquires a dependency, not after someone
    # discovers the mirror will not run.
    "scripts/docs/asvs_tally_lint.py",
)


def test_the_verifier_is_at_the_path_the_vault_hardcodes() -> None:
    assert VERIFIER.is_file(), (
        f"{VERIFIER_REL} is missing from this tree. Two vault workflows resolve that literal path "
        f"in an engine checkout; asvs-scorecard.yml's parity step treats a missing file as the "
        f"sentinel 'MISSING' and WARNS rather than failing, so a rename here degrades the ASVS "
        f"gate silently. If the file must move, move the vault's two references in the same change."
    )


@pytest.mark.parametrize("rel", MIRRORED_TOOLS)
def test_a_mirrored_tool_imports_only_the_standard_library(rel: str) -> None:
    assert (REPO_ROOT / rel).is_file(), f"{rel} is listed as a mirrored tool but is not in the tree"
    source, roots, bad = scan(rel)
    n_lines = source.count("\n") + 1
    n_imports = sum(len(v) for v in roots.values())

    # Print the inventory, not just the verdict: a scan that silently stopped seeing imports and a
    # scan that legitimately found none are the same number, and only the inventory tells them apart.
    print(f"SCANNED: {rel} ({n_lines} lines, {n_imports} import statements)")
    print(f"FOUND:   {len(roots)} distinct import roots: {sorted(roots)}")
    print(f"FOUND:   {len(bad)} non-stdlib roots: {sorted(bad)}")

    # The scan must be capable of seeing anything at all. Zero imports means a broken scanner far
    # more plausibly than it means a 1,000-line tool that imports nothing.
    assert n_imports > 0, (
        f"scanned {rel} ({n_lines} lines) and found ZERO import statements -- that is a "
        f"broken scan, not a clean file"
    )

    assert not bad, (
        f"{rel} imports {sorted(bad)} outside the standard library "
        f"(lines {sorted(ln for lines in bad.values() for ln in lines)}). "
        f"Scanned {n_imports} import statements across {n_lines} lines. "
        f"The vault runs mirrored tools on a bare interpreter with NO install step. "
        f"A non-stdlib import does not red the ASVS gate -- it strands the auto-mirror as an "
        f"unmergeable draft and leaves the vault verifying its record with the previous copy."
    )


def test_the_verifier_runs_as_a_bare_script_with_nothing_installed(tmp_path: Path) -> None:
    """Execute it the way the vault does, from a directory that is not this repo.

    ``-S`` drops site-packages, so only the standard library is importable -- a faithful stand-in
    for the vault's freshly-provisioned ``setup-python`` interpreter. ``-I`` additionally ignores
    ``PYTHONPATH`` and the user site directory, so a developer's environment cannot make this pass
    where CI would fail. The working directory is a temp dir because the vault's cwd is its own
    checkout, never this one: anything resolved relative to cwd is already wrong there.
    """
    cmd = [sys.executable, "-I", "-S", str(VERIFIER), "--help"]
    print(f"SCANNED: {' '.join(cmd)} (cwd={tmp_path})")
    proc = subprocess.run(cmd, cwd=tmp_path, capture_output=True, text=True, timeout=120)
    print(
        f"FOUND:   rc={proc.returncode}, {len(proc.stdout)} bytes stdout, {len(proc.stderr)} stderr"
    )

    assert proc.returncode == 0, (
        f"{VERIFIER_REL} does not run on a stdlib-only interpreter from an unrelated working "
        f"directory (rc={proc.returncode}).\n"
        f"--- stderr ---\n{proc.stderr}\n"
        f"The vault invokes it exactly this way: `python scripts/asvs/scorecard.py` in "
        f"asvs-scorecard.yml, and `python ../engine/scripts/asvs/scorecard.py` from the vault "
        f"checkout in asvs-verifier-drift.yml's preflight job. Neither installs anything."
    )
    assert "--scorecard" in proc.stdout, (
        f"the bare-interpreter run exited 0 but did not print the verifier's own CLI; got "
        f"{proc.stdout[:400]!r}. An exit code alone does not prove the right program ran."
    )


# --------------------------------------------------------------------------------------------
# The scanner's own tests. A guard nothing drives ships looking green, so the detector is proved
# to fire on each shape it exists to catch, and proved SILENT on the shapes it must not flag.
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("import httpx\n", "httpx"),
        ("from fastapi import FastAPI\n", "fastapi"),
        ("import os\nimport yaml.parser\n", "yaml"),
        # Deferred into a function body -- invisible to any smoke test of the entry point.
        ("def f():\n    import pydantic\n    return pydantic\n", "pydantic"),
        # Deferred into a branch that only runs on the failure path.
        ("import sys\nif sys.argv:\n    import requests\n", "requests"),
        # A first-party import. Legal here, fatal there: the vault puts only scripts/asvs on the path.
        ("from messagefoundry.config import settings\n", "messagefoundry"),
        ("import messagefoundry\n", "messagefoundry"),
        # A relative import needs a package; scripts/asvs has no __init__.py.
        ("from . import helpers\n", "<relative import level 1>"),
    ],
)
def test_the_scanner_reds_on_a_contract_violation(mutation: str, expected: str) -> None:
    bad = non_stdlib(import_roots(mutation, "<mutation>"))
    assert expected in bad, f"scanner did not flag {expected!r} in {mutation!r}; it reported {bad}"


def test_the_scanner_is_silent_on_stdlib_only_source() -> None:
    """Negative control. A pattern that cannot occur must return zero, not 'no output'.

    This mirrors the verifier's real import shape -- module level, a ``from`` import, and two
    deferred ones -- so a scanner that had degenerated into matching everything would show up
    here as a non-empty result rather than as a passing test.
    """
    clean = (
        "from __future__ import annotations\n"
        "import argparse\n"
        "import tomllib\n"
        "from pathlib import Path\n"
        "def f():\n"
        "    import hashlib\n"
        "    import json\n"
        "    return hashlib, json, Path, argparse, tomllib\n"
    )
    roots = import_roots(clean, "<control>")
    bad = non_stdlib(roots)
    # The control is only meaningful if the scan saw something: assert on both halves.
    assert len(roots) == 6, f"control source should yield 6 import roots, got {sorted(roots)}"
    assert bad == {}, f"negative control flagged {bad} on stdlib-only source"


def main() -> int:
    if not VERIFIER.is_file():
        print(f"MISSING: {VERIFIER_REL}")
        return 1
    source, roots, bad = scan()
    n_lines = source.count("\n") + 1
    n_imports = sum(len(v) for v in roots.values())
    print(f"SCANNED: {VERIFIER_REL} ({n_lines} lines, {n_imports} import statements)")
    for name in sorted(roots):
        mark = "STDLIB" if name not in bad else "NOT-STDLIB"
        print(f"  {mark:11s} {name:24s} line(s) {sorted(roots[name])}")
    print(f"FOUND:   {len(bad)} non-stdlib import root(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
