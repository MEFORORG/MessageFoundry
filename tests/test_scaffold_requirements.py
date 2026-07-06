# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SEC-021 (CWE-494): the adopter scaffold must harden the live, unhashed transitive resolve.

The generated ``requirements.txt`` pins only the engine, so ``pip install -r requirements.txt``
resolves the whole transitive closure live and unhashed. These tests assert the scaffold's
generated CI + README teach the two defences (a hash-pinned ``--require-hashes`` lock and an
index pin against dependency-confusion) and that the emitted CI workflow is still valid YAML
(the template is a Python triple-quoted heredoc — a slip would silently break every adopter's CI).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from messagefoundry.scaffold import scaffold


def test_scaffolded_ci_is_valid_yaml_and_hardens_the_transitive_resolve(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    scaffold(repo)
    ci_path = repo / ".github" / "workflows" / "check.yml"
    # the heredoc rendered to parseable YAML (no broken triple-quoted template)
    doc = yaml.safe_load(ci_path.read_text(encoding="utf-8"))
    assert "audit-pin" in doc["jobs"]

    ci = ci_path.read_text(encoding="utf-8")
    # verify a hash-pinned lock when present; warn (fail-soft) on the unhashed default path
    assert "--require-hashes" in ci
    assert "requirements.lock" in ci
    assert "::warning::" in ci


def test_scaffolded_readme_teaches_dependency_confusion_defences(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    scaffold(repo)
    readme = (repo / "README.md").read_text(encoding="utf-8")
    assert "dependency-confusion" in readme
    assert "--index-url" in readme and "PIP_CONSTRAINT" in readme
    assert "--require-hashes" in readme
    assert "--generate-hashes" in readme or "uv export" in readme


def test_scaffolded_requirements_still_pins_only_the_engine(tmp_path: Path) -> None:
    """The DEFAULT scaffold keeps the engine-only pin (the adopter owns the repo); the hardening is
    documented/CI-warned, not forced — so a first-commit `pip install -r requirements.txt` works."""
    repo = tmp_path / "repo"
    scaffold(repo)
    reqs = (repo / "requirements.txt").read_text(encoding="utf-8")
    assert reqs.startswith("messagefoundry==")
    # no hashes forced on the default path (would break the engine-only resolve)
    assert "--hash=" not in reqs
