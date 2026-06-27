# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""`messagefoundry init` scaffolds a standalone config repo whose starter config passes `check`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry import __version__
from messagefoundry.__main__ import main
from messagefoundry.scaffold import scaffold

_EXPECTED = {
    "README.md",
    "requirements.txt",
    ".gitignore",
    ".gitattributes",
    ".vscode/settings.json",
    ".github/workflows/check.yml",
    "messagefoundry.toml",
    "config/IB_EXAMPLE_ADT.py",
    "environments/dev.toml",
    "environments/prod.toml",
    "messages/sets/example_adt.hl7",
}


def _rels(paths: list[Path], root: Path) -> set[str]:
    return {str(p.relative_to(root)).replace("\\", "/") for p in paths}


def test_scaffold_writes_the_skeleton(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    written = scaffold(repo)
    assert _rels(written, repo) == _EXPECTED
    for rel in _EXPECTED:
        assert (repo / rel).is_file()
    # the engine is pinned to the running version (a read-only dependency)
    assert (repo / "requirements.txt").read_text() == f"messagefoundry=={__version__}\n"
    # the fixture keeps HL7 CR segment separators (write_text newline="" wrote them verbatim);
    # read the raw bytes (Path.read_text gained `newline` only in 3.13; the engine targets 3.11+).
    assert b"\r" in (repo / "messages" / "sets" / "example_adt.hl7").read_bytes()
    # the service settings template carries the new posture model, not the retired enum
    toml = (repo / "messagefoundry.toml").read_text()
    assert 'environment = "dev"' in toml and "data_class" in toml and "production" in toml
    # D11: the .gitignore must ignore the one-time bootstrap admin credential the engine writes next
    # to the store, so it is never committed
    gitignore = (repo / ".gitignore").read_text()
    assert "bootstrap-admin.txt" in gitignore
    # the template + README teach WS-1's env-anchor so a config repo run under a service (CWD != repo
    # root) still resolves environments/<env>.toml (ADR 0017): base_dir in the toml, --project-root in docs
    assert "base_dir" in toml
    readme = (repo / "README.md").read_text()
    assert "--project-root" in readme
    # the .vscode settings point the IDE at this repo's layout (not the engine's samples/)
    vscode = json.loads((repo / ".vscode" / "settings.json").read_text())
    assert vscode["messagefoundry.configDir"] == "config"
    # the CI gate runs validate+dryrun; advisory lint is skipped (ruff/mypy aren't in requirements.txt)
    ci = (repo / ".github" / "workflows" / "check.yml").read_text()
    assert "messagefoundry check --config config" in ci and "--no-lint" in ci
    # WP-BL3-07: a fail-closed engine-provenance verify gate runs before the check job, skippable via a
    # repo variable for indexes that strip attestations; the check job gates on it (never on verify failure)
    assert "verify-engine:" in ci
    assert (
        "gh attestation verify dist-verify/messagefoundry-*.whl --repo wshallwshall/MessageFoundry"
        in ci
    )
    assert "vars.MEFOR_VERIFY_ENGINE != 'off'" in ci
    assert "needs: verify-engine" in ci
    assert "needs.verify-engine.result != 'failure'" in ci
    # Dependency fast-response C3: an adopter-side "your pin is now vulnerable" tripwire — pip-audit the
    # pinned engine + its dependency closure, so a CVE disclosed against the pinned version reds the
    # adopter's own CI (their remediation clock starts without reading an advisory).
    assert "audit-pin:" in ci
    assert "pip-audit -r requirements.txt" in ci
    # SEC-021 (CWE-494): the engine attestation does NOT vouch for the live, unhashed transitive
    # resolve. The audit-pin job must verify a hash-pinned lock with --require-hashes when present
    # and otherwise WARN that the closure resolves live + recommend an index pin.
    assert "--require-hashes" in ci
    assert "requirements.lock" in ci
    assert "::warning::" in ci  # fails-soft warning wording on the unpinned default path
    # SEC-021: the README teaches the dependency-confusion defences — index pin + hash-pinned lock.
    assert "dependency-confusion" in readme
    assert "--index-url" in readme and "PIP_CONSTRAINT" in readme
    assert "--require-hashes" in readme
    assert "--generate-hashes" in readme or "uv export" in readme


def test_scaffold_refuses_nonempty_without_force(tmp_path: Path) -> None:
    (tmp_path / "existing.txt").write_text("hi", encoding="utf-8")
    with pytest.raises(FileExistsError, match="not empty"):
        scaffold(tmp_path)


def test_scaffold_force_skips_existing_files(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("MINE", encoding="utf-8")
    written = scaffold(tmp_path, force=True)
    rels = _rels(written, tmp_path)
    assert "README.md" not in rels  # an existing file is never clobbered
    assert "config/IB_EXAMPLE_ADT.py" in rels  # the rest is still written
    assert (tmp_path / "README.md").read_text() == "MINE"


def test_scaffolded_config_passes_check(tmp_path: Path) -> None:
    # The headline guarantee: a freshly scaffolded repo is green on the engine's own check gate
    # (validate + dryrun of the starter feed against the synthetic fixture).
    repo = tmp_path / "repo"
    scaffold(repo)
    rc = main(
        [
            "check",
            "--config",
            str(repo / "config"),
            "--messages",
            str(repo / "messages" / "sets"),
            "--no-lint",
        ]
    )
    assert rc == 0


def test_init_command_writes_and_reports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["init", str(tmp_path / "repo"), "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    written = {r.replace("\\", "/") for r in out["written"]}
    assert "config/IB_EXAMPLE_ADT.py" in written and "requirements.txt" in written


def test_init_refuses_nonempty_dir(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "x.txt").write_text("hi", encoding="utf-8")
    rc = main(["init", str(tmp_path)])
    assert rc == 1
    assert "not empty" in capsys.readouterr().out
