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
    # The template documents the posture model in its CURRENT spelling. THIS ASSERTION IS WEAK BY
    # CONSTRUCTION and is kept only as a readability check: until #1318 it read `"data_class" in toml
    # and "production" in toml`, which ADR 0118 had RELOCATED -- so it asserted the presence of names
    # the loader was by then refusing, and stayed green while `init` emitted an unloadable config. The
    # real guard is the round trip in test_the_config_init_writes_is_accepted_by_the_loader_that_reads_it.
    toml = (repo / "messagefoundry.toml").read_text()
    assert 'environment = "dev"' in toml
    assert "handles_real_patient_data" in toml and "production_instance" in toml
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
        "gh attestation verify dist-verify/messagefoundry-*.whl --repo MEFORORG/MessageFoundry"
        in ci
    )
    # The scaffolded gate must name the repo that BUILDS the release — attestations are minted by the
    # public repo's release workflow, so a private-vault slug here verifies against something no
    # adopter can read. Pin the negative too: the retired slug must never creep back in.
    assert "wshallwshall" not in ci
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


# --- BACKLOG #1318: what `init` writes, the loader must accept ---------------------------------
#
# This file already ran `messagefoundry check` over a scaffolded repo and asserted rc == 0. That
# passed while the generated config was REFUSED, because the gate LOADED the file, got the refusal,
# printed it, and returned SKIP. Asserting rc == 0 over a skip is the silent-control shape (ADR 0158):
# the test exercised the defect and certified it.
#
# The scaffold was not careless, it was STRANDED. `[api].host` was correct until the ADR 0118
# relocation added ("api","host") to _RELOCATED_TO_SECURITY and wired _reject_relocated_keys into the
# load path. The relocation swept the docs and the settings and missed the one place that WRITES a
# config file. So the durable guard is not "assert this one key is gone" -- it is the round trip.


def test_the_config_init_writes_is_accepted_by_the_loader_that_reads_it(tmp_path: Path) -> None:
    """THE DEFECT, directly. Round-trip rather than string presence.

    Asserting a string is absent would pass the day the next key is relocated. Loading the file is
    the only assertion that stays true under a change made somewhere else.
    """
    from messagefoundry.config.settings import load_settings

    repo = tmp_path / "repo"
    scaffold(repo)
    load_settings(config_path=repo / "messagefoundry.toml")


def test_no_commented_line_in_the_template_is_a_relocated_key(tmp_path: Path) -> None:
    """THE DURABLE HALF. Every commented setting carries an instruction to uncomment it, so each is a
    latent copy of this defect -- three were already armed behind `[api].host`.

    Uncomments each commented key ON ITS OWN and requires that no RELOCATION refusal results. Other
    validation errors are legitimate and are allowed: `[security].listen_address` alone is correctly
    refused as contradicting the loopback default, which is a real check rather than staleness.

    Mutation: put `host = "127.0.0.1"` back under `[api]`, or move any live key into its old section.
    Red: that key is named in the failure.
    """
    import re

    from messagefoundry.config.settings import load_settings
    from messagefoundry.scaffold import _SERVICE_TOML

    lines = _SERVICE_TOML.splitlines()
    section: str | None = None
    tested: list[str] = []
    relocated: list[str] = []
    for i, raw in enumerate(lines):
        stripped = raw.strip()
        header = re.match(r"^\[([a-z_]+)\]\s*$", stripped)
        if header:
            section = header.group(1)
            continue
        key = re.match(r"^#\s*([a-z_]+)\s*=", stripped)
        if not key or section is None:
            continue
        trial = list(lines)
        trial[i] = raw.replace("# ", "", 1)
        path = tmp_path / f"trial_{i}.toml"
        path.write_text("\n".join(trial), encoding="utf-8")
        tested.append(f"[{section}].{key.group(1)}")
        try:
            load_settings(config_path=path)
        except Exception as exc:  # noqa: BLE001 - the message is the subject
            if "moved to [security]" in str(exc):
                relocated.append(f"[{section}].{key.group(1)}")

    assert tested, "no commented keys found -- the scan is broken, not the template"
    assert not relocated, (
        f"commented settings sit in a section the loader REFUSES: {relocated}. An operator following "
        f"the instruction beside them gets a config that will not load. (Scanned: {tested})"
    )


def test_check_fails_on_a_config_that_is_present_but_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The gate must not downgrade a refusal to a skip -- that is what hid this for two releases.

    Asserts the POSTURE ROW specifically, not just a nonzero rc. Three call sites in ``checks.py``
    load the service config, so an rc-only assertion stays green while any ONE of them regresses to a
    skip -- measured: reverting posture alone reddened nothing, and only reverting all three was
    caught. A test that needs every site to break before it fails is not guarding any of them.
    """
    repo = tmp_path / "repo"
    scaffold(repo)
    toml = repo / "messagefoundry.toml"
    toml.write_text(
        toml.read_text(encoding="utf-8").replace(
            "[api]\nport = 8765", '[api]\nhost = "127.0.0.1"\nport = 8765'
        ),
        encoding="utf-8",
    )
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
    out = capsys.readouterr().out
    assert rc != 0, f"check passed over a service config the loader refuses:\n{out}"
    posture = [ln for ln in out.splitlines() if "posture:" in ln]
    assert posture, f"no posture row in the check output:\n{out}"
    assert any(ln.strip().lower().startswith("fail") for ln in posture), (
        f"the posture check did not FAIL on an unloadable config; it reported: {posture}"
    )


def test_check_still_skips_when_there_is_no_service_config(tmp_path: Path) -> None:
    """NEGATIVE CONTROL for the test above: ABSENT stays a legitimate skip.

    The two states must not be conflated in either direction -- making absence fail would break every
    config-only repo that never writes a messagefoundry.toml.
    """
    repo = tmp_path / "repo"
    scaffold(repo)
    (repo / "messagefoundry.toml").unlink()
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
    assert rc == 0, "an ABSENT service config must remain a skip, not a failure"
