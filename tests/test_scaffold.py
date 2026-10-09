# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""`messagefoundry init` scaffolds a standalone config repo whose starter config passes `check`."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml
from _bash_resolver import explain_returncode, probe_env, require_bash
from packaging.version import Version

from messagefoundry import __version__
from messagefoundry.__main__ import main
from messagefoundry.api.tls import _generated_pair
from messagefoundry.checks import CheckResult, run_checks
from messagefoundry.config.retention_classification import warn_only_windows
from messagefoundry.config.settings import load_settings, security_loosenings
from messagefoundry.scaffold import scaffold
from scripts.release.tag_spelling import allowed

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
    # `handles_real_patient_data` sat beside `production_instance` here until BACKLOG #1279 retired it.
    # The ABSENCE is now the assertion, and it is the same class of bug as the comment above records:
    # asserting the presence of a name the loader refuses keeps a test green while `init` emits an
    # unloadable config. tests/test_relocated_key_messages.py carries the general form of this guard.
    assert "production_instance" in toml
    assert "handles_real_patient_data" not in toml
    # D11: the .gitignore still ignores the one-time password file engines before ADR 0183 Amendment
    # A wrote beside the store: a development checkout may hold a live one, and it must never commit
    gitignore = (repo / ".gitignore").read_text()
    assert "bootstrap-admin.txt" in gitignore
    # ...and the API TLS pair it mints beside the store (ADR 0172), the key above all. The names come
    # from the minting code, so a rename there cannot leave this list silently stale.
    ignored = set(gitignore.splitlines())
    for minted in _generated_pair(repo):
        assert minted.name in ignored
    # ...and the config editors' lock file and a killed edit's candidate directory (vault BACKLOG
    # #2782), named from the module that creates them.
    from messagefoundry.config import atomic_edit

    assert atomic_edit.LOCK_FILE_NAME in ignored
    assert f".*.????????{atomic_edit.CANDIDATE_DIR_SUFFIX}/" in ignored
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
    # The verify step's command (BACKLOG #2534) is executed, not read, by
    # test_the_scaffolded_verify_step_pins_the_release_workflow_and_tag.
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


_VERIFY_STEP = "Verify SLSA build provenance before install"
_RELEASE_WORKFLOW = "MEFORORG/MessageFoundry/.github/workflows/release.yml"


@pytest.fixture(scope="module")
def verify_step(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, Path]:
    """The generated verify step written to disk, and a bash that can run it, found once per module."""
    root = tmp_path_factory.mktemp("verify-step")
    repo = root / "repo"
    scaffold(repo)
    ci = yaml.safe_load((repo / ".github" / "workflows" / "check.yml").read_text(encoding="utf-8"))
    [step] = [s for s in ci["jobs"]["verify-engine"]["steps"] if s.get("name") == _VERIFY_STEP]
    script = root / "verify.sh"
    # Bytes, so Windows does not turn each newline into CRLF, which bash would read as part of a line.
    script.write_bytes(str(step["run"]).encode("utf-8"))
    return require_bash(root), script


#: A ``gh`` that answers ``--version`` with ``$FAKE_GH_VERSION`` and records any other call's argv.
_GH_STUB = (
    b"#!/usr/bin/env bash\n"
    b'if [ "$1" = "--version" ]; then echo "gh version $FAKE_GH_VERSION (2026-09-30)"; exit 0; fi\n'
    b'printf "%s\\n" "$@" > "$GH_LOG"\n'
)


def _run_verify_step(
    verify_step: tuple[str, Path],
    tmp_path: Path,
    wheels: list[str],
    gh_version: str = "2.102.0",
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run the step with ``wheels`` in dist-verify/ and a ``gh`` on PATH that records its argv."""
    bash, script = verify_step
    work = tmp_path / "work"
    (work / "dist-verify").mkdir(parents=True)
    for wheel in wheels:
        (work / "dist-verify" / wheel).write_bytes(b"not a real wheel")
    stub_dir = tmp_path / "ghstub"
    stub_dir.mkdir()
    stub = stub_dir / "gh"
    stub.write_bytes(_GH_STUB)
    stub.chmod(0o755)
    log = tmp_path / "gh.log"
    env = probe_env(Path(bash), dict(os.environ))
    env["PATH"] = f"{stub_dir.as_posix()}{os.pathsep}{env.get('PATH', '')}"
    env["GH_LOG"] = log.as_posix()
    env["FAKE_GH_VERSION"] = gh_version
    proc = subprocess.run(
        [bash, "-e", script.as_posix()],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return proc, log


@pytest.mark.parametrize(
    "tag", ["v0.4.0", "v1.10.0", "v0.5.0-a1", "v0.5.0-b2", "v0.5.0-rc1", "v2.0.0-rc10"]
)
def test_the_scaffolded_verify_step_rebuilds_the_release_tag(
    verify_step: tuple[str, Path], tmp_path: Path, tag: str
) -> None:
    """BACKLOG #2534: the gate names the release workflow and the exact tag the wheel came from.

    Each tag here is one the release accepts (scripts/release/tag_spelling.py), and its wheel says
    the version as PEP 440 normalises it, which is what the release's own version gate requires.
    So the step must turn that wheel back into this tag: a final, an alpha, a beta and two rcs.
    """
    assert allowed(tag), f"{tag} is not a tag the release accepts, so this row tests nothing real"
    wheel = f"messagefoundry-{Version(tag[1:])}-py3-none-any.whl"
    proc, log = _run_verify_step(verify_step, tmp_path, [wheel])
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, f"{explain_returncode(proc.returncode)}\n{output}"
    assert log.read_text(encoding="utf-8").splitlines() == [
        "attestation",
        "verify",
        f"dist-verify/{wheel}",
        "--repo",
        "MEFORORG/MessageFoundry",
        "--signer-workflow",
        _RELEASE_WORKFLOW,
        "--source-ref",
        f"refs/tags/{tag}",
    ]


@pytest.mark.parametrize(
    ("wheels", "message"),
    [
        ([], "expected one engine wheel"),
        (
            ["messagefoundry-0.4.0-py3-none-any.whl", "messagefoundry-0.4.1-py3-none-any.whl"],
            "expected one engine wheel",
        ),
        # No release tag spells these, so the step refuses rather than guess one.
        (["messagefoundry-0.4.0.post1-py3-none-any.whl"], "has no release tag spelling"),
        (["messagefoundry-0.5.0.dev1-py3-none-any.whl"], "has no release tag spelling"),
    ],
    ids=["no-wheel", "two-wheels", "post-release", "dev-release"],
)
def test_the_scaffolded_verify_step_refuses_what_it_cannot_verify(
    verify_step: tuple[str, Path], tmp_path: Path, wheels: list[str], message: str
) -> None:
    """The refusals require that ``gh`` never ran, so no other file can be verified instead."""
    proc, log = _run_verify_step(verify_step, tmp_path, wheels)
    output = proc.stdout + proc.stderr
    assert proc.returncode == 1, f"{explain_returncode(proc.returncode)}\n{output}"
    assert message in output, output
    assert not log.exists(), f"gh ran although the step should have refused: {log.read_text()}"


_WEAK_PIN = "gives a weaker pin"


@pytest.mark.parametrize(
    ("gh_version", "verifies", "warns"),
    [
        ("2.67.0", False, False),  # no --source-ref at all: refuse
        ("2.68.0", True, True),  # the floor: verify, but warn the pin is weaker
        ("2.101.9", True, True),
        ("2.102.0", True, False),  # signer-workflow and source-ref matched exactly
        ("3.0.0", True, False),
    ],
)
def test_the_scaffolded_verify_step_checks_the_gh_version(
    verify_step: tuple[str, Path], tmp_path: Path, gh_version: str, verifies: bool, warns: bool
) -> None:
    """Below gh 2.68.0 the step refuses; below 2.102.0 it verifies and warns (BACKLOG #2534).

    The rows on each side of both thresholds are each other's control.
    """
    proc, log = _run_verify_step(
        verify_step, tmp_path, ["messagefoundry-0.4.0-py3-none-any.whl"], gh_version
    )
    output = proc.stdout + proc.stderr
    if not verifies:
        assert proc.returncode == 1, f"{explain_returncode(proc.returncode)}\n{output}"
        assert "needs gh 2.68.0 or later" in output, output
        assert not log.exists(), f"gh verify ran on a gh with no --source-ref: {log.read_text()}"
        return
    assert proc.returncode == 0, f"{explain_returncode(proc.returncode)}\n{output}"
    assert log.read_text(encoding="utf-8").splitlines()[:2] == ["attestation", "verify"]
    assert (_WEAK_PIN in output) is warns, output


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
    # text-mode errors go to stderr (BACKLOG #1673)
    assert "not empty" in capsys.readouterr().err


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


# --- vault BACKLOG #2280: the scaffold answers the retention gate, and only that -------------------
#
# `messagefoundry check` runs the retention start gate as a required leg. rc == 0 alone would also
# pass if that leg skipped, so these read the leg itself.

_STATE_ACK = "allow_keeping_transform_state_indefinitely"


def _scaffold_without_mefor_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A scaffolded repo, judged with no ``MEFOR_*`` variable from the host or another fixture."""
    for name in list(os.environ):
        if name.upper().startswith("MEFOR_"):
            monkeypatch.delenv(name)
    repo = tmp_path / "repo"
    scaffold(repo)
    return repo


def _retention_leg(repo: Path) -> CheckResult:
    """The ``retention`` leg, with the settings file found the way the scaffold's own command
    finds it: ``messagefoundry check --config config`` names no ``--service-config``, so the file
    is found by the walk up from the config dir."""
    report = run_checks(repo / "config", run_lint=False)
    legs = {r.name: r for r in report.results}
    assert "retention" in legs, f"no retention leg in the report; it has {sorted(legs)}"
    return legs["retention"]


def test_the_scaffold_passes_the_retention_leg_without_skipping_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    leg = _retention_leg(_scaffold_without_mefor_env(tmp_path, monkeypatch))
    assert leg.required and leg.ok and not leg.skipped, leg.detail
    # It ran on the scaffold's own settings, and the tier is acknowledged, not merely warned
    # about: the line carries the gate's audit record for it. A warning names the switch too.
    assert (
        "audit record: starting a PHI instance (environment 'dev') with "
        f"[retention].state_max_age_days (PL-2) unbounded, permitted because [security].{_STATE_ACK}"
        "=true" in leg.detail
    )
    assert "warning:" not in leg.detail


@pytest.mark.parametrize(
    ("line", "tier"),
    [
        (f"{_STATE_ACK} = true\n", "[retention].state_max_age_days"),
        ("search_preset_days = 30\n", "[retention].search_preset_days"),
    ],
    ids=["state-ack", "search-presets"],
)
def test_removing_either_retention_line_fails_the_leg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, line: str, tier: str
) -> None:
    """THE CONTROL. Each line the scaffold writes for the gate is one the gate needs."""
    repo = _scaffold_without_mefor_env(tmp_path, monkeypatch)
    toml = repo / "messagefoundry.toml"
    text = toml.read_text(encoding="utf-8")
    assert text.count(line) == 1, "the scaffold no longer writes this line; re-point the control"
    toml.write_text(text.replace(line, ""), encoding="utf-8")
    leg = _retention_leg(repo)
    assert not leg.ok and not leg.skipped
    assert leg.detail.startswith("serve would refuse to start (exit 2): ") and tier in leg.detail


def test_the_scaffold_names_one_loosening_and_it_is_the_state_acknowledgement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The acknowledgement is an audited loosening, so it must be the only one a new repo carries.

    Read from the settings the scaffold writes, with no graph and no process posture. The hop and
    process entries of the list are out of scope here."""
    repo = _scaffold_without_mefor_env(tmp_path, monkeypatch)
    settings = load_settings(config_path=repo / "messagefoundry.toml")
    names = [
        name
        for name, _ in security_loosenings(
            settings.security,
            settings.store,
            settings.auth,
            settings.alerts,
            settings.secret_rotation,
            cleartext_hops=(),
            expiry_relaxed_hops=(),
            hostname_unchecked_hops=(),
            query_credential_hops=(),
            unverified_db_hops=(),
            attested_hops=(),
            revocation_attested_hops=(),
            path_form_fhir_hops=(),
            api=settings.api,
            approvals=settings.approvals,
            cert_monitor=settings.cert_monitor,
            backup=settings.backup,
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
        )
    ]
    # The whole list, so this one line also says no other retention acknowledgement is set.
    assert names == [_STATE_ACK]
    # Control: the state switch is a real per-tier acknowledgement, so the list above is the
    # registry naming it rather than a coincidence of spelling.
    assert _STATE_ACK in {w.acknowledged_by for w in warn_only_windows()}
    assert not settings.retention.allow_unbounded_phi
