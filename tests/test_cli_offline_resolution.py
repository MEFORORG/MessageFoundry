# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0050 §3 / AC-6 — the offline subcommands (validate/graph/dryrun/check) carry the same
project-root / active-env / service-config flags serve does, resolve the same bundle root, and check
suppresses its messagefoundry.toml upward-walk when --service-config / --project-root is supplied —
WITHOUT adopting serve's required-active-env / explicit-posture refusal.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from messagefoundry.__main__ import main

_NO_ENV_GRAPH = """
    from messagefoundry import inbound, outbound, MLLP, router, handler, Send

    inbound("IB_T", MLLP(port=2599), router="r")
    outbound("OB_T", MLLP(host="10.0.0.1", port=6000))

    @router(name="r")
    def r(msg):
        return ["h"]

    @handler(name="h")
    def h(msg):
        return [Send("OB_T", msg.raw)]
"""

_ENV_GRAPH = """
    from messagefoundry import inbound, outbound, MLLP, router, handler, Send, env

    inbound("IB_T", MLLP(port=2599), router="r")
    outbound("OB_T", MLLP(host=env("peer_host"), port=6000))

    @router(name="r")
    def r(msg):
        return ["h"]

    @handler(name="h")
    def h(msg):
        return [Send("OB_T", msg.raw)]
"""


def _config_dir(parent: Path, *, name: str = "config", body: str = _NO_ENV_GRAPH) -> Path:
    d = parent / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "feed.py").write_text(textwrap.dedent(body), encoding="utf-8")
    return d


# --- every newly-flagged subcommand accepts the trio ---------------------------------------------


@pytest.mark.parametrize("command", ["validate", "graph", "dryrun", "check"])
def test_subcommand_accepts_anchor_flags(command: str) -> None:
    """The argparse parser accepts --project-root/--env/--service-config on each offline subcommand
    (dispatch patched so nothing runs). Without the flags wired in, parse would SystemExit."""
    from messagefoundry import __main__ as cli

    captured: dict[str, object] = {}

    def _capture(args: object) -> int:
        captured["args"] = args
        return 0

    monkey = pytest.MonkeyPatch()
    monkey.setitem(cli._DISPATCH, command, _capture)
    try:
        argv = [
            command,
            "--config",
            "c",
            "--project-root",
            "R",
            "--env",
            "dev",
            "--service-config",
            "s.toml",
        ]
        if command == "dryrun":
            argv += ["--messages", "m"]
        assert cli.main(argv) == 0
    finally:
        monkey.undo()
    args = captured["args"]
    assert args.project_root == "R"  # type: ignore[attr-defined]
    assert args.env == "dev"  # type: ignore[attr-defined]
    assert args.service_config == "s.toml"  # type: ignore[attr-defined]


# --- check: posture resolution via the explicit service config (AC-6) ----------------------------


def _custom_posture_toml(parent: Path, *, name: str = "messagefoundry.toml") -> Path:
    # A CUSTOM active-environment name with NO [ai].data_class/[ai].production: serve fails closed at
    # require_posture(), and the posture check mirrors that fail-closed gate.
    toml = parent / name
    toml.write_text('[ai]\nenvironment = "qa"\n', encoding="utf-8")
    return toml


def test_check_uses_explicit_service_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # With an explicit --service-config naming an unresolved-posture toml, check's posture gate FAILS
    # (matching serve's runtime refusal) — proving the explicit service config is resolved, not ignored.
    cfg = _config_dir(tmp_path)
    toml = _custom_posture_toml(tmp_path)
    rc = main(["check", "--config", str(cfg), "--service-config", str(toml), "--no-lint", "--json"])
    assert rc == 1  # a required check (posture) failed
    assert "qa" in capsys.readouterr().out


def test_check_suppresses_upward_walk_under_project_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The bad-posture toml sits ABOVE the config dir. With --project-root pointing at a clean subdir
    # (no toml), the upward-walk is SUPPRESSED so the parent's toml is NOT discovered -> posture SKIPs
    # (no spurious failure). This is the AC-6 suppression: explicit flags beat the legacy walk.
    _custom_posture_toml(tmp_path)  # would be found by the legacy upward-walk
    sub = tmp_path / "clean"
    sub.mkdir()
    cfg = _config_dir(sub)
    rc = main(["check", "--project-root", str(sub), "--config", str(cfg), "--no-lint", "--json"])
    assert rc == 0  # posture SKIPped (no toml at the root) -> gate passes


def test_check_legacy_upward_walk_preserved_without_flags(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # No --service-config and no --project-root: the legacy _find_service_toml upward-walk is preserved,
    # so the parent's bad-posture toml IS discovered and the posture gate FAILS (no regression for the
    # documented `messagefoundry check --config config` invocation).
    _custom_posture_toml(tmp_path)
    cfg = _config_dir(tmp_path)
    rc = main(["check", "--config", str(cfg), "--no-lint", "--json"])
    assert rc == 1  # the upward-walk found the bad toml -> posture failed
    assert "qa" in capsys.readouterr().out


# --- offline does NOT inherit serve's required-env / posture refusal (AC-6) -----------------------


def test_offline_does_not_inherit_serve_posture_refusal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The documented gate invocation `check --config config --messages ...` has NO --env. serve would
    # refuse to start with no active environment; the offline gate must NOT — it stays green.
    cfg = _config_dir(tmp_path)
    rc = main(["check", "--config", str(cfg), "--no-lint", "--json"])
    assert rc == 0  # no required-env refusal offline
    # And validate/graph with --project-root but no --env also resolve cleanly (value resolution only).
    assert main(["validate", "--project-root", str(tmp_path), "--config", str(cfg), "--json"]) == 0
    assert main(["graph", "--project-root", str(tmp_path), "--config", str(cfg), "--json"]) == 0


# --- AC-3 offline: a CUSTOM [environments].dir is honored, not false-positive-failed ---------------


def test_offline_ac3_honors_custom_env_dir_from_service_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A repo with [environments].dir = "envs" + env() refs: `validate --project-root R --env prod` must
    # look under R/envs (read from the service config), NOT the hardcoded R/environments — so a present
    # envs/prod.toml passes (no spurious AC-3 hard-fail), while the absent-file case still fails loud.
    cfg = _config_dir(tmp_path, body=_ENV_GRAPH)
    svc = tmp_path / "messagefoundry.toml"
    svc.write_text('[environments]\ndir = "envs"\n', encoding="utf-8")
    # File present under the CUSTOM dir -> no false-positive failure.
    envs = tmp_path / "envs"
    envs.mkdir()
    (envs / "prod.toml").write_text('peer_host = "10.0.0.9"\n', encoding="utf-8")
    rc = main(
        [
            "validate",
            "--project-root",
            str(tmp_path),
            "--service-config",
            str(svc),
            "--config",
            str(cfg),
            "--env",
            "prod",
            "--json",
        ]
    )
    assert rc == 0  # honored R/envs/prod.toml; did NOT false-fail on R/environments/prod.toml
    assert capsys.readouterr().out.strip() == "[]"


def test_offline_ac3_custom_env_dir_missing_file_still_fails_loud(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Same custom-dir repo, but envs/prod.toml is ABSENT -> the scoped AC-3 hard-fail still fires, now
    # naming the custom dir (the fail-loud is preserved, just env-dir-aware).
    cfg = _config_dir(tmp_path, body=_ENV_GRAPH)
    svc = tmp_path / "messagefoundry.toml"
    svc.write_text('[environments]\ndir = "envs"\n', encoding="utf-8")
    rc = main(
        [
            "validate",
            "--project-root",
            str(tmp_path),
            "--service-config",
            str(svc),
            "--config",
            str(cfg),
            "--env",
            "prod",
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "envs" in err and "prod.toml" in err


def test_graph_and_dryrun_honor_relative_config_under_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # graph + dryrun resolve a relative --config under --project-root from an unrelated CWD.
    _config_dir(tmp_path, name="config")
    msg = tmp_path / "adt.hl7"
    msg.write_text(
        "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"
        "EVN|A01|20260101\rPID|1||100^^^H^MR||DOE^JANE\r",
        encoding="utf-8",
    )
    elsewhere = tmp_path / "wd"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert main(["graph", "--project-root", str(tmp_path), "--config", "config", "--json"]) == 0
    capsys.readouterr()
    rc = main(
        [
            "dryrun",
            "--project-root",
            str(tmp_path),
            "--config",
            "config",
            "--messages",
            str(msg),
            "--json",
        ]
    )
    assert rc == 0
