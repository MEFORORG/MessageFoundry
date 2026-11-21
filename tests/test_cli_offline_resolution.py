# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0050 §3 / AC-6 — the offline subcommands (validate/graph/dryrun/check) carry the same
project-root / active-env / service-config flags serve does, resolve the same bundle root, and check
suppresses its messagefoundry.toml upward-walk when --service-config / --project-root is supplied —
WITHOUT adopting serve's required-active-env / explicit-posture refusal. ADR 0050 Amendment A makes
one exception: `check --env`'s settings checks read the name as `serve --env` does
(tests/test_checks_gate_parity.py covers it through run_checks; the vault BACKLOG #5554 tests at the
end of this file pin it from the command line, and pin that --env on the other three resolves
the named environment's env() values).
"""

from __future__ import annotations

import argparse
import functools
import os
import textwrap
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from tests.test_checks_gate_parity import _cli_check


@pytest.fixture(autouse=True)
def _no_mefor_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every MEFOR_* variable: an exported MEFOR_ENVIRONMENTS_DIR moves the value dir these
    tests look in, and other settings variables reach check's settings legs."""
    for name in list(os.environ):
        if name.upper().startswith("MEFOR_"):
            monkeypatch.delenv(name)


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
    # And validate/graph with --project-root but no --env also resolve cleanly (anchoring only).
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


# --- AC-3 offline: MEFOR_ENVIRONMENTS_DIR beats the file's dir, as in serve (vault BACKLOG #2355) ---


@pytest.mark.parametrize("command", ["check", "validate"])
@pytest.mark.parametrize("present", ["envs", "environments"])
def test_offline_ac3_reads_the_env_dir_variable_as_serve_does(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    present: str,
) -> None:
    # serve's load_settings puts MEFOR_ENVIRONMENTS_DIR above the file's [environments].dir, and its
    # AC-3 check looks for <root>/<that dir>/<env>.toml. The offline pre-check read the file alone,
    # so it failed loud on a file serve finds, and passed a layout serve refuses.
    from messagefoundry.config.settings import load_settings

    cfg = _config_dir(tmp_path, body=_ENV_GRAPH)
    svc = tmp_path / "messagefoundry.toml"
    svc.write_text('[environments]\ndir = "environments"\n', encoding="utf-8")
    (tmp_path / present).mkdir()
    (tmp_path / present / "prod.toml").write_text('peer_host = "10.0.0.9"\n', encoding="utf-8")
    argv = [command, "--project-root", str(tmp_path), "--service-config", str(svc)]
    argv += ["--config", str(cfg), "--env", "prod"]
    if command == "check":
        argv.append("--no-lint")

    # The variable set, then unset as the control: whichever dir serve's reader names decides.
    for variable in ("envs", None):
        if variable is None:
            monkeypatch.delenv("MEFOR_ENVIRONMENTS_DIR")
        else:
            monkeypatch.setenv("MEFOR_ENVIRONMENTS_DIR", variable)
        expected = load_settings(config_path=svc).environments.dir
        assert expected == (variable or "environments")
        rc = main(argv)
        err = capsys.readouterr().err
        if present == expected:
            assert rc != 2 and "no value file" not in err, err
        else:
            assert rc == 2 and str(tmp_path / expected / "prod.toml") in err, err


def test_offline_ac3_takes_a_blank_env_dir_as_serve_does(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # serve's loader takes [environments].dir = "" as given, so it reads <root>/<env>.toml. The
    # offline check put "environments" in its place and failed loud on a layout serve starts.
    from messagefoundry.config.settings import load_settings

    cfg = _config_dir(tmp_path, body=_ENV_GRAPH)
    svc = tmp_path / "messagefoundry.toml"
    svc.write_text('[environments]\ndir = ""\n', encoding="utf-8")
    (tmp_path / "prod.toml").write_text('peer_host = "10.0.0.9"\n', encoding="utf-8")
    assert load_settings(config_path=svc).environments.dir == ""  # serve's reader
    argv = ["--project-root", str(tmp_path), "--service-config", str(svc), "--config", str(cfg)]
    rc = main(["validate", *argv, "--env", "prod", "--json"])
    assert rc == 0, capsys.readouterr().err


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


# --- BACKLOG #5554: what --env does on each offline command -------------------------------------


def _empty_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run from an empty directory, so a messagefoundry.toml in the working directory is not read."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)


def test_check_env_alone_judges_posture_for_that_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A site naming its environment only on the command line: no messagefoundry.toml, no
    # MEFOR_AI_ENVIRONMENT. A custom name with no production tier is the name serve refuses, so the
    # gate must refuse it too, not skip posture and exit 0. --project-root suppresses check's upward
    # search, so a messagefoundry.toml above the temp dir cannot reach the result.
    cfg = _config_dir(tmp_path)
    _empty_cwd(tmp_path, monkeypatch)
    anchor = ["--project-root", str(tmp_path), "--config", str(cfg)]
    rc, legs = _cli_check(capsys, *anchor, "--env", "poc")
    assert rc == 1, legs["posture"]
    assert not legs["posture"]["ok"] and not legs["posture"]["skipped"], legs["posture"]
    assert "production_instance" in str(legs["posture"]["detail"])
    # Control: with no --env nothing names an instance, so posture skips and the gate passes.
    rc, legs = _cli_check(capsys, *anchor)
    assert rc == 0 and legs["posture"]["skipped"], legs["posture"]


@functools.cache
def _subcommands() -> dict[str, argparse.ArgumentParser]:
    from messagefoundry import __main__ as cli

    parser, _dispatch = cli._build_parser()
    subparsers = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    return dict(subparsers.choices)


def _rendered_help(command: str, monkeypatch: pytest.MonkeyPatch) -> str:
    """The subcommand's --help as argparse renders it in an 80-column terminal."""
    monkeypatch.setenv("COLUMNS", "80")
    return _subcommands()[command].format_help()


@pytest.mark.parametrize("command", ["validate", "graph", "dryrun"])
def test_offline_env_help_says_the_flag_resolves_values(
    command: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # validate, graph and dryrun resolve env() against the --env value file (vault BACKLOG #5554).
    # The help must say so, name the working-directory default, say no value is printed, and leave
    # the posture checks to check --env.
    rendered = _rendered_help(command, monkeypatch)
    # argparse breaks help on hyphens; a reader copying the flag must not get "--project-".
    assert "--project-\n" not in rendered
    text = " ".join(rendered.split())
    assert "It selects no values" not in text
    assert "resolves every env() reference" in text
    assert "default: the working directory" in text
    assert "never printed" in text and "left to check --env" in text
    # Control: check's own help still says it reads the name as serve does.
    assert "read as serve --env reads it" in " ".join(_rendered_help("check", monkeypatch).split())


_MSG = (
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260101\rPID|1||100^^^H^MR||DOE^JANE\r"
)

#: A value no command may print: a resolved value is never shown (vault BACKLOG #5554).
_SECRET_HOST = "10.77.66.55"


def _offline_argv(command: str, tmp_path: Path, *extra: str) -> list[str]:
    argv = [command, *extra, "--json"]
    if command == "dryrun":
        msg = tmp_path / "adt.hl7"
        msg.write_text(_MSG, encoding="utf-8")
        argv += ["--messages", str(msg)]
    return argv


def _values_file(base: Path, env_name: str, body: str) -> None:
    (base / "environments").mkdir(parents=True, exist_ok=True)
    (base / "environments" / f"{env_name}.toml").write_text(body, encoding="utf-8")


@pytest.mark.parametrize("command", ["validate", "graph", "dryrun"])
def test_offline_env_resolves_the_named_environment_under_project_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    # A value file that lacks a key the graph references: serve would refuse to build OB_T, so the
    # offline command must fail on that environment too, naming the key, not exit 0.
    cfg = _config_dir(tmp_path, body=_ENV_GRAPH)
    _values_file(tmp_path, "dev", 'other = "x"\n')
    _values_file(tmp_path, "prod", f'peer_host = "{_SECRET_HOST}"\n')
    _empty_cwd(tmp_path, monkeypatch)
    anchor = ["--project-root", str(tmp_path), "--config", str(cfg)]
    rc = main(_offline_argv(command, tmp_path, *anchor, "--env", "dev"))
    captured = capsys.readouterr()
    assert rc != 0, captured
    assert "peer_host" in captured.out + captured.err
    # The environment that has the key passes, and its value is never printed.
    rc = main(_offline_argv(command, tmp_path, *anchor, "--env", "prod"))
    captured = capsys.readouterr()
    assert rc == 0, captured
    assert _SECRET_HOST not in captured.out + captured.err
    # Control: with no --env no values are loaded, so the command behaves as before.
    rc = main(_offline_argv(command, tmp_path, *anchor))
    captured = capsys.readouterr()
    assert rc == 0, captured


@pytest.mark.parametrize("command", ["validate", "graph", "dryrun"])
def test_offline_env_without_project_root_reads_the_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    # serve's default root is the working directory, so --env alone resolves against
    # ./environments/<env>.toml there; it no longer does nothing (vault BACKLOG #5554).
    cfg = _config_dir(tmp_path, body=_ENV_GRAPH)
    cwd = tmp_path / "cwd"
    _values_file(cwd, "dev", 'other = "x"\n')
    _values_file(cwd, "prod", f'peer_host = "{_SECRET_HOST}"\n')
    monkeypatch.chdir(cwd)
    rc = main(_offline_argv(command, tmp_path, "--config", str(cfg), "--env", "dev"))
    captured = capsys.readouterr()
    assert rc != 0, captured
    assert "peer_host" in captured.out + captured.err
    rc = main(_offline_argv(command, tmp_path, "--config", str(cfg), "--env", "prod"))
    captured = capsys.readouterr()
    assert rc == 0, captured
    assert _SECRET_HOST not in captured.out + captured.err
    # A name with no value file in the working directory resolves nothing, as serve's silent-empty
    # read does, so the referenced key is reported missing.
    rc = main(_offline_argv(command, tmp_path, "--config", str(cfg), "--env", "qa"))
    captured = capsys.readouterr()
    assert rc != 0 and "peer_host" in captured.out + captured.err, captured


def test_offline_env_reads_mefor_value_variables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # serve's reader overlays MEFOR_VALUE_* on the value file; the offline commands use that reader.
    cfg = _config_dir(tmp_path, body=_ENV_GRAPH)
    cwd = tmp_path / "cwd"
    _values_file(cwd, "dev", 'other = "x"\n')
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("MEFOR_VALUE_PEER_HOST", _SECRET_HOST)
    rc = main(["validate", "--config", str(cfg), "--env", "dev", "--json"])
    captured = capsys.readouterr()
    assert rc == 0, captured
    assert _SECRET_HOST not in captured.out + captured.err


def test_offline_env_skips_a_not_deployed_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The engine never builds a deployed=False connection, so its env() references are not resolved
    # there; the offline commands must not fail an environment on one either.
    body = _ENV_GRAPH.replace(
        'outbound("OB_T", MLLP(host=env("peer_host"), port=6000))',
        'outbound("OB_T", MLLP(host="10.0.0.1", port=6000))\n'
        '    outbound("OB_OFF", MLLP(host=env("off_host"), port=6001), deployed=False)',
    )
    assert "OB_OFF" in body
    cfg = _config_dir(tmp_path, body=body)
    cwd = tmp_path / "cwd"
    _values_file(cwd, "dev", 'other = "x"\n')
    monkeypatch.chdir(cwd)
    rc = main(["validate", "--config", str(cfg), "--env", "dev", "--json"])
    assert rc == 0, capsys.readouterr()


@pytest.mark.parametrize("command", ["validate", "graph", "dryrun"])
def test_offline_env_reports_a_malformed_value_file_without_its_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    cfg = _config_dir(tmp_path, body=_ENV_GRAPH)
    cwd = tmp_path / "cwd"
    _values_file(cwd, "dev", f'peer_host = "{_SECRET_HOST}\n')
    monkeypatch.chdir(cwd)
    rc = main(_offline_argv(command, tmp_path, "--config", str(cfg), "--env", "dev"))
    captured = capsys.readouterr()
    assert rc != 0, captured
    assert "dev.toml" in captured.out + captured.err, captured
    assert _SECRET_HOST not in captured.out + captured.err, captured


@pytest.mark.parametrize("command", ["validate", "graph", "dryrun"])
def test_offline_env_leaves_an_unresolved_reference_set_to_its_sync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    # serve starts with a reference set whose source env() does not resolve, and check --env's build
    # check lets it through: only that set's sync fails. The offline commands must not be stricter.
    body = _NO_ENV_GRAPH.replace(
        "from messagefoundry import inbound, outbound, MLLP, router, handler, Send",
        "from messagefoundry import inbound, outbound, MLLP, router, handler, Send, Reference, "
        "FileRef, env\n"
        "    Reference('codes', source=FileRef(path=env('codes_csv')), refresh_seconds=3600)",
    )
    assert "codes_csv" in body
    cfg = _config_dir(tmp_path, body=body)
    cwd = tmp_path / "cwd"
    _values_file(cwd, "dev", 'other = "x"\n')
    monkeypatch.chdir(cwd)
    rc = main(_offline_argv(command, tmp_path, "--config", str(cfg), "--env", "dev"))
    assert rc == 0, capsys.readouterr()


@pytest.mark.parametrize("command", ["validate", "graph", "dryrun"])
def test_offline_env_refuses_a_service_config_that_is_no_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    # serve refuses a --service-config that is no file. Reading a default value folder in its place
    # would judge an environment serve never reads.
    cfg = _config_dir(tmp_path, body=_ENV_GRAPH)
    cwd = tmp_path / "cwd"
    _values_file(cwd, "prod", f'peer_host = "{_SECRET_HOST}"\n')
    monkeypatch.chdir(cwd)
    typo = ["--service-config", str(tmp_path / "typo.toml")]
    rc = main(_offline_argv(command, tmp_path, "--config", str(cfg), *typo, "--env", "prod"))
    captured = capsys.readouterr()
    assert rc != 0 and "service config not found" in captured.out + captured.err, captured
    # Control: without --env no values are read, so the flag is not judged here, as before.
    rc = main(_offline_argv(command, tmp_path, "--config", str(cfg), *typo))
    assert rc == 0, capsys.readouterr()


def test_offline_env_without_project_root_reads_the_dir_named_in_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # With no root and no --service-config, serve reads ./messagefoundry.toml, so its
    # [environments].dir names the folder the value file is read from.
    cfg = _config_dir(tmp_path, body=_ENV_GRAPH)
    cwd = tmp_path / "cwd"
    (cwd / "envs").mkdir(parents=True)
    (cwd / "envs" / "prod.toml").write_text(f'peer_host = "{_SECRET_HOST}"\n', encoding="utf-8")
    (cwd / "messagefoundry.toml").write_text('[environments]\ndir = "envs"\n', encoding="utf-8")
    monkeypatch.chdir(cwd)
    rc = main(["validate", "--config", str(cfg), "--env", "prod", "--json"])
    assert rc == 0, capsys.readouterr()
    # Control: without the settings file, the default environments/ holds no value file.
    (cwd / "messagefoundry.toml").unlink()
    rc = main(["validate", "--config", str(cfg), "--env", "prod", "--json"])
    assert rc == 1 and "peer_host" in capsys.readouterr().out
