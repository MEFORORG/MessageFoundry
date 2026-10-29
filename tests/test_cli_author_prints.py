# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A print() in an author's config module never lands on a ``--json`` command's stdout.

CLI commands import config modules in the CLI's own process. A debugging ``print()`` at the top of
one used to write to stdout ahead of the JSON, so the document did not parse. ``dryrun`` was fixed
first (vault BACKLOG #1187) and its Handler arm is pinned in ``tests/test_cli.py``; ``validate``
and ``graph`` followed (vault BACKLOG #2727). Since vault BACKLOG #3474 one seam covers every
subcommand (``messagefoundry/author_output.py``), and the later tests here pin it.

Two loads are covered, because a command can import the config twice. Under an explicit
``--project-root`` with ``--env``, the anchor helper loads the graph first to ask whether it
references ``env()``, and the command then loads it again.

Synthetic data only: the marker below is not message data.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import messagefoundry
from messagefoundry import author_output
from messagefoundry.__main__ import main
from tests._ast_sites import source_uses

#: What the config module prints. Not JSON, so one copy on stdout breaks the parse.
MARKER = "AUTHOR-PRINT-MARKER"

PRINTING_CONFIG = f"""\
# SPDX-License-Identifier: AGPL-3.0-or-later
from messagefoundry import File, handler, inbound, router

print("{MARKER}")

inbound("IB_TEST", File(directory="in"), router="r")


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def h(msg):
    return []
"""

#: The same module, failing after its print. ``validate`` reports it as a diagnostic and ``graph``
#: as an ``{"error"}`` body, so the error documents are covered as well as the success ones.
RAISING_CONFIG = PRINTING_CONFIG + '\nraise RuntimeError("config module failed on purpose")\n'

ADT_A01 = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\rEVN|A01|20260101\r"


def _config(tmp_path: Path, source: str) -> str:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "IB_TEST.py").write_text(source, encoding="utf-8")
    return str(cfg)


def _anchored(tmp_path: Path) -> list[str]:
    """The flags that make the anchor helper load the graph before the command does."""
    return ["--project-root", str(tmp_path), "--env", "dev"]


@pytest.fixture(params=[False, True], ids=["plain", "anchored"])
def anchor(request: pytest.FixtureRequest, tmp_path: Path) -> list[str]:
    """No extra flags, then the anchoring flags: one load of the config, then two."""
    return _anchored(tmp_path) if request.param else []


def _stdout_json(capsys: pytest.CaptureFixture[str], anchor: list[str]) -> object:
    """Stdout parsed as one JSON document, after checking each load's print went to stderr."""
    captured = capsys.readouterr()
    # Control: the print ran once per load of the config, so its absence from stdout is not
    # vacuous. The command loads it once, and the anchor helper once more under its flags.
    assert captured.err.count(MARKER) == (2 if anchor else 1), captured.err
    assert MARKER not in captured.out
    return json.loads(captured.out)


def test_validate_sends_a_config_modules_print_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], anchor: list[str]
) -> None:
    cfg = _config(tmp_path, PRINTING_CONFIG)
    assert main(["validate", "--config", cfg, "--json", *anchor]) == 0
    assert _stdout_json(capsys, anchor) == []


def test_validate_reports_a_failing_module_as_json_despite_its_print(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], anchor: list[str]
) -> None:
    cfg = _config(tmp_path, RAISING_CONFIG)
    assert main(["validate", "--config", cfg, "--json", *anchor]) == 1
    diags = _stdout_json(capsys, anchor)
    assert isinstance(diags, list) and diags, diags
    assert any(str(d["file"]).endswith("IB_TEST.py") for d in diags), diags


@pytest.mark.parametrize("compact", [["--json"], []])
def test_graph_sends_a_config_modules_print_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], anchor: list[str], compact: list[str]
) -> None:
    """``graph`` prints JSON with and without ``--json``; the flag only makes it compact."""
    cfg = _config(tmp_path, PRINTING_CONFIG)
    assert main(["graph", "--config", cfg, *compact, *anchor]) == 0
    graph = _stdout_json(capsys, anchor)
    assert isinstance(graph, dict)
    assert [c["name"] for c in graph["inbound"]] == ["IB_TEST"]


def test_graph_reports_a_failing_module_as_json_despite_its_print(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], anchor: list[str]
) -> None:
    cfg = _config(tmp_path, RAISING_CONFIG)
    assert main(["graph", "--config", cfg, "--json", *anchor]) != 0
    body = _stdout_json(capsys, anchor)
    assert isinstance(body, dict) and set(body) == {"error"}, body


def test_dryrun_under_a_project_root_sends_a_config_modules_print_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The anchor helper's own load of the graph runs before ``dryrun`` redirects anything."""
    cfg = _config(tmp_path, PRINTING_CONFIG)
    message = tmp_path / "a.hl7"
    message.write_bytes(ADT_A01.encode("utf-8"))
    anchor = _anchored(tmp_path)
    rc = main(["dryrun", "--config", cfg, "--messages", str(message), "--json", *anchor])
    assert rc == 0
    results = _stdout_json(capsys, anchor)
    assert isinstance(results, list) and len(results) == 1


# --- One seam for every command (vault BACKLOG #3474) ---------------------------------------------
#
# Per-command wraps left the rest uncovered: at least check's later loads, connection, impact and
# cert inventory let a print through. `run_cli` now marks every subcommand but the named few, and
# the loader and the dry-run preview redirect under the mark.

#: What the Router prints, so the check gate's dry-run leg, which runs it, is covered too.
ROUTER_MARKER = "ROUTER-PRINT-MARKER"

ROUTER_PRINTING_CONFIG = PRINTING_CONFIG.replace(
    '    return ["h"]', f'    print("{ROUTER_MARKER}")\n    return ["h"]'
)


def _no_print_on_stdout(capsys: pytest.CaptureFixture[str], *markers: str) -> object:
    """Stdout parsed as one JSON document, after checking each marker reached stderr and not stdout."""
    captured = capsys.readouterr()
    for marker in markers:
        # Control: the print ran, so its absence from stdout is not vacuous.
        assert marker in captured.err, captured.err
        assert marker not in captured.out
    return json.loads(captured.out)


def test_check_sends_every_loads_print_and_the_routers_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """``check`` loads the config once per leg, then runs the Router over each fixture."""
    assert ROUTER_PRINTING_CONFIG != PRINTING_CONFIG, "the fixture swap did not apply"
    monkeypatch.chdir(tmp_path)
    cfg = _config(tmp_path, ROUTER_PRINTING_CONFIG)
    messages = tmp_path / "messages"
    messages.mkdir()
    (messages / "a.hl7").write_bytes(ADT_A01.encode("utf-8"))
    main(["check", "--config", cfg, "--messages", str(messages), "--no-lint", "--json"])
    captured = capsys.readouterr()
    # More than one load printed, so the later legs' loads are covered, not only the first.
    assert captured.err.count(MARKER) > 1, captured.err
    assert ROUTER_MARKER in captured.err
    assert MARKER not in captured.out and ROUTER_MARKER not in captured.out
    report = json.loads(captured.out)
    dryrun = [c for c in report["checks"] if c["name"] == "dryrun"]
    assert dryrun and not dryrun[0]["skipped"], report


def test_impact_sends_a_config_modules_print_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = _config(tmp_path, PRINTING_CONFIG)
    assert main(["impact", "--config", cfg, "router", "r", "--json"]) == 0
    assert isinstance(_no_print_on_stdout(capsys, MARKER), dict)


def test_cert_inventory_sends_a_config_modules_print_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = _config(tmp_path, PRINTING_CONFIG)
    assert main(["cert", "inventory", "--config", cfg, "--json"]) == 0
    _no_print_on_stdout(capsys, MARKER)


def test_connection_remove_sends_a_config_modules_print_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The edit validates the candidate graph by loading it before it writes."""
    monkeypatch.chdir(tmp_path)
    cfg = _config(tmp_path, PRINTING_CONFIG)
    Path(cfg, "connections.toml").write_text(
        '[[outbound]]\nname = "OB_TEST"\ntransport = "file"\n'
        '  [outbound.settings]\n  directory = "out"\n',
        encoding="utf-8",
    )
    assert main(["connection", "remove", "--config", cfg, "--name", "OB_TEST", "--json"]) == 0
    _no_print_on_stdout(capsys, MARKER)


def test_run_cli_marks_every_subcommand_but_the_named_ones() -> None:
    """The guard: a subcommand is covered unless its name is listed, so a new one is covered."""
    from messagefoundry.cli_common import Dispatch, run_cli

    seen: dict[str, bool] = {}

    def record(args: argparse.Namespace) -> int:
        seen[args.command] = author_output._result_on_stdout
        return 0

    def build() -> tuple[argparse.ArgumentParser, Dispatch]:
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command", required=True)
        sub.add_parser("result")
        sub.add_parser("service")
        return parser, {"result": record, "service": record}

    for command in ("result", "service"):
        assert run_cli([command], build, author_prints_keep_stdout=frozenset({"service"})) == 0
    assert seen == {"result": True, "service": False}
    assert not author_output._result_on_stdout, "the mark outlived the command"


def test_the_engine_cli_leaves_only_serve_and_supervise_on_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Adding a name takes a subcommand out of the default; that is a decision, so it fails here."""
    import messagefoundry.__main__ as cli

    assert frozenset({"serve", "supervise"}) == cli._AUTHOR_PRINTS_KEEP_STDOUT
    passed: dict[str, object] = {}

    def fake_run_cli(*_args: object, **kwargs: object) -> int:
        passed.update(kwargs)
        return 0

    monkeypatch.setattr(cli, "run_cli", fake_run_cli)
    assert cli.main(["validate"]) == 0
    assert passed["author_prints_keep_stdout"] is cli._AUTHOR_PRINTS_KEEP_STDOUT


def test_only_the_seam_redirects_stdout() -> None:
    """One seam: no other engine module points ``sys.stdout`` elsewhere for a block of its own.

    A command that wraps its own load again would pass every other test here, and leave the next
    command's author to remember the wrap. This keeps the redirect in one place."""
    package = Path(messagefoundry.__file__).parent
    hits = []
    for path in sorted(package.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        # The substring screen only skips the parse; the code read below decides.
        if "redirect_stdout" in source and source_uses(source, "redirect_stdout"):
            hits.append(path.relative_to(package).as_posix())
    # Control: the scan reaches the seam's own use, so an empty list elsewhere is not vacuous.
    assert hits == ["author_output.py"], hits


def test_the_loader_and_the_preview_redirect_only_under_the_mark(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``serve`` loads with the mark unset, so its prints stay where they were."""
    from messagefoundry.author_output import stdout_carries_a_result
    from messagefoundry.config.wiring import load_config, validate_config
    from messagefoundry.pipeline.dryrun import dry_run

    cfg = _config(tmp_path, ROUTER_PRINTING_CONFIG)
    reg = load_config(cfg)
    validate_config(cfg)
    dry_run(reg, ADT_A01)
    unmarked = capsys.readouterr()
    assert unmarked.out.count(MARKER) == 2 and ROUTER_MARKER in unmarked.out, unmarked.out
    with stdout_carries_a_result():
        reg = load_config(cfg)
        validate_config(cfg)
        dry_run(reg, ADT_A01)
    marked = capsys.readouterr()
    assert marked.err.count(MARKER) == 2 and ROUTER_MARKER in marked.err, marked.err
    assert MARKER not in marked.out and ROUTER_MARKER not in marked.out
