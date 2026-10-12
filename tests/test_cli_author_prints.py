# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A print() in an author's config module never lands on a ``--json`` command's stdout.

``validate``, ``graph`` and ``dryrun`` import config modules in the CLI's own process. A debugging
``print()`` at the top of one used to write to stdout ahead of the JSON, so the document did not
parse. ``dryrun`` was fixed first (vault BACKLOG #1187) and its Handler arm is pinned in
``tests/test_cli.py``. This file pins the config-import arm for all three (vault BACKLOG #2727).

Two loads are covered, because a command can import the config twice. Under an explicit
``--project-root`` with ``--env``, the anchor helper loads the graph first to ask whether it
references ``env()``, and the command then loads it again.

Synthetic data only: the marker below is not message data.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main

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
#: as an ``{{"error"}}`` body, so the error documents are covered as well as the success ones.
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


def _stdout_json(capsys: pytest.CaptureFixture[str]) -> object:
    """Stdout parsed as one JSON document, after checking the print ran and went to stderr."""
    captured = capsys.readouterr()
    # Control: the print ran, so its absence from stdout below is not vacuous.
    assert MARKER in captured.err, "the config module's print did not run"
    assert MARKER not in captured.out
    return json.loads(captured.out)


@pytest.mark.parametrize("anchored", [False, True])
def test_validate_sends_a_config_modules_print_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], anchored: bool
) -> None:
    cfg = _config(tmp_path, PRINTING_CONFIG)
    extra = _anchored(tmp_path) if anchored else []
    assert main(["validate", "--config", cfg, "--json", *extra]) == 0
    assert _stdout_json(capsys) == []


@pytest.mark.parametrize("anchored", [False, True])
def test_validate_reports_a_failing_module_as_json_despite_its_print(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], anchored: bool
) -> None:
    cfg = _config(tmp_path, RAISING_CONFIG)
    extra = _anchored(tmp_path) if anchored else []
    assert main(["validate", "--config", cfg, "--json", *extra]) == 1
    diags = _stdout_json(capsys)
    assert isinstance(diags, list) and diags, diags
    assert any(str(d["file"]).endswith("IB_TEST.py") for d in diags), diags


@pytest.mark.parametrize("anchored", [False, True])
@pytest.mark.parametrize("compact", [["--json"], []])
def test_graph_sends_a_config_modules_print_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], anchored: bool, compact: list[str]
) -> None:
    """``graph`` prints JSON with and without ``--json``; the flag only makes it compact."""
    cfg = _config(tmp_path, PRINTING_CONFIG)
    extra = _anchored(tmp_path) if anchored else []
    assert main(["graph", "--config", cfg, *compact, *extra]) == 0
    graph = _stdout_json(capsys)
    assert isinstance(graph, dict)
    assert [c["name"] for c in graph["inbound"]] == ["IB_TEST"]


def test_graph_reports_a_failing_module_as_json_despite_its_print(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = _config(tmp_path, RAISING_CONFIG)
    assert main(["graph", "--config", cfg, "--json"]) != 0
    body = _stdout_json(capsys)
    assert isinstance(body, dict) and set(body) == {"error"}, body


def test_dryrun_under_a_project_root_sends_a_config_modules_print_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The anchor helper's own load of the graph runs before ``dryrun`` redirects anything."""
    cfg = _config(tmp_path, PRINTING_CONFIG)
    message = tmp_path / "a.hl7"
    message.write_bytes(ADT_A01.encode("utf-8"))
    rc = main(
        ["dryrun", "--config", cfg, "--messages", str(message), "--json", *_anchored(tmp_path)]
    )
    assert rc == 0
    results = _stdout_json(capsys)
    assert isinstance(results, list) and len(results) == 1
