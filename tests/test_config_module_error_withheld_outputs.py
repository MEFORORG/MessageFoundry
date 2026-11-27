# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The three other outputs vault BACKLOG #3249 named -- ``graph``, ``dryrun`` and the toolkit's
``impact`` -- print no config module's own exception text to stdout or stderr (vault BACKLOG #3765
item 24).

Each command loads the config through ``load_config``, so the withholding in ``_exec_module`` is
what these pin, through each command's own error print. Every planted string is assembled at run
time, so no committed literal looks like a secret."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry_toolkit.__main__ import main as toolkit_main

NEEDLE = "-".join(["planted", "output", "text", "5c1e"])


def _graph(cfg: Path, tmp: Path) -> int:
    return main(["graph", "--config", str(cfg), "--json"])


def _dryrun(cfg: Path, tmp: Path) -> int:
    message = tmp / "m.hl7"
    message.write_text("MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5.1\r", encoding="utf-8")
    return main(["dryrun", "--config", str(cfg), "--messages", str(message), "--json"])


def _impact(cfg: Path, tmp: Path) -> int:
    return toolkit_main(["impact", "--config", str(cfg), "router", "r", "--json"])


@pytest.mark.parametrize("run", [_graph, _dryrun, _impact], ids=["graph", "dryrun", "impact"])
def test_a_module_exception_text_is_withheld_from_the_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    run: Callable[[Path, Path], int],
) -> None:
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "feed.py").write_text(f"x = 1\nraise ValueError({NEEDLE!r})\n", encoding="utf-8")
    assert run(cfg, tmp_path) != 0
    captured = capsys.readouterr()
    printed = captured.out + captured.err
    assert NEEDLE not in printed
    # A positive control: the output is the loader's diagnostic, not some other refusal.
    assert "feed.py" in printed and "ValueError" in printed and "line 2" in printed
