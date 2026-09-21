# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Wide Corepoint branch lists and clean command-line import failures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.corepoint_import import (
    Control,
    ImportResult,
    _split_branches,
    import_corepoint,
)


def _package(body: str) -> str:
    return f'<Package Name="WIDTH"><ActionList Name="T"><List>{body}</List></ActionList></Package>'


def test_wide_branch_list_imports_every_body_in_order(tmp_path: Path) -> None:
    """Sibling width must not consume parser stack or drop later branch bodies."""
    width = 1500
    branches = "".join(
        f'<Line Data="ElseIf branch_{i:04d}"/><Line Data="Unknown body_{i:04d}"/>'
        for i in range(width)
    )
    export = tmp_path / "wide.xml"
    export.write_text(
        _package(f'<If Data="If opening"><List><Line Data="Unknown lead"/>{branches}</List></If>'),
        encoding="utf-8",
    )
    result = import_corepoint(export, tmp_path / "out")
    assert result.total_mapped == width + 1
    assert result.total_unmapped == width + 1
    source = (tmp_path / "out" / "IB_WIDTH.py").read_text(encoding="utf-8")
    compile(source, "IB_WIDTH.py", "exec")
    positions = [source.index("Unknown lead")]
    for i in range(width):
        positions.extend((source.index(f"branch_{i:04d}"), source.index(f"Unknown body_{i:04d}")))
    assert positions == sorted(positions)


@pytest.mark.parametrize("kind", ["elif", "else", "except", "match"])
def test_split_preserves_empty_branches_and_already_owned_bodies(kind: str) -> None:
    """Only empty markers split the body; a marker with its own body stays intact."""
    lead = Control("block", "Comment", "lead")
    owned = Control(kind, "marker", "owned", body=(lead,))
    first = Control(kind, "marker", "first")
    second = Control(kind, "marker", "second")
    last = Control(kind, "marker", "last")
    body, branches = _split_branches([lead, first, second, owned, last])
    assert body == (lead,)
    assert branches == (
        first,
        Control(kind, "marker", "second", body=(owned,)),
        last,
    )
    assert _split_branches([lead, owned]) == ((lead, owned), ())
    assert _split_branches([]) == ((), ())


@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize("failure", ["directory", "write", "recursion"])
def test_cli_reports_import_failures_on_the_right_stream(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    as_json: bool,
    failure: str,
) -> None:
    """Filesystem and stack failures must return an error, never escape the CLI."""
    export = tmp_path / "export.xml"
    export.write_text(_package('<Line Data="Unknown synthetic"/>'), encoding="utf-8")
    out = tmp_path / "out"
    if failure == "directory":
        out.write_text("existing file", encoding="utf-8")
    elif failure == "write":
        (out / "IB_WIDTH.py").mkdir(parents=True)
    else:
        # Inject this at the importer boundary: sibling width no longer causes recursion,
        # but the command must still report a stack failure from another import stage.
        def fail_import(export_path: str | Path, out_dir: str | Path) -> ImportResult:
            raise RecursionError("synthetic recursion failure")

        monkeypatch.setattr("messagefoundry.corepoint_import.import_corepoint", fail_import)

    args = ["import", "corepoint", str(export), "--out", str(out)]
    if as_json:
        args.append("--json")
    assert main(args) == 1
    captured = capsys.readouterr()
    if as_json:
        payload = json.loads(captured.out)
        assert set(payload) == {"error"}
        assert captured.err == ""
        error = payload["error"]
    else:
        assert captured.out == ""
        assert captured.err.startswith("error: ")
        error = captured.err
    assert "Traceback" not in error
    if failure == "recursion":
        assert "synthetic recursion failure" in error
    else:
        failed_path = out / "IB_WIDTH.py" if failure == "write" else out
        assert repr(str(failed_path)) in error
