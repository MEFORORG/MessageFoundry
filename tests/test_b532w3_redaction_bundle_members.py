# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The support-bundle help and ``docs/PHI.md`` stream 14 name every member the bundle writes
(BACKLOG #5385, added item 1).

The member list is derived from the code, not copied: every ``members["<name>"] = ...`` assignment
in :func:`messagefoundry.support.bundle.build_bundle`, read off its AST. A live bundle with a log
tail is the control that the AST reading finds what the function really writes. The help must also
describe ``status.json`` the way the manifest's ``phi_contract`` does, "metadata-only", and must not
call it "PHI-free", which the contract does not claim. Synthetic values only.
"""

from __future__ import annotations

import ast
import inspect
import json
import re
import textwrap
import zipfile
from pathlib import Path

import pytest

from messagefoundry.support import build_bundle
from messagefoundry.support import bundle as bundle_mod

_REPO = Path(__file__).resolve().parents[1]


def _members_written_by_build_bundle() -> set[str]:
    """Every ``members["<literal>"] = ...`` in ``build_bundle``. A store under any other key, or
    any method call on ``members`` such as ``update`` or ``setdefault``, fails here, because this
    reading would not see the member it adds."""
    source = textwrap.dedent(inspect.getsource(bundle_mod.build_bundle))
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "members"
        ):
            raise AssertionError(f"build_bundle calls members.{node.attr}; read its names here")
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Store)
            and isinstance(node.value, ast.Name)
            and node.value.id == "members"
        ):
            key = node.slice
            assert isinstance(key, ast.Constant) and isinstance(key.value, str), ast.dump(key)
            names.add(key.value)
    return names


def _help_text(capsys: pytest.CaptureFixture[str]) -> str:
    # The parser alone, which builds with no side effect, so main()'s process-wide hooks stay out.
    from messagefoundry.__main__ import _build_parser

    parser, _ = _build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["support-bundle", "--help"])
    assert exc.value.code == 0
    # argparse wraps at a hyphen too, so a wrapped name is joined back before matching.
    return re.sub(r"-\s+", "-", " ".join(capsys.readouterr().out.split()))


def _stream_14_row() -> str:
    text = (_REPO / "docs" / "PHI.md").read_text(encoding="utf-8")
    rows = [line for line in text.splitlines() if line.startswith("| **14. ")]
    assert len(rows) == 1, rows
    return rows[0]


def test_the_ast_reading_finds_every_member_a_live_bundle_writes(tmp_path: Path) -> None:
    """Control: with a log tail, the live bundle's member set equals the AST reading, so the
    reading is not a set that only happens to pass the two tests below."""
    from messagefoundry.config.settings import load_settings

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "engine.log").write_text("INFO synthetic line\n", encoding="utf-8")
    toml = tmp_path / "messagefoundry.toml"
    # The store path is pinned under tmp_path, so the status snapshot never opens a store in the
    # working directory.
    store = (tmp_path / "absent.db").as_posix()
    toml.write_text(
        f'[logging]\nlog_dir = "{log_dir.as_posix()}"\n[store]\npath = "{store}"\n',
        encoding="utf-8",
    )
    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=None, settings=load_settings(config_path=toml))
    with zipfile.ZipFile(out) as zf:
        written = set(zf.namelist())
        manifest = json.loads(zf.read("manifest.json"))
    derived = _members_written_by_build_bundle()
    assert written == derived, (written, derived)
    # manifest.json is written after its own listing is taken, so it lists the others only.
    assert set(manifest["members"]) == derived - {"manifest.json"}
    assert {"version.txt", "manifest.json"} <= derived


def test_the_cli_help_names_every_member(capsys: pytest.CaptureFixture[str]) -> None:
    help_text = _help_text(capsys)
    missing = sorted(name for name in _members_written_by_build_bundle() if name not in help_text)
    assert not missing, f"support-bundle --help does not name: {missing}"


def test_phi_md_stream_14_names_every_member() -> None:
    row = _stream_14_row()
    missing = sorted(name for name in _members_written_by_build_bundle() if f"`{name}`" not in row)
    assert not missing, f"docs/PHI.md stream 14 does not name: {missing}"


def test_the_help_describes_status_as_the_phi_contract_does(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "bundle.zip"
    build_bundle(out, config_dir=None, settings=None)
    with zipfile.ZipFile(out) as zf:
        contract = json.loads(zf.read("manifest.json"))["phi_contract"].lower()
    help_text = _help_text(capsys).lower()
    assert "status is the metadata-only status models" in contract
    # Anchored on the member, so "metadata-only" elsewhere on the screen does not pass.
    assert "status.json (the metadata-only status models)" in help_text, help_text
    # The contract makes no PHI-free claim about any member, so the help may not either, except
    # in the "not as secret-free or PHI-free" residual sentence it shares with the contract.
    residual = "not as secret-free or phi-free"
    assert residual in contract and residual in help_text
    assert "phi-free" not in contract.replace(residual, "")
    assert "phi-free" not in help_text.replace(residual, ""), help_text
