# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Corepoint import: it never overwrites a module on disk (vault BACKLOG #2786), and a generated
handler ``def`` never shadows a name the module imports (vault BACKLOG #2788). Synthetic data only."""

from __future__ import annotations

import ast
import json
import os
import sys
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.corepoint_import import (
    CorepointImportError,
    generate_module,
    import_corepoint,
    parse_export,
    parse_package,
)
from messagefoundry.parsing.message import Message

_HAND_FINISHED = "# hand-finished by an operator\n"


def _export(tmp_path: Path) -> Path:
    """A two-channel export, so a refusal can be shown to write NEITHER module."""
    channels = [
        {
            "name": name,
            "inbound": {"connector": "mllp", "port": port},
            "destinations": [{"name": f"OB_{name}", "connector": "mllp", "host": "h", "port": 1}],
            "handlers": [
                {
                    "name": "h",
                    "actions": [{"class": "ItemReplace", "target": "MSH-6", "value": "X"}],
                }
            ],
        }
        for name, port in (("ALPHA", 2620), ("BETA", 2621))
    ]
    path = tmp_path / "export.json"
    path.write_text(json.dumps({"channels": channels}), encoding="utf-8")
    return path


# --- #2786: an existing module is refused, never overwritten -----------------


def test_a_second_import_into_the_same_directory_is_refused(tmp_path: Path) -> None:
    export, out = _export(tmp_path), tmp_path / "out"
    import_corepoint(export, out)
    finished = out / "IB_ALPHA.py"
    finished.write_text(_HAND_FINISHED, encoding="utf-8")

    with pytest.raises(CorepointImportError) as caught:
        import_corepoint(export, out)

    message = str(caught.value)
    assert "refusing to overwrite 2 existing module(s)" in message
    assert "IB_ALPHA.py, IB_BETA.py" in message  # every file it would have replaced, named
    assert "--force" in message
    assert finished.read_text(encoding="utf-8") == _HAND_FINISHED  # the hand edit survives


def test_one_existing_module_refuses_the_whole_import(tmp_path: Path) -> None:
    """Nothing is written at all, not even the module that did not exist yet."""
    out = tmp_path / "out"
    out.mkdir()
    (out / "IB_BETA.py").write_text(_HAND_FINISHED, encoding="utf-8")

    with pytest.raises(CorepointImportError, match=r"1 existing module\(s\).*: IB_BETA\.py;"):
        import_corepoint(_export(tmp_path), out)

    assert sorted(p.name for p in out.iterdir()) == ["IB_BETA.py"]
    assert (out / "IB_BETA.py").read_text(encoding="utf-8") == _HAND_FINISHED


def test_force_replaces_the_existing_modules(tmp_path: Path) -> None:
    export, out = _export(tmp_path), tmp_path / "out"
    import_corepoint(export, out)
    (out / "IB_ALPHA.py").write_text(_HAND_FINISHED, encoding="utf-8")

    result = import_corepoint(export, out, force=True)

    assert (out / "IB_ALPHA.py").read_text(encoding="utf-8") == result.channels[0].source


def test_an_unrelated_module_in_the_directory_is_left_alone(tmp_path: Path) -> None:
    """The control: only a name this import writes is refused."""
    out = tmp_path / "out"
    out.mkdir()
    (out / "IB_OTHER.py").write_text(_HAND_FINISHED, encoding="utf-8")

    import_corepoint(_export(tmp_path), out)

    assert sorted(p.name for p in out.iterdir()) == ["IB_ALPHA.py", "IB_BETA.py", "IB_OTHER.py"]


@pytest.mark.skipif(sys.platform == "win32", reason="creating a symlink needs a privilege there")
def test_a_dangling_symlink_counts_as_an_existing_module(tmp_path: Path) -> None:
    """``Path.exists`` reads a dangling link as absent; following it would write through the link."""
    out = tmp_path / "out"
    out.mkdir()
    (out / "IB_ALPHA.py").symlink_to(tmp_path / "elsewhere.py")

    with pytest.raises(CorepointImportError, match=r"IB_ALPHA\.py"):
        import_corepoint(_export(tmp_path), out)

    assert not (tmp_path / "elsewhere.py").exists()


def test_a_module_that_appears_after_the_check_is_still_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exclusive create holds where the up-front check is raced: blind the check, plant a file."""
    out = tmp_path / "out"
    out.mkdir()
    (out / "IB_BETA.py").write_text(_HAND_FINISHED, encoding="utf-8")
    monkeypatch.setattr(os, "listdir", lambda _p: [])

    with pytest.raises(CorepointImportError, match=r"IB_BETA\.py .*appeared during the import"):
        import_corepoint(_export(tmp_path), out)

    assert (out / "IB_BETA.py").read_text(encoding="utf-8") == _HAND_FINISHED
    # IB_ALPHA.py was written before the race was seen; it is removed, so a re-run is not refused
    # over a module the failed run itself created.
    assert sorted(p.name for p in out.iterdir()) == ["IB_BETA.py"]


@pytest.mark.skipif(sys.platform == "win32", reason="creating a symlink needs a privilege there")
def test_force_replaces_a_symlink_rather_than_writing_through_it(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text(_HAND_FINISHED, encoding="utf-8")
    (out / "IB_ALPHA.py").symlink_to(outside)

    import_corepoint(_export(tmp_path), out, force=True)

    assert outside.read_text(encoding="utf-8") == _HAND_FINISHED  # the link's target is untouched
    assert not (out / "IB_ALPHA.py").is_symlink()


def test_a_force_import_that_fails_while_staging_changes_nothing(tmp_path: Path) -> None:
    """Every module is staged before any is replaced, so a failed stage leaves the old modules."""
    export, out = _export(tmp_path), tmp_path / "out"
    import_corepoint(export, out)
    (out / "IB_ALPHA.py").write_text(_HAND_FINISHED, encoding="utf-8")
    # Occupy IB_BETA's staging name, so staging the second module fails after the first is staged.
    # A regular FILE, never a directory: an exclusive create over an existing directory is EEXIST
    # on POSIX but ERROR_ACCESS_DENIED (PermissionError) on Windows, while over an existing file it
    # is FileExistsError on both.
    occupied = out / f".IB_BETA.py.{os.getpid()}.tmp"
    occupied.write_text("occupied", encoding="utf-8")

    with pytest.raises(FileExistsError):
        import_corepoint(export, out, force=True)

    assert occupied.read_text(encoding="utf-8") == "occupied"  # not ours, so never discarded
    assert (out / "IB_ALPHA.py").read_text(encoding="utf-8") == _HAND_FINISHED
    assert sorted(p.name for p in out.iterdir()) == [
        f".IB_BETA.py.{os.getpid()}.tmp",  # the planted one; IB_ALPHA's staged copy is gone
        "IB_ALPHA.py",
        "IB_BETA.py",
    ]


def test_an_existing_module_differing_only_in_case_is_refused(tmp_path: Path) -> None:
    """On NTFS ``IB_alpha.py`` IS ``IB_ALPHA.py``, so it is refused on a case-sensitive host too."""
    out = tmp_path / "out"
    out.mkdir()
    (out / "IB_alpha.py").write_text(_HAND_FINISHED, encoding="utf-8")

    with pytest.raises(CorepointImportError, match=r"1 existing module\(s\).*: IB_alpha\.py;"):
        import_corepoint(_export(tmp_path), out)


def test_stems_that_differ_only_in_case_are_kept_apart(tmp_path: Path) -> None:
    """On NTFS, the deployment target, ``IB_Acme.py`` and ``IB_ACME.py`` are one file, so the second
    is renamed like any other collision instead of overwriting or refusing against the first."""
    channels = [
        {
            "name": f"C{i}",
            "inbound": {"connector": "mllp", "port": 2620 + i, "name": inbound},
            "destinations": [{"name": f"OB_C{i}", "connector": "mllp", "host": "h", "port": 1}],
            "handlers": [{"name": f"h{i}", "actions": []}],
        }
        for i, inbound in enumerate(("IB_Acme", "IB_ACME"))
    ]
    export = tmp_path / "export.json"
    export.write_text(json.dumps({"channels": channels}), encoding="utf-8")

    result = import_corepoint(export, tmp_path / "out")

    assert [c.filename for c in result.channels] == ["IB_Acme.py", "IB_ACME_2.py"]
    assert result.channels[1].renamed_from == "IB_ACME"


def test_the_cli_refuses_without_force_and_replaces_with_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    export, out = str(_export(tmp_path)), str(tmp_path / "out")
    assert main(["import", "corepoint", export, "--out", out]) == 0
    Path(out, "IB_ALPHA.py").write_text(_HAND_FINISHED, encoding="utf-8")
    capsys.readouterr()

    assert main(["import", "corepoint", export, "--out", out]) == 1
    captured = capsys.readouterr()
    assert captured.err.startswith("error: refusing to overwrite 2 existing module(s)")
    assert "IB_ALPHA.py" in captured.err
    assert Path(out, "IB_ALPHA.py").read_text(encoding="utf-8") == _HAND_FINISHED

    assert main(["import", "corepoint", export, "--out", out, "--force"]) == 0
    assert Path(out, "IB_ALPHA.py").read_text(encoding="utf-8") != _HAND_FINISHED


# --- #2788: a handler def never shadows a name the module imports --------------


def _defs_and_imports(source: str) -> tuple[list[str], set[str]]:
    tree = ast.parse(source)
    defs = [n.name for n in tree.body if isinstance(n, ast.FunctionDef)]
    imported = {
        alias.asname or alias.name
        for n in tree.body
        if isinstance(n, ast.ImportFrom)
        for alias in n.names
    }
    return defs, imported


_SEND = '<Line Data="MsgSend $out [OB_ACME]"/>'
_STAMP = '<Line Data="ItemCopy &quot;X&quot; %ADT/MSH-5"/>'


def _shadowing_package() -> str:
    """Lists named after a vocabulary helper the module imports, the decorators, and the router."""
    lists = "".join(
        f'<ActionList Name="{name}"><List>{_STAMP}{_SEND}</List></ActionList>'
        for name in ("Set_Field", "Handler", "Router", "Route", "Stamp", "Set_Field")
    )
    return f'<Package Name="ACME X">{lists}</Package>'


def test_an_xml_list_name_never_shadows_an_imported_name() -> None:
    channel = parse_package(_shadowing_package())[0]
    assert [h.name for h in channel.handlers] == [
        "set_field_2",
        "handler_2",
        "router_2",
        "route_2",
        "stamp",
        "set_field_3",  # deterministic: the in-run duplicate takes the next free suffix
    ]
    defs, imported = _defs_and_imports(generate_module(channel))
    assert "set_field" in imported and "handler" in imported  # the names the bug would replace
    assert not set(defs) & imported
    assert len(defs) == len(set(defs))  # one def per name, `route` included


def test_a_json_handler_name_never_shadows_an_imported_name() -> None:
    """The JSON path ran no de-duplication at all, and keeps case, so it could emit ``def Send``."""
    export = {
        "channels": [
            {
                "name": "ACME",
                "inbound": {"connector": "mllp", "port": 2620},
                "destinations": [{"name": "OB_A", "connector": "mllp", "host": "h", "port": 1}],
                "handlers": [
                    {
                        "name": name,
                        "actions": [{"class": "ItemReplace", "target": "MSH-6", "value": "X"}],
                    }
                    for name in ("Send", "set_field", "set_field", "MLLP", "NotImplementedError")
                ],
            }
        ]
    }
    channel = parse_export(json.dumps(export))[0]
    assert [h.name for h in channel.handlers] == [
        "Send_2",
        "set_field_2",
        "set_field_3",
        "MLLP_2",
        "NotImplementedError_2",
    ]
    defs, imported = _defs_and_imports(generate_module(channel))
    assert {"Send", "set_field", "MLLP"} <= imported
    assert not set(defs) & imported


_FULLWIDTH_SET_FIELD = "\uff53\uff45\uff54_\uff46\uff49\uff45\uff4c\uff44"
_FULLWIDTH_HANDLER = "\uff48\uff41\uff4e\uff44\uff4c\uff45\uff52"


def test_a_fullwidth_name_is_compared_as_python_will_bind_it() -> None:
    """CPython NFKC-normalizes identifiers, so a fullwidth ``def set_field`` binds ``set_field``.

    The XML path lower-cases after the fold, so a letter that folds to upper case (U+210C, which
    folds to ``H``) still yields a lower-case id."""
    lists = "".join(
        f'<ActionList Name="{name}"><List>{_STAMP}</List></ActionList>'
        for name in (_FULLWIDTH_SET_FIELD, _FULLWIDTH_HANDLER, "\u210candle")
    )
    channel = parse_package(f'<Package Name="ACME X">{lists}</Package>')[0]
    assert [h.name for h in channel.handlers] == ["set_field_2", "handler_2", "handle"]


def test_a_plain_list_name_is_not_renamed() -> None:
    """The control: a name the module does not bind is kept as it is."""
    channel = parse_package(
        f'<Package Name="ACME X"><ActionList Name="Stamp"><List>{_STAMP}</List></ActionList></Package>'
    )[0]
    assert [h.name for h in channel.handlers] == ["stamp"]


def test_the_other_handlers_still_reach_the_vocabulary_at_run_time(tmp_path: Path) -> None:
    """The silent failure the finding names: with ``def set_field`` in the module, every OTHER
    handler's ``set_field(msg, ...)`` called the handler and raised ``TypeError`` on every message."""
    from messagefoundry.config.wiring import load_config

    export = tmp_path / "pkg.xml"
    export.write_text(_shadowing_package(), encoding="utf-8")
    out = tmp_path / "out"
    import_corepoint(export, out)
    registry = load_config(out)

    msg = Message.parse("MSH|^~\\&|A|B|C|D|20260930||ADT^A01|1|P|2.5\rPID|1||123")
    sends = registry.handlers["stamp"](msg)
    assert isinstance(sends, list) and len(sends) == 1
    assert msg.field("MSH-5") == "X"
