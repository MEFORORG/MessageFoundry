# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Deterministic Corepoint action-list import (ADR 0086) — mapping, count-and-log, check gate, security.

The lens round-trip half of the correctness gate (AC-4) lives in ``tests/test_lens_parse.py`` beside
the other lens property tests; here we cover the mapping fidelity, the never-drop count-and-log ethos,
the ``messagefoundry check`` structural gate on emitted modules, and the untrusted-input handling."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.checks import run_checks
from messagefoundry.corepoint_import import (
    Action,
    CorepointImportError,
    UnmappedAction,
    generate_module,
    import_corepoint,
    parse_export,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "corepoint"


def _acme_export() -> str:
    return (FIXTURES / "acme_adt.json").read_text(encoding="utf-8")


# --- mapping fidelity (AC-1) -------------------------------------------------


def test_maps_every_vocabulary_class() -> None:
    """Each mapped Corepoint action class emits its inverse ADR 0076 §2 vocabulary call (AC-1)."""
    channels = parse_export(_acme_export())
    assert len(channels) == 1
    handler = channels[0].handlers[0]
    mapped = [s for s in handler.steps if isinstance(s, Action)]
    by_class = {s.source_class: s.vocabulary for s in mapped}
    assert by_class == {
        "ItemCopy": "copy_field",
        "ItemReplace": "set_field",
        "ItemAppend": "append_to_field",
        "ItemFormatDate": "format_date",
        "ItemConvert": "convert_case",
        "ItemCodeLookup": "code_lookup",
        "ItemSplit": "split_field",
        "SegmentCopy": "copy_segment",
        "SegmentDelete": "delete_segment",
    }
    src = generate_module(channels[0])
    # The exported field paths ride through as literal arguments.
    assert 'copy_field(msg, "PID-5.1", "NK1-2.1")' in src
    assert 'set_field(msg, "MSH-6", "ACME")' in src
    assert 'code_lookup(msg, "PID-8", {"M": "male", "F": "female"}, default="unknown")' in src
    assert 'split_field(msg, "PID-5", "^", ["PID-5.1", "PID-5.2"])' in src
    assert 'return Send("OB_ACME_ADT", msg)' in src


def test_format_date_carries_optional_input_format() -> None:
    export = json.dumps(
        {
            "channels": [
                {
                    "name": "X",
                    "inbound": {"connector": "mllp", "port": 2610},
                    "destinations": [{"name": "OB_X", "connector": "mllp", "host": "h", "port": 7}],
                    "handlers": [
                        {
                            "name": "h",
                            "actions": [
                                {
                                    "class": "ItemFormatDate",
                                    "target": "PID-7",
                                    "outputFormat": "%Y%m%d",
                                    "inputFormat": "%m/%d/%Y",
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    )
    src = generate_module(parse_export(export)[0])
    assert 'format_date(msg, "PID-7", "%Y%m%d", in_fmt="%m/%d/%Y")' in src


def test_multiple_destinations_emit_list_of_sends() -> None:
    export = json.dumps(
        {
            "channels": [
                {
                    "name": "X",
                    "inbound": {"connector": "mllp", "port": 2611},
                    "destinations": [
                        {"name": "OB_A", "connector": "mllp", "host": "a", "port": 1},
                        {"name": "OB_B", "connector": "file", "directory": "./out"},
                    ],
                    "handlers": [{"name": "h", "actions": []}],
                }
            ]
        }
    )
    src = generate_module(parse_export(export)[0])
    assert 'return [Send("OB_A", msg), Send("OB_B", msg)]' in src
    # File outbound connector is imported and rendered.
    assert 'outbound("OB_B", File(directory="./out"))' in src
    assert "from messagefoundry import File, MLLP, Send" in src


# --- count-and-log: unmapped is stubbed, never dropped (AC-2) ----------------


def test_unmapped_action_is_stubbed_not_dropped() -> None:
    """An unmapped class becomes an in-place TODO + best-effort stub and is counted (AC-2)."""
    channels = parse_export(_acme_export())
    steps = channels[0].handlers[0].steps
    unmapped = [s for s in steps if isinstance(s, UnmappedAction)]
    assert [u.source_class for u in unmapped] == ["ItemCustomScript"]
    assert unmapped[0].stub_path == "OBX-5"

    src = generate_module(channels[0])
    assert "# TODO: Corepoint ItemCustomScript — hand-finish" in src
    assert 'msg.set("OBX-5", msg.field("OBX-5") or "")' in src


def test_import_summary_counts_mapped_and_unmapped(tmp_path: Path) -> None:
    result = import_corepoint(FIXTURES / "acme_adt.json", tmp_path)
    assert result.total_mapped == 9
    assert result.total_unmapped == 1
    assert result.channels[0].unmapped_classes == ("ItemCustomScript",)
    summary = result.to_json()
    assert summary["total_mapped"] == 9
    assert summary["total_unmapped"] == 1
    # The module file was actually written.
    assert (tmp_path / "IB_ACME_ADT.py").is_file()


def test_unmapped_without_target_emits_marker_only() -> None:
    export = json.dumps(
        {
            "channels": [
                {
                    "name": "X",
                    "inbound": {"connector": "mllp", "port": 2612},
                    "destinations": [{"name": "OB_X", "connector": "mllp", "host": "h", "port": 7}],
                    "handlers": [{"name": "h", "actions": [{"class": "ItemMysteryOp"}]}],
                }
            ]
        }
    )
    channels = parse_export(export)
    step = channels[0].handlers[0].steps[0]
    assert isinstance(step, UnmappedAction)
    assert step.stub_path is None
    src = generate_module(channels[0])
    assert "# TODO: Corepoint ItemMysteryOp — hand-finish" in src
    # No stub line when no target field is recoverable, but the marker records it (never dropped).
    assert "msg.set(" not in src


def test_colliding_module_names_are_deduped_not_overwritten(tmp_path: Path) -> None:
    """Two channels resolving to the same module_name each get their own file — never silently lost.

    ``_sanitize`` folds "DUP ADT" and "DUP-ADT" onto the same stem, so both channels would otherwise
    write ``IB_DUP_ADT.py`` and the first would be clobbered by the second. The importer must suffix the
    collision (count-and-log ethos) and surface the rename."""
    export = json.dumps(
        {
            "channels": [
                {
                    "name": "DUP ADT",
                    "inbound": {"connector": "mllp", "port": 2620},
                    "destinations": [{"name": "OB_1", "connector": "mllp", "host": "a", "port": 1}],
                    "handlers": [
                        {
                            "name": "h",
                            "actions": [
                                {"class": "ItemReplace", "target": "MSH-6", "value": "FIRST"}
                            ],
                        }
                    ],
                },
                {
                    "name": "DUP-ADT",
                    "inbound": {"connector": "mllp", "port": 2621},
                    "destinations": [{"name": "OB_2", "connector": "mllp", "host": "b", "port": 2}],
                    "handlers": [
                        {
                            "name": "h",
                            "actions": [
                                {"class": "ItemReplace", "target": "MSH-6", "value": "SECOND"}
                            ],
                        }
                    ],
                },
            ]
        }
    )
    src_path = tmp_path / "export.json"
    src_path.write_text(export, encoding="utf-8")
    result = import_corepoint(src_path, tmp_path / "out")

    assert len(result.channels) == 2
    filenames = [c.filename for c in result.channels]
    assert filenames == ["IB_DUP_ADT.py", "IB_DUP_ADT_2.py"]
    # Both files exist on disk and each carries its own channel's distinct value — nothing overwritten.
    first = (tmp_path / "out" / "IB_DUP_ADT.py").read_text(encoding="utf-8")
    second = (tmp_path / "out" / "IB_DUP_ADT_2.py").read_text(encoding="utf-8")
    assert '"FIRST"' in first and '"SECOND"' not in first
    assert '"SECOND"' in second and '"FIRST"' not in second
    # The de-duplicated channel's inbound connection name matches its new stem (no registry collision).
    assert 'inbound("IB_DUP_ADT_2"' in second
    # The rename is surfaced, not silent.
    assert result.channels[0].renamed_from is None
    assert result.channels[1].renamed_from == "IB_DUP_ADT"
    assert result.to_json()["channels"][1]["renamed_from"] == "IB_DUP_ADT"


# --- the check gate on emitted modules (AC-3) --------------------------------


def test_generated_module_passes_check(tmp_path: Path) -> None:
    """Emitted modules pass ``messagefoundry check`` (the required validate leg) (AC-3)."""
    import_corepoint(FIXTURES / "acme_adt.json", tmp_path)
    report = run_checks(tmp_path, run_lint=False)
    validate = next(r for r in report.results if r.name == "validate")
    assert validate.ok, validate.detail
    assert report.ok


def test_generated_module_imports_and_wires(tmp_path: Path) -> None:
    """The emitted module loads through the real wiring loader (inbound/router/handler/outbound wired)."""
    from messagefoundry.config.wiring import load_config

    import_corepoint(FIXTURES / "acme_adt.json", tmp_path)
    registry = load_config(tmp_path)
    assert "IB_ACME_ADT" in registry.inbound
    assert "OB_ACME_ADT" in registry.outbound


# --- untrusted input (AC-5) --------------------------------------------------


def test_hostile_values_are_escaped_not_injected() -> None:
    """A value carrying quotes/newlines/backslashes rides across as an inert literal (no code injection)."""
    hostile = 'x") ; import os ; os.system("echo pwned'
    export = json.dumps(
        {
            "channels": [
                {
                    "name": "X",
                    "inbound": {"connector": "mllp", "port": 2613},
                    "destinations": [{"name": "OB_X", "connector": "mllp", "host": "h", "port": 7}],
                    "handlers": [
                        {
                            "name": "h",
                            "actions": [
                                {"class": "ItemReplace", "target": "MSH-6", "value": hostile}
                            ],
                        }
                    ],
                }
            ]
        }
    )
    src = generate_module(parse_export(export)[0])
    # The dangerous payload appears only inside a single escaped string literal — the injected
    # ``import os`` / ``os.system`` never becomes a top-level statement.
    assert json.dumps(hostile) in src
    assert "\nimport os" not in src
    assert "os.system(" not in src.replace(json.dumps(hostile), "")
    # And the generated source still parses as a single, well-formed module (no literal breakout).
    import ast

    ast.parse(src)


def test_malformed_export_raises() -> None:
    with pytest.raises(CorepointImportError):
        parse_export("{ not json ")
    with pytest.raises(CorepointImportError):
        parse_export(json.dumps({"channels": []}))  # empty
    with pytest.raises(CorepointImportError):
        parse_export(json.dumps({"channels": [{"name": "X"}]}))  # no inbound
    with pytest.raises(CorepointImportError):
        # ItemCopy missing its required 'destination'
        parse_export(
            json.dumps(
                {
                    "channels": [
                        {
                            "name": "X",
                            "inbound": {"connector": "mllp", "port": 2614},
                            "destinations": [],
                            "handlers": [
                                {"name": "h", "actions": [{"class": "ItemCopy", "source": "PID-5"}]}
                            ],
                        }
                    ]
                }
            )
        )


def test_import_corepoint_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(CorepointImportError):
        import_corepoint(tmp_path / "nope.json", tmp_path / "out")
