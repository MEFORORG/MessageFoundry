# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Deterministic Corepoint action-list import (ADR 0086) — mapping, count-and-log, check gate, security.

The lens round-trip half of the correctness gate (AC-4) lives in ``tests/test_lens_parse.py`` beside
the other lens property tests; here we cover the mapping fidelity, the never-drop count-and-log ethos,
the ``messagefoundry check`` structural gate on emitted modules, and the untrusted-input handling."""

from __future__ import annotations

import ast
import html
import json
import re
from dataclasses import replace
from pathlib import Path

import pytest

from messagefoundry.checks import run_checks
from messagefoundry.corepoint_import import (
    Action,
    Control,
    CorepointImportError,
    Step,
    UnmappedAction,
    _corepoint_path,
    _corepoint_segment,
    _count_steps,
    _Deferred,
    _operands_from_roles,
    _role_prose,
    _role_verb,
    generate_module,
    import_corepoint,
    parse_any,
    parse_export,
    parse_package,
    parse_roles,
    strip_markup,
    tokenize_statement,
)
from messagefoundry.parsing.message import Message

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "corepoint"


def _acme_export() -> str:
    return (FIXTURES / "acme_adt.json").read_text(encoding="utf-8")


def _acme_package() -> str:
    return (FIXTURES / "acme_adt_package.xml").read_text(encoding="utf-8")


def _package_source() -> str:
    """The generated module for the synthetic ``<Package>`` XML fixture."""
    return generate_module(parse_package(_acme_package(), source_name="acme_adt_package")[0])


def _one_action_export(
    action: dict[str, object], *, inbound_name: str | None = None, port: int = 2610
) -> str:
    """A minimal one-channel JSON export carrying exactly ``action`` — the untrusted value under test.

    One builder for the whole file. A test that needs a hostile *inbound name* rather than a hostile
    action passes ``inbound_name``; everything else varies only in ``action``."""
    inbound: dict[str, object] = {"connector": "mllp", "port": port}
    if inbound_name is not None:
        inbound["name"] = inbound_name
    return json.dumps(
        {
            "channels": [
                {
                    "name": "X",
                    "inbound": inbound,
                    "destinations": [{"name": "OB_X", "connector": "mllp", "host": "h", "port": 7}],
                    "handlers": [{"name": "h", "actions": [action]}],
                }
            ]
        }
    )


def _assert_no_live_stub(source: str) -> None:
    """The unmapped-action rule, asserted in ONE place: a TODO marker emits no live code (#1681).

    ``msg.field(`` is the stronger half. It pins the withdrawn stub's READ, which no marker or hint
    text has any reason to mention, so it still fails on a passthrough rewritten to write through
    something other than ``Message.set`` — which is exactly the shape a partial revert would take."""
    assert "msg.field(" not in source
    assert "msg.set(" not in source


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


# --- count-and-log: unmapped is marked, never dropped and never live (AC-2) --


def test_unmapped_action_is_marked_not_dropped() -> None:
    """An unmapped class becomes an in-place TODO marker, emits NO live code, and is counted (AC-2).

    The JSON layer used to emit ``msg.set(p, msg.field(p) or "")`` here. That line was never the inert
    passthrough its comment claimed — ``Message.set`` raises ``KeyError`` on an absent segment and
    materialises the field and its empty components on a present one — so the recovered target now
    rides into the marker text, exactly as the validated role-parsed path already did."""
    channels = parse_export(_acme_export())
    steps = channels[0].handlers[0].steps
    unmapped = [s for s in steps if isinstance(s, UnmappedAction)]
    assert [u.source_class for u in unmapped] == ["ItemCustomScript"]
    assert "intended target OBX-5" in unmapped[0].detail

    src = generate_module(channels[0])
    assert "# TODO: Corepoint ItemCustomScript — hand-finish" in src
    assert "intended target OBX-5" in src
    _assert_no_live_stub(src)


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
    channels = parse_export(_one_action_export({"class": "ItemMysteryOp"}, port=2612))
    step = channels[0].handlers[0].steps[0]
    assert isinstance(step, UnmappedAction)
    # Nothing to recover, so the marker names no target — and there is no stub field to hold one.
    assert "intended target" not in step.detail
    src = generate_module(channels[0])
    assert "# TODO: Corepoint ItemMysteryOp — hand-finish" in src
    # The marker records it (never dropped) and emits no live code either way.
    _assert_no_live_stub(src)


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
    export = _one_action_export(
        {"class": "ItemReplace", "target": "MSH-6", "value": hostile}, port=2613
    )
    src = generate_module(parse_export(export)[0])
    # The dangerous payload appears only inside a single escaped string literal — the injected
    # ``import os`` / ``os.system`` never becomes a top-level statement.
    assert json.dumps(hostile) in src
    assert "\nimport os" not in src
    assert "os.system(" not in src.replace(json.dumps(hostile), "")
    # And the generated source still parses as a single, well-formed module (no literal breakout).
    ast.parse(src)


def test_an_unmapped_actions_recovered_target_cannot_escape_its_comment() -> None:
    """The recovered target rides into a ``#`` comment, so it needs the comment-side escape.

    #1681 moved this value out of a ``_lit``-rendered ``msg.set`` line and into the marker text. A
    ``_lit`` literal contains a newline by escaping it; a comment does not — the line simply ends and
    whatever follows is a statement. So the move is only safe because the renderer flattens both the
    action class and the marker text through ``_comment_text``. Without that, this export injects a
    top-level ``import os`` into a module that still compiles."""
    payload = 'MSH-6\nimport os\nos.system("echo pwned")'
    export = _one_action_export({"class": "ItemMystery", "target": payload})
    src = generate_module(parse_export(export)[0])
    # The payload stays VISIBLE (count-and-log) — so "it is gone" is not the property to assert. The
    # property is that every line carrying it is a comment, and that nothing it named is a statement.
    tainted = [ln for ln in src.splitlines() if "import os" in ln or "os.system(" in ln]
    assert tainted, "the payload vanished — an unmapped action must stay visible to the migrator"
    assert all(ln.lstrip().startswith("#") for ln in tainted)
    imported = {
        alias.name
        for node in ast.walk(ast.parse(src))
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert "os" not in imported
    assert "# TODO: Corepoint ItemMystery — hand-finish" in src
    # The value is not dropped either — it is still visible to the migrator, flattened onto one line.
    assert 'intended target MSH-6 import os os.system("echo pwned")' in src
    ast.parse(src)


def test_a_nul_in_an_action_class_cannot_make_the_module_uncompilable() -> None:
    """Python refuses to compile a source string containing NUL, so the comment path must strip it."""
    src = generate_module(parse_export(_one_action_export({"class": "Item\x00Script"}))[0])
    assert "\x00" not in src
    assert "# TODO: Corepoint ItemScript — hand-finish" in src
    compile(src, "generated.py", "exec")  # the shape that used to raise ValueError


@pytest.mark.parametrize(
    ("action", "needle", "position"),
    [
        # The table's OWN values are rendered by _lit too, and ``null`` is a NameError at import. The
        # message must say WHICH entry, or a 200-code lookup table sends the migrator hunting.
        ({"class": "ItemCodeLookup", "target": "PID-8", "table": {"M": None}}, "null", "['M']"),
        # So is an explicit JSON ``null`` default — a top-level value, so there is no position to name.
        (
            {"class": "ItemCodeLookup", "target": "PID-8", "table": {"M": "male"}, "default": None},
            "null",
            "",
        ),
        # ``true``/``false`` are names to Python as well.
        ({"class": "ItemCodeLookup", "target": "PID-8", "table": {"M": True}}, "true", "['M']"),
    ],
)
def test_a_json_scalar_python_cannot_read_is_refused_not_rendered(
    action: dict[str, object], needle: str, position: str
) -> None:
    """``{"table": {"M": null}}`` rendered ``{"M": null}`` — a ``NameError`` the moment it imports.

    Refused at render time instead, because a module that cannot be imported is a worse outcome than a
    named error on the export. The refusal is deliberately NOT "no non-string scalars": the ``table``
    dict and an ``ItemSplit`` ``destinations`` list are legitimate input, and
    ``test_a_nested_container_of_strings_still_renders`` pins that they keep working."""
    with pytest.raises(CorepointImportError) as excinfo:
        parse_export(_one_action_export(action))
    message = str(excinfo.value)
    assert needle in message
    # The position is what distinguishes a bad table entry from a bad top-level value; without it the
    # three cases below would all report the same thing and the parametrization would test nothing.
    assert f"export value{position} is" in message


def test_a_nested_container_of_strings_still_renders() -> None:
    """The container values _lit is legitimately handed are not collateral damage of the refusal."""
    src = generate_module(
        parse_export(
            _one_action_export(
                {
                    "class": "ItemSplit",
                    "source": "PID-5",
                    "separator": "^",
                    "destinations": ["PID-5.1", "PID-5.2"],
                }
            )
        )[0]
    )
    assert 'split_field(msg, "PID-5", "^", ["PID-5.1", "PID-5.2"])' in src
    ast.parse(src)


def test_an_unpaired_surrogate_is_refused_before_it_reaches_the_file(tmp_path: Path) -> None:
    """A lone surrogate survives json.dumps AND ast.parse, then dies at UTF-8 encode.

    That is the last step, where the traceback blames the file write rather than the export, so the
    value is refused at render time instead. An astral character is the neighbouring case and must
    still work: ``ensure_ascii=False`` keeps it one raw code point instead of splitting it into the
    surrogate pair the default ASCII escaping would emit."""
    lone = json.loads(
        '"\\ud83d"'
    )  # a high surrogate with no low half, exactly as an export carries it
    with pytest.raises(CorepointImportError, match="unpaired surrogate"):
        parse_export(_one_action_export({"class": "ItemReplace", "target": "MSH-6", "value": lone}))

    astral = "\U0001f6f0"  # the same code point, properly paired
    src = generate_module(
        parse_export(
            _one_action_export({"class": "ItemReplace", "target": "MSH-6", "value": astral})
        )[0]
    )
    assert astral in src
    assert "\ud83d" not in src  # never split into surrogates
    (tmp_path / "generated.py").write_text(src, encoding="utf-8")  # the step that used to raise
    ast.parse(src)


def _named_inbound_export(inbound_name: str) -> str:
    """A minimal one-channel export whose ``inbound.name`` is caller-chosen (the untrusted value)."""
    return _one_action_export(
        {"class": "ItemReplace", "target": "MSH-6", "value": "V"},
        inbound_name=inbound_name,
        port=2615,
    )


def _import_and_census(
    inbound_name: str, root: Path, census_base: Path | None = None
) -> tuple[list[Path], list[Path]]:
    """Import an export naming ``inbound_name``, then census EVERY .py under ``census_base``.

    Returns ``(inside_out_dir, outside_out_dir)``. The out dir is nested several levels below
    ``root`` so a traversal escape still lands inside the temp tree and can be seen, rather than
    escaping the census and reading as containment.

    ``census_base`` defaults to ``root`` and exists because that nesting only covers escapes SHALLOW
    ENOUGH to stay under ``root``. A deeper traversal, an absolute path or a drive-letter path lands
    ABOVE it, where an ``rglob`` rooted at ``root`` cannot see it -- and an escape the census cannot
    see reads exactly like containment. Pass a wider base to close that. Found by the adversarial
    pass on BACKLOG #1130."""
    out = root / "a" / "b" / "c" / "out"
    export = root / "export.json"
    export.write_text(_named_inbound_export(inbound_name), encoding="utf-8")
    import_corepoint(export, out)
    found = sorted((census_base or root).rglob("*.py"))
    return (
        [p for p in found if p.is_relative_to(out)],
        [p for p in found if not p.is_relative_to(out)],
    )


def test_a_hostile_inbound_name_cannot_write_outside_the_output_directory(tmp_path: Path) -> None:
    """``inbound.name`` is the one export value that becomes a filesystem path (the module's filename
    stem, and the emitted ``inbound()`` connection name with it), so it is untrusted text reaching a
    write. A traversal name must land inside the output directory and nowhere else."""
    # POSITIVE CONTROL, same census, benign name: the module IS written and the census DOES see it,
    # so the empty escape list on the hostile run below is a containment result, not a blind probe.
    benign_root = tmp_path / "benign"
    benign_root.mkdir()
    benign_inside, benign_outside = _import_and_census("IB_ACME_ADT", benign_root)
    assert benign_inside == [benign_root / "a" / "b" / "c" / "out" / "IB_ACME_ADT.py"]
    assert benign_outside == []

    hostile_root = tmp_path / "hostile"
    hostile_root.mkdir()
    hostile_inside, hostile_outside = _import_and_census("../../../evil", hostile_root)
    assert hostile_outside == []
    # The channel is still imported, under a folded stem: the name is sanitized, never dropped. The
    # exact stem is deliberately not asserted, because that would pin the fold, not the containment.
    assert len(hostile_inside) == 1


@pytest.mark.parametrize(
    "hostile",
    [
        "../../../../../../evil",
        "/etc/cron.d/evil",
        "C:\\Windows\\Temp\\evil",
        "\\\\server\\share\\evil",
        "a/b/evil",
        "..",
    ],
    ids=["deep-traversal", "posix-absolute", "drive-absolute", "unc", "subdir", "bare-dotdot"],
)
def test_no_hostile_inbound_name_escapes_a_census_WIDER_than_the_out_root(
    tmp_path: Path, hostile: str
) -> None:
    """Escape classes the original census could not have seen, so its silence meant nothing.

    The helper nests the out dir three levels under ``root`` so that ``../../../x`` still lands
    inside ``root``. That covers exactly one class. A DEEPER traversal, a POSIX-absolute path, a
    drive-letter path or a UNC path all resolve ABOVE ``root`` -- outside an ``rglob`` rooted there,
    where the escape is invisible and the empty result reads as containment.

    Censusing from ``tmp_path`` instead is what makes the assertion mean anything: it is the widest
    base this test can see, and it contains every target the classes above can reach in-process.

    Mutation: drop the ``_sanitize`` call at ``corepoint_import.py``'s ``module_name`` site.
    MEASURED RED, and it is NOT the failure this docstring first predicted -- recorded exactly
    because the two are easy to confuse. Five of six ids go red; the observed mechanism is
    ``FileNotFoundError`` on the write, because the unsanitized stem names a parent directory the
    importer never created. That still proves the thing under test -- the name reached the
    filesystem path unsanitized -- but it is a WRITE FAILURE, not a non-empty ``outside`` census.
    A reader re-running the mutation and expecting an escape would see an unrelated-looking error
    and distrust the test.

    ``bare-dotdot`` PASSES under the plant and is kept deliberately: ``..`` alone resolves to the out
    dir's parent as a directory rather than a new stem, so it produces no write for the census to
    catch. It is a must-not-trip control -- if it ever starts failing, the fold changed shape."""
    root = tmp_path / "hostile"
    root.mkdir()
    inside, outside = _import_and_census(hostile, root, census_base=tmp_path)
    assert outside == [], f"{hostile!r} wrote outside the out dir: {outside}"
    assert len(inside) == 1, f"{hostile!r} did not produce exactly one module: {inside}"


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


def test_non_utf8_export_raises_corepoint_import_error(tmp_path: Path) -> None:
    """`UnicodeDecodeError` subclasses `ValueError`, not `OSError` — a non-UTF-8 export must still
    become the clean `CorepointImportError` the function's docstring promises, not a raw traceback."""
    export = tmp_path / "export.json"
    export.write_bytes(b"\xff\xfe not valid utf-8: \x80\x81\xfe")
    with pytest.raises(CorepointImportError, match=re.escape(str(export))):
        import_corepoint(export, tmp_path / "out")


def test_parse_export_converts_a_recursion_error_from_json_loads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`json.loads` also raises `RecursionError` on deeply nested input, and that is a `RuntimeError`
    — not a `ValueError` — so the `except json.JSONDecodeError` arm above never sees it.

    Drives :func:`parse_export` directly, not through the CLI: ``_import`` in ``__main__.py`` already
    catches ``RecursionError`` too, so a CLI-level test would pass for the wrong reason even with this
    conversion missing from :func:`parse_export` itself — exactly what a library caller other than the
    CLI would hit.

    Manufactures the ``RecursionError`` rather than nesting real input deeply enough to trigger one:
    ``json.loads``'s C accelerator does not respect ``sys.getrecursionlimit()``, and the depth where it
    actually raises is both far larger and measured to vary widely by platform/runner — a sibling case
    in ``tests/test_sandbox_codec.py`` (``test_recursion_error_is_not_a_value_error``, BACKLOG #1222)
    recorded a 6x spread between two boxes and a CI runner that never raised at all at 100,000. Real
    nesting is therefore both unreliable as a test trigger and, at extreme depth, a risk of a native
    stack overflow rather than a clean Python exception. This test uses that sibling's own technique,
    adapted: :func:`parse_export`'s ``except`` arm names ``json.JSONDecodeError`` explicitly (the
    codec's does not), so only ``json.loads`` itself is replaced -- swapping the whole ``json``
    reference would leave that name unresolvable and fail for an unrelated reason."""

    def _raise_recursion(*_args: object, **_kwargs: object) -> object:
        raise RecursionError("simulated deep nesting")

    monkeypatch.setattr("messagefoundry.corepoint_import.json.loads", _raise_recursion)
    with pytest.raises(CorepointImportError, match="nested too deeply"):
        parse_export('{"channels": []}')


# --- the VALIDATED <Package> XML layer (ADR 0086 §2 amendment, BACKLOG #105) -------------------
#
# Everything below drives the real export shape: the recursive <List> tree, the rich-text markup
# wrapper on @Data, <Block> as a label, @Disabled, and the branch markers carried as plain <Line>s.
# The fixture is hand-authored and synthetic (see its header comment) — no real export is read.


def _package(body: str) -> str:
    """Wrap ``body`` (the statements of one ``<List>``) in a minimal synthetic ``<Package>``."""
    return f'<Package Name="ACME X"><ActionList Name="T"><List>{body}</List></ActionList></Package>'


def _handler_source(body: str) -> str:
    return generate_module(parse_package(_package(body))[0])


def test_strip_markup_recovers_the_verb() -> None:
    """``@Data`` is rich text: without the strip the head token is markup, not a verb (#105)."""
    # What the XML parser hands back for a doubly-escaped, syntax-coloured statement.
    raw = '<span class="kw">ItemCopy</span> %ADT/PID-5.1 &quot;ACME&quot;'
    assert raw.split()[0] != "ItemCopy"  # unstripped, nothing classifies
    assert strip_markup(raw) == 'ItemCopy %ADT/PID-5.1 "ACME"'
    # Order matters: tag-strip first, THEN unescape — otherwise an unescaped ``&lt;`` would turn into
    # a ``<`` that the tag-strip then eats out of the statement itself.
    assert strip_markup("<b>ItemCopy</b> &amp;lt;kept&amp;gt;") == "ItemCopy &lt;kept&gt;"
    assert strip_markup("   <i></i>  ") == ""


def test_markup_stripped_statements_classify_in_the_fixture() -> None:
    """Every markup-wrapped statement in the fixture reaches the vocabulary through the strip."""
    src = _package_source()
    assert 'copy_field(msg, "PID-5.1", "NK1-2.1")' in src
    assert 'set_field(msg, "MSH-6", "ACME")' in src  # ItemCopy from a literal == set
    assert 'set_field(msg, "PID-19", "")' in src  # ItemClear == set empty
    assert 'append_to_field(msg, "MSH-3", "_IMPORTED")' in src


def test_tokenize_keeps_literals_conditions_and_options_whole() -> None:
    assert tokenize_statement('If (%ADT/PID-8 = "M F")') == ["If", '(%ADT/PID-8 = "M F")']
    assert tokenize_statement('ItemCopy "a b" %ADT/MSH-6') == ["ItemCopy", '"a b"', "%ADT/MSH-6"]
    assert tokenize_statement("MsgSend $out [OB A]") == ["MsgSend", "$out", "[OB A]"]
    assert tokenize_statement("If (a (b) c)") == ["If", "(a (b) c)"]  # nested parens survive
    assert tokenize_statement("   ") == []


def test_block_becomes_a_comment_never_an_action() -> None:
    """A ``<Block>`` is a section LABEL: a comment whose body stays inline, never a step (#105)."""
    steps = parse_package(_acme_package())[0].handlers[0].steps
    block = steps[0]
    assert isinstance(block, Control)
    assert (block.kind, block.source_verb, block.detail) == ("block", "Block", "Patient identity")
    # Its body is emitted, at the SAME indentation — the label adds no nesting and no call.
    src = _package_source()
    assert "    # Corepoint Block: Patient identity\n" in src
    assert '    copy_field(msg, "PID-5.1", "NK1-2.1")\n' in src
    # An operator's @Comment rides along beside the step it annotates.
    assert "# Corepoint Comment: family name to next-of-kin" in src


def test_unmapped_verb_emits_a_todo_marker_and_is_counted(tmp_path: Path) -> None:
    """An unmapped verb is never silently dropped — TODO marker naming the target, counted (AC-2).

    The marker is all it emits: no ``msg.set`` passthrough, on this layer or any other (#1681)."""
    src = _package_source()
    assert "# TODO: Corepoint ItemCustomScript — hand-finish" in src
    assert "intended target OBX-5" in src
    assert "msg.field(" not in src
    # Message-lifecycle / logging verbs have no honest vocabulary equivalent either.
    assert "# TODO: Corepoint MsgParse — hand-finish" in src
    assert "# TODO: Corepoint EnvLogText — hand-finish" in src

    result = import_corepoint(FIXTURES / "acme_adt_package.xml", tmp_path)
    classes = result.channels[0].unmapped_classes
    # The first action-list's three unmapped verbs, in order, ahead of the role-grammar list's.
    assert classes[:3] == ("MsgParse", "EnvLogText", "ItemCustomScript")
    assert result.total_unmapped == len(classes)


def test_a_path_that_does_not_resolve_is_never_guessed() -> None:
    """A ``$variable`` / non-HL7 tree path degrades to a TODO — a wrong path is worse than a marker."""
    src = _handler_source(
        '<Line Data="ItemCopy $scratch %ADT/PID-3.1"/>'
        '<Line Data="ItemCopy %ADT/Patient/FamilyName %ADT/NK1-2.1"/>'
    )
    assert src.count("# TODO: Corepoint ItemCopy — hand-finish") == 2
    assert "copy_field(" not in src
    # The recoverable half of each statement rides across in the marker TEXT — never as a live write.
    assert "intended target PID-3.1" in src
    assert "intended target NK1-2.1" in src
    assert "msg.field(" not in src
    assert "msg.set(" not in src


def test_disabled_element_is_preserved_as_comment_not_live_code(tmp_path: Path) -> None:
    """``@Disabled`` never emits live code, and its whole subtree stays visible + counted (#105)."""
    src = _package_source()
    assert "# DISABLED in Corepoint (@Disabled)" in src
    assert "#   Block: Legacy address rewrite" in src
    # The disabled subtree's statements are listed in the comment block...
    assert "ItemCopy -> copy_field" in src
    assert "ItemClear -> set_field" in src
    # ...and NONE of them is emitted as a live call.
    assert 'copy_field(msg, "PID-11.1", "PID-11.3")' not in src
    assert 'set_field(msg, "PID-11.4", "")' not in src

    result = import_corepoint(FIXTURES / "acme_adt_package.xml", tmp_path)
    assert result.total_disabled == 1
    assert result.to_json()["channels"][0]["disabled"] == 1
    # A disabled step is neither claimed as shipped nor silently lost: the two statements inside
    # the disabled <Block> are counted as `disabled`, never as unmapped work still to do.
    assert result.channels[0].disabled == 1


def test_a_disabled_send_is_not_resurrected_as_a_trailing_send() -> None:
    """The subtle failure mode of ``@Disabled``: a handler with destinations but no *inline* send
    falls back to a trailing ``return Send(...)``, so collecting a disabled ``MsgSend``'s destination
    would switch a disabled send back on."""
    src = _handler_source('<Line Disabled="1" Data="MsgSend $out [OB_ACME_ADT]"/>')
    assert "Send(" not in src.split("@handler")[-1]
    assert "outbound(" not in src
    assert "return None  # TODO: Corepoint export named no destination" in src
    assert "# DISABLED in Corepoint (@Disabled)" in src


def test_a_hostile_destination_name_cannot_become_a_traversal_path() -> None:
    """A destination name is untrusted export text — it must not ride raw into the wiring."""
    src = _handler_source(_role_send("input-handle", "%ADT", "../../etc/passwd"))
    assert "../.." not in src
    # ONE sanitized name, used identically as the connection id, the Send target and the directory.
    assert 'sends.append(Send("etc_passwd", msg))' in src
    assert 'outbound("etc_passwd", File(directory="./corepoint-import/IB_ACME_X/etc_passwd")' in src

    # The markup-free send of a ``$variable`` is refused (BACKLOG #313 step 2), so its statement
    # rides only into the TODO comment. The wiring and the raise still carry the sanitized name alone.
    flat = _handler_source('<Line Data="MsgSend $out [../../etc/passwd]"/>')
    code = [ln for ln in flat.splitlines() if not ln.lstrip().startswith("#")]
    assert not any("../.." in ln for ln in code)
    assert (
        'outbound("etc_passwd", File(directory="./corepoint-import/IB_ACME_X/etc_passwd")' in flat
    )
    assert 'raise NotImplementedError("Corepoint import: MsgSend to etc_passwd:' in flat


def test_nested_control_flow_round_trips() -> None:
    """If/ElseIf/Else, ForEach+LoopExit, Try/Catch and Call keep their shape through parse → codegen."""
    steps = parse_package(_acme_package())[0].handlers[0].steps
    kinds = [s.kind if isinstance(s, Control) else type(s).__name__ for s in steps]
    assert kinds == ["block", "for", "if", "try", "call", "disabled", "UnmappedAction", "send"]

    loop = steps[1]
    conditional = steps[2]
    attempt = steps[3]
    assert isinstance(loop, Control) and isinstance(conditional, Control)
    assert isinstance(attempt, Control)
    # The branch markers carried as plain <Line>s inside the construct became real branches.
    assert [b.kind for b in conditional.branches] == ["elif", "else"]
    assert conditional.detail == '(%ADT/PID-8 = "M")'
    assert [b.kind for b in attempt.branches] == ["except"]
    assert isinstance(loop.body[-1], Control) and loop.body[-1].kind == "break"

    src = _package_source()
    assert "    for _item in []:  # TODO: Corepoint ForEach" in src
    assert "        break  # Corepoint LoopExit" in src
    assert '    if False:  # TODO: Corepoint If condition — hand-finish: (%ADT/PID-8 = "M")' in src
    assert "    elif False:  # TODO: Corepoint ElseIf" in src
    # The fallback is rendered ``elif False:``, NOT ``else:`` — see
    # test_else_under_a_dead_condition_is_not_emitted_as_a_live_branch.
    assert "    elif False:  # TODO: Corepoint Else" in src
    assert "    else:" not in src
    assert "    try:" in src
    assert "    except Exception:  # TODO: Corepoint Catch" in src
    # A <Call> inlines the called list under a provenance comment (no invented helper function).
    assert "# Corepoint ActionListCall (called list inlined)" in src
    assert '    copy_field(msg, "PID-3.1", "PID-2.1")' in src


def test_conditions_are_dead_placeholders_never_guessed() -> None:
    """A Corepoint condition is not Python: every branch is inert until a human writes the test."""
    src = _package_source()
    tree = ast.parse(src)
    tests = [
        node.test for node in ast.walk(tree) if isinstance(node, ast.If | ast.While)
    ]  # every emitted branch/loop condition
    assert tests, "the fixture exercises conditionals"
    assert all(isinstance(t, ast.Constant) and t.value is False for t in tests)


def test_loop_exit_outside_a_loop_degrades_to_a_marker() -> None:
    """A stray ``LoopExit`` must not emit a bare ``break`` — that would not even parse."""
    src = _handler_source('<Line Data="LoopExit"/>')
    assert "# TODO: Corepoint LoopExit outside a loop" in src
    assert "\n    break" not in src
    ast.parse(src)


# --- a LoopExit is counted the way it is rendered (BACKLOG #1860) --------------------------------

_CLEAR = '<Line Data="ItemClear %ADT/PID-19"/>'
_LOOP_EXIT = '<Line Data="LoopExit"/>'


def test_loop_exit_outside_a_loop_is_counted_unmapped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The render marks a ``LoopExit`` outside a loop, so the summary may not count it shipped."""
    body = _CLEAR + _LOOP_EXIT
    assert _count_steps(_handler_steps(body), in_loop=False) == (1, ["LoopExit"], 0)

    # The control: inside a loop the render emits a real ``break``, and the count stays mapped.
    loop = f"<Foreach>{_CLEAR}{_LOOP_EXIT}</Foreach>"
    assert "        break  # Corepoint LoopExit" in _handler_source(loop)
    assert _count_steps(_handler_steps(loop), in_loop=False) == (3, [], 0)

    # The line a migrator reads: the stub is reported, not hidden under "0 left as TODO stubs".
    from messagefoundry.__main__ import main

    export = tmp_path / "loop_exit.xml"
    export.write_text(_package(body), encoding="utf-8")
    assert main(["import", "corepoint", str(export), "--out", str(tmp_path / "out")]) == 0
    printed = capsys.readouterr().out
    assert "(1 action(s) mapped, 1 left as TODO stubs):" in printed
    assert "1 unmapped: LoopExit" in printed


def test_loop_exit_count_follows_the_loop_context_through_nesting() -> None:
    """A conditional passes its caller's loop context down; only a loop body is inside a loop."""
    in_loop = f'<Foreach><If Data="If (a)">{_LOOP_EXIT}</If></Foreach>'
    assert "            break  # Corepoint LoopExit" in _handler_source(in_loop)
    assert _count_steps(_handler_steps(in_loop), in_loop=False) == (3, [], 0)

    no_loop = f'<If Data="If (a)">{_LOOP_EXIT}</If>'
    assert "# TODO: Corepoint LoopExit outside a loop" in _handler_source(no_loop)
    assert _count_steps(_handler_steps(no_loop), in_loop=False) == (1, ["LoopExit"], 0)


def test_loop_exit_in_a_stray_branch_of_a_loop_is_counted_unmapped() -> None:
    """A loop's stray branch is inlined OUTSIDE the loop, so its ``LoopExit`` is a marker there."""
    body = f'<Foreach>{_CLEAR}<Line Data="Catch"/>{_LOOP_EXIT}</Foreach>'
    src = _handler_source(body)
    assert "# TODO: Corepoint LoopExit outside a loop" in src
    assert "break" not in src
    assert _count_steps(_handler_steps(body), in_loop=False) == (2, ["LoopExit", "Catch"], 0)


def test_loop_exit_marker_says_hand_finish_once() -> None:
    """The marker carries the house ``_hint`` tail, not a doubled one."""
    src = _handler_source('<Line Data="LoopExit early"/>')
    assert "# TODO: Corepoint LoopExit outside a loop — hand-finish: LoopExit early\n" in src


def test_try_without_catch_reraises_rather_than_swallowing() -> None:
    src = _handler_source('<Try><List><Line Data="ItemClear %ADT/PID-19"/></List></Try>')
    assert "except Exception:  # TODO: Corepoint Try with no Catch" in src
    assert "        raise" in src
    ast.parse(src)


# --- a branch marker its container cannot continue (BACKLOG #1854) -----------------------------
#
# Why a ``Try`` can end up holding an ``Else`` at all is stated once, in ``_stray_branches``.


def _handler_steps(body: str) -> tuple[Step, ...]:
    """The parsed step tree of the one handler in a minimal synthetic ``<Package>``."""
    return parse_package(_package(body))[0].handlers[0].steps


_STRAY_ELSE_UNDER_TRY = (
    "<Try>"
    '<Line Data="ItemClear %ADT/PID-19"/>'
    '<Line Data="Catch"/>'
    '<Line Data="ItemClear %ADT/PID-20"/>'
    '<Line Data="Else"/>'
    '<Line Data="ItemClear %ADT/PID-21"/>'
    "</Try>"
)


def test_a_stray_branch_under_try_keeps_its_body(tmp_path: Path) -> None:
    """An ``Else`` a ``Try`` cannot continue keeps its body and is flagged, never dropped (#1854)."""
    src = _handler_source(_STRAY_ELSE_UNDER_TRY)
    # The Catch still renders as a real ``except``; what the Try cannot continue degrades to a marker.
    # The tail is the house ``_hint`` wording, pinned whole so the two markers cannot drift apart.
    assert "    except Exception:  # TODO: Corepoint Catch — hand-finish\n" in src
    assert "# TODO: Corepoint Else cannot continue a Corepoint Try" in src
    # The dropped half. Its scope is unknowable, so the body rides inline under the marker.
    assert 'set_field(msg, "PID-21", "")' in src
    ast.parse(src)

    # And the summary must not claim the branch itself shipped: a marker-only element is unmapped,
    # exactly as ``exit`` and ``unknown`` are, while its body statements keep counting on normally.
    assert _count_steps(_handler_steps(_STRAY_ELSE_UNDER_TRY), in_loop=False) == (5, ["Else"], 0)

    # The same accounting through the public entry point the CLI prints.
    export = tmp_path / "stray.xml"
    export.write_text(_package(_STRAY_ELSE_UNDER_TRY), encoding="utf-8")
    result = import_corepoint(export, tmp_path / "out")
    assert result.total_mapped == 5
    assert result.channels[0].unmapped_classes == ("Else",)


def test_a_stray_branch_under_a_loop_keeps_its_body() -> None:
    """A loop render reads no branches at all, so an adopted marker took its body with it (#1854)."""
    body = (
        "<Foreach>"
        '<Line Data="ItemClear %ADT/PID-19"/>'
        '<Line Data="Catch"/>'
        '<Line Data="ItemClear %ADT/PID-21"/>'
        "</Foreach>"
    )
    src = _handler_source(body)
    assert "    for _item in []:  # TODO: Corepoint Foreach" in src
    assert "# TODO: Corepoint Catch cannot continue a Corepoint Foreach" in src
    assert 'set_field(msg, "PID-21", "")' in src
    ast.parse(src)
    assert _count_steps(_handler_steps(body), in_loop=False) == (3, ["Catch"], 0)

    # ``while`` reads its branches through the same render path.
    loop = body.replace("Foreach", "Loop")
    loop_src = _handler_source(loop)
    assert "    while False:  # TODO: Corepoint Loop" in loop_src
    assert "# TODO: Corepoint Catch cannot continue a Corepoint Loop" in loop_src
    assert '    set_field(msg, "PID-21", "")' in loop_src
    ast.parse(loop_src)
    assert _count_steps(_handler_steps(loop), in_loop=False) == (3, ["Catch"], 0)


def test_a_stray_branch_body_is_live_code_outside_the_loop_it_was_adopted_by() -> None:
    """The inlined body lands OUTSIDE the ``for`` block, and it is real code, not a comment (#1854).

    Two things ride on the indentation. A ``LoopExit`` there is no longer inside a Python loop, so a
    bare ``break`` would not even parse; and a ``MsgSend`` there must still reach the handler's
    ``sends`` list, or the emitted call would dangle."""
    src = _handler_source(
        "<Foreach>"
        '<Line Data="ItemClear %ADT/PID-19"/>'
        '<Line Data="Catch"/>'
        '<Line Data="LoopExit"/>' + _role_send("input-handle", "%ADT", "OB_ACME_ADT") + "</Foreach>"
    )
    assert "# TODO: Corepoint LoopExit outside a loop" in src
    assert "break" not in src
    assert "    sends = []" in src
    assert '    sends.append(Send("OB_ACME_ADT", msg))' in src
    ast.parse(src)

    # And nested, where an enclosing loop WOULD make a ``break`` parse. It must still not be emitted:
    # it would bind the outer loop, silently changing which loop the export meant to exit.
    nested = _handler_source(
        '<Foreach Data="ForEach %ADT/PID-3(*)"><List>'
        "<Foreach>"
        '<Line Data="Catch"/>'
        '<Line Data="LoopExit"/>'
        '<Line Data="ItemClear %ADT/PID-5"/>'
        "</Foreach>"
        "</List></Foreach>"
    )
    assert "# TODO: Corepoint LoopExit outside a loop" in nested
    assert "break" not in nested
    # The statement after the LoopExit is still emitted, and is not left unreachable behind a break.
    assert 'set_field(msg, "PID-5", "")' in nested
    ast.parse(nested)


def test_a_branch_marker_with_no_construct_is_counted_unmapped() -> None:
    """An orphaned marker emits a TODO and nothing else, so it may not be counted mapped (#1854).

    ``else``/``elif``/``except``/``match`` are all in ``_MAPPED_CONTROL_KINDS`` -- they name real
    Python control flow when a construct adopts them. Standing alone there is no construct to
    continue, the render degrades to a marker, and the count has to follow the render."""
    body = '<Line Data="Else"/><Line Data="ItemClear %ADT/PID-21"/>'
    src = _handler_source(body)
    assert "# TODO: Corepoint Else with no enclosing construct" in src
    assert 'set_field(msg, "PID-21", "")' in src
    assert _count_steps(_handler_steps(body), in_loop=False) == (1, ["Else"], 0)


def test_a_stray_branch_under_a_conditional_keeps_its_scope() -> None:
    """The ``If``/``ChooseFrom`` render iterates EVERY branch, so it drops nothing (#1854).

    A stray ``Catch`` there is a mislabelled arm, not an accept-and-drop: the body is emitted, the
    scope is preserved, and the arm stays dead like every other. That is real control flow, so it
    counts mapped -- pinned here so the Try/loop fix above is not mistaken for a licence to degrade
    a render that was never losing anything."""
    body = (
        '<If Data="If (a)">'
        '<Line Data="ItemClear %ADT/PID-19"/>'
        '<Line Data="Catch"/>'
        '<Line Data="ItemClear %ADT/PID-21"/>'
        "</If>"
    )
    src = _handler_source(body)
    assert "    if False:  # TODO: Corepoint If condition" in src
    assert "    elif False:  # TODO: Corepoint Catch" in src
    assert '        set_field(msg, "PID-21", "")' in src
    ast.parse(src)
    assert _count_steps(_handler_steps(body), in_loop=False) == (4, [], 0)

    # Same for a ``ChooseFrom``: its ``Matching`` arms and a stray marker alike become real arms.
    case = (
        '<Line Data="ChooseFrom"><List>'
        '<Line Data="ItemClear %ADT/PID-19"/>'
        '<Line Data="Matching (a)"/>'
        '<Line Data="ItemClear %ADT/PID-20"/>'
        '<Line Data="Catch"/>'
        '<Line Data="ItemClear %ADT/PID-21"/>'
        "</List></Line>"
    )
    case_src = _handler_source(case)
    assert "    if False:  # TODO: Corepoint Matching" in case_src
    assert "    elif False:  # TODO: Corepoint Catch" in case_src
    assert _count_steps(_handler_steps(case), in_loop=False) == (6, [], 0)


def test_exit_verbs_are_flagged_never_flattened() -> None:
    """``Returns``/``ActionListExit`` have no faithful form — a marker, not a silent drop or a
    ``return`` that would swallow the handler's Sends."""
    src = _handler_source('<Line Data="Returns"/><Line Data="ActionListExit"/>')
    assert "# TODO: Corepoint Returns (ends this list)" in src
    assert "# TODO: Corepoint ActionListExit (ends this list)" in src
    assert "\n    return None" in src  # the handler's own return, not the export's


def test_msgsend_becomes_an_inline_send_and_a_placeholder_outbound() -> None:
    """A ``MsgSend`` sends where the export put it — flattening it to a trailing Send would turn a
    conditional send into an unconditional one. The shape is unchanged by the handle flow of
    BACKLOG #313 step 2; the send names the input handle, which is msg."""
    src = _handler_source(
        '<If Data="If (%ADT/PID-8 = &quot;M&quot;)"><List>'
        + _role_send("input-handle", "%ADT", "OB_ACME_ADT")
        + "</List></If>"
    )
    assert "    sends = []" in src
    assert '        sends.append(Send("OB_ACME_ADT", msg))' in src
    assert "    return sends" in src
    # The destination is declared, as an inert placeholder (the export's connection config is not
    # modelled), so the emitted Send never dangles.
    assert 'outbound("OB_ACME_ADT", File(directory=' in src
    assert "deployed=False)" in src


def test_msgsend_without_a_recoverable_destination_is_a_marker() -> None:
    """A send of msg with no destination is a marker. A send of a handle nobody bound, with no
    destination, is still a refusal and raises (see test_a_refused_send_with_no_destination_still_raises)."""
    src = _handler_source(
        _role_line(_span("keyword", "MsgSend") + " " + _span("input-handle", "%ADT"))
    )
    assert "# TODO: Corepoint MsgSend — hand-finish: no destination named" in src
    assert "Send(" not in src.split('"""')[-1]
    assert "raise NotImplementedError" not in src

    flat = _handler_body(_handler_source('<Line Data="MsgSend $out"/>'))
    assert "Send(" not in flat
    assert 'raise NotImplementedError("Corepoint import: MsgSend (no destination named):' in flat


# --- a MsgSend of a handle that is not msg (BACKLOG #313, step 1) -------------------------------
#
# A Handler has one ``msg``: the inbound message. A role-parsed ``MsgSend`` that names another handle
# used to render ``Send(dest, msg)`` and so deliver the unmodified input in place of the message
# Corepoint built. It now raises at the send site. All fixtures here are synthetic.


def _span(cls: str, text: str) -> str:
    return f"<span class='{cls}'>{text}</span>"


def _role_line(data: str) -> str:
    """A ``<Line>`` whose ``@Data`` carries role markup, escaped as the export writes it."""
    escaped = data.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # XML attribute normalisation turns a raw newline into a space, so it rides as a character reference.
    escaped = escaped.replace('"', "&quot;").replace("\n", "&#10;")
    return f'<Line Data="{escaped}"/>'


def _write(handle_class: str, handle: str, value: str) -> str:
    """A role-marked ``ItemCopy "<value>" to <handle>/MSH-6``."""
    return _role_line(
        _span("keyword", "ItemCopy")
        + " "
        + _span("literal", '"' + value + '"')
        + " to "
        + _span(handle_class, handle)
        + _span("path", "/MSH-6")
    )


_WRITE_INPUT = _write("input-handle", "%ADT", "X")


def _role_send(handle_class: str, handle: str, dest: str) -> str:
    literal = _span("literal", '"' + dest + '"')
    return _role_line(
        _span("keyword", "MsgSend")
        + " "
        + _span(handle_class, handle)
        + " to connection "
        + literal
    )


def _handler_body(src: str) -> str:
    return src.split("@handler")[-1]


def test_a_msgsend_of_the_subject_handle_still_sends() -> None:
    """The control arm: the input handle IS msg, so its send renders exactly as before."""
    src = _handler_source(_WRITE_INPUT + _role_send("input-handle", "%ADT", "OB_IN"))
    body = _handler_body(src)
    assert 'set_field(msg, "MSH-6", "X")' in body  # the subject resolved, so the write mapped
    assert '    sends.append(Send("OB_IN", msg))  # Corepoint MsgSend' in body
    assert "raise NotImplementedError" not in body


def test_a_msgsend_of_a_non_subject_handle_fails_loudly_and_sends_nothing() -> None:
    """A send of another handle raises at the send site. It must not send msg, must not filter
    silently, and must not gain a trailing unconditional ``Send``."""
    src = _handler_source(_WRITE_INPUT + _role_send("other-handle", "%OUT", "OB_ACME"))
    body = _handler_body(src)
    assert "Send(" not in body  # no Send of msg anywhere: not inline, not trailing
    assert "    sends = []" in body and body.rstrip().endswith("return sends")
    assert "return None" not in body  # not a silent filter
    assert (
        '    raise NotImplementedError("Corepoint import: MsgSend to OB_ACME: MsgSend delivers %OUT, '
        "which at this point is not the input handle, nor bound by a whole-tree clone or a "
        "MsgCreate on every path before this send" in body
    )
    assert "# TODO: Corepoint MsgSend to OB_ACME — hand-finish: MsgSend delivers %OUT" in body
    # The destination stays declared, so the hand-finisher has somewhere to send the right message.
    assert 'outbound("OB_ACME", File(directory=' in src


def test_a_non_subject_send_raises_when_the_handler_runs(tmp_path: Path) -> None:
    """The refusal is a runtime ERROR (dead-letter), not only a comment: calling the loaded handler
    raises, where the old render returned a Send of the unmodified input."""
    with pytest.raises(NotImplementedError, match="MsgSend delivers %OUT"):
        _run_handler(tmp_path, _role_send("other-handle", "%OUT", "OB_ACME"))


def test_a_subject_send_returns_a_send_when_the_handler_runs(tmp_path: Path) -> None:
    """The control arm for the runtime test: the same harness returns a Send for the input handle."""
    result = _run_handler(tmp_path, _role_send("input-handle", "%ADT", "OB_IN"))
    assert isinstance(result, list) and len(result) == 1


def test_a_non_subject_send_is_counted_unmapped(tmp_path: Path) -> None:
    """The count-and-log summary must not report the refused send as shipped."""
    export = tmp_path / "pkg.xml"
    export.write_text(_package(_role_send("other-handle", "%OUT", "OB_ACME")), encoding="utf-8")
    summary = import_corepoint(export, tmp_path / "out").to_json()
    assert summary["total_mapped"] == 0
    assert summary["total_unmapped"] == 1


def test_a_send_with_no_single_input_handle_is_refused() -> None:
    """With no input handle at all, no handle is known to be msg, so the send is refused too."""
    body = _handler_body(_handler_source(_role_send("other-handle", "%OUT", "OB_ACME")))
    assert "Send(" not in body
    assert (
        "no handle in this action-list holds a message this import can identify at this point"
        in body
    )
    assert "raise NotImplementedError" in body


def test_a_mixed_list_refuses_only_the_non_subject_send() -> None:
    """One list sending both handles: the input send stays live, the other one raises. The write
    addresses the input, which is msg at that point, so it maps (BACKLOG #313 step 2: each handle has
    its own local, so a write can no longer land in another handle's send)."""
    src = _handler_source(
        _WRITE_INPUT
        + _role_send("input-handle", "%ADT", "OB_IN")
        + _role_send("other-handle", "%OUT", "OB_ACME")
    )
    body = _handler_body(src)
    assert '    sends.append(Send("OB_IN", msg))' in body
    assert 'Send("OB_ACME"' not in body
    assert "raise NotImplementedError" in body
    assert 'set_field(msg, "MSH-6", "X")' in body


def test_a_conditional_non_subject_send_raises_inside_its_branch() -> None:
    """The raise sits where the send was, so a conditional send stays conditional."""
    src = _handler_source(
        '<If Data="If (%ADT/PID-8 = &quot;M&quot;)"><List>'
        + _role_send("other-handle", "%OUT", "OB_ACME")
        + "</List></If>"
    )
    body = _handler_body(src)
    assert "    if False:  # TODO: Corepoint If condition" in body
    assert "        raise NotImplementedError(" in body
    assert "Send(" not in body
    assert body.rstrip().endswith("return sends")


def test_a_hostile_handle_name_cannot_escape_the_raise_or_its_comment() -> None:
    """The handle is untrusted export text: it rides into a string literal and a comment, flattened
    and elided, so neither a newline nor a huge span reaches the module or the stored error."""
    src = _handler_source(_role_send("other-handle", '%O"UT)\nimport os', "OB_ACME"))
    compile(src, "generated.py", "exec")
    assert "\nimport os" not in src
    # Positive control: the handle did reach the render, flattened, with its quote escaped.
    assert (
        'raise NotImplementedError("Corepoint import: MsgSend to OB_ACME: MsgSend delivers %O\\"UT) '
        "import os" in src
    )
    long_src = _handler_source(_role_send("other-handle", "%" + "X" * 5000, "OB_ACME"))
    raise_line = next(ln for ln in long_src.splitlines() if "raise NotImplementedError" in ln)
    assert len(raise_line) < 400


def _root_copy(
    src_class: str, src: str, dst_class: str, dst: str, *, disabled: bool = False
) -> str:
    """A role-marked ``MsgTreeCopy <src>/ to <dst>/``: a whole-tree clone."""
    line = _role_line(
        _span("keyword", "MsgTreeCopy")
        + " "
        + _span(src_class, src)
        + _span("path", "/")
        + " to "
        + _span(dst_class, dst)
        + _span("path", "/")
    )
    return line.replace("<Line ", '<Line Disabled="1" ', 1) if disabled else line


_INBOUND = "MSH|^~\\&|A|B|C|D|20260930||ADT^A01|1|P|2.5\rPID|1||123"


def _run_handler(tmp_path: Path, body: str, inbound: Message | None = None) -> object:
    """Import a one-list package, load it through the real loader, and call its handler once.

    ``inbound`` lets a test keep a reference to the message it passed in; by default a fresh
    synthetic ADT is used."""
    from messagefoundry.config.wiring import load_config

    export = tmp_path / "pkg.xml"
    export.write_text(_package(body), encoding="utf-8")
    out = tmp_path / "out"
    import_corepoint(export, out)
    handler_fn = load_config(out).handlers["t"]
    return handler_fn(inbound if inbound is not None else Message.parse(_INBOUND))


def test_a_catch_cannot_swallow_a_refused_send(tmp_path: Path) -> None:
    """Every Catch renders as ``except Exception:``. Without a re-raise arm ahead of it, the refusal
    would be caught and the Catch body would deliver msg (or filter) with no ERROR recorded."""
    body = (
        "<Try><List>"
        + _role_send("other-handle", "%OUT", "OB_ACME")
        + '<Line Data="Catch"/>'
        + _role_send("input-handle", "%ADT", "OB_ERR")
        + "</List></Try>"
    )
    src = _handler_body(_handler_source(body))
    assert src.index("except NotImplementedError:") < src.index("except Exception:")
    with pytest.raises(NotImplementedError, match="MsgSend delivers %OUT"):
        _run_handler(tmp_path, body)


def test_a_try_with_no_refused_send_renders_as_before() -> None:
    """The control arm: the re-raise arm appears only where a refusal sits in the try body."""
    body = (
        "<Try><List>"
        + _role_send("input-handle", "%ADT", "OB_IN")
        + '<Line Data="Catch"/>'
        + '<Line Data="ItemClear %ADT/PID-19"/>'
        + "</List></Try>"
    )
    src = _handler_body(_handler_source(body))
    assert "except NotImplementedError" not in src
    assert '        sends.append(Send("OB_IN", msg))' in src


@pytest.mark.parametrize(
    "operand",
    [
        pytest.param(_span("other-handle", "%OUT") + _span("path", "/"), id="root-path-form"),
        pytest.param(_span("variable", "$Out"), id="variable"),
        pytest.param(_span("other-handle", "%OUT") + _span("path", "/PID"), id="partial-path"),
    ],
)
def test_a_send_of_an_unidentified_or_other_message_is_refused(operand: str) -> None:
    """Fail closed: a send is live only when its handle holds a known message. A root-path spelling
    of another handle, a ``$variable`` and a partial path all refuse. The list's write to the input
    still maps: it is a write to msg, whatever the list later sends."""
    literal = _span("literal", '"OB_ACME"')
    send = _role_line(_span("keyword", "MsgSend") + " " + operand + " to connection " + literal)
    body = _handler_body(_handler_source(_WRITE_INPUT + send))
    assert "Send(" not in body
    assert "raise NotImplementedError" in body
    assert 'set_field(msg, "MSH-6", "X")' in body


def test_a_root_path_send_of_the_input_handle_still_sends() -> None:
    """The control arm for the root-path spelling: ``%ADT/`` is the input, so it sends."""
    literal = _span("literal", '"OB_IN"')
    operand = _span("input-handle", "%ADT") + _span("path", "/")
    send = _role_line(_span("keyword", "MsgSend") + " " + operand + " to connection " + literal)
    body = _handler_body(_handler_source(_WRITE_INPUT + send))
    assert '    sends.append(Send("OB_IN", msg))' in body
    assert 'set_field(msg, "MSH-6", "X")' in body


def test_a_live_whole_tree_clone_still_sends() -> None:
    """The control arm: a live root copy of the input binds the clone to its own local, and the
    send delivers that local (BACKLOG #313 step 2), never msg itself."""
    body = _handler_body(
        _handler_source(
            _root_copy("input-handle", "%ADT", "other-handle", "%OUT")
            + _role_send("other-handle", "%OUT", "OB_ACME")
        )
    )
    assert "    out_msg = msg.copy()  # Corepoint MsgTreeCopy %ADT/ to %OUT/" in body
    assert '    sends.append(Send("OB_ACME", out_msg))' in body
    assert "raise NotImplementedError" not in body


def test_a_disabled_clone_does_not_make_its_handle_msg() -> None:
    """A switched-off ``MsgTreeCopy`` never ran, so the handle it would have cloned into is not msg."""
    body = _handler_body(
        _handler_source(
            _root_copy("input-handle", "%ADT", "other-handle", "%OUT", disabled=True)
            + _role_send("other-handle", "%OUT", "OB_ACME")
        )
    )
    assert "Send(" not in body
    assert "raise NotImplementedError" in body


def test_an_input_overwritten_by_another_tree_is_not_msg() -> None:
    """A root copy of another tree INTO the input means the input may no longer be msg's content."""
    body = _handler_body(
        _handler_source(
            _root_copy("other-handle", "%OUT", "input-handle", "%ADT")
            + _role_send("input-handle", "%ADT", "OB_IN")
        )
    )
    assert "Send(" not in body
    assert "no handle in this action-list holds a message this import can identify" in body


def test_an_unstyled_send_verb_is_judged_like_a_styled_one() -> None:
    """The input scan and the parse read the verb the same way. A ``MsgSend`` with no ``keyword``
    span is still a send of another handle, so it refuses."""
    literal = _span("literal", '"OB_ACME"')
    send = _role_line("MsgSend " + _span("other-handle", "%OUT") + " to connection " + literal)
    body = _handler_body(_handler_source(_WRITE_INPUT + send))
    assert "raise NotImplementedError" in body
    assert "Send(" not in body


def test_two_input_handle_names_refuse_even_an_input_classed_send() -> None:
    """With two input names nothing is provably msg, so every role-parsed send refuses. A disabled
    line naming a second input does not count, because it never ran."""
    second_input = _role_line(
        _span("keyword", "ItemClear")
        + " "
        + _span("input-handle", "%IN2")
        + _span("path", "/PID-19")
    )
    send = _role_send("input-handle", "%ADT", "OB_IN")
    body = _handler_body(_handler_source(second_input + send))
    assert "Send(" not in body
    assert "no handle in this action-list holds a message this import can identify" in body
    disabled_second = second_input.replace("<Line ", '<Line Disabled="1" ', 1)
    body = _handler_body(_handler_source(disabled_second + send))
    assert '    sends.append(Send("OB_IN", msg))' in body


def test_a_send_with_no_destination_is_counted_unmapped() -> None:
    """It renders only a TODO marker, so the summary must not report it as shipped."""
    assert _count_steps(_handler_steps('<Line Data="MsgSend $out"/>'), in_loop=False) == (
        0,
        ["MsgSend"],
        0,
    )


def _tree_copy(src: str, dst: str) -> str:
    """A role-marked ``MsgTreeCopy`` from raw operand markup ``src`` into raw operand markup ``dst``."""
    return _role_line(_span("keyword", "MsgTreeCopy") + " " + src + " to " + dst)


@pytest.mark.parametrize(
    "copy",
    [
        pytest.param(
            _tree_copy(
                _span("variable", "$saved"), _span("input-handle", "%ADT") + _span("path", "/")
            ),
            id="variable-into-root",
        ),
        pytest.param(
            _tree_copy(
                _span("other-handle", "%OUT") + _span("path", "/"), _span("input-handle", "%ADT")
            ),
            id="tree-into-bare-handle",
        ),
        pytest.param(
            _tree_copy(
                _span("other-handle", "%OUT") + _span("path", "/PID"),
                _span("input-handle", "%ADT") + _span("path", "/"),
            ),
            id="partial-path-into-root",
        ),
    ],
)
def test_an_input_overwritten_by_anything_else_is_not_msg(copy: str) -> None:
    """Any whole-tree copy INTO the input from something that is not the input overwrites it, so
    from that point neither a send nor a field write may treat the input as msg. A write made BEFORE
    the overwrite was a write to msg and still maps: the flow reads statement order (#313 step 2)."""
    write_after = _write("input-handle", "%ADT", "Z")
    body = _handler_body(
        _handler_source(
            _WRITE_INPUT + copy + write_after + _role_send("input-handle", "%ADT", "OB_IN")
        )
    )
    assert "Send(" not in body
    assert "raise NotImplementedError" in body
    assert 'set_field(msg, "MSH-6", "X")' in body
    assert 'set_field(msg, "MSH-6", "Z")' not in body


def test_an_overwrite_inside_an_unmodelled_element_still_counts() -> None:
    """An unmodelled tag ran in Corepoint even though the render only marks it."""
    copy = _root_copy("other-handle", "%OUT", "input-handle", "%ADT").replace(
        "<Line ", "<Switch ", 1
    )
    body = _handler_body(_handler_source(copy + _role_send("input-handle", "%ADT", "OB_IN")))
    assert "Send(" not in body
    assert "raise NotImplementedError" in body


def test_a_write_to_an_unsent_clone_does_not_reach_the_input_send() -> None:
    """Only the ONE delivered tree is msg. A write to a clone that is never sent is a write to a
    different Corepoint tree, so it must not land in the input's send."""
    write_clone = _write("other-handle", "%OUT", "Y")
    body = _handler_body(
        _handler_source(
            _root_copy("input-handle", "%ADT", "other-handle", "%OUT")
            + write_clone
            + _role_send("input-handle", "%ADT", "OB_IN")
        )
    )
    assert '    sends.append(Send("OB_IN", msg))' in body
    assert 'set_field(msg, "MSH-6", "Y")' not in body


def test_a_write_to_the_sent_clone_still_maps() -> None:
    """The control arm: a write to the clone maps onto the clone's own local, which is what the list
    sends (BACKLOG #313 step 2)."""
    write_clone = _write("other-handle", "%OUT", "Y")
    body = _handler_body(
        _handler_source(
            _root_copy("input-handle", "%ADT", "other-handle", "%OUT")
            + write_clone
            + _role_send("other-handle", "%OUT", "OB_ACME")
        )
    )
    assert '    sends.append(Send("OB_ACME", out_msg))' in body
    assert 'set_field(out_msg, "MSH-6", "Y")' in body
    assert 'set_field(msg, "MSH-6", "Y")' not in body


def test_a_disabled_list_wrapper_is_scanned_as_the_render_emits_it() -> None:
    """The render flattens a ``<List>`` wrapper even under ``@Disabled``, so its send is live and
    is judged like any other: a send of a handle nobody bound refuses beside the live input send."""
    wrapped = '<List Disabled="1">' + _role_send("other-handle", "%OUT", "OB_ACME") + "</List>"
    body = _handler_body(
        _handler_source(_WRITE_INPUT + wrapped + _role_send("input-handle", "%ADT", "OB_IN"))
    )
    assert "raise NotImplementedError" in body
    assert 'Send("OB_ACME"' not in body
    assert '    sends.append(Send("OB_IN", msg))' in body


def test_a_refused_send_with_no_destination_still_raises() -> None:
    """A refused send with no destination is still a refusal: a TODO alone would let the handler
    fall through to a silent filter."""
    send = _role_line(_span("keyword", "MsgSend") + " " + _span("other-handle", "%OUT"))
    body = _handler_body(_handler_source(_WRITE_INPUT + send))
    assert "Send(" not in body
    assert (
        '    raise NotImplementedError("Corepoint import: MsgSend (no destination named):' in body
    )


def test_a_refused_send_still_passes_the_required_check_gate(tmp_path: Path) -> None:
    """The module stays valid config. ``check`` does report the kept outbound as unreferenced, an
    advisory that is accurate: nothing sends to it until the hand-finish."""
    export = tmp_path / "pkg.xml"
    export.write_text(_package(_role_send("other-handle", "%OUT", "OB_ACME")), encoding="utf-8")
    out = tmp_path / "out"
    import_corepoint(export, out)
    report = run_checks(out, run_lint=False)
    assert report.ok
    dead = next(r for r in report.results if r.name == "dead-config")
    assert not dead.required and "outbound:OB_ACME" in dead.detail


# --- each handle becomes a Python local, settled in statement order (BACKLOG #313, step 2) --------
#
# The input handle is msg. A whole-tree clone binds ``<local> = <source>.copy()``, a MsgCreate naming a
# type and a version binds ``<local> = Message.parse(<skeleton>)``, and a send of a bound handle
# delivers its local. What the flow cannot settle keeps the step 1 raise. All fixtures are synthetic.


def _create(handle: str, *operands: str) -> str:
    """A role-marked ``MsgCreate <handle> <operands>``; each operand is raw markup."""
    return _role_line(
        _span("keyword", "MsgCreate") + " " + _span("other-handle", handle) + "".join(operands)
    )


_ADT_A04 = " as " + _span("literal", '"ADT^A04"') + " version " + _span("literal", '"2.5.1"')

_CLONE_WRITE_SEND = (
    _root_copy("input-handle", "%ADT", "other-handle", "%OUT")
    + _write("other-handle", "%OUT", "Y")
    + _role_send("other-handle", "%OUT", "OB_ACME")
)


def test_clone_then_write_then_send_delivers_the_clone_and_leaves_the_input_alone(
    tmp_path: Path,
) -> None:
    """The clone is its own Message: the write lands on it, the send delivers it, and the inbound
    message the Handler received is not changed or sent."""

    body = _handler_body(_handler_source(_CLONE_WRITE_SEND))
    assert "    out_msg = msg.copy()" in body
    assert '    set_field(out_msg, "MSH-6", "Y")' in body
    assert '    sends.append(Send("OB_ACME", out_msg))' in body
    assert "raise NotImplementedError" not in body

    inbound = Message.parse(_INBOUND)
    result = _run_handler(tmp_path, _CLONE_WRITE_SEND, inbound)
    assert isinstance(result, list) and len(result) == 1
    sent = result[0].message
    assert sent is not inbound
    assert sent.field("MSH-6") == "Y"
    assert sent.field("PID-3") == "123"  # a whole-tree clone carries the input's content
    assert inbound.field("MSH-6") == "D"  # the input stays untouched


def test_a_send_that_falls_back_to_msg_is_caught(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mutation arm. If a send the flow cannot settle fell back to sending msg, the render and
    the runtime checks this section relies on both go red."""
    import messagefoundry.corepoint_import as importer

    send_before_clone = _role_send("other-handle", "%OUT", "OB_ACME") + _root_copy(
        "input-handle", "%ADT", "other-handle", "%OUT"
    )

    def delivers_msg(body: str) -> bool:
        return 'Send("OB_ACME", msg)' in _handler_body(_handler_source(body))

    assert not delivers_msg(send_before_clone)

    def falls_back(self: object, step: Control, env: object) -> Control:
        return replace(step, message="msg")  # the mutant: every send delivers msg

    monkeypatch.setattr(importer._Flow, "_send", falls_back)
    assert delivers_msg(send_before_clone)  # the mutant renders the old fallback ...
    inbound = Message.parse(_INBOUND)
    result = _run_handler(tmp_path, send_before_clone, inbound)
    assert isinstance(result, list) and result[0].message is inbound  # ... and delivers the input


def test_msgcreate_then_send_delivers_the_new_message(tmp_path: Path) -> None:
    """A MsgCreate naming a type and a version builds a skeleton through the Message API: default
    encoding characters, MSH-9 and MSH-12, nothing else. The send delivers it, not msg."""

    body = _create("%NEW", _ADT_A04) + _role_send("other-handle", "%NEW", "OB_NEW")
    src = _handler_source(body)
    assert "from messagefoundry import File, Message, Send, handler" in src
    assert '    new_msg = Message.parse("MSH|^~\\\\&|||||||ADT^A04|||2.5.1")' in src
    assert '    sends.append(Send("OB_NEW", new_msg))' in src

    inbound = Message.parse(_INBOUND)
    result = _run_handler(tmp_path, body, inbound)
    assert isinstance(result, list) and len(result) == 1
    created = result[0].message
    assert created is not inbound
    assert created.field("MSH-9") == "ADT^A04"
    assert created.field("MSH-12") == "2.5.1"
    assert created.field("PID-3") is None


@pytest.mark.parametrize(
    "operands",
    [
        pytest.param("", id="nothing"),
        pytest.param(" as " + _span("literal", '"ADT^A04"'), id="type-only"),
        pytest.param(" version " + _span("literal", '"2.5"'), id="version-only"),
        pytest.param(
            " as " + _span("literal", '"ADT_A04"') + " v " + _span("literal", '"2.5"'),
            id="structure-form",
        ),
        pytest.param(_ADT_A04 + " from " + _span("variable", "$template"), id="extra-operand"),
    ],
)
def test_a_msgcreate_without_a_type_and_version_raises(operands: str, tmp_path: Path) -> None:
    """Too little to build a valid MSH: a TODO and a raise at the MsgCreate, and the handle stays
    unbound, so a later send of it refuses too. Nothing guesses the header."""
    body = _create("%NEW", operands) + _role_send("other-handle", "%NEW", "OB_NEW")
    src = _handler_body(_handler_source(body))
    assert "Message.parse(" not in src
    assert "Send(" not in src
    assert '    raise NotImplementedError("Corepoint import: MsgCreate: %NEW is not built:' in src
    with pytest.raises(NotImplementedError, match="MsgCreate: %NEW is not built"):
        _run_handler(tmp_path, body)


def test_a_msgcreate_into_the_input_handle_raises() -> None:
    """Building a new message in the input handle would replace msg; it refuses instead."""
    create = _role_line(
        _span("keyword", "MsgCreate") + " " + _span("input-handle", "%ADT") + _ADT_A04
    )
    body = _handler_body(_handler_source(create + _role_send("input-handle", "%ADT", "OB_IN")))
    assert "would replace msg, the message that arrived" in body
    assert "Send(" not in body


def test_a_catch_cannot_swallow_a_refused_msgcreate(tmp_path: Path) -> None:
    """A refused MsgCreate raises like a refused send, so the Try gains the same re-raise arm."""
    body = "<Try><List>" + _create("%NEW") + '<Line Data="Catch"/>' + "</List></Try>"
    src = _handler_body(_handler_source(body))
    assert src.index("except NotImplementedError:") < src.index("except Exception:")
    with pytest.raises(NotImplementedError, match="MsgCreate"):
        _run_handler(tmp_path, body)


def test_a_send_before_its_clone_fails_loudly(tmp_path: Path) -> None:
    """Statement order counts: at the send, the clone does not exist yet."""
    body = _role_send("other-handle", "%OUT", "OB_ACME") + _root_copy(
        "input-handle", "%ADT", "other-handle", "%OUT"
    )
    src = _handler_body(_handler_source(body))
    assert "Send(" not in src
    assert src.index("raise NotImplementedError") < src.index("out_msg = msg.copy()")
    with pytest.raises(NotImplementedError, match="MsgSend delivers %OUT"):
        _run_handler(tmp_path, body)


def test_a_clone_on_one_branch_is_unbound_after_the_join(tmp_path: Path) -> None:
    """A clone made inside a branch delivers there, but after the join the handle may hold nothing,
    so a send of it refuses. Bound before a branch that does not touch it, the same send delivers
    (the control arm)."""
    branch = (
        '<If Data="If (a)"><List>'
        + _root_copy("input-handle", "%ADT", "other-handle", "%OUT")
        + _role_send("other-handle", "%OUT", "OB_IN_BRANCH")
        + "</List></If>"
    )
    body = branch + _role_send("other-handle", "%OUT", "OB_AFTER")
    src = _handler_body(_handler_source(body))
    assert '        sends.append(Send("OB_IN_BRANCH", out_msg))' in src
    assert 'Send("OB_AFTER"' not in src
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_AFTER:' in src
    with pytest.raises(NotImplementedError, match="MsgSend to OB_AFTER"):
        _run_handler(tmp_path, body)

    untouched = '<If Data="If (a)"><List>' + _role_send("other-handle", "%OUT", "OB_IN_BRANCH")
    control = (
        _CLONE_OUT + untouched + "</List></If>" + _role_send("other-handle", "%OUT", "OB_AFTER")
    )
    control_src = _handler_body(_handler_source(control))
    assert '    sends.append(Send("OB_AFTER", out_msg))' in control_src
    assert "raise NotImplementedError" not in control_src


def test_a_handle_rebound_inside_a_branch_is_unbound_after_the_join() -> None:
    """Bound before the branch AND rebound inside it, the handle may hold either tree after the
    join. Its local keeps one name for the whole handler, so a join that compared local names read
    the rebind as no change and sent ``out_msg`` after it (the differential guard's finding on
    d26545d6f, PR 1900)."""
    rebuilt = '<If Data="If (a)"><List>' + _create("%OUT", _ADT_A04) + "</List></If>"
    body = _handler_body(_handler_source(_CLONE_OUT + rebuilt + _SEND_OUT))
    assert 'Send("OB_OUT"' not in body
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_OUT:' in body


def test_a_clone_on_every_branch_is_still_unbound_after_the_join() -> None:
    """Conservative by design: every condition is a dead placeholder until a human writes it, so no
    branch is known to run, and a handle bound only inside branches is unknown after them."""
    clone = _root_copy("input-handle", "%ADT", "other-handle", "%OUT")
    body = (
        '<If Data="If (a)"><List>'
        + clone
        + '<Line Data="Else"/>'
        + clone
        + "</List></If>"
        + _role_send("other-handle", "%OUT", "OB_AFTER")
    )
    src = _handler_body(_handler_source(body))
    assert 'Send("OB_AFTER"' not in src
    assert "raise NotImplementedError" in src


def test_a_handle_overwritten_on_one_branch_is_unbound_after_the_join() -> None:
    """Bound before the branch, but overwritten by something unknown on one path: after the join it
    may hold either, so it is unbound."""
    body = (
        _root_copy("input-handle", "%ADT", "other-handle", "%OUT")
        + '<If Data="If (a)"><List>'
        + _tree_copy(
            _span("variable", "$saved"), _span("other-handle", "%OUT") + _span("path", "/")
        )
        + "</List></If>"
        + _role_send("other-handle", "%OUT", "OB_AFTER")
    )
    src = _handler_body(_handler_source(body))
    assert 'Send("OB_AFTER"' not in src
    assert "raise NotImplementedError" in src


def test_a_loop_body_cannot_trust_a_handle_it_overwrites() -> None:
    """A later pass may start from what an earlier pass overwrote. A send at the top of the body of
    a handle the body later overwrites refuses; one after a clone in the same pass delivers."""
    overwrite = _tree_copy(
        _span("variable", "$saved"), _span("other-handle", "%OUT") + _span("path", "/")
    )
    clone = _root_copy("input-handle", "%ADT", "other-handle", "%OUT")
    stale = _handler_body(
        _handler_source(
            clone
            + "<Foreach><List>"
            + _role_send("other-handle", "%OUT", "OB_TOP")
            + overwrite
            + "</List></Foreach>"
        )
    )
    assert 'Send("OB_TOP"' not in stale
    assert "raise NotImplementedError" in stale

    fresh = _handler_body(
        _handler_source(
            "<Foreach><List>"
            + clone
            + _role_send("other-handle", "%OUT", "OB_FRESH")
            + "</List></Foreach>"
        )
    )
    assert '        sends.append(Send("OB_FRESH", out_msg))' in fresh
    assert "raise NotImplementedError" not in fresh


def test_a_flat_msgsend_of_the_input_sends_msg() -> None:
    """Brief decision (BACKLOG #313 step 2, Manager's call): a markup-free ``MsgSend`` of a handle
    the flow knows sends that local, judged from the handle its first operand names."""
    body = _handler_body(_handler_source(_WRITE_INPUT + '<Line Data="MsgSend %ADT [OB_FLAT]"/>'))
    assert '    sends.append(Send("OB_FLAT", msg))' in body
    assert "raise NotImplementedError" not in body
    root = _handler_body(_handler_source(_WRITE_INPUT + '<Line Data="MsgSend %ADT/ [OB_FLAT]"/>'))
    assert '    sends.append(Send("OB_FLAT", msg))' in root


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param("MsgSend $out [OB_FLAT]", id="variable"),
        pytest.param("MsgSend %OUT [OB_FLAT]", id="unbound-handle"),
        pytest.param("MsgSend %ADT/PID [OB_FLAT]", id="partial-path"),
        pytest.param("MsgSend [OB_FLAT]", id="no-handle"),
    ],
)
def test_a_flat_msgsend_the_flow_cannot_settle_fails_loudly(statement: str) -> None:
    """The same rule refuses a markup-free send it cannot settle. This is what turned the synthetic
    fixture's ``MsgSend $out [OB_ACME_ADT]`` from a send of msg into a raise."""
    body = _handler_body(_handler_source(_WRITE_INPUT + f'<Line Data="{statement}"/>'))
    assert "Send(" not in body
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_FLAT:' in body


def test_the_fixtures_flat_send_now_refuses() -> None:
    """The synthetic package's markup-free list ends ``MsgSend $out [OB_ACME_ADT]``. A ``$variable``
    names no handle, so it raises where it used to send msg. The outbound stays declared."""
    src = _package_source()
    flat = src.split("def acme_adt_transform")[1].split("@handler")[0]
    assert "Send(" not in flat
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_ACME_ADT:' in flat
    assert 'outbound("OB_ACME_ADT", File(directory=' in src


def test_a_flat_whole_tree_write_unbinds_the_handle() -> None:
    """The markup-free reading maps without handles, but a whole-tree write it makes still unbinds
    the handle it names, so a later send of that handle refuses."""
    body = _handler_body(
        _handler_source(
            _WRITE_INPUT
            + '<Line Data="MsgTreeCopy %OTHER %ADT"/>'
            + '<Line Data="MsgSend %ADT [OB_FLAT]"/>'
        )
    )
    assert "Send(" not in body
    assert "raise NotImplementedError" in body


@pytest.mark.parametrize(
    ("verb", "sends"),
    [
        pytest.param("MsgLoad", False, id="unread-verb-unbinds"),
        pytest.param("MsgLog", True, id="read-only-verb-keeps"),
    ],
)
def test_a_verb_the_flow_does_not_read_unbinds_a_whole_handle(verb: str, sends: bool) -> None:
    """A verb outside the small read-only set may overwrite every handle it names whole, so a later
    send of that handle refuses. ``MsgLoad`` keeps its own TODO marker; only the send changes."""
    statement = _role_line(_span("keyword", verb) + " " + _span("input-handle", "%ADT"))
    body = _handler_body(_handler_source(statement + _role_send("input-handle", "%ADT", "OB_IN")))
    assert ('sends.append(Send("OB_IN", msg))' in body) is sends
    assert ("raise NotImplementedError" in body) is not sends
    assert f"# TODO: Corepoint {verb} — hand-finish" in body


def test_a_hostile_handle_name_becomes_a_safe_local() -> None:
    """The local is derived from untrusted export text: folded to ASCII word characters, suffixed
    ``_msg``, de-duplicated when two handles fold onto one name, and never able to inject code."""
    first = '%O"UT)\nimport os'
    second = "%O-UT import.os"
    src = _handler_source(
        _root_copy("input-handle", "%ADT", "other-handle", first)
        + _root_copy("input-handle", "%ADT", "other-handle", second)
        + _role_send("other-handle", first, "OB_A")
        + _role_send("other-handle", second, "OB_B")
    )
    compile(src, "generated.py", "exec")
    assert "\nimport os" not in src
    body = _handler_body(src)
    assert "    o_ut_import_os_msg = msg.copy()" in body
    assert "    o_ut_import_os_msg_2 = msg.copy()" in body
    assert 'sends.append(Send("OB_A", o_ut_import_os_msg))' in body
    assert 'sends.append(Send("OB_B", o_ut_import_os_msg_2))' in body


def test_colliding_handle_names_number_on_from_the_last_one() -> None:
    """Handles that fold onto one base get ``_msg``, ``_msg_2``, ``_msg_3`` in the order they are
    first bound, and a handle bound again keeps its first name."""
    handles = ["%A-B", "%A.B", "%a b"]
    body = "".join(_root_copy("input-handle", "%ADT", "other-handle", h) for h in handles)
    body += _root_copy("input-handle", "%ADT", "other-handle", handles[0])
    src = _handler_body(_handler_source(body))
    assert [ln.split(" = ")[0].strip() for ln in src.splitlines() if ".copy()" in ln] == [
        "a_b_msg",
        "a_b_msg_2",
        "a_b_msg_3",
        "a_b_msg",
    ]


def test_deeply_nested_loops_and_trys_settle_in_linear_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The export is untrusted, so the flow must not rewalk a body once per enclosing loop or Try,
    nor once per bound handle. Counted in calls to the write reader rather than in seconds, so the
    budget is exact: a body walked again at every level costs about depth x statements calls."""
    import messagefoundry.corepoint_import as importer

    depth, statements = 20, 40
    inner = "".join(
        _root_copy("input-handle", "%ADT", "other-handle", f"%T{i}") for i in range(statements)
    )
    body = inner  # the same handles bound up front too, so every level has many live handles
    for level in range(depth):
        tag = "Foreach" if level % 2 else "Try"
        body = f"<{tag}>{body}</{tag}>"
    body = inner + body + _role_send("other-handle", "%T0", "OB_A")

    calls = 0
    real = importer._whole_written

    def counting(deferred: _Deferred) -> frozenset[str]:
        nonlocal calls
        calls += 1
        return real(deferred)

    monkeypatch.setattr(importer, "_whole_written", counting)
    src = _handler_source(body)
    compile(src, "generated.py", "exec")
    # Linear: each nested statement is read once by the memoized walk. Rewalking at every level
    # would cost about depth x statements = 800 calls.
    assert 0 < calls <= 2 * statements
    # The handle the loops overwrite is unknown after them, so the send refuses rather than guess.
    assert 'Send("OB_A"' not in _handler_body(src)


_CLONE_OUT = _root_copy("input-handle", "%ADT", "other-handle", "%OUT")
_SEND_OUT = _role_send("other-handle", "%OUT", "OB_OUT")


@pytest.mark.parametrize(
    "overwrite",
    [
        pytest.param(
            _tree_copy(
                _span("input-handle", "%ADT") + _span("path", "/"),
                _span("other-handle", "%OUT") + _span("path", "/"),
            ).replace(" to ", " merging into "),
            id="mode-word",
        ),
        pytest.param(
            _role_line(
                _span("keyword", "MsgTreeCopy")
                + " "
                + _span("variable", "$saved")
                + " to "
                + _span("other-handle", "%OUT")
                + _span("path", "/")
                + " mode "
                + _span("literal", '"replace"')
            ),
            id="third-operand",
        ),
        pytest.param(
            _role_line(
                _span("keyword", "MsgCreate")
                + " "
                + _span("literal", '"ADT^A04"')
                + " "
                + _span("literal", '"2.5.1"')
                + " in "
                + _span("other-handle", "%OUT")
            ),
            id="msgcreate-handle-last",
        ),
        pytest.param(
            "<Line Data=\"&lt;span class='kw'&gt;MsgTreeCopy&lt;/span&gt; "
            "&lt;span class='pth'&gt;%OTHER/&lt;/span&gt; "
            "&lt;span class='pth'&gt;%OUT/&lt;/span&gt;\"/>",
            id="unlisted-span-classes",
        ),
        pytest.param(
            '<Call Data="ActionListCall &quot;Rebuild&quot; pass %OUT"><Actions/></Call>',
            id="call-naming-the-handle",
        ),
        pytest.param('<Line Data="ItemAppend %OUT/ &quot;x&quot;"/>', id="flat-whole-write"),
    ],
)
def test_a_statement_that_may_overwrite_a_bound_handle_unbinds_it(overwrite: str) -> None:
    """Fail closed: a statement this module does not read as a plain clone or a field write may
    overwrite every handle it names, whatever operand order or markup it uses. A later send of
    that handle raises rather than deliver the clone made before it."""
    body = _handler_body(_handler_source(_CLONE_OUT + overwrite + _SEND_OUT))
    assert "out_msg = msg.copy()" in body
    assert 'Send("OB_OUT"' not in body
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_OUT:' in body


def test_a_tree_copy_read_the_other_way_round_does_not_bind() -> None:
    """``MsgTreeCopy %OUT/ from %A2/`` names its operands in the other order: it overwrites %OUT.
    Reading it as a clone would bind %A2 from the stale %OUT and keep %OUT, so it is not a clone and
    both handles it names are unknown after it."""
    reverse = _tree_copy(
        _span("other-handle", "%OUT") + _span("path", "/"),
        _span("other-handle", "%A2") + _span("path", "/"),
    ).replace(" to ", " from ")
    body = _handler_body(_handler_source(_CLONE_OUT + reverse + _SEND_OUT))
    assert "a2_msg" not in body
    assert 'Send("OB_OUT"' not in body


def test_a_msgcreate_with_a_word_it_does_not_read_raises() -> None:
    """An unstyled word beyond ``as``/``version`` may change what is built, so it refuses."""
    merging = _create("%NEW", _ADT_A04, " merging input")
    body = _handler_body(_handler_source(merging + _role_send("other-handle", "%NEW", "OB_NEW")))
    assert "Message.parse(" not in body
    assert "a word this import does not read" in body


def test_a_markup_free_write_lands_on_the_handle_it_addresses() -> None:
    """Once the list names an input, a markup-free write to a clone lands on the clone's local, and
    one to a handle nobody bound declines rather than land on msg."""
    body = _handler_body(
        _handler_source(
            _CLONE_OUT
            + '<Line Data="ItemClear %OUT/PID-19"/>'
            + '<Line Data="ItemClear %GONE/PID-20"/>'
            + _SEND_OUT
        )
    )
    assert '    set_field(out_msg, "PID-19", "")' in body
    assert "PID-20" not in body.split("# TODO")[0]
    assert "(cross-message); intended target PID-20" in body
    assert 'set_field(msg, "PID-20"' not in body
    assert '    sends.append(Send("OB_OUT", out_msg))' in body


def test_a_try_with_no_catch_keeps_what_its_body_bound() -> None:
    """No Catch renders as ``except Exception: raise``, so the code after it runs only when the body
    completed: a clone made in the body is bound there."""
    body = _handler_body(_handler_source("<Try><List>" + _CLONE_OUT + "</List></Try>" + _SEND_OUT))
    assert '    sends.append(Send("OB_OUT", out_msg))' in body
    with_catch = _handler_body(
        _handler_source(
            "<Try><List>" + _CLONE_OUT + '<Line Data="Catch"/></List></Try>' + _SEND_OUT
        )
    )
    assert 'Send("OB_OUT"' not in with_catch


def test_a_disabled_write_names_the_local_it_would_write() -> None:
    """Re-enabling a preserved write must not lose which message it targeted."""
    disabled = (
        '<Block Disabled="1" Data="old"><List>'
        + _write("other-handle", "%OUT", "Y")
        + "</List></Block>"
    )
    src = _handler_source(_CLONE_OUT + disabled + _SEND_OUT)
    assert 'ItemCopy -> set_field("MSH-6", "Y") on out_msg' in src


def _reverse_copy(verb_markup: str = "", from_markup: str = " from ") -> str:
    """``MsgTreeCopy %OUT/ from %A2/``: overwrites %OUT, with the verb and ``from`` styled or not."""
    return _role_line(
        (verb_markup or _span("keyword", "MsgTreeCopy"))
        + " "
        + _span("other-handle", "%OUT")
        + _span("path", "/")
        + from_markup
        + _span("other-handle", "%A2")
        + _span("path", "/")
    )


@pytest.mark.parametrize(
    "reverse",
    [
        pytest.param(_reverse_copy(from_markup=" " + _span("keyword", "from") + " "), id="styled"),
        pytest.param(_reverse_copy().replace("<Line ", "<Lines ", 1), id="in-unknown-tag"),
    ],
)
def test_a_reversed_copy_is_never_read_as_a_clone(reverse: str) -> None:
    """A ``from`` reverses the copy whether the exporter styles it as a keyword or leaves it as
    text, and whether the statement sits in a modelled tag or an unknown one."""
    body = _handler_body(_handler_source(_CLONE_OUT + reverse + _SEND_OUT))
    assert "a2_msg" not in body
    assert 'Send("OB_OUT"' not in body


def test_an_unstyled_msgcreate_verb_is_not_read_as_a_word() -> None:
    """When the exporter leaves the verb unstyled, the verb itself is not an extra word."""
    create = _role_line("MsgCreate " + _span("other-handle", "%NEW") + _ADT_A04)
    body = _handler_body(_handler_source(create + _role_send("other-handle", "%NEW", "OB_NEW")))
    assert '    sends.append(Send("OB_NEW", new_msg))' in body


def test_a_msgcreate_type_with_a_trailing_newline_is_refused() -> None:
    """The shapes are matched whole: a type literal carrying a newline is not ``ADT^A04``."""
    create = _create(
        "%NEW", " as " + _span("literal", '"ADT^A04\n"') + " version " + _span("literal", '"2.5"')
    )
    body = _handler_body(_handler_source(create))
    assert "Message.parse(" not in body
    assert "raise NotImplementedError" in body


def test_a_write_to_a_built_message_outside_its_msh_declines() -> None:
    """A MsgCreate skeleton holds only an MSH, and ``Message.set`` raises on an absent segment. A
    write to its MSH maps; a write to any other segment is a TODO, never a call certain to raise."""
    body = _handler_body(
        _handler_source(
            _create("%NEW", _ADT_A04)
            + _write("other-handle", "%NEW", "X")
            + _role_line(
                _span("keyword", "ItemCopy")
                + " "
                + _span("literal", '"M"')
                + " to "
                + _span("other-handle", "%NEW")
                + _span("path", "/PID-8")
            )
            + _role_send("other-handle", "%NEW", "OB_NEW")
        )
    )
    assert '    set_field(new_msg, "MSH-6", "X")' in body
    assert 'set_field(new_msg, "PID-8"' not in body
    assert "skeleton has only an MSH segment" in body
    assert "intended target PID-8" in body


def test_a_markup_free_write_without_an_input_still_lands_on_its_handle() -> None:
    """A list with role markup but no input handle does not fall back to msg either."""
    body = _handler_body(
        _handler_source(
            _create("%NEW", _ADT_A04)
            + '<Line Data="ItemClear %NEW/MSH-12"/>'
            + _role_send("other-handle", "%NEW", "OB_NEW")
        )
    )
    assert '    set_field(new_msg, "MSH-12", "")' in body
    assert 'set_field(msg, "MSH-12"' not in body


def test_an_inlined_call_passing_a_handle_still_unbinds_it() -> None:
    """The Lander's PR 1900 repro. An inlined list names the passed message by its OWN handle, which
    nothing ties to the caller's, so it can rebuild the message unseen: here a MsgCreate under %P.
    What the call line passes is unknown after it, inlined or not, and a later send raises."""
    rebuild = (
        '<Call Data="ActionListCall &quot;Rebuild&quot; pass %OUT"><Actions>'
        + _create("%P", _ADT_A04)
        + "</Actions></Call>"
    )
    body = _handler_body(
        _handler_source(_CLONE_OUT + rebuild + '<Line Data="MsgSend %OUT [OB_OUT]"/>')
    )
    assert 'Send("OB_OUT"' not in body
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_OUT:' in body

    # The input handed to an inlined list is unknown after it too: an edit the list makes in place
    # is a TODO in its body (it never lands on msg), so sending msg would drop it. A raise instead.
    call = (
        '<Call Data="ActionListCall &quot;Sub&quot; pass %ADT"><Actions>'
        '<Line Data="ItemClear %ADT/PID-19"/></Actions></Call>'
    )
    passed = _handler_body(
        _handler_source(_WRITE_INPUT + call + _role_send("input-handle", "%ADT", "OB_IN"))
    )
    assert 'Send("OB_IN"' not in passed
    assert 'set_field(msg, "PID-19"' not in passed

    # A called list that builds any message may be replacing the input under its own name.
    rebuilt = _handler_body(
        _handler_source(
            _WRITE_INPUT
            + _inlined_call(_create("%P", _ADT_A04), passing=" pass %ADT")
            + _role_send("input-handle", "%ADT", "OB_IN")
        )
    )
    assert 'Send("OB_IN"' not in rebuilt
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_IN:' in rebuilt

    # The control arm: a call whose list only reads (MsgLog) leaves the input bound.
    plain = _inlined_call(_MSGLOG_P, passing="")
    kept = _handler_body(
        _handler_source(_WRITE_INPUT + plain + _role_send("input-handle", "%ADT", "OB_IN"))
    )
    assert '    sends.append(Send("OB_IN", msg))' in kept


_MSGLOG_P = _role_line(_span("keyword", "MsgLog") + " " + _span("other-handle", "%P"))


def _inlined_call(*statements: str, passing: str = " pass %OUT") -> str:
    return (
        f'<Call Data="ActionListCall &quot;Sub&quot;{passing}"><Actions>'
        + "".join(statements)
        + "</Actions></Call>"
    )


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(_inlined_call(_create("%OUT", _ADT_A04)), id="rebuilt-under-the-same-name"),
        pytest.param(
            _inlined_call(_write("other-handle", "%OUT", "SUB"), passing=""),
            id="body-writes-a-caller-name",
        ),
        pytest.param(
            _inlined_call('<Line Data="EnvLogText &quot;x&quot;"/>', passing=" pass %OUT/PID"),
            id="partial-path-pass",
        ),
        pytest.param(
            _inlined_call(_create("%P", _ADT_A04), passing=" (%OUT)"), id="parenthesised-pass"
        ),
        pytest.param(
            _inlined_call(
                _create("%P", _ADT_A04),
                passing=" &lt;span class='action-list-call-pass'&gt;Pass: OUT&lt;/span&gt;",
            ),
            id="pass-span-without-percent",
        ),
        pytest.param(_inlined_call(_create("%out", _ADT_A04), passing=""), id="other-case"),
        pytest.param(
            _inlined_call('<Switch Data="Mystery %OUT/PID-5"/>', passing=""),
            id="unknown-tag-in-the-list",
        ),
        pytest.param('<Line Data="ActionListCall &quot;Rebuild&quot;"/>', id="not-inlined"),
    ],
)
def test_an_inlined_call_runs_in_its_own_scope(call: str) -> None:
    """A called list starts knowing no handle, and every handle its call line passes (whole or as a
    path) or its body names or binds is unknown to the caller afterwards. So none of these sends the
    caller's %OUT, and a send inside the list of a handle it did not bind refuses."""
    body = _handler_body(_handler_source(_CLONE_OUT + call + _SEND_OUT))
    assert 'Send("OB_OUT"' not in body
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_OUT:' in body


def _call_of(passing: str, *statements: str) -> str:
    """An inlined ``ActionListCall "Sub"<passing>``. ``passing`` is raw text, escaped here, where
    :func:`_inlined_call` takes it already escaped."""
    return (
        f'<Call Data="ActionListCall &quot;Sub&quot;{html.escape(passing)}"><Actions>'
        + "".join(statements)
        + "</Actions></Call>"
    )


def _lander_case(handle: str, call: str, *, loop: bool = False) -> str:
    """Clone the input into ``handle``, run ``call``, then send ``handle``. With ``loop``, the send
    and the call sit in a ForEach, so a later pass would send what an earlier call rebuilt."""
    send = _role_send("other-handle", handle, "OB_OUT")
    clone = _root_copy("input-handle", "%ADT", "other-handle", handle)
    if loop:
        return clone + "<Foreach>" + send + call + "</Foreach>"
    return clone + call + send


@pytest.mark.parametrize(
    "export",
    [
        pytest.param(
            _lander_case("%OUT-A", _call_of(" pass %OUT-A", _create("%P", _ADT_A04))),
            id="hyphen-passed",
        ),
        pytest.param(
            _lander_case("%OUT-A", _call_of("", _create("%OUT-A", _ADT_A04))),
            id="hyphen-rebuilt-without-a-pass",
        ),
        pytest.param(
            _lander_case("%OUT.A", _call_of(" pass %OUT.A", _create("%P", _ADT_A04))),
            id="dot",
        ),
        pytest.param(
            _lander_case("%AUSGANGÄ", _call_of("", _create("%AUSGANGÄ", _ADT_A04))),
            id="non-ascii",
        ),
        pytest.param(
            _root_copy("input-handle", "ADT", "other-handle", "OUT")
            + _call_of("", _create("OUT", _ADT_A04))
            + _role_send("other-handle", "OUT", "OB_OUT"),
            id="no-percent-anywhere",
        ),
        pytest.param(
            _lander_case("%OUT-A", _call_of(" pass %OUT-A", _create("%P", _ADT_A04)), loop=True),
            id="hyphen-in-a-foreach",
        ),
    ],
)
def test_the_landers_stale_local_repros_all_raise(export: str) -> None:
    """The Lander's QA of d401cdb5b on PR 1900: name matching missed ``-``, ``.``, non-ASCII and
    ``%``-free handles, so each of these sent the clone a called list had rebuilt. A call now leaves
    every caller handle but the input unknown, whatever its name."""
    body = _handler_body(_handler_source(export))
    assert 'Send("OB_OUT"' not in body
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_OUT:' in body


# Handle spellings an export may carry, each one the clone below binds to its own local (the control
# in the test proves that). A rule that matched handles by name missed at least the first four.
_HOSTILE_HANDLES = (
    "%OUT-A",
    "%OUT.A",
    "%AUSGANGÄ",
    "OUT",
    "%out",
    "%OUT A",
    "%OUT-",
    "%Ω",
    "%ÄÖ-ß.x",
    "%OUT$1",
    "%OUT(1)",
    "%OUT;A",
    '%O"UT',
    "%OUT/X",
    "%_",
    "%1OUT",
    "%ADT2",
)


def _call_shapes(handle: str) -> list[str]:
    """Calls that may rebuild ``handle`` or leave it alone, passing it or not."""
    log = '<Line Data="EnvLogText &quot;x&quot;"/>'
    return [
        _call_of(f" pass {handle}", _create("%P", _ADT_A04)),
        _call_of("", _create(handle, _ADT_A04)),
        _call_of(f" pass {handle}", log),
        _call_of("", log),
        # The only shape that spares the input: the clone must still be unknown after it.
        _call_of(f" pass {handle}", _MSGLOG_P),
        _call_of("", _MSGLOG_P),
        _call_of(f" ({handle})", _write("other-handle", handle, "SUB")),
        '<Line Data="ActionListCall &quot;Sub&quot;"/>',
    ]


@pytest.mark.parametrize("handle", _HOSTILE_HANDLES)
def test_no_handle_spelling_sends_a_clone_made_before_a_call(handle: str) -> None:
    """Property: for every spelling and every call shape, clone, then call, then send never renders
    a Send of the clone. The control arm, the same clone sent BEFORE the call, does send it, so the
    spelling really binds and the refusal is the call's doing."""
    clone = _root_copy("input-handle", "%ADT", "other-handle", handle)
    send = _role_send("other-handle", handle, "OB_OUT")
    for call in _call_shapes(handle):
        before = _handler_body(_handler_source(clone + send + call))
        assert re.search(r'sends\.append\(Send\("OB_OUT", \w+_msg(_\d+)?\)\)', before), handle
        after = _handler_body(_handler_source(clone + call + send))
        assert 'Send("OB_OUT"' not in after, (handle, call)
        assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_OUT:' in after


def test_a_call_that_only_reads_leaves_the_input_bound() -> None:
    """The control for the input: a call whose list only reads leaves the input as msg, whatever
    it passes, while a clone made before the same call is unknown after it."""
    body = _handler_body(
        _handler_source(
            _CLONE_OUT
            + _call_of(" pass %ADT", _MSGLOG_P)
            + _role_send("input-handle", "%ADT", "OB_IN")
            + _SEND_OUT
        )
    )
    assert '    sends.append(Send("OB_IN", msg))' in body
    assert 'Send("OB_OUT"' not in body


_A04 = "as &quot;ADT^A04&quot; version &quot;2.5.1&quot;"


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(
            _call_of(" pass ADT", f'<Line Data="MsgCreate ADT {_A04}"/>'),
            id="markup-free-msgcreate-without-percent",
        ),
        pytest.param(
            _call_of(" pass ADT", '<Line Data="MsgTreeCopy NEW/ to ADT/"/>'),
            id="markup-free-copy-without-percent",
        ),
        pytest.param(
            _call_of(
                " pass ADT",
                f"<Line Data=\"&lt;span class='handle'&gt;MsgCreate&lt;/span&gt; "
                f"&lt;span class='handle'&gt;ADT&lt;/span&gt; {_A04}\"/>",
            ),
            id="unlisted-span-class",
        ),
        pytest.param(
            _call_of(" pass ADT", f'<Switch Data="MsgCreate ADT {_A04}"/>'),
            id="unknown-tag",
        ),
        pytest.param(
            '<Call Data="ActionListCall &quot;Sub&quot; pass ADT"><Param Name="x"/></Call>',
            id="param-only",
        ),
        pytest.param(_call_of(" pass ADT", "<Line/>"), id="empty-line-only"),
        pytest.param(_call_of(" pass ADT", '<Line Comment="see Sub"/>'), id="comment-only"),
        pytest.param(_call_of(" pass ADT", '<Line Data="Returns %P"/>'), id="returns"),
        pytest.param(
            _call_of(" pass ADT returning ADT", '<Line Data="EnvLogText &quot;x&quot;"/>'),
            id="unread-verb-and-a-result-clause",
        ),
        pytest.param(_call_of(" pass ADT", _write("other-handle", "%P", "SUB")), id="field-write"),
        pytest.param(
            _call_of(" pass ADT", _call_of("", _MSGLOG_P)), id="nested-call-that-only-reads"
        ),
    ],
)
def test_a_call_that_may_do_more_than_read_unbinds_the_input(call: str) -> None:
    """The input survives a call only when the called list does nothing but read, judged by verb.
    Each of these could replace the input whole under a spelling no operand reading sees, or edit
    it in place in a TODO, so the send of the input after it raises. The control (no call) sends."""
    write = _write("input-handle", "ADT", "X")
    send = _role_send("input-handle", "ADT", "OB_IN")
    control = _handler_body(_handler_source(write + send))
    assert '    sends.append(Send("OB_IN", msg))' in control
    body = _handler_body(_handler_source(write + call + send))
    assert 'Send("OB_IN"' not in body
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_IN:' in body


_ELSE = '<Line Data="Else"/>'


def _else_hiding(*statements: str) -> str:
    """An If whose Else list holds a second bodyless Else marker, so what follows it becomes a
    branch of the Else branch: a shape the walk and the render never reach."""
    return (
        f'<Line Data="If (x)"><List>{_MSGLOG_P}</List></Line>'
        f'<Line Data="Else"><List>{_MSGLOG_P}{_ELSE}' + "".join(statements) + "</List></Line>"
    )


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(_call_of(" returning %ADT", _MSGLOG_P), id="result-clause"),
        pytest.param(_call_of(" pass %ADT", _else_hiding(_create("%Q", _ADT_A04))), id="hidden"),
        pytest.param(
            _call_of(
                " pass %ADT",
                _role_line(
                    _span("keyword", "MsgLog")
                    + " "
                    + _span("other-handle", "%P")
                    + " into "
                    + _span("other-handle", "%ADT")
                    + _span("path", "/")
                ),
            ),
            id="log-with-a-second-handle",
        ),
        pytest.param(
            _call_of(
                " pass %ADT",
                _role_line(
                    "MsgCreate " + _span("keyword", "MsgLog") + " " + _span("other-handle", "%P")
                ),
            ),
            id="verb-misread-as-msglog",
        ),
        pytest.param(
            _call_of(
                " pass %ADT",
                _MSGLOG_P,
                _create("%ADT", _ADT_A04).replace("<Line ", '<Line Disabled="off" ', 1),
            ),
            id="unrecognised-disabled-spelling",
        ),
        pytest.param(_call_of(" pass %ADT", _MSGLOG_P, '<Line Data="LoopExit"/>'), id="loop-exit"),
        pytest.param(
            _call_of(" pass %ADT", _role_send("other-handle", "%P", "OB_P")), id="send-in-the-list"
        ),
    ],
)
def test_round_two_call_shapes_unbind_the_input(call: str) -> None:
    """Code review round 2 of the re-cut: each of these sent msg after a call that could replace or
    edit it. The input now survives only a plain call line over a list of plain ``MsgLog`` lines."""
    body = _handler_body(
        _handler_source(_WRITE_INPUT + call + _role_send("input-handle", "%ADT", "OB_IN"))
    )
    assert 'Send("OB_IN"' not in body
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_IN:' in body


def test_a_call_hidden_in_a_branch_of_a_branch_unbinds_every_handle() -> None:
    """The walk never reaches a branch's own branches, so a construct carrying one leaves nothing
    vouched for after it: a call hidden there cannot leave a stale clone bound."""
    call = _call_of(" pass %OUT", _create("%OUT", _ADT_A04))
    body = _handler_body(_handler_source(_CLONE_OUT + _else_hiding(call) + _SEND_OUT))
    assert 'Send("OB_OUT"' not in body
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_OUT:' in body


def test_a_call_in_a_loops_stray_branch_unbinds_the_clone_inside_the_loop() -> None:
    """A misplaced Catch moves the rest of a loop's list into a stray branch that renders after the
    loop. In the source the call is still inside the loop, so a send early in the loop raises."""
    loop = (
        "<Foreach><List>"
        + _SEND_OUT
        + '<Line Data="Catch"/>'
        + _call_of(" pass %OUT", _create("%P", _ADT_A04))
        + "</List></Foreach>"
    )
    body = _handler_body(_handler_source(_CLONE_OUT + loop))
    assert 'Send("OB_OUT"' not in body


@pytest.mark.parametrize("tag", ["Line", "Block"])
def test_a_call_on_a_line_or_block_never_supplies_the_callers_input(tag: str) -> None:
    """A call spelled on a ``<Line>`` or ``<Block>`` is a call too: its list's input name never
    becomes the caller's input, so a caller scratch handle with that name is not read as msg."""
    log_input = _role_line(_span("keyword", "MsgLog") + " " + _span("input-handle", "%P"))
    call = f'<{tag} Data="ActionListCall &quot;Sub&quot;"><Actions>{log_input}</Actions></{tag}>'
    body = _handler_body(
        _handler_source(
            _write("other-handle", "%P", "BUILT")
            + call
            + _role_send("other-handle", "%P", "OB_OUT")
        )
    )
    assert "set_field(msg" not in body
    assert 'Send("OB_OUT"' not in body


def test_a_called_lists_input_name_never_becomes_the_callers_input() -> None:
    """Code review of the re-cut: with no input-handle of the caller's own, the called list's input
    name must not decide the caller's input, or a caller scratch handle with that name is read as
    msg. The control (no call) refuses the same send."""
    write = _write("other-handle", "%OUT", "BUILT")
    send = _role_send("other-handle", "%OUT", "OB_OUT")
    call = _call_of(" pass %OUT", _write("input-handle", "%OUT", "STAMP"))
    for export in (write + send, write + call + send):
        body = _handler_body(_handler_source(export))
        assert "set_field(msg" not in body
        assert 'Send("OB_OUT"' not in body


def test_a_call_with_no_data_wrapping_a_nested_call_keeps_its_own_scope() -> None:
    """A ``<Call>`` with no ``@Data`` is never dissolved as a branch-group wrapper, so its list
    runs in its own scope even when it holds a nested call, and a handle it rebuilds is unknown."""
    call = (
        '<Call Name="Sub"><Actions><Line Data="ActionListCall &quot;Inner&quot;"/>'
        + _create("%OUT", _ADT_A04)
        + "</Actions></Call>"
    )
    body = _handler_body(_handler_source(_CLONE_OUT + call + _SEND_OUT))
    assert 'Send("OB_OUT"' not in body
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_OUT:' in body


# --- a statement the flow does not read unbinds every handle; handle case is ignored --------------
#
# The Manager's decisions after the re-cut, all fail closed. Synthetic fixtures only.

_WRITE_BARE_INPUT = _write("input-handle", "ADT", "X")
_SEND_BARE_INPUT = _role_send("input-handle", "ADT", "OB_IN")


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param(f'<Line Data="MsgCreate ADT {_A04}"/>', id="markup-free-msgcreate"),
        pytest.param('<Line Data="MsgTreeCopy NEW/ to ADT/"/>', id="markup-free-copy"),
        pytest.param('<Line Data="MsgLoad ADT"/>', id="unread-verb"),
    ],
)
def test_a_whole_write_of_a_handle_without_percent_unbinds_the_input(statement: str) -> None:
    """Open finding 1 of the re-cut, verified as ``Send("OB_IN", msg)``: a markup-free whole-tree
    write of a handle spelled without ``%`` was invisible. Now the send raises. The control, the
    same list without the statement, still sends msg."""
    control = _handler_body(_handler_source(_WRITE_BARE_INPUT + _SEND_BARE_INPUT))
    assert '    sends.append(Send("OB_IN", msg))' in control
    body = _handler_body(_handler_source(_WRITE_BARE_INPUT + statement + _SEND_BARE_INPUT))
    assert 'Send("OB_IN"' not in body
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_IN:' in body


_UNREAD_STATEMENTS = [
    pytest.param('<Line Data="CallActionList &quot;Rebuild&quot; pass %ADT"/>', id="call-alias"),
    pytest.param(
        f'<Call Data="ActionListExit"><Actions>{_create("%OUT", _ADT_A04)}</Actions></Call>',
        id="call-tag-with-another-verb",
    ),
    pytest.param('<Line Data="EnvLogText &quot;x&quot;"/>', id="unread-verb-naming-no-handle"),
    pytest.param(
        _role_line("MsgCreate " + _span("keyword", "MsgLog") + " " + _span("other-handle", "%P")),
        id="verb-misread-from-a-later-span",
    ),
    pytest.param(
        _role_line(
            _span("keyword", "MsgTreeCopy")
            + " "
            + _span("other-handle", "%NEW")
            + _span("path", "/")
            + " to "
            + "<span class='handle'>OUT</span>"
        ),
        id="unlisted-span-class",
    ),
]


@pytest.mark.parametrize("statement", _UNREAD_STATEMENTS)
def test_a_statement_the_flow_does_not_read_unbinds_every_handle(statement: str) -> None:
    """Open findings 2 and 3, and their family: a verb the flow does not model, an
    ``ActionListCall`` under another spelling, a ``<Call>`` carrying another verb, or a verb read
    from a later span may write any handle. Neither the clone nor the input is sent after it."""
    body = _handler_body(
        _handler_source(
            _WRITE_INPUT
            + _CLONE_OUT
            + statement
            + _SEND_OUT
            + _role_send("input-handle", "%ADT", "OB_IN")
        )
    )
    assert 'Send("OB_OUT"' not in body
    assert 'Send("OB_IN"' not in body


@pytest.mark.parametrize("statement", _UNREAD_STATEMENTS)
def test_a_statement_the_flow_does_not_read_unbinds_every_handle_in_a_loop(statement: str) -> None:
    """The same rule through a loop: a later pass may start from what it wrote, so the send at the
    top of the loop raises too."""
    loop = "<Foreach><List>" + _SEND_OUT + statement + "</List></Foreach>"
    body = _handler_body(_handler_source(_CLONE_OUT + loop))
    assert 'Send("OB_OUT"' not in body


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param(_MSGLOG_P, id="msglog"),
        pytest.param('<Line Data="MsgLog %P"/>', id="markup-free-msglog"),
        pytest.param(_write("input-handle", "%ADT", "Y"), id="field-write"),
        pytest.param('<Line Data="ItemClear %OUT/PID-19"/>', id="markup-free-field-write"),
    ],
)
def test_a_read_only_statement_between_a_clone_and_its_send_keeps_the_clone(
    statement: str,
) -> None:
    """The control: a statement the flow does read, and that names the clone only as a path or
    not at all, leaves the clone bound."""
    body = _handler_body(_handler_source(_CLONE_OUT + statement + _SEND_OUT))
    assert '    sends.append(Send("OB_OUT", out_msg))' in body


@pytest.mark.parametrize(
    ("export", "dest"),
    [
        pytest.param(
            _WRITE_INPUT + _create("%adt", _ADT_A04) + _role_send("input-handle", "%ADT", "OB_IN"),
            "OB_IN",
            id="msgcreate-into-the-input-in-another-case",
        ),
        pytest.param(
            _WRITE_INPUT
            + _root_copy("other-handle", "%NEW", "other-handle", "%adt")
            + _role_send("input-handle", "%ADT", "OB_IN"),
            "OB_IN",
            id="copy-into-the-input-in-another-case",
        ),
        pytest.param(
            _CLONE_OUT + _create("%out", _ADT_A04) + _SEND_OUT,
            "OB_OUT",
            id="msgcreate-over-a-clone-in-another-case",
        ),
        pytest.param(
            _CLONE_OUT
            + _root_copy("input-handle", "%ADT", "other-handle", "%Out")
            + _write("other-handle", "%Out", "Y")
            + _SEND_OUT,
            "OB_OUT",
            id="clone-over-a-clone-in-another-case",
        ),
    ],
)
def test_handle_case_is_ignored_for_every_unbind(export: str, dest: str) -> None:
    """Corepoint's handle case-sensitivity is unverified, so the import assumes the worst: a write
    to ``%adt`` may overwrite ``%ADT``. A later send of ``%ADT`` raises rather than send the old
    local."""
    body = _handler_body(_handler_source(export))
    assert f'Send("{dest}"' not in body
    assert f'raise NotImplementedError("Corepoint import: MsgSend to {dest}:' in body


_SEND_INPUT = _role_send("input-handle", "%ADT", "OB_IN")
_REPLACE_ADT = _root_copy("other-handle", "%NEW", "other-handle", "%ADT")


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param(
            _role_line(
                "MsgCreate "
                + _span("keyword", "Returns")
                + " "
                + _span("other-handle", "%ADT")
                + _ADT_A04
            ),
            id="exit-verb-misread-from-a-later-span",
        ),
        pytest.param(
            _role_line(
                "MsgLoad " + _span("keyword", "LoopExit") + " " + _span("other-handle", "%ADT")
            ),
            id="break-verb-misread-from-a-later-span",
        ),
        pytest.param(
            _role_line(
                _span("keyword", "MsgCreate")
                + " "
                + _span("literal", "ADT")
                + " as "
                + _span("literal", '"ADT^A04"')
                + " version "
                + _span("literal", '"2.5.1"')
            ),
            id="handle-in-a-bare-literal-span",
        ),
        pytest.param(
            _role_line(
                _span("keyword", "MsgTreeCopy")
                + " "
                + _span("other-handle", "%NEW")
                + _span("path", "/")
                + " to "
                + _span("variable", "ADT")
            ),
            id="handle-in-a-variable-span",
        ),
        pytest.param(
            _role_line(
                _span("keyword", "MsgTreeCopy")
                + " "
                + _span("other-handle", "%NEW")
                + _span("path", "/")
                + " to "
                + _span("other-handle", "%OUT")
                + _span("path", "/")
                + " "
                + _span("action-list-call-pass", "%ADT")
            ),
            id="handle-in-a-pass-span",
        ),
        pytest.param(
            _role_line(
                _span("keyword", "MsgTreeCopy")
                + " "
                + _span("other-handle", "%NEW")
                + _span("path", "/*")
                + " to "
                + _span("input-handle", "%ADT")
                + _span("path", "/*")
            ),
            id="whole-tree-path-not-spelled-slash",
        ),
        pytest.param(
            _role_line(
                _span("keyword", "MsgLog")
                + " "
                + _span("other-handle", "%NEW")
                + " "
                + _span("other-handle", "%ADT")
            ),
            id="msglog-with-two-handles",
        ),
        pytest.param(
            _REPLACE_ADT.replace("<Line ", '<Line Disabled="N" ', 1), id="disabled-spelled-N"
        ),
        pytest.param("<Line>MsgTreeCopy %NEW/ to %ADT/</Line>", id="statement-in-element-text"),
        pytest.param('<MsgCreate Handle="%ADT" Type="ADT^A04"/>', id="unmodelled-element-no-data"),
    ],
)
def test_round_three_shapes_unbind_the_input(statement: str) -> None:
    """Code review of the unread-statement rule: each of these could replace the input in a way no
    rule saw, and the send of the input after it rendered ``Send("OB_IN", msg)``. Now it raises."""
    body = _handler_body(_handler_source(_WRITE_INPUT + statement + _SEND_INPUT))
    assert 'Send("OB_IN"' not in body
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_IN:' in body


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param(
            _role_line(
                _span("keyword", "ItemClear") + " " + _span("variable", "ADT"),
            ),
            id="variable-span-without-a-dollar",
        ),
        pytest.param(
            _role_line(
                _span("keyword", "ItemClear")
                + " "
                + _span("input-handle", "%ADT")
                + _span("path", "/*")
            ),
            id="field-write-to-a-whole-tree-path",
        ),
        pytest.param(
            '<Line Data="ItemClear %ADT/*"/>', id="markup-free-field-write-to-a-whole-tree"
        ),
        pytest.param(_create("％ADT", _ADT_A04), id="fullwidth-percent"),
        pytest.param(
            _role_line(
                _span("keyword", "MsgLog")
                + " "
                + _span("other-handle", "%NEW")
                + " "
                + _span("detail", "into ADT")
            ),
            id="msglog-with-a-detail-span",
        ),
        pytest.param(
            _create("%OUT", _ADT_A04, " " + _span("variable", "ADT")),
            id="msgcreate-with-a-trailing-handle",
        ),
        pytest.param('<Line Data=" ">MsgTreeCopy %NEW/ to %ADT/</Line>', id="blank-data-and-text"),
        pytest.param(
            '<Line Data="MsgLog %P">MsgTreeCopy %NEW/ to %ADT/</Line>', id="data-and-text"
        ),
        pytest.param(
            _role_line(
                _span("keyword", "MsgSend")
                + " "
                + _span("other-handle", "%NEW")
                + " to connection "
                + _span("literal", '"OB_X"')
                + " reply into "
                + _span("input-handle", "%ADT")
            ),
            id="send-with-a-second-handle",
        ),
        pytest.param(
            '<Foreach Data="ForEach %ADT in %BATCH"><List>' + _MSGLOG_P + "</List></Foreach>",
            id="foreach-binding-a-handle",
        ),
        pytest.param(
            '<Call Comment=\'ActionListCall "Sub"\' Returning="%ADT"><Actions>'
            + _MSGLOG_P
            + "</Actions></Call>",
            id="call-line-in-a-comment",
        ),
        pytest.param(
            _role_line(
                _span("keyword", "MsgCreate")
                + " "
                + _span("other-handle", "%NEW")
                + _ADT_A04
                + " "
                + _span("action-list-call-custom", "from template X")
            )
            + _role_send("other-handle", "%NEW", "OB_NEW"),
            id="unread-msgcreate-never-binds",
        ),
    ],
)
def test_round_four_shapes_unbind_the_input(statement: str) -> None:
    """Code review round 2 of the unread-statement rule: each of these sent msg, or a message the
    export never built, after Corepoint could have replaced it. Now each send raises."""
    body = _handler_body(_handler_source(_WRITE_INPUT + statement + _SEND_INPUT))
    assert 'Send("OB_IN"' not in body
    assert 'Send("OB_NEW"' not in body
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_IN:' in body


def test_a_line_that_may_not_be_disabled_votes_on_the_input() -> None:
    """A ``Disabled="2"`` line may have run, so its input-handle name makes the input ambiguous,
    and even a send BEFORE it raises."""
    maybe = _role_line(_span("keyword", "MsgLog") + " " + _span("input-handle", "%OTHER")).replace(
        "<Line ", '<Line Disabled="2" ', 1
    )
    body = _handler_body(_handler_source(_WRITE_INPUT + _SEND_INPUT + maybe))
    assert 'Send("OB_IN"' not in body


def test_a_self_copy_keeps_its_clone() -> None:
    """Reading the source before the destination's spellings are unbound keeps a copy onto itself
    a clone, rather than a false refusal."""
    again = _root_copy("other-handle", "%OUT", "other-handle", "%OUT")
    body = _handler_body(_handler_source(_CLONE_OUT + again + _SEND_OUT))
    assert "out_msg = out_msg.copy()" in body
    assert '    sends.append(Send("OB_OUT", out_msg))' in body


def test_a_call_carrying_a_control_verb_keeps_its_construct() -> None:
    """A ``<Call>`` whose verb is ``If`` still renders under the dead placeholder, so nothing in it
    runs unconditionally, and markers around it leave every handle unknown."""
    call = (
        '<Call Data="If %ADT/PID-3 = &quot;x&quot;"><Actions>'
        + _create("%OUT", _ADT_A04)
        + _SEND_OUT
        + "</Actions></Call>"
    )
    body = _handler_body(_handler_source(_WRITE_INPUT + call + _SEND_INPUT))
    assert "    if False:" in body
    assert '\n    sends.append(Send("OB_OUT"' not in body  # never at the handler's own level
    assert 'Send("OB_IN"' not in body


def test_a_call_carrying_msgsend_raises_rather_than_filter() -> None:
    """A ``<Call>`` whose verb is ``MsgSend`` keeps its send and its declared destination, and the
    marker before it makes that send raise: never a silent filter."""
    src = _handler_source(
        _WRITE_INPUT + '<Call Data="MsgSend %ADT to connection &quot;OB_IN&quot;"><Actions/></Call>'
    )
    body = _handler_body(src)
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_IN:' in body
    assert "return None" not in body
    assert 'outbound("OB_IN"' in src


def test_an_input_handle_spelled_with_a_trailing_slash_is_still_overwritten() -> None:
    """The key drops a trailing ``/``, so a handle span written ``%ADT/`` and a write to ``%ADT``
    are one handle."""
    write = _write("input-handle", "%ADT/", "X")
    send = _role_send("input-handle", "%ADT/", "OB_IN")
    control = _handler_body(_handler_source(write + send))
    assert '    sends.append(Send("OB_IN", msg))' in control
    body = _handler_body(_handler_source(write + _REPLACE_ADT + send))
    assert 'Send("OB_IN"' not in body


@pytest.mark.parametrize(
    ("input_handle", "written"),
    [
        pytest.param("%ADI", "%adı", id="dotless-i"),
        pytest.param("%CAFÉ", "%café", id="decomposed-accent"),
    ],
)
def test_handle_case_folding_covers_unicode(input_handle: str, written: str) -> None:
    """The key upper-cases before it folds and normalises compatibility forms, so neither a dotless
    ``i`` nor a decomposed accent keeps a write from reaching the input."""
    write = _write("input-handle", input_handle, "X")
    send = _role_send("input-handle", input_handle, "OB_IN")
    body = _handler_body(_handler_source(write + _create(written, _ADT_A04) + send))
    assert 'Send("OB_IN"' not in body


def test_two_data_attributes_that_differ_only_in_case_are_refused() -> None:
    """One reader would take ``data`` and another ``Data``, so the import refuses the export."""
    with pytest.raises(CorepointImportError, match="more than one Data attribute"):
        _handler_source('<Line data="MsgLog %P" Data="MsgTreeCopy %NEW/ to %ADT/"/>')


def test_a_called_lists_input_is_not_the_callers_msg() -> None:
    """Inside the called list, its input handle is whatever was passed, not the caller's msg. A
    write there must not land on msg, and a handle the list binds is not the caller's to send."""
    inner = _inlined_call(
        _write("input-handle", "%ADT", "SUB"),
        _create("%P", _ADT_A04),
    )
    body = _handler_body(
        _handler_source(
            _CLONE_OUT
            + inner
            + _role_send("other-handle", "%P", "OB_P")
            + _role_send("input-handle", "%ADT", "OB_IN")
        )
    )
    assert 'set_field(msg, "MSH-6", "SUB")' not in body
    assert "    p_msg = Message.parse(" in body  # bound inside the list's own scope
    assert 'Send("OB_P"' not in body and 'Send("OB_IN"' not in body


@pytest.mark.parametrize(
    "rebuild",
    [
        pytest.param(_create("%P", _ADT_A04), id="lander-repro"),
        pytest.param("", id="input-handle-only"),
    ],
)
def test_a_called_lists_input_handle_makes_the_callers_input_ambiguous(rebuild: str) -> None:
    """The Lander's LOW 2 on PR 1900. Nothing establishes that a call passing nothing does not hand
    the caller's input to the called list's input handle, so a second input-handle name inside an
    inlined list makes the caller's input ambiguous: no handle is msg, and the send raises. The
    ``input-handle-only`` arm overwrites no tree, so only this rule refuses it."""
    inner = _inlined_call(
        _role_line(_span("keyword", "MsgLog") + " " + _span("input-handle", "%P")),
        rebuild,
        passing="",
    )
    body = _handler_body(
        _handler_source(_WRITE_INPUT + inner + _role_send("input-handle", "%ADT", "OB_IN"))
    )
    assert 'set_field(msg, "MSH-6", "X")' not in body
    assert 'Send("OB_IN"' not in body
    assert 'raise NotImplementedError("Corepoint import: MsgSend to OB_IN:' in body


def test_a_markup_free_write_in_a_branch_of_a_marked_list_declines() -> None:
    """Inside a construct a role-parsed write declines (its condition is a dead placeholder), so a
    markup-free one in the same list does too, rather than run live inside ``try:``."""
    body = _handler_body(
        _handler_source(
            _WRITE_INPUT
            + '<Try><Line Data="ItemClear %ADT/PID-19"/></Try>'
            + _role_send("input-handle", "%ADT", "OB_IN")
        )
    )
    assert 'set_field(msg, "PID-19"' not in body
    assert "inside a branch or loop declines" in body


def test_a_markup_free_framing_write_is_never_emitted() -> None:
    """MSH-1/MSH-2 corrupt the framing, so even a list with no role markup never writes them."""
    src = _handler_body(_handler_source('<Line Data="ItemCopy &quot;#&quot; %ADT/MSH-2"/>'))
    assert "set_field(" not in src
    assert "a framing field this import never writes" in src


def test_a_call_with_no_inlined_list_is_a_marker_and_counted_unmapped() -> None:
    """Nothing was inlined, so the render must not say it was, nor count it as shipped."""
    steps = '<Line Data="ActionListCall &quot;Sub&quot;"/>'
    src = _handler_body(_handler_source(steps))
    assert "# TODO: Corepoint ActionListCall — called list not inlined" in src
    assert "(called list inlined)" not in src
    assert _count_steps(_handler_steps(steps), in_loop=False) == (0, ["ActionListCall"], 0)


def test_framing_and_markup_free_copies_never_reach_a_built_or_cloned_message() -> None:
    """MSH-2 is refused on a built message as everywhere else, and in a list with role markup a
    markup-free copy (which clears an absent source's destination) or a repeating-segment write
    declines as the role layer would."""
    body = _handler_body(
        _handler_source(
            _create("%NEW", _ADT_A04)
            + '<Line Data="ItemClear %NEW/MSH-2"/>'
            + _CLONE_OUT
            + '<Line Data="ItemCopy %OUT/PID-5 %OUT/PID-6"/>'
            + '<Line Data="ItemClear %OUT/OBX-5"/>'
            + _SEND_OUT
        )
    )
    assert "MSH-2" not in body.split("# TODO")[0]
    assert 'set_field(new_msg, "MSH-2"' not in body
    assert "copy_field(" not in body
    assert 'set_field(out_msg, "OBX-5"' not in body
    assert "intended target PID-6" in body


def test_an_unstyled_field_write_verb_still_declines() -> None:
    """Reading words styled or not must not widen field-write mapping: a field write whose verb is
    unstyled declined before step 2 and still does. A keyword-styled ``to`` still maps."""
    unstyled = _role_line(
        "ItemCopy "
        + _span("literal", '"X"')
        + " to "
        + _span("input-handle", "%ADT")
        + _span("path", "/MSH-6")
    )
    assert "set_field(" not in _handler_body(_handler_source(unstyled))
    styled_to = _role_line(
        _span("keyword", "ItemCopy")
        + " "
        + _span("literal", '"X"')
        + " "
        + _span("keyword", "to")
        + " "
        + _span("input-handle", "%ADT")
        + _span("path", "/MSH-6")
    )
    assert '    set_field(msg, "MSH-6", "X")' in _handler_body(_handler_source(styled_to))


def test_a_keyword_styled_word_stops_a_field_write_mapping() -> None:
    """A mode word the exporter styles as a keyword counts like an unstyled one: ``ItemAppend "x"
    before PID-8`` is not an append, so it declines rather than map to ``append_to_field``."""
    styled = _role_line(
        _span("keyword", "ItemAppend")
        + " "
        + _span("literal", '"x"')
        + " "
        + _span("keyword", "before")
        + " "
        + _span("input-handle", "%ADT")
        + _span("path", "/PID-8")
    )
    body = _handler_body(_handler_source(styled))
    assert "append_to_field(" not in body
    assert "# TODO: Corepoint ItemAppend" in body


def test_a_declined_copy_into_a_built_message_names_the_field_it_writes() -> None:
    """``copy_field(src, dst)`` writes its LAST path, so the decline names the destination."""
    body = _handler_body(
        _handler_source(
            _create("%NEW", _ADT_A04)
            + '<Line Data="ItemCopy %NEW/MSH-6 %NEW/PID-5"/>'
            + _role_send("other-handle", "%NEW", "OB_NEW")
        )
    )
    assert "copy_field(" not in body
    assert "intended target PID-5" in body


def test_a_send_in_a_branch_the_render_does_not_emit_never_becomes_a_send_of_msg() -> None:
    """A marker nested inside a branch is not rendered. Its send must not be collected as a
    destination, or the handler would gain a trailing, unconditional ``Send(dest, msg)``."""
    nested = (
        '<If><Line Data="If (a)"><List><Line Data="ItemClear %ADT/PID-19"/></List></Line>'
        '<Line Data="Else"><List><Line Data="Catch"/>'
        + _role_send("other-handle", "%OUT", "OB_NESTED")
        + "</List></Line></If>"
    )
    body = _handler_body(_handler_source(_WRITE_INPUT + nested))
    assert "Send(" not in body


def test_a_module_with_scratch_locals_round_trips_through_the_lens() -> None:
    """ADR 0086 AC-4 for the new shapes: no whole-file refusal, and every live send is a send row.
    What the rows do NOT show (which message a write or a send addresses) is recorded in the ADR."""
    from messagefoundry.lens import parse_source

    src = _handler_source(
        _CLONE_WRITE_SEND + _create("%NEW", _ADT_A04) + _role_send("other-handle", "%NEW", "OB_NEW")
    )
    (contract,) = parse_source(src)
    sends = [row for row in contract["rows"] if row["kind"] == "send"]
    assert [row["outbounds"] for row in sends] == [["OB_ACME"], ["OB_NEW"]]


def test_generated_xml_module_compiles_and_passes_check(tmp_path: Path) -> None:
    """The emitted module parses, passes ``messagefoundry check``, and wires through the loader."""
    from messagefoundry.config.wiring import load_config

    result = import_corepoint(FIXTURES / "acme_adt_package.xml", tmp_path)
    assert result.channels[0].filename == "IB_ACME_ADT.py"
    written = (tmp_path / "IB_ACME_ADT.py").read_text(encoding="utf-8")
    compile(written, "IB_ACME_ADT.py", "exec")

    report = run_checks(tmp_path, run_lint=False)
    validate = next(r for r in report.results if r.name == "validate")
    assert validate.ok, validate.detail
    assert report.ok

    registry = load_config(tmp_path)
    assert "IB_ACME_ADT" in registry.inbound
    assert "OB_ACME_ADT" in registry.outbound
    # Placeholder wiring binds nothing: an unfinished import can never open a socket or poll a path.
    assert registry.inbound["IB_ACME_ADT"].deployed is False
    assert registry.outbound["OB_ACME_ADT"].deployed is False


def test_every_statement_is_accounted_for(tmp_path: Path) -> None:
    """Count-and-log: mapped + unmapped + disabled covers the fixture, nothing silently vanishes."""
    result = import_corepoint(FIXTURES / "acme_adt_package.xml", tmp_path)
    summary = result.to_json()
    # 3 vocabulary calls from the flat list + 3 from the role list + 14 control constructs.
    assert summary["total_mapped"] == 20
    # 3 from the flat list + its refused ``MsgSend $out`` (BACKLOG #313 step 2: a ``$variable`` names
    # no handle the import can identify) + 5 role statements the guards correctly refuse to map.
    assert summary["total_unmapped"] == 9
    assert summary["total_disabled"] == 1
    # The whole fixture is accounted for: every source element lands in exactly one bucket.
    assert summary["total_mapped"] + summary["total_unmapped"] + summary["total_disabled"] == 30


def test_parse_any_sniffs_xml_versus_json() -> None:
    """A leading ``<`` selects the validated XML layer; anything else stays on the legacy model."""
    assert parse_any(_acme_package())[0].source_format == "xml"
    # A UTF-8-with-BOM export (the Windows default) must not defeat the sniff or the parse.
    assert parse_any("﻿" + _acme_package())[0].source_format == "xml"
    assert parse_any("\n  " + _package('<Line Data="ItemClear %ADT/PID-19"/>'))[
        0
    ].source_format == ("xml")
    assert parse_any(_acme_export())[0].source_format == "json"


def test_unmodelled_subtrees_are_tolerated_not_crashed() -> None:
    """``<Connection>``/``<Codeset>``/``<OtherObjects>`` are ignored — a real package carries them."""
    channels = parse_package(_acme_package())
    assert len(channels) == 1 and len(channels[0].handlers) == 2


def test_malformed_or_hostile_xml_raises_cleanly() -> None:
    """Untrusted input: malformed XML, an entity payload, and an empty package are clean errors."""
    with pytest.raises(CorepointImportError):
        parse_package("<Package><ActionList>")  # not well-formed
    with pytest.raises(CorepointImportError):
        parse_package("<Package/>")  # nothing to import
    # A DOCTYPE is rejected outright, so a billion-laughs payload can never expand.
    billion = (
        '<!DOCTYPE p [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]>'
        '<Package><ActionList Name="T"><List><Line Data="&b;"/></List></ActionList></Package>'
    )
    with pytest.raises(CorepointImportError):
        parse_package(billion)


def test_pathologically_nested_export_is_refused_cleanly() -> None:
    """The list→statement walk is mutually recursive: depth is bounded, not left to blow the stack."""
    depth = 200
    body = "<List>" * depth + '<Line Data="ItemClear %ADT/PID-19"/>' + "</List>" * depth
    with pytest.raises(CorepointImportError, match="levels deep"):
        parse_package(f'<Package><ActionList Name="T">{body}</ActionList></Package>')


def test_an_element_with_no_statement_is_reported_not_skipped() -> None:
    """A silently-ignored element is exactly the accept-and-drop this importer refuses."""
    src = _handler_source("<Line/>")
    assert "# TODO: Corepoint Line — hand-finish (<Line> carries no statement to translate)" in src


# --- the ROLE layer: @Data markup is semantic, not decorative (#105 verb coverage) ------------
#
# The rich-text wrapper carries semantic role classes, so the markup IS the parse the exporter already
# computed. Flattening it fuses the operator's prose into the statement and hides the operand roles —
# which is why the flat tokenizer sees hundreds of shapes per verb where the roles show a handful.


def _role_handler() -> str:
    """The generated body of the fixture's role-grammar action-list."""
    src = generate_module(parse_package(_acme_package())[0])
    return src.split("def acme_adt_role_grammar")[-1]


def test_roles_separate_operands_from_prose_and_labels() -> None:
    """A path's human label and the operator's description are text, never operands."""
    data = (
        "<span class='keyword'>ItemCopy</span> <span class='literal'>\"ACME\"</span> to "
        "<span class='input-handle'>%ADT</span><span class='path'>/MSH-6 (Receiving Facility)</span>"
        "<span class='description'>stamp it</span>"
    )
    tokens = parse_roles(data)
    assert _role_verb(tokens) == "ItemCopy"
    assert _role_prose(tokens) == "stamp it"
    operands = _operands_from_roles(tokens)
    # Two operands only: the label and the description are NOT among them.
    assert [(o.kind, o.text) for o in operands] == [
        ("literal", "ACME"),
        ("path", "/MSH-6 (Receiving Facility)"),
    ]
    # The path is addressed against the handle that precedes it, and that handle is the input.
    assert operands[1].handle == "%ADT" and operands[1].primary
    # The literal span carried its own quotes; they are stripped exactly once.
    assert operands[0].quoted


def test_markup_free_data_falls_back_to_the_flat_tokenizer() -> None:
    """An export without role markup must keep working — the role layer is additive, not a rewrite."""
    assert parse_roles("ItemCopy %ADT/PID-5.1 %ADT/NK1-2.1") == ()


def test_corepoint_dash_coordinates_translate_to_message_paths() -> None:
    """Corepoint writes ``PID-5-1`` where :class:`Message` writes ``PID-5.1`` — a mechanical rewrite.

    Nothing in a real export is dot-separated, so without this every path looks like an unresolvable
    named node and no field statement can map at all."""
    assert _corepoint_path("/PID-5-1 (Patient Name)") == "PID-5.1"
    assert _corepoint_path("/PID-3-1-2") == "PID-3.1.2"
    assert _corepoint_path("/MSH-6") == "MSH-6"
    assert _corepoint_path("/PID-5.1") == "PID-5.1"  # already dotted: accepted unchanged
    # A named tree node carries no coordinates and is NEVER guessed at.
    assert _corepoint_path("/Patient/FamilyName (Family Name)") is None
    assert _corepoint_path("/OBX") is None  # a bare segment is not a field
    assert _corepoint_segment("/OBX (Observation)") == "OBX"


def test_role_statements_map_onto_the_vocabulary() -> None:
    """The three genuinely-equivalent field verbs emit real vocabulary calls from role markup."""
    body = _role_handler()
    assert 'set_field(msg, "MSH-6", "ACME")' in body  # a constant source IS a set
    assert 'set_field(msg, "PID-19", "")' in body  # clearing IS setting empty
    # ItemAppend is VALUE-first / target-second, and PID-3-1 became PID-3.1.
    assert 'append_to_field(msg, "PID-3.1", "_IMPORTED")' in body
    # The literal's own quotes are not doubled into the generated string.
    assert '\\"' not in body


def test_a_cross_message_write_never_becomes_a_msg_set() -> None:
    """A write to another message tree is refused: ``msg`` is the message this Handler delivers.

    A Corepoint action-list manipulates several messages at once; a Handler has exactly one. Rendering
    a write to a *different* tree as ``msg.set`` would silently mutate the wrong message — so it is a
    marker that names the cause, never a call."""
    body = _role_handler()
    assert "cross-message" in body
    assert 'set_field(msg, "MSH-5"' not in body


def test_declines_name_the_cause_rather_than_a_generic_hand_finish() -> None:
    """A migrator triages 5,000 TODOs by their REASON — an undifferentiated marker is unusable."""
    body = _role_handler()
    assert "segment can repeat" in body  # OBX-11
    assert "MSH-1/MSH-2" in body  # the framing fields
    assert "$variable" in body
    assert "no HL7 field coordinates" in body  # a named tree node


def test_a_repeating_segment_and_the_framing_fields_are_never_written() -> None:
    """``Message.set`` writes occurrence 1 and accepts MSH-1/MSH-2 — both corrupt silently."""
    body = _role_handler()
    assert 'set_field(msg, "OBX-11"' not in body
    assert 'set_field(msg, "MSH-1"' not in body


def test_a_declined_statement_emits_no_live_stub() -> None:
    """The old ``msg.set(p, msg.field(p) or "")`` passthrough was NOT inert.

    ``Message.set`` raises ``KeyError`` on an absent segment, and on a present segment with an absent
    field it materialises the field and its empty components on the wire — so a line whose only job was
    to stay visible could dead-letter the message or change it. The target rides into the comment."""
    body = _role_handler()
    assert "msg.field(" not in body
    assert "intended target OBX-11" in body


def test_the_operators_prose_is_preserved_as_a_comment() -> None:
    """``description``/``comment`` spans are lifted OUT of the statement and kept beside the step."""
    assert "# Corepoint Comment: stamp the receiving facility" in _role_handler()


def test_a_branch_group_wrapper_does_not_emit_a_second_dead_conditional() -> None:
    """The export writes ``<If>`` with no ``@Data``, holding one child per branch.

    Emitting a construct for the wrapper too wrapped an already-complete if/elif/else chain in a
    second, condition-less ``if False:`` — and counted it as a mapped step it never was."""
    src = _handler_source(
        '<If><Line Data="If (%ADT/PID-8 = &quot;M&quot;)">'
        '<List><Line Data="ItemClear %ADT/PID-19"/></List></Line>'
        '<Line Data="Else"><List><Line Data="ItemClear %ADT/PID-22"/></List></Line></If>'
    )
    # Exactly ONE chain opener — counted per line, since "elif False:" contains "if False:".
    openers = [ln for ln in src.splitlines() if ln.strip().startswith("if False:")]
    assert len(openers) == 1
    assert 'set_field(msg, "PID-19", "")' in src
    ast.parse(src)


# --- the four never-silently-drop defects (adversarial review, #105) --------------------------
#
# Each test below FAILS on the pre-fix module: a @Disabled action-list came back ON as live code, and
# three distinct paths dropped a source element with its whole subtree — no marker, no count. They are
# the sharp edge of the module's stated contract, so they are pinned individually.


def test_disabled_action_list_is_never_emitted_as_live_code(tmp_path: Path) -> None:
    """``@Disabled`` on the ``<ActionList>`` switches the WHOLE list off — the statement-level check
    never sees that element, so without an explicit ancestor walk an operator who switched a list off
    before exporting got it silently switched back ON: live transform, live ``Send``, a declared
    outbound, a router forwarding to it, and ``total_disabled: 0`` telling the human nothing."""
    xml = (
        '<Package Name="P"><ActionList Name="T" Disabled="1"><List>'
        '<Line Data="ItemCopy %ADT/PID-5.1 %ADT/NK1-2.1"/>'
        '<Line Data="MsgSend $o [OB_A]"/>'
        "</List></ActionList></Package>"
    )
    channel = parse_package(xml)[0]
    handler = channel.handlers[0]
    assert handler.disabled is True
    # Nothing live: no destination collected, so no outbound is declared and no trailing Send appears.
    assert handler.destinations == ()
    assert channel.destinations == ()

    src = generate_module(channel)
    # Nothing live, proved structurally: the handler's body carries no call of any kind.
    tree = ast.parse(src)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "t")
    calls = [n for stmt in fn.body for n in ast.walk(stmt) if isinstance(n, ast.Call)]
    assert not calls  # the @handler(...) decorator is on the def, not in the body
    assert "copy_field(msg," not in src  # the live call form (the pseudo-source form has no msg)
    assert "sends.append(" not in src
    assert "outbound(" not in src
    assert "from messagefoundry.actions import" not in src  # no vocabulary is used at all
    # A visible marker naming the disabled scope, and the subtree preserved as pseudo-source.
    assert "# DISABLED in Corepoint (@Disabled)" in src
    assert "#   ActionList: T" in src
    assert "ItemCopy -> copy_field" in src
    assert "MsgSend: MsgSend $o [OB_A]" in src
    # The router does not forward to a switched-off list, and says so rather than dropping the name.
    assert "# DISABLED in Corepoint (@Disabled) — NOT routed: t" in src
    assert "return []  # TODO: Corepoint routing" in src

    export = tmp_path / "disabled_list.xml"
    export.write_text(xml, encoding="utf-8")
    result = import_corepoint(export, tmp_path / "out")
    assert result.total_disabled == 1
    assert result.total_mapped == 0
    assert result.to_json()["total_disabled"] == 1


def test_disabled_package_disables_every_action_list_beneath_it() -> None:
    """``@Disabled`` marks a SUBTREE: on ``<Package>`` it switches off every list it encloses."""
    src = generate_module(
        parse_package(
            '<Package Name="P" Disabled="1"><ActionList Name="T"><List>'
            '<Line Data="ItemCopy %ADT/PID-5.1 %ADT/NK1-2.1"/>'
            "</List></ActionList></Package>"
        )[0]
    )
    assert "copy_field(msg," not in src
    assert "ItemCopy -> copy_field" in src  # preserved as pseudo-source, not lost
    assert "#   Package: P" in src
    assert "# DISABLED in Corepoint (@Disabled) — NOT routed: t" in src
    ast.parse(src)


def test_a_disabled_action_list_still_passes_the_check_gate(tmp_path: Path) -> None:
    """The switched-off module must still be a loadable config — a comment-only handler that filters —
    and the switched-off ``MsgSend`` must not have opened an outbound in the real registry."""
    from messagefoundry.config.wiring import load_config

    export = tmp_path / "off.xml"
    export.write_text(
        '<Package Name="P"><ActionList Name="T" Disabled="1"><List>'
        '<Line Data="ItemClear %ADT/PID-19"/>'
        '<Line Data="MsgSend $o [OB_A]"/>'
        "</List></ActionList></Package>",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    import_corepoint(export, out)
    report = run_checks(out, run_lint=False)
    assert report.ok, [r.detail for r in report.results if not r.ok]
    registry = load_config(out)
    assert "IB_P" in registry.inbound
    # The disabled list named a destination; wiring it would be the switched-off send coming back on.
    assert registry.outbound == {}


def test_an_unmodelled_element_in_a_list_is_reported_with_its_subtree() -> None:
    """An element inside a ``<List>`` is a STATEMENT position: an unmodelled tag there must not be
    skipped. The pre-fix ``continue`` dropped the element *and its whole subtree* — no marker, no
    count — justified by ``<Connection>``/``<Codeset>``/``<DataPoint>``, which are ``<Package>``-level
    subtrees that never appear inside a ``<List>`` at all."""
    src = _handler_source(
        '<Line Data="ItemCopy %ADT/PID-5.1 %ADT/NK1-2.1"/>'
        '<Switch Data="Switch (%ADT/PID-8)"><List>'
        '<Line Data="ItemClear %ADT/PID-11.1"/>'
        "</List></Switch>"
    )
    assert "# TODO: Corepoint <Switch> — element not modelled" in src
    assert "the element's own scope is lost" in src
    # The subtree survives — the nested statement still maps, rather than vanishing with its parent.
    assert 'set_field(msg, "PID-11.1", "")' in src
    ast.parse(src)


def test_an_unmodelled_element_is_counted_never_silently_skipped(tmp_path: Path) -> None:
    """A ``<Lines>`` typo carries a real statement: reported by tag and counted (count-and-log)."""
    export = tmp_path / "typo.xml"
    export.write_text(
        '<Package Name="P"><ActionList Name="T"><List>'
        '<Lines Data="ItemClear %ADT/PID-11.1"/>'
        '<Line Data="ItemClear %ADT/PID-19"/>'
        "</List></ActionList></Package>",
        encoding="utf-8",
    )
    result = import_corepoint(export, tmp_path / "out")
    assert result.channels[0].unmapped_classes == ("Lines",)
    assert result.total_unmapped == 1
    assert result.total_mapped == 1  # only the well-formed <Line> is claimed as shipped
    # The lost statement's own text rides into the marker, so nothing about it is unrecoverable.
    assert "ItemClear %ADT/PID-11.1" in result.channels[0].source


def test_a_statement_beside_a_nested_list_is_not_discarded() -> None:
    """A container's direct statement children are SIBLINGS of its ``<List>``: taking only the
    wrapper's children (the moment any wrapper exists) discarded them — here an ``Else`` marker and
    its entire branch body vanished, leaving only the if-branch."""
    src = _handler_source(
        '<If Data="If (%ADT/PID-8 = &quot;M&quot;)">'
        '<List><Line Data="ItemClear %ADT/PID-19"/></List>'
        '<Line Data="Else"/>'
        '<Line Data="ItemClear %ADT/PID-22"/>'
        "</If>"
    )
    assert 'set_field(msg, "PID-19", "")' in src
    assert "# TODO: Corepoint Else" in src
    assert 'set_field(msg, "PID-22", "")' in src
    ast.parse(src)


def test_else_under_a_dead_condition_is_not_emitted_as_a_live_branch() -> None:
    """A bare ``else:`` beneath a dead ``if False:`` runs its body for EVERY message.

    The conditions are deliberate placeholders (a Corepoint condition is not a Python expression), so
    the fallback must be dead too — otherwise the import inverts the source: the branch the export took
    only sometimes becomes the branch that always runs. Rendered ``elif False:`` until a human writes
    the real condition."""
    src = _handler_source(
        '<If Data="If (%ADT/PID-8 = &quot;M&quot;)">'
        '<List><Line Data="ItemClear %ADT/PID-19"/>'
        '<Line Data="Else"/>'
        '<Line Data="ItemClear %ADT/PID-22"/></List>'
        "</If>"
    )
    assert "if False:" in src
    # The whole chain is inert: no branch of it can execute. Checked per LINE, because the marker
    # text itself mentions ``else:`` when it tells the migrator what to restore.
    assert not [ln for ln in src.splitlines() if ln.strip().startswith("else:")]
    assert "elif False:" in src
    assert "would run this branch for EVERY message" in src
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            assert node.orelse == [] or isinstance(node.orelse[0], ast.If), (
                "an if-chain whose conditions are dead placeholders must carry no live else branch"
            )


def test_a_send_statement_keeps_its_nested_body() -> None:
    """The ``send`` path returned only the ``Send`` and dropped ``*body`` — unlike ``break``/``exit``
    beside it, which have always carried theirs."""
    send = _role_send("input-handle", "%ADT", "OB_A")
    assert send.endswith("/>")
    src = _handler_source(send[:-2] + '><List><Line Data="ItemClear %ADT/PID-19"/></List></Line>')
    assert 'sends.append(Send("OB_A", msg))' in src
    assert 'set_field(msg, "PID-19", "")' in src
    ast.parse(src)


def test_cli_imports_the_xml_package(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """``messagefoundry import corepoint`` drives the XML path end to end and reports the accounting."""
    from messagefoundry.__main__ import main

    out = tmp_path / "config"
    code = main(
        [
            "import",
            "corepoint",
            str(FIXTURES / "acme_adt_package.xml"),
            "--out",
            str(out),
            "--json",
        ]
    )
    assert code == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["total_mapped"] == 20
    assert summary["total_unmapped"] == 9
    assert summary["total_disabled"] == 1
    assert (out / "IB_ACME_ADT.py").is_file()


def test_cli_reports_a_malformed_export_without_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Untrusted input: a broken export is a clean error + exit 1, never an uncaught traceback."""
    from messagefoundry.__main__ import main

    bad = tmp_path / "broken.xml"
    bad.write_text("<Package><ActionList>", encoding="utf-8")
    code = main(["import", "corepoint", str(bad), "--out", str(tmp_path / "out"), "--json"])
    assert code == 1
    assert "well-formed XML" in capsys.readouterr().out


def test_hostile_xml_values_cannot_inject_code() -> None:
    """A ``@Data`` carrying a newline rides into an escaped literal / a flattened comment (AC-5)."""
    # &#10; is a character reference, so it survives XML attribute-value normalization as a real
    # newline — the sharpest available test of both the literal and the comment escape paths.
    src = _handler_source(
        '<Line Data="ItemCopy &amp;quot;A&#10;import os&amp;quot; %ADT/MSH-6"/>'
        '<Line Data="ItemCustomScript %ADT/OBX-5&#10;os.system(&amp;quot;pwned&amp;quot;)"/>'
    )
    assert "\nimport os" not in src
    assert "\nos.system(" not in src
    assert 'set_field(msg, "MSH-6", "A\\nimport os")' in src  # escaped, inert literal
    ast.parse(src)  # still one well-formed module — no literal or comment breakout


# --- the d26545d6f HIGH on PR 1900, and the shapes the differential guard found with it ----------
# tests/test_corepoint_import_differential.py runs these shapes and about 2,900 more against step 1;
# these name the HIGH's four shapes so a reader sees them without the guard's machinery.

_NEW_SENT = _create("%NEW", _ADT_A04) + _role_send("other-handle", "%NEW", "OB_NEW")


def _line_with(data: str, body: str) -> str:
    return _role_line(data).replace("/>", f"><List>{body}</List></Line>")


_IF_ADT_EXISTS = _span("keyword", "If") + " " + _span("input-handle", "%ADT") + " exists"


@pytest.mark.parametrize(
    "export",
    [
        pytest.param(
            "<If>"
            + _line_with(_IF_ADT_EXISTS, _MSGLOG_P)
            + _line_with("Else", _NEW_SENT)
            + "</If>",
            id="if-names-a-handle-then-else",
        ),
        pytest.param(
            '<If><Line Data="If $X = &quot;1&quot;"><List>'
            + _MSGLOG_P
            + "</List></Line>"
            + _line_with(
                _span("keyword", "ElseIf") + " " + _span("input-handle", "%ADT") + " exists",
                _NEW_SENT,
            )
            + "</If>",
            id="elseif-names-a-handle",
        ),
        pytest.param(
            '<Try><Line Data="Try"><List>'
            + _MSGLOG_P
            + "</List></Line>"
            + _line_with(
                _span("keyword", "Catch") + " into " + _span("other-handle", "%ERR"), _NEW_SENT
            )
            + "</Try>",
            id="catch-names-a-handle",
        ),
        pytest.param(
            '<If Data="If %ADT exists"><List>'
            + _MSGLOG_P
            + "</List></If>"
            + _line_with("Else", _NEW_SENT),
            id="sibling-if-names-a-handle-then-else",
        ),
    ],
)
def test_a_branch_whose_construct_names_a_handle_stays_a_branch(export: str) -> None:
    """The Lander's HIGH on d26545d6f: markers around an If, ElseIf or Catch that names a whole
    message hid the branch from its construct, so the branch rendered with no enclosing construct
    and its body ran for every message. The line now carries the reason instead, and stays in its
    chain."""
    body = _handler_body(_handler_source(export))
    assert '\n    sends.append(Send("OB_NEW"' not in body  # never at the handler's own level
    assert "with no enclosing construct" not in body
    assert "elif False:" in body or "    except Exception:" in body


def test_a_send_where_the_scope_was_lost_raises_unless_step1_sent_msg() -> None:
    """A branch marker with no construct inlines what follows it, which Corepoint may never have
    run. A send there of a message the list built raises; a send of msg stays as step 1 had it."""
    lost = '<Block Data="Section"><List>' + _ELSE + _NEW_SENT + _SEND_INPUT + "</List></Block>"
    body = _handler_body(_handler_source(_WRITE_INPUT + lost))
    assert 'Send("OB_NEW"' not in body
    assert "where the import lost the export's scope" in body
    assert '    sends.append(Send("OB_IN", msg))' in body


@pytest.mark.parametrize(
    "line",
    [
        pytest.param('<Line Data="ForEach OUT in %SRC/OBX">', id="foreach-no-percent"),
        pytest.param(
            "<Line Data=\"&lt;span class='keyword'&gt;ForEach&lt;/span&gt; "
            "&lt;span class='handle'&gt;%OUT&lt;/span&gt;\">",
            id="foreach-unlisted-span-class",
        ),
        pytest.param('<Line Data="Catch into OUT">', id="catch-no-percent"),
    ],
)
def test_a_foreach_or_catch_naming_a_handle_in_any_spelling_unbinds_it(line: str) -> None:
    """A ForEach or Catch may bind the handle it names. A spelling neither reading sees made the
    flow keep the clone, so a send of it went out after the construct had rebound it. The line is
    now judged word by word: anything it cannot classify may be a handle."""
    clone = _root_copy("input-handle", "%ADT", "other-handle", "OUT")
    send = _role_send("other-handle", "OUT", "OB_OUT")
    construct = line + "<List>" + _MSGLOG_P + "</List></Line>"
    if "Catch" in line:
        construct = '<Try><Line Data="Try"><List>' + _MSGLOG_P + "</List></Line>" + construct
        construct += "</Try>"
    body = _handler_body(_handler_source(clone + construct + send))
    assert 'Send("OB_OUT"' not in body
    control = _handler_body(_handler_source(clone + send))
    assert '    sends.append(Send("OB_OUT", out_msg))' in control


def test_a_foreach_over_a_path_with_a_variable_still_reads() -> None:
    """The control for the word rule: ``ForEach %ADT/OBX $obx`` names a path into a handle and a
    variable, neither a whole tree, so a clone made before it is still sent after it."""
    loop = '<Foreach Data="ForEach %ADT/OBX $obx"><List>' + _MSGLOG_P + "</List></Foreach>"
    body = _handler_body(_handler_source(_CLONE_OUT + loop + _SEND_OUT))
    assert '    sends.append(Send("OB_OUT", out_msg))' in body


def test_a_try_holding_a_nested_try_is_not_a_branch_group_wrapper() -> None:
    """A ``<Try>`` with no ``@Data`` dissolved whenever its body held another Try, so its Catch came
    loose and a clone made in its body read as made on every path. Only a wrapper whose children
    are all the construct's own branch lines dissolves (the differential guard's sweep, seed 4)."""
    inner = "<Try><List>" + _MSGLOG_P + _CATCH_LINE + _MSGLOG_P + "</List></Try>"
    outer = "<Try><List>" + inner + _CLONE_OUT + _CATCH_LINE + _MSGLOG_P + "</List></Try>"
    # In a Block, so a loose Catch's lost scope ends before the send (see _Flow._lost).
    block = '<Block Data="Section"><List>' + outer + "</List></Block>"
    body = _handler_body(_handler_source(_WRITE_INPUT + block + _SEND_OUT))
    assert "with no enclosing construct" not in body
    assert body.count("try:") == 2
    assert 'Send("OB_OUT"' not in body


_CATCH_LINE = '<Line Data="Catch"/>'
