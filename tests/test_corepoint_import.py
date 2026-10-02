# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Deterministic Corepoint action-list import (ADR 0086) — mapping, count-and-log, check gate, security.

The lens round-trip half of the correctness gate (AC-4) lives in ``tests/test_lens_parse.py`` beside
the other lens property tests; here we cover the mapping fidelity, the never-drop count-and-log ethos,
the ``messagefoundry check`` structural gate on emitted modules, and the untrusted-input handling."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from messagefoundry.checks import run_checks
from messagefoundry.corepoint_import import (
    _CONTAINER_KIND_BY_TAG,
    _STATEMENT_VERBS,
    _UNDERSTOOD,
    _VERB_CONNECTIVES,
    Action,
    Control,
    CorepointImportError,
    Step,
    UnmappedAction,
    _corepoint_path,
    _corepoint_segment,
    _count_steps,
    _hardened_fromstring,
    _message_handles,
    _operands_from_roles,
    _role_prose,
    _role_verb,
    _understood_list,
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
    src = _handler_source('<Line Data="MsgSend $out [../../etc/passwd]"/>')
    assert "../.." not in src
    # ONE sanitized name, used identically as the connection id, the Send target and the directory.
    assert 'sends.append(Send("etc_passwd", msg))' in src
    assert 'outbound("etc_passwd", File(directory="./corepoint-import/IB_ACME_X/etc_passwd")' in src


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
        '<Line Data="LoopExit"/>'
        '<Line Data="MsgSend $out [OB_ACME_ADT]"/>'
        "</Foreach>"
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
    conditional send into an unconditional one."""
    src = _handler_source(
        '<If Data="If (%ADT/PID-8 = &quot;M&quot;)">'
        '<List><Line Data="MsgSend $out [OB_ACME_ADT]"/></List></If>'
    )
    assert "    sends = []" in src
    assert '        sends.append(Send("OB_ACME_ADT", msg))' in src
    assert "    return sends" in src
    # The destination is declared, as an inert placeholder (the export's connection config is not
    # modelled), so the emitted Send never dangles.
    assert 'outbound("OB_ACME_ADT", File(directory=' in src
    assert "deployed=False)" in src


def test_msgsend_without_a_recoverable_destination_is_a_marker() -> None:
    src = _handler_source('<Line Data="MsgSend $out"/>')
    assert "# TODO: Corepoint MsgSend — hand-finish: no destination named" in src
    assert "Send(" not in src.split('"""')[-1]


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


_WRITE_INPUT = _role_line(
    _span("keyword", "ItemCopy")
    + " "
    + _span("literal", '"X"')
    + " to "
    + _span("input-handle", "%ADT")
    + _span("path", "/MSH-6")
)


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
        "which at this point holds no message this import can identify" in body
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
    assert "holds no message this import can identify" in body
    assert "raise NotImplementedError" in body


def test_a_mixed_list_refuses_only_the_non_subject_send() -> None:
    """One list sending both handles: the input send stays live, the other one raises. The list is
    fully understood, so the write to the input maps onto msg (BACKLOG #313 step 2)."""
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


def _run_handler(tmp_path: Path, body: str) -> object:
    """Import a one-list package, load it through the real loader, and call its handler once."""
    from messagefoundry.config.wiring import load_config
    from messagefoundry.parsing.message import Message

    export = tmp_path / "pkg.xml"
    export.write_text(_package(body), encoding="utf-8")
    out = tmp_path / "out"
    import_corepoint(export, out)
    handler_fn = load_config(out).handlers["t"]
    return handler_fn(Message.parse("MSH|^~\\&|A|B|C|D|20260930||ADT^A01|1|P|2.5\rPID|1||123"))


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
    """Fail closed: a send is live only when its handle is provably msg. A root-path spelling of
    another handle, a ``$variable`` and a partial path all refuse, and the list's field write then
    degrades to a TODO because the list does not provably deliver msg."""
    literal = _span("literal", '"OB_ACME"')
    send = _role_line(_span("keyword", "MsgSend") + " " + operand + " to connection " + literal)
    body = _handler_body(_handler_source(_WRITE_INPUT + send))
    assert "Send(" not in body
    assert "raise NotImplementedError" in body
    assert 'set_field(msg, "MSH-6"' not in body


def test_a_root_path_send_of_the_input_handle_still_sends() -> None:
    """The control arm for the root-path spelling: ``%ADT/`` is the input, so it sends."""
    literal = _span("literal", '"OB_IN"')
    operand = _span("input-handle", "%ADT") + _span("path", "/")
    send = _role_line(_span("keyword", "MsgSend") + " " + operand + " to connection " + literal)
    body = _handler_body(_handler_source(_WRITE_INPUT + send))
    assert '    sends.append(Send("OB_IN", msg))' in body
    assert 'set_field(msg, "MSH-6", "X")' in body


def test_a_live_whole_tree_clone_still_sends() -> None:
    """The control arm: a live root copy of the input binds the clone to its own local, and the send
    delivers that local, never msg (BACKLOG #313 step 2)."""
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
    assert "no handle in this action-list is known to be msg" in body


def test_an_unstyled_send_verb_is_judged_like_a_styled_one() -> None:
    """The scan and the parse read the verb the same way. A ``MsgSend`` with no ``keyword`` span is
    still a send of another handle, so the list's field write degrades as well as the send refusing."""
    literal = _span("literal", '"OB_ACME"')
    send = _role_line("MsgSend " + _span("other-handle", "%OUT") + " to connection " + literal)
    body = _handler_body(_handler_source(_WRITE_INPUT + send))
    assert "raise NotImplementedError" in body
    assert 'set_field(msg, "MSH-6"' not in body


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
    assert "no handle in this action-list is known to be msg" in body
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
    neither the send nor the field write may treat the input as msg any more."""
    body = _handler_body(
        _handler_source(_WRITE_INPUT + copy + _role_send("input-handle", "%ADT", "OB_IN"))
    )
    assert "Send(" not in body
    assert "raise NotImplementedError" in body
    assert 'set_field(msg, "MSH-6"' not in body


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
    write_clone = _role_line(
        _span("keyword", "ItemCopy")
        + " "
        + _span("literal", '"Y"')
        + " to "
        + _span("other-handle", "%OUT")
        + _span("path", "/MSH-6")
    )
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
    """The control arm: a write to the clone lands on the clone's own local, which is what the list
    sends (BACKLOG #313 step 2)."""
    write_clone = _role_line(
        _span("keyword", "ItemCopy")
        + " "
        + _span("literal", '"Y"')
        + " to "
        + _span("other-handle", "%OUT")
        + _span("path", "/MSH-6")
    )
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
    """The render flattens a ``<List>`` wrapper even under ``@Disabled``, so the scan must see its
    statements too, or the field write maps live beside a send the scan never counted."""
    wrapped = '<List Disabled="1">' + _role_send("other-handle", "%OUT", "OB_ACME") + "</List>"
    body = _handler_body(
        _handler_source(_WRITE_INPUT + wrapped + _role_send("input-handle", "%ADT", "OB_IN"))
    )
    assert 'set_field(msg, "MSH-6"' not in body


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


# --- each handle becomes a Python local, in a fully understood list (BACKLOG #313, step 2) --------
#
# The whole-list gate (ADR 0086): a list binds locals only when every element in it is on the
# allow-list. Any other list renders exactly as step 1 does; the differential guard
# (tests/test_corepoint_import_differential.py) checks that byte for byte. All fixtures are synthetic.

_INBOUND = "MSH|^~\\&|A|B|C|D|20260930||ADT^A01|1|P|2.5\rPID|1||123"
_ADT_A04 = " as " + _span("literal", '"ADT^A04"') + " version " + _span("literal", '"2.5.1"')


def _write(handle_class: str, handle: str, value: str, path: str = "/MSH-6") -> str:
    """A role-marked ``ItemCopy "<value>" to <handle><path>``."""
    return _role_line(
        _span("keyword", "ItemCopy")
        + " "
        + _span("literal", '"' + value + '"')
        + " to "
        + _span(handle_class, handle)
        + _span("path", path)
    )


def _create(handle: str, operands: str = _ADT_A04) -> str:
    return _role_line(
        _span("keyword", "MsgCreate") + " " + _span("other-handle", handle) + operands
    )


def _run_with(tmp_path: Path, body: str) -> tuple[object, Message]:
    """Import a one-list package, load it, call its handler once; return the result and the input."""
    from messagefoundry.config.wiring import load_config

    export = tmp_path / "pkg.xml"
    export.write_text(_package(body), encoding="utf-8")
    import_corepoint(export, tmp_path / "out")
    inbound = Message.parse(_INBOUND)
    return load_config(tmp_path / "out").handlers["t"](inbound), inbound


_CLONE_WRITE_SEND = (
    _root_copy("input-handle", "%ADT", "other-handle", "%OUT")
    + _write("other-handle", "%OUT", "Y")
    + _role_send("other-handle", "%OUT", "OB_ACME")
)


def test_clone_then_write_then_send_delivers_the_clone_and_leaves_the_input_alone(
    tmp_path: Path,
) -> None:
    """The clone is its own Message: the write lands on it, the send delivers it, and the input the
    Handler received is neither changed nor sent."""
    body = _handler_body(_handler_source(_CLONE_WRITE_SEND))
    assert "    out_msg = msg.copy()" in body
    assert '    set_field(out_msg, "MSH-6", "Y")' in body
    assert '    sends.append(Send("OB_ACME", out_msg))' in body
    result, inbound = _run_with(tmp_path, _CLONE_WRITE_SEND)
    assert isinstance(result, list) and len(result) == 1
    sent = result[0].message
    assert sent is not inbound
    assert sent.field("MSH-6") == "Y" and sent.field("PID-3") == "123"
    assert inbound.field("MSH-6") == "D"


def test_msgcreate_then_send_delivers_the_new_message(tmp_path: Path) -> None:
    """A MsgCreate naming a type and a version builds a skeleton through the Message API: default
    encoding characters, MSH-9 and MSH-12, nothing else. The send delivers it, not msg."""
    body = _create("%NEW") + _role_send("other-handle", "%NEW", "OB_NEW")
    src = _handler_source(body)
    assert "from messagefoundry import File, Message, Send, handler" in src
    assert '    new_msg = Message.parse("MSH|^~\\\\&|||||||ADT^A04|||2.5.1")' in src
    assert '    sends.append(Send("OB_NEW", new_msg))' in src
    result, inbound = _run_with(tmp_path, body)
    assert isinstance(result, list)
    created = result[0].message
    assert created is not inbound
    assert created.field("MSH-9") == "ADT^A04" and created.field("MSH-12") == "2.5.1"


def test_a_send_before_its_clone_fails_loudly(tmp_path: Path) -> None:
    """Statement order counts: at the send, the clone does not exist yet."""
    body = _role_send("other-handle", "%OUT", "OB_ACME") + _root_copy(
        "input-handle", "%ADT", "other-handle", "%OUT"
    )
    src = _handler_body(_handler_source(body))
    assert "Send(" not in src
    assert src.index("raise NotImplementedError") < src.index("out_msg = msg.copy()")
    with pytest.raises(NotImplementedError, match="MsgSend delivers %OUT"):
        _run_with(tmp_path, body)


def test_a_write_after_a_send_never_reaches_the_sent_message(tmp_path: Path) -> None:
    """A Send holds the object, so a write after it would change the message already sent. The write
    is a TODO instead, and the handle is unknown from there: sending it again raises."""
    body = (
        _CLONE_WRITE_SEND
        + _write("other-handle", "%OUT", "LATE")
        + _role_send("other-handle", "%OUT", "OB_AGAIN")
    )
    src = _handler_body(_handler_source(body))
    assert 'set_field(out_msg, "MSH-6", "LATE")' not in src
    assert "after a MsgSend of it, which would change the message already sent" in src
    assert 'Send("OB_AGAIN"' not in src
    with pytest.raises(NotImplementedError, match="MsgSend to OB_AGAIN"):
        _run_with(tmp_path, body)
    # Without the second send: the first send still carries what it held when it was sent.
    (tmp_path / "control").mkdir()
    first = _run_with(tmp_path / "control", _CLONE_WRITE_SEND + _write("other-handle", "%OUT", "Z"))
    assert isinstance(first[0], list) and first[0][0].message.field("MSH-6") == "Y"


def test_a_write_to_a_built_message_outside_its_msh_declines_and_its_send_raises() -> None:
    """The skeleton holds only an MSH, and Message.set raises on an absent segment, so a write to
    another segment of a built message is a TODO. Any write the binder declines leaves its handle
    unknown, so the send raises rather than deliver the skeleton without the write. A write to the
    MSH maps (the control arm)."""
    body = _handler_body(
        _handler_source(
            _create("%NEW")
            + _write("other-handle", "%NEW", "B", "/MSH-10")
            + _write("other-handle", "%NEW", "A", "/PID-8")
            + _role_send("other-handle", "%NEW", "OB_NEW")
        )
    )
    assert 'set_field(new_msg, "MSH-10", "B")' in body
    assert 'set_field(new_msg, "PID-8"' not in body
    assert "whose skeleton has only an MSH segment" in body
    assert 'Send("OB_NEW"' not in body
    assert "raise NotImplementedError" in body


def test_an_enclosing_element_with_an_unread_attribute_closes_the_gate() -> None:
    """The list and every element around it carry only Name and Desc; anything else, such as an
    ``Enabled`` on the package, renders the list as step 1 does."""
    src = generate_module(
        parse_package(
            '<Package Name="ACME X" Enabled="false"><ActionList Name="T"><List>'
            + _CLONE_WRITE_SEND
            + "</List></ActionList></Package>"
        )[0]
    )
    assert "out_msg" not in src
    assert "out_msg = msg.copy()" in _handler_source(_CLONE_WRITE_SEND)  # the control arm


@pytest.mark.parametrize(
    "spoiler",
    [
        pytest.param(_write("other-handle", "%out", "Q"), id="a-case-variant-of-a-handle"),
        pytest.param(
            _CLONE_WRITE_SEND.replace("<Line ", '<Line Enabled="false" ', 1), id="unread-attribute"
        ),
        pytest.param(
            _role_line(
                _span("keyword", "MsgLog")
                + " "
                + _span("input-handle", "%ADT")
                + " "
                + _span("description", "note")
            ),
            id="a-description-span",
        ),
        pytest.param(
            _role_line(_span("keyword", "msglog") + " " + _span("input-handle", "%ADT")),
            id="a-lowercase-verb",
        ),
        pytest.param('<Block Data="itemclear OUT"><List></List></Block>', id="a-verb-label"),
        pytest.param('<Block Data="Section"><List></List></Block>', id="any-block-label"),
        pytest.param(_write("other-handle", "%OUT", "Q", "/MSH-6 (Facility)"), id="a-path-note"),
        pytest.param('<If Data="If (x)"><List></List></If>', id="any-construct"),
        pytest.param('<Line Data="ItemClear %ADT/PID-19"/>', id="a-markup-free-statement"),
    ],
)
def test_one_element_off_the_allow_list_renders_the_whole_list_as_step_1(spoiler: str) -> None:
    """The gate is decided for the WHOLE list: one element it does not fully understand, anywhere,
    and the clone is msg again exactly as step 1 renders it. No local is bound."""
    body = _handler_body(_handler_source(_CLONE_WRITE_SEND + spoiler))
    assert "_msg = " not in body
    assert "out_msg" not in body


def test_a_module_with_locals_round_trips_through_the_lens() -> None:
    """ADR 0086 AC-4 for the new shapes: no whole-file refusal, and every live send is a send row."""
    from messagefoundry.lens import parse_source

    src = _handler_source(
        _CLONE_WRITE_SEND + _create("%NEW") + _role_send("other-handle", "%NEW", "OB_NEW")
    )
    (contract,) = parse_source(src)
    sends = [row for row in contract["rows"] if row["kind"] == "send"]
    assert [row["outbounds"] for row in sends] == [["OB_ACME"], ["OB_NEW"]]


def test_a_fully_understood_module_passes_check(tmp_path: Path) -> None:
    """The emitted module with locals parses, compiles and passes ``messagefoundry check``."""
    export = tmp_path / "pkg.xml"
    body = _CLONE_WRITE_SEND + _create("%NEW") + _role_send("other-handle", "%NEW", "OB_NEW")
    export.write_text(_package(body), encoding="utf-8")
    summary = import_corepoint(export, tmp_path / "out").to_json()
    assert summary["total_unmapped"] == 0
    assert run_checks(tmp_path / "out", run_lint=False).ok


# --- a statement anywhere but on a <Line> (BACKLOG #2632) -----------------------------------------
#
# A ``<Block>``, ``<Call>`` or construct whose ``@Data`` is a statement used to render as a label, or
# as the text of a dead condition, and count nothing, while the handle scan read its ``MsgTreeCopy``
# as a clone that was made. A send of that clone then rendered as a send of ``msg``. One rule,
# ``_label_statement``, now answers for both, for every element that is not a ``<Line>``: the render
# marks the statement as a counted TODO ahead of the element's body and never emits it as live
# code, and the scan holds no handle for the list. All fixtures are synthetic.

_CLONE_LINE = _root_copy("input-handle", "%ADT", "other-handle", "%OUT")
_SEND_COPY = _role_send("other-handle", "%OUT", "OB_ACME")
_SEND_INPUT = _role_send("input-handle", "%ADT", "OB_IN")
_WRITE_COPY = _write("other-handle", "%OUT", "Y")
_MERGE_LINE = _role_line(_span("keyword", "MsgTreeMerge") + " " + _span("other-handle", "%NEW"))
_LABEL_MARKER = "not on a Line, so it may never have run"
_CONTAINER_TAGS = ("Block", "Call", "Case", "Foreach", "If", "Loop", "Try")
# One spelling of each statement verb, by the table's own key.
_VERB_SPELLINGS = {
    "itemappend": "ItemAppend",
    "itemclear": "ItemClear",
    "itemcopy": "ItemCopy",
    "msgcreate": "MsgCreate",
    "msglog": "MsgLog",
    "msgsend": "MsgSend",
    "msgtreecopy": "MsgTreeCopy",
}


def _container(tag: str, line: str, body: str = "", disabled: bool = False) -> str:
    """A ``<tag>`` carrying the ``@Data`` of ``line``, a ``<Line .../>`` as :func:`_role_line`
    builds one, around ``body``."""
    opening = line.replace("<Line ", f"<{tag} ", 1).removesuffix("/>")
    return f"{opening}{' Disabled="1"' if disabled else ''}><List>{body}</List></{tag}>"


def _labelled(tag: str, data: str, body: str = "") -> str:
    """A ``<tag>`` whose ``@Data`` is the plain text ``data``."""
    return _container(tag, _role_line(data), body)


@pytest.mark.parametrize("tag", _CONTAINER_TAGS)
def test_a_clone_where_a_label_belongs_is_marked_and_its_send_is_judged_on_the_marker(
    tag: str,
) -> None:
    """The defect as filed, on each container. The copy is marked and counted, at the handler's own
    level and ahead of everything in the container's body. It is not emitted as a clone, so the
    later send of the copy is refused, where it used to send msg."""
    body = _container(tag, _CLONE_LINE, _WRITE_COPY) + _SEND_COPY
    lines = _handler_body(_handler_source(body)).splitlines()
    marker = next(i for i, line in enumerate(lines) if _LABEL_MARKER in line)
    assert lines[marker].startswith("    # TODO: Corepoint MsgTreeCopy — hand-finish (")
    assert marker < next(i for i, line in enumerate(lines) if "Corepoint ItemCopy" in line)
    assert not any("Send(" in line or "_msg = " in line for line in lines)
    assert not any("set_field(" in line for line in lines)
    assert any("raise NotImplementedError" in line for line in lines)
    unmapped = _count_steps(_handler_steps(body), in_loop=False)[1]
    assert unmapped == ["MsgTreeCopy", "ItemCopy", "MsgSend"]


def test_a_blocks_marker_follows_its_label_comment_and_nothing_counts_as_mapped() -> None:
    body = _container("Block", _CLONE_LINE, _WRITE_COPY) + _SEND_COPY
    lines = _handler_body(_handler_source(body)).splitlines()
    label = lines.index("    # Corepoint Block: MsgTreeCopy %ADT/ to %OUT/")
    assert _LABEL_MARKER in lines[label + 1]
    assert lines[label + 1].endswith("taken to be msg: MsgTreeCopy %ADT/ to %OUT/)")
    assert _count_steps(_handler_steps(body), in_loop=False)[0] == 0


def test_a_prose_block_label_stays_a_label() -> None:
    """The control: prose is a label. Nothing is marked, the write maps and the input still sends."""
    body = _labelled("Block", "Patient identity", _WRITE_INPUT) + _SEND_INPUT
    src = _handler_body(_handler_source(body))
    assert "    # Corepoint Block: Patient identity\n" in src
    assert _LABEL_MARKER not in src and "TODO" not in src
    assert '    set_field(msg, "MSH-6", "X")\n' in src
    assert '    sends.append(Send("OB_IN", msg))' in src
    assert _count_steps(_handler_steps(body), in_loop=False) == (2, [], 0)


def test_the_same_clone_on_a_line_is_still_read_as_made() -> None:
    """The control for the scan. The clone is a ``<Line>`` under a prose Block, which closes the
    gate, so this is the step 1 path too. There the copy still counts, and its send still sends. So
    the refusals above come from where the statement sits, not from the copy itself."""
    src = _handler_body(
        _handler_source(_labelled("Block", "Patient identity", _CLONE_LINE) + _SEND_COPY)
    )
    assert '    sends.append(Send("OB_ACME", msg))' in src
    assert "raise NotImplementedError" not in src and _LABEL_MARKER not in src


def test_a_field_write_in_a_block_label_is_marked_and_never_mapped() -> None:
    """Whether Corepoint runs the label is not known, so the write is a TODO, not a ``set_field``."""
    body = _container("Block", _WRITE_INPUT) + _SEND_INPUT
    src = _handler_body(_handler_source(body))
    assert "    # TODO: Corepoint ItemCopy — hand-finish (not on a Line" in src
    assert "set_field(" not in src and "Send(" not in src
    assert _count_steps(_handler_steps(body), in_loop=False) == (0, ["ItemCopy", "MsgSend"], 0)


@pytest.mark.parametrize(
    ("element", "carried"),
    [
        pytest.param(_container("Block", _CLONE_LINE), True, id="block-role-clone"),
        # The row's own example: no role markup, so the scan could never read what it overwrites.
        pytest.param(
            _labelled("Block", "MsgTreeCopy %NEW/ to %ADT/"), True, id="block-flat-copy-over-input"
        ),
        pytest.param(_labelled("Block", "itemclear OUT"), True, id="block-flat-lowercase-verb"),
        pytest.param(
            _labelled("Block", _span("block", "MsgTreeCopy %NEW/ to %ADT/")),
            True,
            id="block-label-span-around-a-statement",
        ),
        pytest.param(_container("Block", _MERGE_LINE), True, id="block-keyword-not-in-the-table"),
        pytest.param(_labelled("If", 'MsgSend %OUT to connection "OB_X"'), True, id="if-flat-send"),
        pytest.param(_labelled("Call", "MsgLog %ADT"), True, id="call-flat-log"),
        # A send would be live code, so a Block or a Call never renders one from its ``@Data``.
        pytest.param(
            _container("Block", _role_send("input-handle", "%ADT", "OB_LABEL")),
            True,
            id="block-send",
        ),
        pytest.param(
            _labelled("Call", 'msgsend %ADT to connection "OB_LABEL"'), True, id="call-send"
        ),
        # A ``<List>`` wrapper is flattened and its own ``@Data`` was never rendered at all.
        pytest.param(_container("Actions", _CLONE_LINE), True, id="actions-wrapper"),
        pytest.param(_container("List", _CLONE_LINE), True, id="list-wrapper"),
        pytest.param(
            _container("List", _CLONE_LINE, disabled=True), True, id="disabled-list-wrapper"
        ),
        # An element the import does not model is already marked as that. Its statement is too.
        pytest.param(_container("Switch", _CLONE_LINE), True, id="unmodelled-tag-clone"),
        pytest.param(
            _container("Switch", _role_send("input-handle", "%ADT", "OB_LABEL")),
            True,
            id="unmodelled-tag-send",
        ),
        pytest.param(_container("If", _MERGE_LINE), False, id="construct-keyword-not-in-the-table"),
        pytest.param(
            _container("Switch", _MERGE_LINE), False, id="unmodelled-keyword-not-in-the-table"
        ),
        # A keyword span that does not LEAD the label is a styled connective, not a verb.
        pytest.param(
            _labelled("Block", "Copy patient " + _span("keyword", "to") + " output"),
            False,
            id="block-keyword-connective-in-prose",
        ),
        # A leading keyword on a wrapper, which has no verb of its own, is a statement too.
        pytest.param(_container("List", _MERGE_LINE), True, id="list-wrapper-keyword"),
        # A limit ADR 0086 records: the verb is read as a Line's is, so it must lead.
        pytest.param(
            _labelled("Block", "Step 1: MsgTreeCopy %NEW/ to %OUT/"), False, id="verb-not-leading"
        ),
        pytest.param(_labelled("Block", "Patient identity"), False, id="prose"),
        pytest.param(_labelled("Block", "Message header"), False, id="prose-near-a-verb"),
        pytest.param(_labelled("If", 'If (%ADT/PID-8 = "M")'), False, id="if-condition"),
        pytest.param(_labelled("Foreach", "ForEach %ADT/OBX $obx"), False, id="foreach"),
        pytest.param(_labelled("Loop", "While (x)"), False, id="loop-with-another-verb"),
        pytest.param(_labelled("Case", "ChooseFrom (x)"), False, id="case"),
        pytest.param(_labelled("Call", 'ActionListCall "Sub"'), False, id="call"),
        pytest.param(_container("Block", _CLONE_LINE, disabled=True), False, id="disabled-block"),
    ],
)
def test_the_scan_and_the_render_ask_one_rule(element: str, carried: bool) -> None:
    """Wherever the render marks a statement, the scan holds nothing, and nowhere else. Each list
    ends with a send of its one input handle, so the scan holds that handle unless the rule fires."""
    body = element + _SEND_INPUT
    src = _handler_body(_handler_source(body))
    held = _message_handles(_hardened_fromstring(_package(body))[0])[1]
    assert (_LABEL_MARKER in src) is carried
    assert (held == frozenset()) is carried
    assert ('Send("OB_IN", msg)' in src) is not carried
    assert ("raise NotImplementedError" in src) is carried
    if carried:
        assert "Send(" not in src  # no live send at all: not the input's, not the statement's


@pytest.mark.parametrize("tag", [*_CONTAINER_TAGS, "Switch", "List"])
@pytest.mark.parametrize("verb", sorted(_STATEMENT_VERBS))
def test_every_statement_verb_is_marked_on_every_element_but_a_line(tag: str, verb: str) -> None:
    """Each verb of the table, in its usual spelling, lower case and upper case, on each container,
    an unmodelled tag and a list wrapper. On a ``<Line>`` the same text is an ordinary statement."""
    for spelling in (_VERB_SPELLINGS[verb], verb, verb.upper()):
        data = f"{spelling} %OUT"
        src = _handler_body(_handler_source(_labelled(tag, data) + _SEND_INPUT))
        assert _LABEL_MARKER in src and "Send(" not in src, spelling
        line = _handler_body(_handler_source(_role_line(data) + _SEND_INPUT))
        assert _LABEL_MARKER not in line, spelling


def test_a_statement_in_a_try_or_a_list_wrapper_is_named_in_its_marker() -> None:
    """Neither prints its ``@Data`` anywhere else, so the marker carries the statement itself."""
    for tag in ("Try", "Actions"):
        src = _handler_body(_handler_source(_container(tag, _CLONE_LINE) + _SEND_COPY))
        assert src.count("MsgTreeCopy %ADT/ to %OUT/") == 1, tag
        assert "taken to be msg: MsgTreeCopy %ADT/ to %OUT/)" in src, tag


def test_a_send_in_a_block_label_is_never_a_delivery() -> None:
    """A ``MsgSend`` in a Block's ``@Data`` used to render as a live send of msg, with its outbound
    declared. It may never have run, so it is marked, and the Block renders as the label it is."""
    body = _container("Block", _role_send("input-handle", "%ADT", "OB_LABEL"))
    src = _handler_source(body)
    assert "Send(" not in _handler_body(src) and 'outbound("OB_LABEL"' not in src
    assert "    # Corepoint Block: MsgSend %ADT to connection" in src
    assert "    # TODO: Corepoint MsgSend — hand-finish (not on a Line" in src
    assert _count_steps(_handler_steps(body), in_loop=False) == (0, ["MsgSend"], 0)
    # On a Call it is no call either: not counted as mapped, not labelled as an inlined list.
    call = _container("Call", _role_send("input-handle", "%ADT", "OB_LABEL"))
    assert _count_steps(_handler_steps(call), in_loop=False) == (0, ["MsgSend"], 0)
    assert "called list inlined" not in _handler_source(call)
    # The control: the same send on a Line under a prose Block is a delivery.
    line = _labelled("Block", "Section", _role_send("input-handle", "%ADT", "OB_LABEL"))
    assert 'sends.append(Send("OB_LABEL", msg))' in _handler_source(line)


@pytest.mark.parametrize("verb", sorted(_STATEMENT_VERBS))
def test_a_call_carrying_a_statement_is_a_label_and_not_a_call(verb: str) -> None:
    """One rule for every element but a Line. A ``<Call>`` whose ``@Data`` is a statement names no
    list to inline, so it is not counted as a mapped call, whichever statement it is. Its body
    still renders beneath the label. The control is a Call that names a list."""
    data = f"{_VERB_SPELLINGS[verb]} %ADT"
    call = _labelled("Call", data, '<Line Data="ItemClear %ADT/PID-19"/>')
    src = _handler_body(_handler_source(call))
    assert f"    # Corepoint Call: {data}\n" in src and "called list inlined" not in src
    assert '    set_field(msg, "PID-19", "")' in src
    assert _count_steps(_handler_steps(call), in_loop=False) == (1, [_VERB_SPELLINGS[verb]], 0)
    named = _labelled("Call", 'ActionListCall "Sub"', '<Line Data="ItemClear %ADT/PID-19"/>')
    assert "called list inlined" in _handler_source(named)
    assert _count_steps(_handler_steps(named), in_loop=False) == (2, [], 0)


_SIBLING_BRANCHES = {
    "if-else": ('<If Data="If (x)"><List/></If>', "Else"),
    "if-elseif": ('<If Data="If (x)"><List/></If>', "ElseIf (y)"),
    "try-catch": ("<Try><List/></Try>", "Catch"),
    "case-matching": ('<Case Data="ChooseFrom (x)"><List/></Case>', 'Matching "M"'),
}
# What sits between a construct and the branch marker written after it as a sibling. ``{S}`` is
# where a wrapper carries a statement; the control is the same text with no statement there.
_EMPTY_WRAPPERS = {
    "one-wrapper": "<List{S}/>",
    "two-wrappers-side-by-side": "<List{S}/><Actions{S}/>",
    "inner-of-two": "<List><List{S}/></List>",
    "outer-of-two": "<List{S}><List/></List>",
    "both-of-two": "<List{S}><List{S}/></List>",
    "innermost-of-three": "<List><List><List{S}/></List></List>",
    "middle-of-three": "<List><List{S}><List/></List></List>",
    "outermost-of-three": "<Actions{S}><List><List/></List></Actions>",
    "all-of-three": "<List{S}><Actions{S}><List{S}/></Actions></List>",
}
_FILLED = '<Line Data="ItemClear %ADT/PID-20"/>'
# A wrapper holding a statement of its own. On main it already orphans the branch, with or
# without a statement on the wrapper, and that is out of scope here: it must not get worse.
_FILLED_WRAPPERS = {
    "filled-one-wrapper": f"<List{{S}}>{_FILLED}</List>",
    "filled-inner-of-two": f"<List><List{{S}}>{_FILLED}</List></List>",
    "filled-outer-of-two": f"<List{{S}}><List>{_FILLED}</List></List>",
    "filled-beside-the-inner-of-two": f"<List>{_FILLED}<List{{S}}/></List>",
}
_WRAPPER_STATEMENT = ' Data="MsgLog %ADT"'
_ORPHAN = "with no enclosing construct"


def _sibling_arm(branch: str) -> str:
    """A branch ``<Line>`` holding a markup-free write and send, which no handle rule refuses."""
    return _labelled("Line", branch, _CLEAR + '<Line Data="MsgSend %ADT [OB_FLAT]"/>')


def _code(src: str) -> list[str]:
    """The lines of a rendered handler that are not comments: what runs, and how deep."""
    return [line for line in src.splitlines() if not line.lstrip().startswith("#")]


def _assert_the_markers_change_no_code(template: str, markers: int) -> str:
    """The rule the whole family below asks: a statement on a wrapper adds its counted marker and
    changes nothing else. The same code runs at the same indentation, and a branch is an orphan
    only where it is one with no statement there. Returns the marked handler body."""
    marked, control = (
        _handler_body(_handler_source(template.replace("{S}", statement)))
        for statement in (_WRAPPER_STATEMENT, "")
    )
    assert marked.count(_LABEL_MARKER) == markers
    assert _code(marked) == _code(control)
    assert marked.count(_ORPHAN) == control.count(_ORPHAN)
    return marked


@pytest.mark.parametrize("between", _EMPTY_WRAPPERS)
@pytest.mark.parametrize("pair", _SIBLING_BRANCHES)
def test_a_wrappers_marker_never_orphans_a_sibling_branch(pair: str, between: str) -> None:
    """A branch marker written after its construct as a sibling is adopted by it, and its body is
    then dead until someone writes the condition. An orphaned branch renders its body live. A
    wrapper's marker is no statement position, so the adoption does not see it: at any depth of
    wrapper, on the inner one or the outer, the branch is adopted exactly as it is with no
    statement there."""
    construct, branch = _SIBLING_BRANCHES[pair]
    template = construct + _EMPTY_WRAPPERS[between] + _sibling_arm(branch)
    src = _assert_the_markers_change_no_code(template, _EMPTY_WRAPPERS[between].count("{S}"))
    # main adopts this branch, so nothing of it runs at the handler's own level.
    assert _ORPHAN not in src
    assert not [
        line for line in src.splitlines() if line.startswith(("    sends.append", "    set_field"))
    ]
    assert '        sends.append(Send("OB_FLAT", msg))' in src


@pytest.mark.parametrize("between", _FILLED_WRAPPERS)
@pytest.mark.parametrize("pair", _SIBLING_BRANCHES)
def test_a_wrappers_marker_changes_nothing_where_main_already_orphans(
    pair: str, between: str
) -> None:
    """The control for the test above, and the limit it leaves. A wrapper with a statement of its
    own between a construct and its sibling branch orphans that branch on main, whatever the
    wrapper's ``@Data``. The marker neither repairs that nor adds to it."""
    construct, branch = _SIBLING_BRANCHES[pair]
    template = construct + _FILLED_WRAPPERS[between] + _sibling_arm(branch)
    src = _assert_the_markers_change_no_code(template, 1)
    assert src.count(_ORPHAN) == 1
    assert '    sends.append(Send("OB_FLAT", msg))' in src


@pytest.mark.parametrize("between", ["<List{S}/>", "<List><List{S}/></List>"])
@pytest.mark.parametrize(
    "frame",
    [
        # A branch-group wrapper: an ``<If>`` with no ``@Data`` whose children are the branches.
        pytest.param(
            '<If><Line Data="If (x)"><List/></Line>{between}</If>{arm}', id="branch-group"
        ),
        # A ``<Line>`` carrying a nested list: its body is flattened to the Line's own level, so
        # a construct at the end of it adopts a branch written after the Line.
        pytest.param(
            '<Line Data="ItemClear %ADT/PID-18"><List>'
            '<If Data="If (x)"><List/></If>{between}</List></Line>{arm}',
            id="tail-of-a-line-body",
        ),
        # The wrapper holds the construct itself, and the branch follows the wrapper.
        pytest.param(
            '<List><If Data="If (x)"><List/></If>{between}</List>{arm}',
            id="wrapper-around-the-construct",
        ),
    ],
)
def test_a_marker_at_the_end_of_any_flattened_body_never_orphans_a_branch(
    frame: str, between: str
) -> None:
    """A marker reaches the list a branch is adopted in by more routes than a wrapper beside the
    construct. Each of them leaves the marker last in a body that is flattened to that level."""
    template = frame.replace("{between}", between).replace("{arm}", _sibling_arm("Else"))
    src = _assert_the_markers_change_no_code(template, 1)
    assert _ORPHAN not in src
    assert '        sends.append(Send("OB_FLAT", msg))' in src


def test_a_send_label_keeps_its_body_where_main_put_it() -> None:
    """main rendered a ``MsgSend`` in a Block's ``@Data`` as a live send and then its body at the
    Block's own level, so a construct ending that body adopted a branch written after the Block.
    The send is now a marker under the label. The body stays at that level, so the branch is
    still adopted and its send stays dead."""
    body = _labelled(
        "Block", "MsgSend %ADT [OB_LABEL]", '<If Data="If (x)"><List/></If>'
    ) + _sibling_arm("Else")
    src = _handler_body(_handler_source(body))
    assert _LABEL_MARKER in src and _ORPHAN not in src
    assert 'Send("OB_LABEL"' not in src
    assert '        sends.append(Send("OB_FLAT", msg))' in src
    assert not [line for line in src.splitlines() if line.startswith("    sends.append")]


@pytest.mark.parametrize("pair", _SIBLING_BRANCHES)
def test_a_branch_marker_holding_only_a_marked_wrapper_still_opens_its_branch(pair: str) -> None:
    """The in-body form. A branch marker written in its construct's own list opens a branch when
    it holds no statement, and what follows it is dead until the condition is written. A wrapper
    carrying a statement, inside that marker's ``<Line>``, adds a label marker and no statement.
    So the branch still opens, and the label marker leads it."""
    construct, branch = _SIBLING_BRANCHES[pair]
    opener = _labelled("Line", branch, "<List{S}/>")
    arm = _CLEAR + '<Line Data="MsgSend %ADT [OB_FLAT]"/>'
    template = construct.replace("<List/>", f"<List>{_FILLED}{opener}{arm}</List>")
    src = _assert_the_markers_change_no_code(template, 1)
    assert '        sends.append(Send("OB_FLAT", msg))' in src
    assert not [line for line in src.splitlines() if line.startswith("    sends.append")]
    assert next(line for line in src.splitlines() if _LABEL_MARKER in line).startswith(
        " " * 8 + "#"
    )


@pytest.mark.parametrize(
    ("outer", "label", "plain", "orphans"),
    [
        # main reads a ``<Call>`` with no ``@Data`` around a call as a branch-group and drops the
        # wrapper, so the If inside it adopts the Else written after it.
        pytest.param(
            "Call",
            _labelled("Call", "MsgLog %ADT"),
            _labelled("Call", 'ActionListCall "Sub"'),
            0,
            id="a-call-in-a-bare-call",
        ),
        # A bare ``<Block>`` around a call or a send is no branch-group on main. It stays a
        # label, and the Else after it is an orphan there, statement or no statement.
        pytest.param(
            "Block",
            _labelled("Call", "MsgLog %ADT"),
            _labelled("Call", 'ActionListCall "Sub"'),
            1,
            id="a-call-in-a-bare-block",
        ),
        pytest.param(
            "Block",
            _labelled("Block", "MsgSend %ADT [OB_LABEL]"),
            '<Line Data="MsgSend %ADT [OB_LABEL]"/>',
            1,
            id="a-send-in-a-bare-block",
        ),
    ],
)
def test_a_demoted_label_changes_no_shape_around_it(
    outer: str, label: str, plain: str, orphans: int
) -> None:
    """A Call or a send label becomes a plain label when its ``@Data`` is a statement. Whether
    the element around it is a branch-group is still read from the kind it had, so the tree keeps
    the shape it has with the plain call, or the plain send, in its place. Only that send goes."""
    construct, branch = _SIBLING_BRANCHES["if-else"]
    marked, control = (
        _handler_body(
            _handler_source(f"<{outer}>{inner}{construct}</{outer}>" + _sibling_arm(branch))
        )
        for inner in (label, plain)
    )
    assert _LABEL_MARKER in marked and _LABEL_MARKER not in control
    assert _code(marked) == [line for line in _code(control) if "OB_LABEL" not in line]
    assert marked.count(_ORPHAN) == control.count(_ORPHAN) == orphans


def test_demoting_a_handlers_only_visible_send_adds_no_trailing_send() -> None:
    """A handler with no send the render reaches ends on ``return Send(...)`` for every
    destination in its tree, and main leaves one kind of send in the tree unrendered: a send in a
    branch that another branch holds. So when a send label is the handler's only visible send,
    demoting it must not move the handler to that form. It keeps its ``sends`` list, and delivers
    nothing. The control is the same list with the label's send on a Line."""
    hidden = (
        '<Block Data="Matching &quot;M&quot;"><Line Data="Matching &quot;M&quot;"/>'
        '<Line Data="MsgSend %ADT [OB_HIDDEN]"/></Block>'
    )
    marked, control = (
        _handler_body(_handler_source(f"<Case>{hidden}{send}</Case>"))
        for send in (
            _labelled("Block", "MsgSend %ADT [OB_LABEL]"),
            '<Line Data="MsgSend %ADT [OB_LABEL]"/>',
        )
    )
    assert _LABEL_MARKER in marked and "Send(" not in marked
    assert "    return sends" in marked and "    return sends" in control
    assert 'Send("OB_HIDDEN"' not in control and 'Send("OB_LABEL", msg)' in control


def test_a_wrappers_marker_stays_where_the_wrapper_sat() -> None:
    """Source order. A marker is not moved ahead of a construct it follows. Where that construct
    adopts a branch written after the wrapper, the marker follows the whole chain."""
    construct, branch = _SIBLING_BRANCHES["if-else"]

    def order(body: str) -> list[str]:
        lines = _handler_body(_handler_source(body)).splitlines()
        named = {"    if ": "if", "    elif ": "else", _LABEL_MARKER: "marker", "PID-21": "next"}
        return [name for line in lines for text, name in named.items() if text in line]

    after = '<Line Data="ItemClear %ADT/PID-21"/>'
    for nesting in ("one-wrapper", "inner-of-two"):
        between = _EMPTY_WRAPPERS[nesting].replace("{S}", _WRAPPER_STATEMENT)
        assert order(construct + between + after) == ["if", "marker", "next"]
        arm = _sibling_arm(branch)
        assert order(construct + between + arm + after) == ["if", "else", "marker", "next"]


def test_a_hostile_label_statement_cannot_escape_its_marker() -> None:
    """The statement is untrusted export text. It rides in a comment, flattened and elided."""
    hostile = "MsgTreeCopy %NEW/ to %ADT/\nimport os  # " + "x" * 5000
    src = _handler_source(_labelled("Try", hostile) + _SEND_INPUT)
    compile(src, "generated.py", "exec")
    assert "\nimport os" not in src
    marker = next(line for line in src.splitlines() if _LABEL_MARKER in line)
    assert "MsgTreeCopy %NEW/ to %ADT/ import os" in marker and len(marker) < 400


@pytest.mark.parametrize("tag", _CONTAINER_TAGS)
def test_a_statement_label_keeps_the_whole_list_gate_closed(tag: str) -> None:
    """The gate admits a ``<Block>`` only with no label, and no construct at all. So a list holding
    such a container never binds a local: it takes the step 1 path, where the rule above applies.
    The same list without the container opens the gate, which
    ``test_an_enclosing_element_with_an_unread_attribute_closes_the_gate`` shows as its control."""
    body = _CLONE_WRITE_SEND + _container(tag, _CLONE_LINE)
    root = _hardened_fromstring(_package(body))
    assert (
        _understood_list(root[0], {child: parent for parent in root.iter() for child in parent})
        is None
    )
    src = _handler_body(_handler_source(body))
    assert "_msg = " not in src and "Send(" not in src


def test_a_send_of_a_clone_only_a_label_names_raises_when_the_handler_runs(tmp_path: Path) -> None:
    with pytest.raises(NotImplementedError, match="MsgSend delivers %OUT"):
        _run_handler(tmp_path, _container("Block", _CLONE_LINE) + _SEND_COPY)


def test_a_marked_label_statement_is_counted_and_the_module_passes_check(tmp_path: Path) -> None:
    export = tmp_path / "pkg.xml"
    export.write_text(_package(_container("Block", _CLONE_LINE) + _SEND_COPY), encoding="utf-8")
    summary = import_corepoint(export, tmp_path / "out").to_json()
    assert (summary["total_mapped"], summary["total_unmapped"]) == (0, 2)
    assert run_checks(tmp_path / "out", run_lint=False).ok


def test_the_statement_verb_table_holds_every_verb_the_importer_reads_on_a_line() -> None:
    """A verb added to the role-parsed step 1 mapping or to the gate's allow-list must join the
    table too, or its statement off a Line would go back to being a label. The table is kept
    apart from both, so taking a verb OFF the allow-list, which narrows the gate, cannot shrink
    it. These are the two tables this test can read: a verb the importer names only in code,
    as the scan names ``msgtreecopy``, is pinned by name."""
    assert {verb.lower() for verb in _UNDERSTOOD} | set(_VERB_CONNECTIVES) <= _STATEMENT_VERBS
    assert "msgtreecopy" in _STATEMENT_VERBS
    assert set(_VERB_SPELLINGS) == _STATEMENT_VERBS


def test_the_container_tags_under_test_are_the_importers_own() -> None:
    """A container tag the importer gains must gain its cases here too."""
    assert {tag.lower() for tag in _CONTAINER_TAGS} == set(_CONTAINER_KIND_BY_TAG)


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
    # 3 vocabulary calls from the flat list + 3 from the role list + 15 control constructs.
    assert summary["total_mapped"] == 21
    # 3 from the flat list + 5 role statements the guards correctly refuse to map.
    assert summary["total_unmapped"] == 8
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
    src = _handler_source(
        '<Line Data="MsgSend $o [OB_A]"><List><Line Data="ItemClear %ADT/PID-19"/></List></Line>'
    )
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
    assert summary["total_mapped"] == 21
    assert summary["total_unmapped"] == 8
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
