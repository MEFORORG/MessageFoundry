# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Deterministic Corepoint action-list import (ADR 0086) — mapping, count-and-log, check gate, security.

The lens round-trip half of the correctness gate (AC-4) lives in ``tests/test_lens_parse.py`` beside
the other lens property tests; here we cover the mapping fidelity, the never-drop count-and-log ethos,
the ``messagefoundry check`` structural gate on emitted modules, and the untrusted-input handling."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from messagefoundry.checks import run_checks
from messagefoundry.corepoint_import import (
    Action,
    Control,
    CorepointImportError,
    UnmappedAction,
    _corepoint_path,
    _corepoint_segment,
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

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "corepoint"


def _acme_export() -> str:
    return (FIXTURES / "acme_adt.json").read_text(encoding="utf-8")


def _acme_package() -> str:
    return (FIXTURES / "acme_adt_package.xml").read_text(encoding="utf-8")


def _package_source() -> str:
    """The generated module for the synthetic ``<Package>`` XML fixture."""
    return generate_module(parse_package(_acme_package(), source_name="acme_adt_package")[0])


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
    """An unmapped verb is never silently dropped — TODO marker, best-effort stub, counted (AC-2)."""
    src = _package_source()
    assert "# TODO: Corepoint ItemCustomScript — hand-finish" in src
    assert 'msg.set("OBX-5", msg.field("OBX-5") or "")' in src
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
    # The recoverable half of each statement still rides across as the stub target.
    assert 'msg.set("PID-3.1"' in src
    assert 'msg.set("NK1-2.1"' in src


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


def test_try_without_catch_reraises_rather_than_swallowing() -> None:
    src = _handler_source('<Try><List><Line Data="ItemClear %ADT/PID-19"/></List></Try>')
    assert "except Exception:  # TODO: Corepoint Try with no Catch" in src
    assert "        raise" in src
    ast.parse(src)


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
