# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Spike S-4: measure the FR-40 Steps-only classifier prototype against FR-41's cases.

Every head in the MUST PASS half is produced by the real ``lens rewrite`` on a ``samples/config``
module, so the classifier is measured against what the generator actually writes. The MUST FAIL
half uses the lens where it accepts the payload today (the R1 hatches have not closed) and a plain
text edit where the change stands for another tool. All sources are synthetic samples.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from messagefoundry.lens import CONTRACT_V2, parse_source, rewrite_source
from scripts.theia_spike.steps_only import Verdict, classify_change, classify_file

CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"
ADT = "samples/config/adt.py"


def _sample(name: str) -> str:
    # Bytes, so a CRLF checkout stays byte-exact through the rewrite and the classifier.
    return (CONFIG / name).read_bytes().decode("utf-8")


def _row(src: str, needle: str) -> dict[str, Any]:
    """The row whose first physical line contains ``needle`` (exactly one must)."""
    lines = src.splitlines()
    found = [
        dict(row, handler=entry["handler"])
        for entry in parse_source(src, contract=CONTRACT_V2)
        for row in entry["rows"]
        if needle in lines[row["line_start"] - 1]
    ]
    assert len(found) == 1, (needle, found)
    return found[0]


def _edit(src: str, needle: str, **edit: Any) -> str:
    row = _row(src, needle)
    spec = {"line_start": row["line_start"], "line_end": row["line_end"], **edit}
    spec.setdefault("handler", row["handler"])
    out = rewrite_source(src, spec, contract=CONTRACT_V2)
    assert out != src, "the edit changed nothing"
    return out


def _passes(base: str, head: str, path: str = ADT) -> None:
    verdict = classify_file(path, base, head)
    assert verdict.steps_only, verdict.reasons


def _fails(base: str, head: str, rule: str, path: str = ADT) -> Verdict:
    verdict = classify_file(path, base, head)
    assert not verdict.steps_only
    assert any(r.startswith(rule) for r in verdict.reasons), verdict.reasons
    return verdict


MNEMONIC = "mnemonic = FACILITY_MNEMONICS.get"  # a hand-written code row in adt.py's handler
SEND = 'return Send("FILE-OUT_Test_ADT", msg)'

# One literal call per insertable vocabulary action, lookup and diagnostic (lens _ACTION_PARAMS,
# _LOOKUP_PARAMS, _DIAGNOSTIC_PARAMS, and the native forms).
INSERTS: list[tuple[str, dict[str, Any], str | None]] = [
    ("copy_field", {"src": "PID-3.1", "dst": "PID-2"}, None),
    ("set_field", {"path": "PID-5.1", "value": "DOE"}, None),
    ("append_to_field", {"path": "PID-5.1", "suffix": " JR"}, None),
    ("trim_field", {"path": "PID-5.1"}, None),
    ("substring_field", {"path": "PID-3.1", "start": 0, "end": 6}, None),
    ("pad_field", {"path": "PID-3.1", "width": 10, "fill": "0"}, None),
    ("replace_literal", {"path": "PID-5.1", "old": "MRS", "new": "MS"}, None),
    ("convert_case", {"path": "PID-5.1", "mode": "upper"}, None),
    ("arith_field", {"path": "OBX-5", "op": "*", "operand": 2}, None),
    ("format_date", {"path": "PID-7", "out_fmt": "%Y%m%d", "in_fmt": "%Y-%m-%d"}, None),
    ("date_diff_field", {"start_path": "PV1-44", "end_path": "PV1-45", "dst": "ZLS-1"}, None),
    ("split_field", {"src": "PID-5", "sep": "^", "dests": {"expr": '["ZNM-1", "ZNM-2"]'}}, None),
    ("copy_segment", {"segment_id": "PID"}, None),
    ("delete_segment", {"segment_id": "NTE"}, None),
    ("add_segment", {"line": "ZZZ|1"}, None),
    ("add_repetition", {"path": "PID-3", "value": "123"}, None),
    (
        "db_lookup",
        {"connection": "DB_MPI", "statement": "SELECT 1", "params": {"expr": "{}"}},
        "row",
    ),
    (
        "db_lookup",
        {
            "connection": "DB_MPI",
            "statement": "SELECT mrn FROM p WHERE id = :id",
            "params": {"expr": '{"id": msg["PID-3.1"] or ""}'},
        },
        "mpi_row",
    ),
    (
        "fhir_lookup",
        {"connection": "FHIR_EHR", "query": "Patient/1", "params": {"expr": "{}"}},
        "pt",
    ),
    ("log_note", {"template": "routed"}, None),
    ("checkpoint", {"label": "after insert"}, None),
]


# --- MUST PASS ------------------------------------------------------------------------------


@pytest.mark.parametrize(("action", "params", "assign_to"), INSERTS, ids=lambda v: str(v)[:20])
def test_pass_insert_each_vocabulary_action(
    action: str, params: dict[str, Any], assign_to: str | None
) -> None:
    base = _sample("adt.py")
    edit: dict[str, Any] = {"op": "insert_row", "action": action, "params": params}
    if assign_to is not None:
        edit["assign_to"] = assign_to
    _passes(base, _edit(base, MNEMONIC, **edit))


def test_pass_insert_above_a_code_row() -> None:
    base = _sample("adt.py")
    head = _edit(
        base,
        MNEMONIC,
        op="insert_row",
        position="before",
        action="set_field",
        params={"path": "PID-8", "value": "U"},
    )
    _passes(base, head)


def test_pass_templated_value_in_one_of_the_four_value_params() -> None:
    base = _edit(
        _sample("adt.py"),
        MNEMONIC,
        op="insert_row",
        action="set_field",
        params={"path": "ZPI-1", "value": "x"},
    )
    head = _edit(
        base,
        'msg.set("ZPI-1"',
        op="set_params",
        params={"value": {"parts": [{"text": "MRN "}, {"path": "PID-3.1"}]}},
    )
    _passes(_sample("adt.py"), head)
    _passes(base, head)


@pytest.mark.parametrize(
    "template",
    [
        {"template": "if", "field": "PID-8", "operator": "equals", "value": "F"},
        {"template": "if", "field": "PID-8"},
        {"template": "if", "field": "PID-8", "operator": "not_equals", "value": "F"},
        {"template": "if", "field": "PID-8", "operator": "contains", "value": "F"},
        {"template": "for_each", "segment_id": "OBX"},
        {"template": "raise", "exc_type": "RuntimeError", "message": "stop"},
        {"template": "filter"},
    ],
    ids=lambda t: f"{t['template']}-{t.get('operator', '')}",
)
def test_pass_control_templates_with_their_pass_seed(template: dict[str, Any]) -> None:
    base = _sample("adt.py")
    _passes(base, _edit(base, MNEMONIC, op="template", **template))


def test_pass_elif_and_else_on_a_generated_if_and_on_a_hand_written_one() -> None:
    adt = _sample("adt.py")
    generated = _edit(adt, MNEMONIC, op="template", template="if", field="PID-8")
    with_elif = _edit(
        generated,
        'if msg.field("PID-8")',
        op="insert_clause",
        clause="elif",
        field="PID-8",
        operator="equals",
        value="M",
    )
    with_else = _edit(with_elif, '    if msg.field("PID-8"):', op="insert_clause", clause="else")
    _passes(adt, with_else)
    # A generated else on the hand-written `if mnemonic:` block.
    _passes(adt, _edit(adt, "if mnemonic:", op="insert_clause", clause="else"))


def test_pass_typed_rows_inserted_into_a_generated_block() -> None:
    adt = _sample("adt.py")
    loop = _edit(adt, MNEMONIC, op="template", template="for_each", segment_id="OBX")
    head = _edit(
        loop,
        "pass",
        op="insert_row",
        action="set_field",
        params={"path": "OBX-11", "value": "F", "occurrence": {"expr": "i"}},
    )
    _passes(adt, head)


def test_pass_add_destination_lays_the_accumulator_scaffold() -> None:
    src = _sample("IB_ACME_ADT.py")
    path = "samples/config/IB_ACME_ADT.py"
    once = _edit(src, 'return Send("OB_ACME_ADT"', op="add_destination", destination="OB_COPY")
    assert "sends = []" in once and "return sends" in once
    _passes(src, once, path)
    twice = _edit(once, 'sends.append(Send("OB_COPY"', op="add_destination", destination="OB_X")
    _passes(src, twice, path)
    _passes(once, twice, path)
    _passes(twice, _edit(twice, 'sends.append(Send("OB_X"', op="delete_row"), path)


def test_pass_insert_code_lookup_with_its_import_and_binding() -> None:
    adt = _sample("adt.py")
    head = _edit(adt, MNEMONIC, op="insert_code_lookup", code_set="sex_codes", path="PID-8")
    assert "SEX_CODES = code_set" in head and "import code_lookup" in head
    _passes(adt, head)


def test_pass_send_template_with_its_import() -> None:
    # A synthetic variant of adt.py that does not yet import Send, so the template injects it.
    adt = _sample("adt.py").replace("File, Send, code_set", "File, code_set")
    head = _edit(adt, MNEMONIC, op="template", template="send", destination="FILE-OUT_Test_ADT")
    assert "from messagefoundry import Send" in head
    _passes(adt, head)


def test_pass_set_params_on_literal_values() -> None:
    adt = _sample("adt.py")
    base = _edit(
        adt, MNEMONIC, op="insert_row", action="pad_field", params={"path": "PID-3.1", "width": 9}
    )
    head = _edit(base, "pad_field(", op="set_params", params={"width": 12, "path": "PID-3.2"})
    _passes(base, head)
    _passes(adt, _edit(adt, SEND, op="set_params", params={"to": "FILE-OUT_Other"}))
    _passes(
        adt,
        _edit(adt, 'return ["archive"]', op="set_params", params={"handlers": ["archive", "b"]}),
    )


def test_pass_move_and_delete_of_typed_rows() -> None:
    adt = _sample("adt.py")
    one = _edit(adt, MNEMONIC, op="insert_row", action="trim_field", params={"path": "PID-5.1"})
    base = _edit(one, "trim_field(", op="insert_row", action="log_note", params={"template": "n"})
    moved = _edit(base, "log_note(", op="move_row", direction="up")
    _passes(base, moved)
    deleted = _edit(base, "trim_field(", op="delete_row")
    _passes(base, deleted)
    _passes(base, _edit(base, SEND, op="delete_row"))
    # A typed row moved into a generated block, past nothing hand-written.
    looped = _edit(base, "log_note(", op="template", template="if", field="PID-8")
    into = _edit(
        looped, "trim_field(", op="move_row", to_line_start=_row(looped, "pass")["line_start"]
    )
    _passes(base, into)


def test_pass_comment_edits_and_router_templates() -> None:
    adt = _sample("adt.py")
    _passes(adt, _edit(adt, "# Stamp the downstream", op="set_params", params={"text": " changed"}))
    _passes(adt, _edit(adt, MNEMONIC, op="insert_comment", text="a note"))
    router = _sample("IB_DEMO_ORU_router.py")
    path = "samples/config/IB_DEMO_ORU_router.py"
    head = _edit(router, 'return ["demo_oru_relay"]', op="template", template="if", field="MSH-3")
    _passes(router, head, path)


def test_pass_whole_change_of_two_modules() -> None:
    adt = _sample("adt.py")
    router = _sample("IB_DEMO_ORU_router.py")
    verdict = classify_change(
        {
            ADT: (adt, _edit(adt, SEND, op="set_params", params={"to": "B"})),
            "samples/config/IB_DEMO_ORU_router.py": (router, router),
        }
    )
    assert verdict.steps_only, verdict.reasons


# --- MUST FAIL ------------------------------------------------------------------------------


def test_fail_disguised_if_header() -> None:
    adt = _sample("adt.py")
    head = _edit(adt, MNEMONIC, op="template", template="if", test='os.system("calc")')
    assert 'if os.system("calc"):' in head
    _fails(adt, head, "header")


def test_fail_disguised_for_header() -> None:
    adt = _sample("adt.py")
    block = '    for g in msg.groups(os.system("calc")):\n        pass'
    head = _edit(adt, MNEMONIC, op="paste_block", block=block)
    assert _row(head, "for g in")["recognized"] is True  # the deny-list reads it back recognized
    _fails(adt, head, "header")


def test_fail_disguised_raise_header() -> None:
    adt = _sample("adt.py")
    head = _edit(adt, MNEMONIC, op="paste_block", block='    raise ValueError(os.system("calc"))')
    assert _row(head, "raise ValueError")["recognized"] is True
    _fails(adt, head, "header")


def test_fail_r1_payloads() -> None:
    adt = _sample("adt.py")
    pasted = _edit(adt, MNEMONIC, op="paste_block", block='    subprocess.run(["calc"])')
    _fails(adt, pasted, "code-row")
    raw_test = _edit(
        adt, MNEMONIC, op="template", template="if", test="__import__('os').system('calc') == 0"
    )
    _fails(adt, raw_test, "header")
    expr_value = _edit(
        adt,
        MNEMONIC,
        op="insert_row",
        action="set_field",
        params={"path": "PID-5", "value": {"expr": "__import__('os').system('calc')"}},
    )
    _fails(adt, expr_value, "param")
    expr_to = _edit(
        adt, SEND, op="set_params", params={"to": {"expr": "__import__('os').getcwd()"}}
    )
    _fails(adt, expr_to, "send")


def test_fail_code_row_changed_added_removed() -> None:
    adt = _sample("adt.py")
    _fails(adt, adt.replace('.get(msg["MSH-4"])', '.get(msg["MSH-6"])'), "code-row")
    _fails(adt, _edit(adt, MNEMONIC, op="paste_block", block="    x = 1"), "code-row")
    removed = adt.replace('    msg["MSH-4"] = mnemonic\n', "    pass\n").replace(
        '    msg["MSH-4"] = mnemonic\r\n', "    pass\r\n"
    )
    assert removed != adt
    _fails(adt, removed, "code-row")


def test_fail_code_row_moved_under_another_condition() -> None:
    adt = _sample("adt.py")
    base = _edit(adt, MNEMONIC, op="template", template="if", field="PID-8")
    head = _edit(base, MNEMONIC, op="move_row", to_line_start=_row(base, "pass")["line_start"])
    _fails(base, head, "code-row")


def test_fail_removed_hand_written_header() -> None:
    router = _sample("IB_DEMO_ORU_router.py")
    path = "samples/config/IB_DEMO_ORU_router.py"
    head = _edit(router, 'if msg["MSH-9.1"] != "ORU"', op="delete_row")
    verdict = _fails(router, head, "header", path)
    assert not any(r.startswith("code-row") for r in verdict.reasons)


def test_fail_moved_hand_written_header() -> None:
    src = _sample("IB_FHIR_INTAKE.py")
    path = "samples/config/IB_FHIR_INTAKE.py"
    head = _edit(
        src,
        'if not msg.raw.lstrip().startswith("{")',
        op="move_row",
        to_line_start=_row(src, "peek = FhirPeek.parse")["line_start"],
        to_position="after",
    )
    verdict = _fails(src, head, "header", path)
    assert not any(r.startswith("code-row") for r in verdict.reasons)


def test_fail_dynamic_send_overwritten_with_a_literal() -> None:
    src = _sample("IB_DEMO_ORU_handler.py")
    path = "samples/config/IB_DEMO_ORU_handler.py"
    head = _edit(src, "return Send(OB_DEMO_ORU", op="set_params", params={"to": {"expr": '"OB_X"'}})
    _fails(src, head, "send", path)


def test_fail_dynamic_route_overwritten_with_a_literal() -> None:
    # A synthetic variant of adt.py whose router returns a dynamic selection.
    adt = _sample("adt.py").replace('return ["archive"]', "return [pick_handler(msg)]")
    head = _edit(adt, "return [pick_handler", op="set_params", params={"handlers": ["archive"]})
    _fails(adt, head, "route")


def test_fail_template_outside_the_four_value_params() -> None:
    adt = _sample("adt.py")
    statement = _edit(
        adt,
        MNEMONIC,
        op="insert_row",
        action="db_lookup",
        assign_to="row",
        params={
            "connection": "DB_MPI",
            "statement": {"expr": "f\"SELECT {msg['PID-3.1'] or ''}\""},
            "params": {"expr": "{}"},
        },
    )
    _fails(adt, statement, "param")
    path_template = _edit(
        adt,
        MNEMONIC,
        op="insert_row",
        action="set_field",
        params={"path": {"expr": "f\"PID-{msg['PID-3.1'] or ''}\""}, "value": "x"},
    )
    _fails(adt, path_template, "param")
    # A log_note operand, written by another tool: the lens has no insert for an operand.
    base = _edit(adt, MNEMONIC, op="insert_row", action="log_note", params={"template": "MRN {}"})
    head = base.replace('log_note("MRN {}")', "log_note(\"MRN {}\", f\"{msg['PID-3.1'] or ''}\")")
    assert head != base
    _fails(base, head, "param")


def test_fail_assign_to_rebinds_msg_or_a_builtin() -> None:
    adt = _sample("adt.py")
    for name in ("msg", "len", "mnemonic"):
        head = _edit(
            adt,
            MNEMONIC,
            op="insert_row",
            action="db_lookup",
            assign_to=name,
            params={"connection": "DB", "statement": "SELECT 1", "params": {"expr": "{}"}},
        )
        _fails(adt, head, "param")


def test_fail_typed_row_with_an_attribute_callee() -> None:
    adt = _sample("adt.py")
    base = _edit(adt, MNEMONIC, op="insert_row", action="trim_field", params={"path": "PID-5.1"})
    head = base.replace('trim_field(msg, "PID-5.1")', 'os.trim_field(msg, "PID-5.1")')
    assert _row(head, "os.trim_field")["kind"] == "action"  # the lens still reads it as a step
    _fails(base, head, "param")


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("port=2575", "port=2576"),
        ('"""Example config', '"""Changed config'),
        (
            "from messagefoundry import MLLP",
            "import os\nfrom messagefoundry import MLLP",
        ),
        ("MLLP, File, Send", "MLLP, File, Send, set_field"),
        ('@handler("archive")', '@handler("archive", accepts=None)'),
        ("def archive(msg):", "def archive(msg, extra=__import__('os')):"),
    ],
    ids=["call-arg", "docstring", "import-os", "changed-import", "decorator", "signature"],
)
def test_fail_byte_change_outside_def_bodies(old: str, new: str) -> None:
    adt = _sample("adt.py")
    head = adt.replace(old, new, 1)
    assert head != adt
    _fails(adt, head, "outside")


def test_fail_aliased_or_unsanctioned_generated_lookalikes() -> None:
    adt = _sample("adt.py")
    marker = "EVENT_LABELS = code_set"
    aliased = adt.replace(marker, "from messagefoundry import set_field as sf\n" + marker, 1)
    _fails(adt, aliased, "outside")
    shadow = adt.replace(marker, 'print = code_set("x")\n\n' + marker, 1)
    _fails(adt, shadow, "outside")


@pytest.mark.parametrize(
    ("path", "base", "head"),
    [
        ("samples/config/_demo_oru_transforms.py", "x = 1\n", "x = 2\n"),
        ("samples/config/connections.toml", "a = 1\n", "a = 2\n"),
        ("samples/config/codesets/sex.csv", "a,b\n", "a,c\n"),
        ("environments/dev.toml", "a = 1\n", "a = 2\n"),
        ("samples/config/new_handler.py", None, "x = 1\n"),
        ("samples/config/adt.py", "x = 1\n", None),
        ("samples/config/plain.py", "x = 1\n", "x = 2\n"),
    ],
    ids=["helper", "connections", "codeset", "environment", "new-file", "deleted", "no-handler"],
)
def test_fail_changed_helper_or_non_handler_file(
    path: str, base: str | None, head: str | None
) -> None:
    verdict = classify_file(path, base, head)
    assert not verdict.steps_only
    assert verdict.reasons[0].startswith("path")


def test_fail_one_bad_path_fails_the_whole_change() -> None:
    adt = _sample("adt.py")
    verdict = classify_change(
        {
            ADT: (adt, _edit(adt, SEND, op="set_params", params={"to": "B"})),
            "samples/config/_demo_oru_transforms.py": ("x = 1\n", "x = 2\n"),
        }
    )
    assert not verdict.steps_only
    assert verdict.reasons == (
        "samples/config/_demo_oru_transforms.py: path: a _-prefixed helper "
        "module is not Steps-only",
    )
