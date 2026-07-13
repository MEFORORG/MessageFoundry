# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0106 authoring palette — the lens recognizes the new vocabulary + diagnostics helpers as rows.

Recognition-side (read) coverage: the six new ``actions.py`` helpers render as editable ``action`` rows
(just like the ADR 0076 wrappers, via ``_ACTION_PARAMS`` registration) and the two ``diagnostics.py``
helpers render as ``diagnostic`` rows. The insert-side (Add-menu codegen) is separate ADR 0106 work.
"""

from __future__ import annotations

import ast

import pytest

from messagefoundry.lens import parse_source, rewrite_source

SOURCE = """\
@handler("H")
def h(msg):
    trim_field(msg, "PID-5.1")
    substring_field(msg, "PID-3.1", 0, 6)
    pad_field(msg, "PID-3.1", 10, fill="0", side="left")
    replace_literal(msg, "PID-5.1", "MRS", "MS")
    arith_field(msg, "OBX-5", "*", 2.20462, ndigits=1)
    date_diff_field(msg, "PV1-44", "PV1-45", "ZLS-1", unit="days")
    log_note("MRN {}", msg.field("PID-3.1"))
    checkpoint(msg, "after normalize")
"""


def _rows() -> list[dict]:
    handlers = parse_source(SOURCE)
    assert len(handlers) == 1, "expected one @handler"
    return handlers[0]["rows"]


def test_new_transform_helpers_recognized_as_action_rows() -> None:
    actions = {r["action"] for r in _rows() if r["kind"] == "action"}
    assert {
        "trim_field",
        "substring_field",
        "pad_field",
        "replace_literal",
        "arith_field",
        "date_diff_field",
    } <= actions


def test_diagnostics_recognized_as_diagnostic_rows() -> None:
    diags = {r["call"] for r in _rows() if r["kind"] == "diagnostic"}
    assert diags == {"log_note", "checkpoint"}


def test_palette_rows_partition_the_body_no_code_rows() -> None:
    # all 8 statements recognized — none fell to a read-only ``code`` row
    assert [r["kind"] for r in _rows()] == ["action"] * 6 + ["diagnostic"] * 2


def test_new_helper_params_are_inline_editable() -> None:
    rows = {r.get("action"): r for r in _rows() if r["kind"] == "action"}
    # scalar literal args surface as inline-editable params (path/start/op/…)
    assert "path" in rows["trim_field"]["literal_params"]
    assert "start" in rows["substring_field"]["literal_params"]
    assert "op" in rows["arith_field"]["literal_params"]


# --- recognizer-safety additions (ADR 0106) ---------------------------------

CONTROL_SOURCE = """\
@handler("H")
def h(msg):
    for seg in msg.segments():
        set_field(msg, "OBX-11", "F")
    for bad in msg.segments("OBX"):
        set_field(msg, "OBX-11", "X")
    if not msg.field("PID-3.1"):
        raise ValueError("stop")
    return []
"""


def _control_rows() -> list[dict]:
    return parse_source(CONTROL_SOURCE)[0]["rows"]


def test_raise_recognized_as_control_row() -> None:
    raises = [r for r in _control_rows() if r.get("control") == "raise"]
    assert len(raises) == 1
    assert raises[0]["kind"] == "control"
    assert raises[0]["recognized"] is True


def test_return_empty_is_a_filtered_send() -> None:
    sends = [r for r in _control_rows() if r["kind"] == "send"]
    assert len(sends) == 1
    assert sends[0].get("filtered") is True
    assert sends[0]["outbounds"] == []


def test_bad_arity_iteration_is_not_falsely_recognized() -> None:
    # msg.segments() (correct arity) is recognized; msg.segments("OBX") (wrong arity) is NOT
    for_rows = [r for r in _control_rows() if r.get("control") == "for"]
    assert [r["recognized"] for r in for_rows] == [True, False]


# --- insert-side: import injection (ADR 0106 §6 H) --------------------------

INSERT_SOURCE = """\
from messagefoundry import handler, set_field


@handler("H")
def h(msg):
    set_field(msg, "PID-3.1", "X")
"""


def _insert(source: str, anchor: dict, action: str, params: dict) -> str:
    return rewrite_source(
        source,
        {
            "op": "insert_row",
            "line_start": anchor["line_start"],
            "line_end": anchor["line_end"],
            "action": action,
            "params": params,
            "position": "after",
        },
    )


def test_insert_unimported_wrapper_injects_the_import() -> None:
    anchor = parse_source(INSERT_SOURCE)[0]["rows"][0]  # the set_field row
    out = _insert(INSERT_SOURCE, anchor, "trim_field", {"path": "PID-5.1"})
    assert "from messagefoundry import trim_field" in out
    assert 'trim_field(msg, "PID-5.1")' in out
    ast.parse(out)  # re-parses to valid Python (no F821)
    assert out.count("from messagefoundry import") == 2  # original + injected
    # the inserted call is now itself a recognized action row
    assert any(r.get("action") == "trim_field" for r in parse_source(out)[0]["rows"])


def test_insert_native_action_injects_no_import() -> None:
    anchor = parse_source(INSERT_SOURCE)[0]["rows"][0]
    out = _insert(INSERT_SOURCE, anchor, "set_field", {"path": "PID-4.1", "value": "Y"})
    # native msg.set(...) form references only ``msg`` — no vocabulary import added
    assert out.count("from messagefoundry import") == 1
    ast.parse(out)


# --- insert-side: structure/flow templates (ADR 0106 §5 A) ------------------


def _template(source: str, anchor: dict, **spec: object) -> str:
    return rewrite_source(
        source,
        {
            "op": "template",
            "line_start": anchor["line_start"],
            "line_end": anchor["line_end"],
            "position": "after",
            **spec,
        },
    )


def _anchor() -> dict:
    return parse_source(INSERT_SOURCE)[0]["rows"][0]


def test_template_if_inserts_a_control_block() -> None:
    out = _template(
        INSERT_SOURCE, _anchor(), template="if", field="PID-3.1", operator="equals", value="A"
    )
    assert 'if msg.field("PID-3.1") == "A":' in out
    assert "pass" in out  # seeded body (an empty suite is invalid Python)
    assert any(
        r.get("control") == "if" for r in parse_source(out)[0]["rows"]
    )  # re-parses + recognizes


def test_template_for_each_inserts_a_segment_count_loop() -> None:
    out = _template(INSERT_SOURCE, _anchor(), template="for_each", segment_id="OBX")
    assert 'for i in range(1, msg.count_segments("OBX") + 1):' in out
    assert any(r.get("control") == "for" for r in parse_source(out)[0]["rows"])


def test_template_filter_inserts_a_filtered_send() -> None:
    out = _template(INSERT_SOURCE, _anchor(), template="filter")
    assert any(r["kind"] == "send" and r.get("filtered") for r in parse_source(out)[0]["rows"])


def test_template_raise_inserts_a_control_row() -> None:
    out = _template(INSERT_SOURCE, _anchor(), template="raise", message="bad MRN")
    assert 'raise ValueError("bad MRN")' in out
    assert any(r.get("control") == "raise" for r in parse_source(out)[0]["rows"])


def test_template_send_inserts_a_return_and_injects_import() -> None:
    # INSERT_SOURCE imports handler + set_field but NOT Send — the template injects the missing import.
    out = _template(INSERT_SOURCE, _anchor(), template="send", destination="OB_ACME_ADT")
    assert 'return Send("OB_ACME_ADT", msg)' in out
    assert "from messagefoundry import Send" in out
    ast.parse(out)  # re-parses to valid Python (no F821 on Send)
    rows = parse_source(out)[0]["rows"]
    assert any(r["kind"] == "send" and r.get("outbounds") == ["OB_ACME_ADT"] for r in rows)


def test_template_send_does_not_double_inject_an_existing_import() -> None:
    source = INSERT_SOURCE.replace(
        "from messagefoundry import handler, set_field",
        "from messagefoundry import Send, handler, set_field",
    )
    anchor = parse_source(source)[0]["rows"][0]
    out = _template(source, anchor, template="send", destination="OB_X")
    assert 'return Send("OB_X", msg)' in out
    assert out.count("import Send") == 1  # already in scope → no second import


def test_template_send_requires_a_destination() -> None:
    with pytest.raises(Exception):  # LensRewriteError — no destination given
        _template(INSERT_SOURCE, _anchor(), template="send")


# --- insert-side: Else If / Else clause-append (ADR 0106 §5 D) --------------

IF_SOURCE = """\
from messagefoundry import handler, set_field


@handler("H")
def h(msg):
    if msg.field("PID-3.1"):
        set_field(msg, "OBX-11", "F")
"""

IF_ELSE_SOURCE = """\
from messagefoundry import handler, set_field


@handler("H")
def h(msg):
    if msg.field("PID-3.1"):
        set_field(msg, "OBX-11", "F")
    else:
        set_field(msg, "OBX-11", "X")
"""

IF_ELIF_SOURCE = """\
from messagefoundry import handler, set_field


@handler("H")
def h(msg):
    if msg.field("PID-3.1") == "A":
        set_field(msg, "OBX-11", "A")
    elif msg.field("PID-3.1") == "B":
        set_field(msg, "OBX-11", "B")
"""


def _clause(source: str, anchor: dict, **spec: object) -> str:
    return rewrite_source(
        source,
        {
            "op": "insert_clause",
            "line_start": anchor["line_start"],
            "line_end": anchor["line_end"],
            **spec,
        },
    )


def _if_row(source: str, control: str = "if") -> dict:
    return next(r for r in parse_source(source)[0]["rows"] if r.get("control") == control)


def _controls(source: str) -> list[str | None]:
    return [r.get("control") for r in parse_source(source)[0]["rows"] if r["kind"] == "control"]


def test_clause_elif_appended_to_plain_if() -> None:
    out = _clause(
        IF_SOURCE, _if_row(IF_SOURCE), clause="elif", field="PID-3.1", operator="equals", value="B"
    )
    assert 'elif msg.field("PID-3.1") == "B":' in out
    ast.parse(out)  # re-parses to valid Python
    assert _controls(out) == ["if", "elif"]


def test_clause_else_appended_to_plain_if() -> None:
    out = _clause(IF_SOURCE, _if_row(IF_SOURCE), clause="else")
    assert "    else:" in out
    ast.parse(out)
    assert _controls(out) == ["if", "else"]


def test_clause_elif_inserted_before_existing_else() -> None:
    out = _clause(
        IF_ELSE_SOURCE, _if_row(IF_ELSE_SOURCE), clause="elif", field="PID-5.1", operator="exists"
    )
    ast.parse(out)
    assert out.index("elif ") < out.index("else:")  # elif precedes else (elif cannot follow else)
    assert _controls(out) == ["if", "elif", "else"]


def test_clause_else_from_elif_anchor_appends_to_whole_chain() -> None:
    # anchoring on the nested elif still appends the else to the OUTER if, not inside the elif body
    out = _clause(IF_ELIF_SOURCE, _if_row(IF_ELIF_SOURCE, "elif"), clause="else")
    ast.parse(out)
    assert _controls(out) == ["if", "elif", "else"]


def test_clause_else_refused_when_else_already_exists() -> None:
    with pytest.raises(Exception):  # LensRewriteError — duplicate else
        _clause(IF_ELSE_SOURCE, _if_row(IF_ELSE_SOURCE), clause="else")


def test_clause_refused_when_anchor_is_not_an_if() -> None:
    body_row = next(r for r in parse_source(IF_SOURCE)[0]["rows"] if r.get("action") == "set_field")
    with pytest.raises(Exception):  # LensRewriteError — anchor is a body row, not an if header
        _clause(IF_SOURCE, body_row, clause="else")


def test_clause_preserves_every_other_byte() -> None:
    # pure line-insert: the original text appears verbatim as a prefix region (only new lines added)
    out = _clause(IF_SOURCE, _if_row(IF_SOURCE), clause="else")
    for original_line in IF_SOURCE.splitlines():
        assert original_line in out


# --- insert-side: lookup + diagnostic vocabulary (ADR 0106 §5 J / diagnostics) ----------------


def _insert_edit(source: str, anchor: dict, **fields: object) -> str:
    return rewrite_source(
        source,
        {
            "op": "insert_row",
            "line_start": anchor["line_start"],
            "line_end": anchor["line_end"],
            "position": "after",
            **fields,
        },
    )


def test_insert_db_lookup_assigned_round_trips_as_lookup_row() -> None:
    # INSERT_SOURCE does not import db_lookup — the import is injected, and the assigned lookup re-recognizes.
    out = _insert_edit(
        INSERT_SOURCE,
        _anchor(),
        action="db_lookup",
        assign_to="row",
        params={"connection": "MPI", "statement": "select 1", "params": {"expr": '["A"]'}},
    )
    assert 'row = db_lookup("MPI", "select 1", ["A"])' in out
    assert "from messagefoundry import db_lookup" in out
    ast.parse(out)
    rows = parse_source(out)[0]["rows"]
    assert any(
        r["kind"] == "lookup" and r["call"] == "db_lookup" and r.get("assign_to") == "row"
        for r in rows
    )


def test_insert_fhir_lookup_assigned_round_trips_as_lookup_row() -> None:
    out = _insert_edit(
        INSERT_SOURCE,
        _anchor(),
        action="fhir_lookup",
        assign_to="pat",
        params={"connection": "epic", "query": "Patient?identifier=X"},
    )
    assert 'pat = fhir_lookup("epic", "Patient?identifier=X")' in out
    assert "from messagefoundry import fhir_lookup" in out
    ast.parse(out)
    assert any(
        r["kind"] == "lookup" and r["call"] == "fhir_lookup" and r.get("assign_to") == "pat"
        for r in parse_source(out)[0]["rows"]
    )


def test_insert_code_lookup_bare_round_trips_as_lookup_row() -> None:
    out = _insert_edit(
        INSERT_SOURCE,
        _anchor(),
        action="code_lookup",
        params={"path": "PID-8", "table": {"expr": "GENDER"}},
    )
    assert 'code_lookup(msg, "PID-8", GENDER)' in out
    assert "from messagefoundry import code_lookup" in out
    ast.parse(out)
    assert any(
        r["kind"] == "lookup" and r["call"] == "code_lookup" for r in parse_source(out)[0]["rows"]
    )


def test_insert_code_lookup_refuses_assign_to() -> None:
    # code_lookup mutates in place / returns None (ADR 0106 §5 J) — assigning it is refused
    with pytest.raises(Exception):
        _insert_edit(
            INSERT_SOURCE,
            _anchor(),
            action="code_lookup",
            assign_to="x",
            params={"path": "PID-8", "table": {"expr": "GENDER"}},
        )


def test_insert_lookup_does_not_double_inject_existing_import() -> None:
    src = INSERT_SOURCE.replace(
        "from messagefoundry import handler, set_field",
        "from messagefoundry import db_lookup, handler, set_field",
    )
    anchor = parse_source(src)[0]["rows"][0]
    out = _insert_edit(
        src,
        anchor,
        action="db_lookup",
        assign_to="row",
        params={"connection": "MPI", "statement": "select 1", "params": {"expr": '["A"]'}},
    )
    assert out.count("import db_lookup") == 1  # already in scope → no second import


def test_insert_log_note_round_trips_as_diagnostic_row() -> None:
    out = _insert_edit(INSERT_SOURCE, _anchor(), action="log_note", params={"template": "MRN seen"})
    assert 'log_note("MRN seen")' in out
    assert "from messagefoundry import log_note" in out
    ast.parse(out)
    assert any(
        r["kind"] == "diagnostic" and r["call"] == "log_note" for r in parse_source(out)[0]["rows"]
    )


def test_insert_checkpoint_round_trips_as_diagnostic_row() -> None:
    out = _insert_edit(
        INSERT_SOURCE, _anchor(), action="checkpoint", params={"label": "after normalize"}
    )
    assert 'checkpoint(msg, "after normalize")' in out
    assert "from messagefoundry import checkpoint" in out
    ast.parse(out)
    assert any(
        r["kind"] == "diagnostic" and r["call"] == "checkpoint"
        for r in parse_source(out)[0]["rows"]
    )


def test_insert_log_note_refuses_assign_to() -> None:
    with pytest.raises(Exception):  # log_note returns None
        _insert_edit(
            INSERT_SOURCE, _anchor(), action="log_note", assign_to="x", params={"template": "t"}
        )


# --- insert-side: native structural add_segment / add_repetition (ADR 0106 §3 Group 1) --------

NATIVE_SRC = """\
@handler("H")
def h(msg):
    msg.add_segment("NTE")
    msg.add_repetition("PID-3", "MR1^^^HOSP")
    msg.add_segment("ZAL", index=2)
    msg.add_repetition("PID-3")
"""


def _native_rows() -> list[dict]:
    return parse_source(NATIVE_SRC)[0]["rows"]


def test_add_segment_native_recognized() -> None:
    r = next(
        r
        for r in _native_rows()
        if r.get("action") == "add_segment" and r["params"].get("line") == "NTE"
    )
    assert r["kind"] == "action"
    assert "line" in r["literal_params"]


def test_add_repetition_native_recognized() -> None:
    r = next(r for r in _native_rows() if r.get("action") == "add_repetition")
    assert r["params"]["path"] == "PID-3"
    assert r["params"]["value"] == "MR1^^^HOSP"


def test_add_segment_index_kwarg_is_read_only() -> None:
    r = next(
        r
        for r in _native_rows()
        if r.get("action") == "add_segment" and r["params"].get("line") == "ZAL"
    )
    assert r["params"].get("index") == 2  # preserved as a display field…
    assert "index" not in r["literal_params"]  # …but never editable (Phase A)


def test_add_repetition_wrong_arity_degrades_to_code() -> None:
    # msg.add_repetition("PID-3") (1 arg) must NOT be a false-green action row
    reps = [r for r in _native_rows() if r.get("action") == "add_repetition"]
    assert len(reps) == 1  # only the 2-arg call recognized; the 1-arg call falls to a code row
    assert any(r["kind"] == "code" for r in _native_rows())


def test_insert_add_segment_round_trips_without_import() -> None:
    out = _insert_edit(INSERT_SOURCE, _anchor(), action="add_segment", params={"line": "NTE"})
    assert 'msg.add_segment("NTE")' in out
    assert out.count("from messagefoundry import") == 1  # native form needs no vocabulary import
    ast.parse(out)
    assert any(r.get("action") == "add_segment" for r in parse_source(out)[0]["rows"])


def test_insert_add_repetition_round_trips() -> None:
    out = _insert_edit(
        INSERT_SOURCE,
        _anchor(),
        action="add_repetition",
        params={"path": "PID-3", "value": "MR1^^^HOSP"},
    )
    assert 'msg.add_repetition("PID-3", "MR1^^^HOSP")' in out
    ast.parse(out)
    assert any(r.get("action") == "add_repetition" for r in parse_source(out)[0]["rows"])


def test_insert_add_segment_refuses_assign_to() -> None:
    with pytest.raises(Exception):  # add_segment returns None
        _insert_edit(
            INSERT_SOURCE, _anchor(), action="add_segment", assign_to="x", params={"line": "NTE"}
        )


# --- insert_row: For-Each occurrence passthrough (ADR 0106 §5 C) ---------------


def test_insert_set_field_with_occurrence_binds_loop_var() -> None:
    out = _insert_edit(
        INSERT_SOURCE,
        _anchor(),
        action="set_field",
        params={"path": "OBX-5", "value": "F", "occurrence": {"expr": "i"}},
    )
    assert 'msg.set("OBX-5", "F", occurrence=i)' in out
    ast.parse(out)
    row = next(
        r
        for r in parse_source(out)[0]["rows"]
        if r.get("action") == "set_field" and r["params"].get("path") == "OBX-5"
    )
    assert row["params"].get("occurrence") == "i"
    assert "occurrence" not in row["literal_params"]  # read-only display kwarg


def test_insert_copy_field_with_occurrence_applies_to_read_and_write() -> None:
    out = _insert_edit(
        INSERT_SOURCE,
        _anchor(),
        action="copy_field",
        params={"src": "OBX-5", "dst": "OBX-6", "occurrence": {"expr": "i"}},
    )
    assert 'msg.set("OBX-6", msg.field("OBX-5", occurrence=i) or "", occurrence=i)' in out
    ast.parse(out)
    row = next(r for r in parse_source(out)[0]["rows"] if r.get("action") == "copy_field")
    assert row["params"].get("occurrence") == "i"
    assert "occurrence" not in row["literal_params"]


def test_insert_add_repetition_with_occurrence() -> None:
    out = _insert_edit(
        INSERT_SOURCE,
        _anchor(),
        action="add_repetition",
        params={"path": "PID-3", "value": "X", "occurrence": {"expr": "i"}},
    )
    assert 'msg.add_repetition("PID-3", "X", occurrence=i)' in out
    ast.parse(out)
    assert any(r.get("action") == "add_repetition" for r in parse_source(out)[0]["rows"])


def test_insert_occurrence_literal_is_read_only() -> None:
    out = _insert_edit(
        INSERT_SOURCE,
        _anchor(),
        action="set_field",
        params={"path": "OBX-5", "value": "F", "occurrence": 2},
    )
    assert 'msg.set("OBX-5", "F", occurrence=2)' in out
    row = next(
        r
        for r in parse_source(out)[0]["rows"]
        if r.get("action") == "set_field" and r["params"].get("path") == "OBX-5"
    )
    assert row["params"].get("occurrence") == 2
    assert "occurrence" not in row["literal_params"]


def test_insert_add_repetition_refuses_repetition() -> None:
    with pytest.raises(Exception):  # Message.add_repetition has no 'repetition' kwarg
        _insert_edit(
            INSERT_SOURCE,
            _anchor(),
            action="add_repetition",
            params={"path": "PID-3", "value": "X", "repetition": {"expr": "i"}},
        )


def test_insert_delete_segment_refuses_occurrence() -> None:
    with pytest.raises(Exception):  # not silently dropped — delete_segments takes no occurrence
        _insert_edit(
            INSERT_SOURCE,
            _anchor(),
            action="delete_segment",
            params={"segment_id": "ZID", "occurrence": {"expr": "i"}},
        )


def test_for_each_loop_is_inhabitable_end_to_end() -> None:
    # build a For-Each loop, then insert an occurrence-bound set_field inside its body
    looped = _template(INSERT_SOURCE, _anchor(), template="for_each", segment_id="OBX")
    for_row = next(r for r in parse_source(looped)[0]["rows"] if r.get("control") == "for")
    body = next(
        r
        for r in parse_source(looped)[0]["rows"]
        if r["kind"] == "code" and r["nesting"] > for_row["nesting"]
    )
    out = rewrite_source(
        looped,
        {
            "op": "insert_row",
            "line_start": body["line_start"],
            "line_end": body["line_end"],
            "position": "before",
            "action": "set_field",
            "params": {"path": "OBX-5", "value": "F", "occurrence": {"expr": "i"}},
        },
    )
    assert '        msg.set("OBX-5", "F", occurrence=i)' in out  # 8-space loop-body indent
    ast.parse(out)
    sf = next(
        r
        for r in parse_source(out)[0]["rows"]
        if r.get("action") == "set_field" and r["params"].get("path") == "OBX-5"
    )
    assert sf["nesting"] > for_row["nesting"]  # nested inside the loop


# --- set_params: diagnostics editable (ADR 0106 §5 K) -------------------------


def _diag_row(source: str, call: str) -> dict:
    return next(r for r in parse_source(source)[0]["rows"] if r.get("call") == call)


def _edit_params(source: str, row: dict, params: dict) -> str:
    return rewrite_source(
        source,
        {
            "op": "set_params",
            "line_start": row["line_start"],
            "line_end": row["line_end"],
            "params": params,
        },
    )


def test_set_params_edits_log_note_template_literal() -> None:
    out = _edit_params(SOURCE, _diag_row(SOURCE, "log_note"), {"template": "MRN {} seen"})
    assert 'log_note("MRN {} seen", msg.field("PID-3.1"))' in out  # operand preserved verbatim
    assert _diag_row(out, "log_note")["kind"] == "diagnostic"  # still a diagnostic row


def test_set_params_edits_checkpoint_label_literal() -> None:
    out = _edit_params(SOURCE, _diag_row(SOURCE, "checkpoint"), {"label": "post"})
    assert 'checkpoint(msg, "post")' in out  # msg receiver untouched
    assert _diag_row(out, "checkpoint")["kind"] == "diagnostic"


def test_log_note_edit_is_byte_stable_outside_row() -> None:
    out = _edit_params(SOURCE, _diag_row(SOURCE, "log_note"), {"template": "MRN {} seen"})
    old = '    log_note("MRN {}", msg.field("PID-3.1"))'
    new = '    log_note("MRN {} seen", msg.field("PID-3.1"))'
    assert out == SOURCE.replace(old, new)  # only the template literal's bytes changed


def test_log_note_operand_not_editable() -> None:
    with pytest.raises(Exception):  # the *values operand is never a slot
        _edit_params(SOURCE, _diag_row(SOURCE, "log_note"), {"values": "x"})


def test_diagnostic_literal_operand_not_advertised() -> None:
    src = '@handler("H")\ndef h(msg):\n    log_note("t", "lit")\n'
    r = _diag_row(src, "log_note")
    assert r["literal_params"] == [
        "template"
    ]  # the literal operand "lit" is NOT offered as editable


def test_diagnostic_expr_template_refuses_scalar_edit() -> None:
    src = '@handler("H")\ndef h(msg):\n    log_note(NOTE, msg.field("PID-3.1"))\n'
    r = _diag_row(src, "log_note")
    with pytest.raises(Exception):  # template is an expression (NOTE), not a literal
        _edit_params(src, r, {"template": "x"})


def test_delete_diagnostic_row() -> None:
    # adding 'diagnostic' to _EDITABLE_KINDS also makes a diagnostic row deletable (desirable)
    row = _diag_row(SOURCE, "checkpoint")
    out = rewrite_source(
        SOURCE, {"op": "delete_row", "line_start": row["line_start"], "line_end": row["line_end"]}
    )
    assert "checkpoint(" not in out
    ast.parse(out)


# --- insert-side: Comment raw-line op (ADR 0106 §5 L) -------------------------

TWO_STMT_SRC = """\
from messagefoundry import handler, set_field


@handler("H")
def h(msg):
    set_field(msg, "PID-3.1", "X")
    set_field(msg, "PID-4.1", "Y")
"""


def _comment(source: str, anchor: dict, **fields: object) -> str:
    return rewrite_source(
        source,
        {
            "op": "insert_comment",
            "line_start": anchor["line_start"],
            "line_end": anchor["line_end"],
            **fields,
        },
    )


def test_insert_comment_adds_hash_line_at_anchor_indent() -> None:
    out = _comment(INSERT_SOURCE, _anchor(), text="fix ORC-2 before send")
    assert "    # fix ORC-2 before send" in out  # 4-space anchor indent + one space after #
    ast.parse(out)


def test_insert_comment_reads_back_as_code_row() -> None:
    # a comment BETWEEN two statements tiles into a read-only code row (no recognizer change)
    anchor = parse_source(TWO_STMT_SRC)[0]["rows"][0]
    out = _comment(TWO_STMT_SRC, anchor, text="normalize first", position="after")
    assert "    # normalize first" in out
    assert any(r["kind"] == "code" for r in parse_source(out)[0]["rows"])


def test_insert_comment_normalizes_single_space_after_hash() -> None:
    out = _comment(INSERT_SOURCE, _anchor(), text="#fix")  # caller-supplied leading # is stripped
    assert "    # fix" in out
    assert "    #fix" not in out


def test_insert_comment_refuses_embedded_newline() -> None:
    with pytest.raises(Exception):  # a newline could add lines / inject code
        _comment(INSERT_SOURCE, _anchor(), text="ok\nimport os")


def test_insert_comment_refuses_over_column_limit() -> None:
    with pytest.raises(Exception):  # ruff would wrap it
        _comment(INSERT_SOURCE, _anchor(), text="x" * 200)


def test_insert_comment_preserves_every_other_byte() -> None:
    out = _comment(INSERT_SOURCE, _anchor(), text="note")
    for original_line in INSERT_SOURCE.splitlines():
        assert original_line in out


def test_insert_comment_before_position_sits_above_the_anchor() -> None:
    out = _comment(INSERT_SOURCE, _anchor(), text="pre", position="before")
    lines = out.splitlines()
    i = next(k for k, line in enumerate(lines) if "# pre" in line)
    assert 'set_field(msg, "PID-3.1", "X")' in lines[i + 1]  # comment directly above the anchor
    ast.parse(out)


# --- insert-side: full Code Lookup injector (ADR 0106 §5 I / §6; ADR 0033 tables) --------------

BOUND_SRC = """\
from messagefoundry import code_lookup, code_set, handler, set_field

GENDER = code_set("gender")


@handler("H")
def h(msg):
    set_field(msg, "PID-3.1", "X")
"""


def _code_lookup(source: str, anchor: dict, **fields: object) -> str:
    return rewrite_source(
        source,
        {
            "op": "insert_code_lookup",
            "line_start": anchor["line_start"],
            "line_end": anchor["line_end"],
            **fields,
        },
    )


def _set_field_row(source: str) -> dict:
    return next(r for r in parse_source(source)[0]["rows"] if r.get("action") == "set_field")


def test_insert_code_lookup_injects_binding_and_imports() -> None:
    out = _code_lookup(INSERT_SOURCE, _anchor(), code_set="gender", path="PID-8")
    assert 'code_lookup(msg, "PID-8", GENDER)' in out  # the step references the captured table var
    assert (
        'GENDER = code_set("gender")' in out
    )  # module-level binding injected (the 3rd §6 exception)
    assert "from messagefoundry import code_lookup" in out
    assert "from messagefoundry import code_set" in out
    ast.parse(out)
    rows = parse_source(out)[0]["rows"]
    assert any(r["kind"] == "lookup" and r["call"] == "code_lookup" for r in rows)


def test_insert_code_lookup_binding_is_blank_separated_from_imports() -> None:
    # ruff format requires a blank line between the import block and a module-level binding
    out = _code_lookup(INSERT_SOURCE, _anchor(), code_set="gender", path="PID-8")
    lines = out.splitlines()
    b = next(i for i, line in enumerate(lines) if line.startswith("GENDER = code_set("))
    assert lines[b - 1] == ""  # blank line directly above the injected binding
    assert lines[b - 2].startswith("from messagefoundry import")  # sits just below the imports


def test_insert_code_lookup_reuses_existing_binding() -> None:
    out = _code_lookup(BOUND_SRC, _set_field_row(BOUND_SRC), code_set="gender", path="PID-8")
    assert 'code_lookup(msg, "PID-8", GENDER)' in out
    assert out.count('code_set("gender")') == 1  # existing binding reused, not duplicated
    assert out.count("import code_lookup") == 1  # already imported, not re-injected
    ast.parse(out)


def test_insert_code_lookup_custom_var() -> None:
    out = _code_lookup(INSERT_SOURCE, _anchor(), code_set="epic_diets", var="DIET", path="ODS-1")
    assert 'DIET = code_set("epic_diets")' in out
    assert 'code_lookup(msg, "ODS-1", DIET)' in out
    ast.parse(out)


def test_insert_code_lookup_with_default() -> None:
    out = _code_lookup(INSERT_SOURCE, _anchor(), code_set="gender", path="PID-8", default="U")
    assert 'code_lookup(msg, "PID-8", GENDER, default="U")' in out
    ast.parse(out)


def test_insert_code_lookup_refuses_var_bound_to_a_different_set() -> None:
    src = INSERT_SOURCE.replace(
        "from messagefoundry import handler, set_field",
        "from messagefoundry import code_set, handler, set_field",
    ).replace('@handler("H")', 'GENDER = code_set("other")\n\n\n@handler("H")')
    with pytest.raises(Exception):  # GENDER already -> code_set("other")
        _code_lookup(src, _set_field_row(src), code_set="gender", path="PID-8")


def test_insert_code_lookup_refuses_non_codeset_var_collision() -> None:
    src = INSERT_SOURCE.replace('@handler("H")', 'GENDER = 5\n\n\n@handler("H")')
    with pytest.raises(Exception):  # GENDER is a non-code-set name
        _code_lookup(src, _set_field_row(src), code_set="gender", path="PID-8")


def test_insert_code_lookup_requires_code_set_and_path() -> None:
    with pytest.raises(Exception):
        _code_lookup(INSERT_SOURCE, _anchor(), path="PID-8")  # no code_set
    with pytest.raises(Exception):
        _code_lookup(INSERT_SOURCE, _anchor(), code_set="gender")  # no path


# --- insert_code_lookup: review-hardening (byte-stability / shadow / annotated reuse) ----------

TRAILING_IMPORT_SRC = """\
from messagefoundry import handler, set_field


@handler("H")
def h(msg):
    set_field(msg, "PID-3.1", "X")


import re
"""

LOCAL_SHADOW_SRC = """\
from messagefoundry import db_lookup, handler


@handler("H")
def h(msg):
    row = db_lookup("C", "select 1", ())
    msg.set("PID-3.1", "X")
"""

ANNOTATED_BIND_SRC = """\
from messagefoundry import code_lookup, code_set, handler, set_field

GENDER: object = code_set("gender")


@handler("H")
def h(msg):
    set_field(msg, "PID-3.1", "X")
"""


def test_insert_code_lookup_binding_lands_above_a_trailing_import() -> None:
    # a stray top-level import AFTER the handler must not misplace the binding (index-shift regression)
    out = _code_lookup(
        TRAILING_IMPORT_SRC, _set_field_row(TRAILING_IMPORT_SRC), code_set="gender", path="PID-8"
    )
    lines = out.splitlines()
    b = next(i for i, line in enumerate(lines) if line.startswith("GENDER = code_set("))
    d = next(i for i, line in enumerate(lines) if line.startswith("@handler"))
    assert b < d  # binding sits at the leading import block, above the handler
    assert "import re" in out  # the trailing import is preserved intact
    ast.parse(out)


def test_insert_code_lookup_refuses_handler_local_shadow() -> None:
    anchor = next(r for r in parse_source(LOCAL_SHADOW_SRC)[0]["rows"] if r["kind"] == "action")
    with pytest.raises(
        Exception
    ):  # 'row' is a handler-local → the module binding would be shadowed
        _code_lookup(LOCAL_SHADOW_SRC, anchor, code_set="gender", var="row", path="PID-8")


def test_insert_code_lookup_reuses_annotated_binding() -> None:
    out = _code_lookup(
        ANNOTATED_BIND_SRC, _set_field_row(ANNOTATED_BIND_SRC), code_set="gender", path="PID-8"
    )
    assert 'code_lookup(msg, "PID-8", GENDER)' in out
    assert (
        out.count('code_set("gender")') == 1
    )  # annotated binding reused, not duplicated or refused
    ast.parse(out)
