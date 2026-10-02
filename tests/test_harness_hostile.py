# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The hostile-content scenarios: well-formed HL7 carrying a value hostile to a downstream sink.

Every registered hostile scenario already runs against the real served graph in
``tests/test_harness_scenarios.py``. This file covers what that cannot: the data file and the
message builder, the controls that prove the traversal-escape check and the round-trip byte check
can each FAIL (in isolation and inside a live run), and the known-defect scenarios as strict xfails.
Test ids are scenario or class names, never payloads. A comparison that involves a payload is taken
into a bool first, so a failure names a label and never prints the payload.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

from harness import drivers, endpoints, sinks
from harness.endpoints import Endpoints
from harness.scenarios import SCENARIOS, ScenarioContext, ScenarioResult, hostile, run_scenario
from harness.scenarios.hostile import (
    KNOWN_DEFECTS,
    HostileMessage,
    HostileScenario,
    HostileValue,
    KnownDefect,
    build_injection,
    build_text,
    delivery_problem,
    escaped_files,
    expected_delivery,
    foreign_problem,
    load_values,
    parse_values,
)
from harness.sinks import Record
from messagefoundry.apiclient import EngineClient
from messagefoundry.parsing import message as message_module
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES

# The shared fixture, imported rather than copied, so the readiness test that drives the
# test_harness_scenarios copy covers this one too.
from tests.test_harness_scenarios import server  # noqa: F401

_HOSTILE = {name: s for name, s in SCENARIOS.items() if isinstance(s, HostileScenario)}

#: The classes the row asks for; dropping one from the data file or the registry must fail here.
_REQUIRED_CLASSES = {
    "path_traversal",
    "sql_metacharacters",
    "hl7_escapes",
    "redefined_delimiters",
    "framing_bytes",
    "line_breaks",
    "oversize_field",
    "non_ascii",
    "spreadsheet_formula",
    "markup",
}


def _value(hostile_class: str, label: str) -> HostileValue:
    return next(v for v in load_values()[hostile_class] if v.label == label)


# --- the data file and the registry -------------------------------------------------------------


def test_every_required_class_has_values_and_a_registered_scenario() -> None:
    values = load_values()
    assert set(values) >= _REQUIRED_CLASSES
    registered = {c for s in _HOSTILE.values() for c in s.classes}
    assert registered >= _REQUIRED_CLASSES
    # Every class in the data file is exercised by some scenario, registered or known-defect.
    used = registered | {c for d in KNOWN_DEFECTS for c in d.scenario.classes}
    assert set(values) == used


def test_known_defects_are_not_registered() -> None:
    # Registered scenarios must all pass; a known defect stays out until its fix lands.
    assert not {d.scenario.name for d in KNOWN_DEFECTS} & set(SCENARIOS)


def test_every_hostile_scenario_names_real_drivers_sinks_and_endpoints() -> None:
    """The foundation's registry check skips a scenario that is not a ``Scenario``; this is the
    same check for the hostile ones, so a renamed endpoint or an unknown driver fails here rather
    than deep inside a live run."""
    declared = set(endpoints.registry())
    scenarios = [*_HOSTILE.values(), *(d.scenario for d in KNOWN_DEFECTS)]
    for scenario in scenarios:
        for kind in scenario.drivers:
            assert kind in drivers.registry(), (scenario.name, kind)
            assert hostile._INBOUND_ENDPOINT[kind] in declared, (scenario.name, kind)
        for kind, direction in scenario.covers:
            if direction == "outbound":
                assert kind in sinks.registry(), (scenario.name, kind)
    assert {hostile._MLLP_SINK_ENDPOINT, hostile._FILE_SINK_ENDPOINT} <= declared


@pytest.mark.parametrize(
    "bad",
    [
        {"class": "c", "label": "l", "path": "PID-5", "text": "x", "expect": "maybe"},
        {"class": "c", "label": "l", "path": "PID-5"},
        {"class": "c", "label": "l", "path": "PID-5", "text": "x", "fill": "X"},
        {"class": "c", "label": "l", "path": "PID-5", "fill": "XY", "cap_fraction": 0.1},
        {"class": "c", "label": "l", "path": "PID-5", "fill": "X"},
        {"class": "c", "label": "l", "path": "PID-5", "fill": "X", "cap_fraction": 1.5},
        {
            "class": "c",
            "label": "l",
            "path": "PID-5",
            "fill": "X",
            "cap_fraction": 0.1,
            "below_cap": 10,
        },
        {"class": "c", "label": "l", "path": "PID-5", "text": "a\nZZZ|1\nZZZ|2"},
        {"class": "c", "label": "l", "path": "MSH-10", "text": "no placeholder"},
    ],
    ids=[
        "unknown-expect",
        "no-text",
        "text-and-fill",
        "long-fill",
        "unsized-fill",
        "fraction-over-one",
        "two-sizes",
        "two-line-breaks",
        "msh10-no-token",
    ],
)
def test_a_malformed_value_is_refused(bad: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        parse_values({"value": [bad]})


def test_a_label_declared_twice_is_refused() -> None:
    entry = {"class": "c", "label": "l", "path": "PID-5", "text": "x"}
    with pytest.raises(ValueError, match="twice"):
        parse_values({"value": [entry, dict(entry)]})


@pytest.mark.parametrize(
    "value",
    [
        HostileValue("c", "no_room", "PID-5.1", fill="X", below_cap=DEFAULT_MAX_MESSAGE_BYTES),
        HostileValue("c", "delimiter_fill", "PID-5.1", fill="^", below_cap=65536),
    ],
    ids=["no-room", "delimiter-fill"],
)
def test_a_fill_that_cannot_be_sized_is_refused(value: HostileValue) -> None:
    with pytest.raises(ValueError):
        build_text(value, "TOKEN123")


# --- building the message -----------------------------------------------------------------------


@pytest.mark.parametrize("hostile_class", sorted(load_values()))
def test_each_value_lands_in_its_field_through_the_model(hostile_class: str) -> None:
    """Read back through the parsed model, each value is exactly what the data file says: a
    component path escapes it, a whole-field path carries it verbatim, and either way it is the
    field's value rather than new structure."""
    for value in load_values()[hostile_class]:
        if value.fill or hostile.split_line_break(value.text) is not None:
            continue  # sized and line-break values have their own tests below
        message = Message.parse(build_text(value, "TOKEN123"))
        lands = message.field(value.path) == value.text.replace(hostile.TOKEN, "TOKEN123")
        assert lands, value.label
        if value.charset:
            assert message["MSH-18"] == value.charset


def test_redefined_delimiters_are_declared_in_the_header() -> None:
    value = _value("redefined_delimiters", "hash_set")
    message = Message.parse(build_text(value, "TOKEN123"))
    assert message["MSH-1"] == "#"
    assert message["MSH-2"] == "$*!@"
    assert message["MSH-10"] == "TOKEN123"


def test_the_model_refuses_a_line_break_so_the_class_exists_only_on_the_wire() -> None:
    message = Message.parse(build_text(_value("markup", "script_tag"), "TOKEN123"))
    for brk in ("\n", "\r", "\r\n"):
        with pytest.raises(ValueError, match="segment separator"):
            message.set("PID-5.1", f"a{brk}b")


@pytest.mark.parametrize("label", ["bare_lf", "bare_crlf", "bare_cr"])
def test_a_line_break_value_becomes_a_segment_boundary(label: str) -> None:
    value = _value("line_breaks", label)
    head, brk, tail = hostile.split_line_break(value.text) or ("", "", "")
    payload = build_text(value, "TOKEN123")
    carries_break = brk in payload
    assert carries_break, label
    normalized = Message.parse(payload)
    ids = normalized.segments()
    assert ids[ids.index("PID") + 1] == tail.split("|", 1)[0]
    head_in_field = normalized["PID-5.1"] == head
    assert head_in_field, label


def test_oversize_values_are_large_and_under_the_cap() -> None:
    for value in load_values()["oversize_field"]:
        size = len(build_text(value, "TOKEN123").encode(value.encoding))
        assert DEFAULT_MAX_MESSAGE_BYTES // 5 < size < DEFAULT_MAX_MESSAGE_BYTES, value.label


def test_a_multibyte_fill_is_sized_in_bytes() -> None:
    value = HostileValue("c", "wide", "PID-5.1", fill="\u00e9", below_cap=65536)
    size = len(build_text(value, "TOKEN123").encode("utf-8"))
    assert DEFAULT_MAX_MESSAGE_BYTES - 65536 - 2 <= size <= DEFAULT_MAX_MESSAGE_BYTES - 65536


def test_expected_delivery_follows_the_documented_rules() -> None:
    # An end block alone, the data file's live check that an MLLP 0x1C ends the frame (ADR 0205).
    framing = build_injection(_value("framing_end_block", "end_block_only"), "mllp")
    assert framing.value.expect == "processed"
    end_block = framing.payload.index(0x1C)
    # Over MLLP the end block delimits the frame: only the bytes before it arrive.
    assert framing.expected is not None
    truncated = framing.expected.rstrip(b"\r") == framing.payload[:end_block]
    assert truncated
    # By File the same bytes are carried whole.
    whole = expected_delivery(framing.payload, "file", "utf-8") == framing.payload
    assert whole
    lf = build_injection(_value("line_breaks", "bare_lf"), "file")
    normalized = lf.expected == lf.payload.replace(b"\n", b"\r")
    assert normalized
    plain = build_injection(_value("markup", "script_tag"), "mllp")
    identical = plain.expected == plain.payload
    assert identical
    refused = build_injection(_value("non_ascii", "latin1_on_a_utf8_connection"), "mllp")
    assert refused.expected is None
    # The data file's framing value arrives raw, though the model would escape it (ADR 0205).
    framed = build_injection(_value("framing_bytes", "start_and_end_block"), "mllp")
    assert b"\x0b" in framed.payload and framed.expected is None


def test_the_raw_only_alphabet_holds_every_byte_the_engine_refuses_to_write() -> None:
    # The harness puts these back raw after the encode, so it must cover what a whole-field write
    # refuses and what a leaf write escapes. The engine-side tables are pinned to each other in
    # tests/test_one_frame_one_message.py.
    raw_only = set(hostile._RAW_ONLY)
    assert set(message_module._STRUCTURE_REFUSED) <= raw_only
    assert {chr(cp) for cp in range(0x20) if cp not in (0x09, 0x0A, 0x0D)} <= raw_only
    assert {"\t", "\r", "\n"}.isdisjoint(raw_only)


def test_the_control_id_is_read_from_what_the_engine_receives() -> None:
    """Over MLLP an end block inside MSH-10 cuts the frame there, so the engine records the part
    before it; the scenario must look that id up, not the one in the full payload."""
    value = HostileValue("c", "eb_in_msh10", "MSH-10", text="{token}\x1cTAIL")
    over_mllp = build_injection(value, "mllp")
    assert over_mllp.control_id == over_mllp.token
    by_file = build_injection(value, "file")
    assert by_file.control_id == f"{by_file.token}\x1cTAIL"


def test_a_long_or_control_char_id_is_not_sent_as_a_filter() -> None:
    assert hostile._queryable("x" * 256)
    assert not hostile._queryable("x" * 257)
    assert not hostile._queryable("a\x1fb")
    assert not hostile._queryable("a\x85b")


# --- controls: the checks can fail --------------------------------------------------------------


def _message(control_id: str, token: str, payload: bytes = b"") -> HostileMessage:
    value = HostileValue("path_traversal", "control", "MSH-10", text="x{token}")
    return HostileMessage(value, "file", token, payload, control_id, payload)


def test_the_escape_check_finds_a_file_where_an_unconfined_writer_would_put_it(
    tmp_path: Path,
) -> None:
    out_dir = tmp_path / "io" / "out"
    out_dir.mkdir(parents=True)
    token = "esc0token"
    control_id = f"../hostile-{token}"
    assert escaped_files(out_dir, [(control_id, token)]) == ([], [])  # the paired zero
    landing = (out_dir / f"{control_id}.hl7").resolve()
    landing.write_bytes(b"x")
    assert escaped_files(out_dir, [(control_id, token)]) == ([landing], [])


def test_the_escape_check_follows_an_absolute_name(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    token = "abs0token"
    control_id = str(tmp_path / "elsewhere" / f"hostile-{token}")
    assert escaped_files(out_dir, [(control_id, token)]) == ([], [])
    landing = Path(f"{control_id}.hl7")
    landing.parent.mkdir()
    landing.write_bytes(b"x")
    assert escaped_files(out_dir, [(control_id, token)]) == ([landing.resolve()], [])


def test_the_escape_check_scans_the_climbable_parents_for_the_token(tmp_path: Path) -> None:
    out_dir = tmp_path / "a" / "out"
    out_dir.mkdir(parents=True)
    token = "anc0token"
    # Not the literal landing name: a writer that mangled the name but still climbed out.
    stray = tmp_path / "a" / f"renamed-{token}.dat"
    names = [("plain-id", "other0token"), (f"../x-{token}", token)]
    assert escaped_files(out_dir, names) == ([], [])
    stray.write_bytes(b"x")
    assert escaped_files(out_dir, names) == ([stray], [])


def test_the_escape_check_reports_a_place_it_could_not_look(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out_dir = tmp_path / "a" / "out"
    out_dir.mkdir(parents=True)
    blocked = (tmp_path / "a").resolve()
    real_iterdir = Path.iterdir

    def iterdir(self: Path) -> Iterator[Path]:
        if self == blocked:
            raise PermissionError(13, "denied")
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", iterdir)
    found, unscanned = escaped_files(out_dir, [("../x-unr0token", "unr0token")])
    assert found == []
    assert unscanned == [blocked]


def test_the_escape_check_ignores_a_name_the_os_cannot_hold(tmp_path: Path) -> None:
    assert escaped_files(tmp_path, [("bad\x00name", "nul0token")]) == ([], [])


def test_the_round_trip_check_fails_on_one_changed_byte() -> None:
    payload = build_text(_value("markup", "script_tag"), "rt0token").encode()
    message = _message("rt0token", "rt0token", payload)
    ok = Record(payload, {"inside": "true", "relpath": "rt0token.hl7"})
    assert delivery_problem("file", message, [ok]) is None
    flipped = bytearray(payload)
    flipped[-2] ^= 0x01
    changed = Record(bytes(flipped), dict(ok.meta))
    assert "differ" in (delivery_problem("file", message, [changed]) or "")
    assert "nothing reached" in (delivery_problem("mllp", message, []) or "")
    assert "2 copies" in (delivery_problem("mllp", message, [ok, ok]) or "")


def test_the_file_check_fails_outside_the_directory_or_below_it() -> None:
    payload = build_text(_value("markup", "script_tag"), "rt1token").encode()
    message = _message("rt1token", "rt1token", payload)
    outside = Record(payload, {"inside": "false", "relpath": "rt1token.hl7"})
    assert "outside" in (delivery_problem("file", message, [outside]) or "")
    nested = Record(payload, {"inside": "true", "relpath": "sub/rt1token.hl7"})
    assert "single name" in (delivery_problem("file", message, [nested]) or "")


def test_the_foreign_check_counts_a_smuggled_frame_but_not_an_earlier_run() -> None:
    mine = build_text(_value("markup", "script_tag"), "fr0token").encode()
    smuggled = build_text(_value("markup", "script_tag"), "SMUGfr0token").encode()
    earlier = build_text(_value("markup", "script_tag"), "other0token").encode()
    messages = [_message("fr0token", "fr0token", mine)]
    assert foreign_problem("mllp", messages, [Record(mine), Record(earlier)]) is None
    assert foreign_problem("mllp", messages, [Record(mine), Record(smuggled)]) is not None
    assert foreign_problem("mllp", messages, [Record(b"no MSH here")]) is not None


def test_a_live_run_fails_when_the_sink_bytes_differ(
    server: tuple[str, Endpoints],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The round-trip check inside a real run: expecting one byte more than the engine delivers
    must fail the scenario, so its pass above is not vacuous."""
    real = hostile.expected_delivery
    monkeypatch.setattr(hostile, "expected_delivery", lambda payload, *a: real(payload, *a) + b"X")
    api_url, eps = server
    with EngineClient(api_url) as client:
        result = run_scenario(SCENARIOS["hostile_markup"], client, timeout=5.0, endpoints=eps)
    assert not result.ok
    assert "differ" in result.detail


def test_a_live_run_fails_when_a_file_escapes(
    server: tuple[str, Endpoints],  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The escape check inside a real run. The engine confines the name, so the escape is planted
    where an unconfined writer would have put it -- one level up, inside this test's tmp_path."""
    values = tmp_path / "values.toml"
    values.write_text(
        '[[value]]\nclass = "path_traversal"\nlabel = "one_up"\npath = "MSH-10"\n'
        'text = "../hostile-{token}"\n',
        encoding="utf-8",
    )
    scenario = HostileScenario("one_up", "", ("path_traversal",), values_file=values)
    api_url, eps = server
    out_dir = Path(eps.value("hostile_file_out"))
    real = hostile.build_injection

    def plant(value: HostileValue, driver: str) -> HostileMessage:
        message = real(value, driver)
        landing = (out_dir / f"{message.control_id}.hl7").resolve()
        assert landing.is_relative_to(tmp_path)  # the plant stays inside this test
        landing.write_bytes(b"planted")
        return message

    with EngineClient(api_url) as client:
        clean = run_scenario(scenario, client, timeout=10.0, endpoints=eps)
        assert clean.ok, clean.detail  # the paired pass: the same run without the plant
        monkeypatch.setattr(hostile, "build_injection", plant)
        result = run_scenario(scenario, client, timeout=10.0, endpoints=eps)
    assert not result.ok
    assert "escaped the output directory" in result.detail


def test_a_stopped_hostile_connection_fails_the_health_check(
    server: tuple[str, Endpoints],  # noqa: F811
) -> None:
    """``/health`` stays ok while one inbound is down, so the scenario's third check also reads
    ``/connections``; stopping an inbound must make that check say so."""
    api_url, _ = server
    with EngineClient(api_url) as client:
        assert hostile.health_problems(client) == []  # the paired pass
        client.stop_connection("IB_Hostile_MLLP")
        problems = hostile.health_problems(client)
    assert any("IB_Hostile_MLLP" in p for p in problems), problems


def test_a_bad_data_file_is_a_failed_result_not_a_traceback(tmp_path: Path) -> None:
    values = tmp_path / "values.toml"
    values.write_text('[[value]]\nclass = "c"\nlabel = "l"\npath = "ZZZ-1"\ntext = "x"\n')
    scenario = HostileScenario("bad", "", ("c",), values_file=values)
    result = scenario.run(ScenarioContext(client=cast(EngineClient, None)))
    assert not result.ok
    assert "could not build" in result.detail


# --- known engine defects -----------------------------------------------------------------------


def test_a_defect_signature_does_not_absorb_another_failure() -> None:
    # KNOWN_DEFECTS is empty since ADR 0205, so the matcher is pinned on a defect built here.
    scenario = HostileScenario("hostile_example", "an example", ("markup",), drivers=("file",))
    defect = KnownDefect(
        scenario,
        reason="example",
        signature=("the mllp sink got", "unexpected record(s) reached the mllp sink"),
    )
    head = "2 hostile message(s) across file: "
    alone = "a via file: the mllp sink got 1 bytes that differ; 1 unexpected record(s) reached"
    assert defect.reproduced_by(ScenarioResult(scenario, False, head + alone + " the mllp sink"))
    mixed = head + alone + " the mllp sink; a via file: nothing reached the file sink"
    assert not defect.reproduced_by(ScenarioResult(scenario, False, mixed))
    assert not defect.reproduced_by(ScenarioResult(scenario, True, head + alone))
    assert not defect.reproduced_by(ScenarioResult(scenario, False, "API error: 500"))


def test_no_known_defect_is_registered_while_nothing_runs_one() -> None:
    # The strict-xfail runner over KNOWN_DEFECTS was removed while the tuple is empty, because an
    # empty parametrization reports a skip that reads like a test. A defect added to the tuple would
    # run nowhere, so this fails until that runner is restored (from git history, ADR 0205).
    assert KNOWN_DEFECTS == ()
