# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Hostile-content scenarios against ``harness/config/hostile.py``: well-formed HL7 whose field
values are hostile to whatever sits downstream.

The fuzz targets cover parser crashes. These cover the other half: a message that parses cleanly
but carries, in one field, a path traversal, SQL or spreadsheet metacharacters, markup, raw HL7
escapes, redefined delimiters, MLLP framing bytes, a bare line break, an oversize value or
non-ASCII text. The values are data in ``hostile_values.toml`` beside this module; each is placed
into a generated ADT^A01 with the :class:`~messagefoundry.parsing.message.Message` API, and no
field's content is ever sliced. Two places do touch the serialized text, both named where they
happen: a bare line break is a segment terminator, so it is chosen when the encoded segments are
joined; and :func:`received_bytes` models the MLLP decoder cutting a frame at its end block.
Nothing here prints or logs a payload; a report names a value by its label.

Every scenario injects each value of its class through the MLLP and File drivers (``framing_bytes``
through MLLP only) into the pass-through graph and asserts three things:

1. the DISPOSITION the API reports (``processed`` unless the value says otherwise);
2. what the MLLP and File SINKS received: the delivered bytes equal the bytes the engine documents
   it delivers -- for almost every class that is exactly the bytes sent -- every written file stays
   a single name inside the output directory, and nothing was written where an unconfined
   ``{MSH-10}.hl7`` would have landed outside it;
3. that the engine still answers ``/health`` and every hostile-graph connection is still running
   (``/health`` alone stays ok while an inbound has failed).

Where the right answer is not "the same bytes", the class says why:

* ``line_breaks``: :meth:`Message.set` refuses CR and LF in a value (it would inject a segment), so
  a bare line break can only exist on the wire, where it IS a segment boundary. The engine
  normalizes every line ending to CR at ingress (:func:`messagefoundry.parsing.normalize`), so the
  delivered copy is the CR-terminated form of what was sent.
* ``framing_bytes`` over MLLP: MLLP has no escape. A 0x1C ends the frame wherever it occurs, so the
  engine receives the bytes before it, and correctly so -- the sender framed it that way. The
  delivered copy is that prefix as the engine serializes it.
* ``framing_bytes`` and ``framing_smuggle`` carried in by FILE and sent out over MLLP: the File
  inbound carries the bytes intact, so the correct outcome is either an intact MLLP delivery
  (impossible: MLLP cannot carry a 0x1C) or a refused one. See :data:`KNOWN_DEFECTS`.
* ``path_traversal`` with a NUL: the ingress guard refuses any body carrying a NUL (INGEST-4), so
  that value is an ERROR (a NAK over MLLP) and reaches no sink.
* ``non_ascii`` with a Latin-1 body on a UTF-8 connection: the connection's ``encoding`` decides,
  not MSH-18, and an undecodable body is an ERROR (an MLLP NAK), never silent U+FFFD replacement.
  Neither refused body has a control id the store records, so each is found as a new ERROR row on
  its inbound.
"""

from __future__ import annotations

import time
import tomllib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from types import MappingProxyType
from typing import Any
from uuid import uuid4

from harness import drivers, sinks
from harness.scenarios._core import (
    _TERMINAL,
    INBOUND,
    OUTBOUND,
    BaseScenario,
    Coverage,
    ScenarioContext,
    ScenarioResult,
    control_id_of,
)
from messagefoundry.apiclient import ApiError, EngineClient
from messagefoundry.generators import (
    _core,
    all_types,  # noqa: F401  (registers the built-in message types)
)
from messagefoundry.parsing import HL7PeekError, normalize
from messagefoundry.parsing.message import Message, reencode_with_separators
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES

#: The data file of hostile values, loaded at run time.
VALUES_FILE = Path(__file__).with_name("hostile_values.toml")

#: Where the token placeholder goes in a value's text.
TOKEN = "{token}"

#: Each driver kind and the endpoint and inbound connection it feeds in the hostile graph.
_INBOUND_ENDPOINT = {"mllp": "hostile_mllp_in", "file": "hostile_file_in"}
_INBOUND_NAME = {"mllp": "IB_Hostile_MLLP", "file": "FILE-IN_Hostile"}
_MLLP_SINK_ENDPOINT = "hostile_mllp_echo"
_FILE_SINK_ENDPOINT = "hostile_file_out"
_OUTBOUND_NAMES = ("OB_Hostile_Echo", "FILE-OUT_Hostile")
#: After the last expected delivery, how long a sink keeps listening for a late duplicate or an
#: extra (smuggled) record before its snapshot is judged.
_SETTLE_SECONDS = 0.5

_EXPECTS = frozenset({"processed", "error"})
_END_BLOCK = 0x1C
_LINE_BREAKS = ("\r\n", "\r", "\n")


@dataclass(frozen=True)
class HostileValue:
    """One hostile value from the data file. ``label`` names it in reports; the value itself is
    never printed."""

    hostile_class: str
    label: str
    path: str
    text: str = ""
    fill: str = ""
    cap_fraction: float = 0.0
    below_cap: int = 0
    charset: str = ""
    encoding: str = "utf-8"
    expect: str = "processed"
    separators: tuple[str, str, str, str, str] | None = None  # field, comp, rep, sub, escape

    def __post_init__(self) -> None:
        if self.expect not in _EXPECTS:
            raise ValueError(f"hostile value {self.label!r}: unknown expect {self.expect!r}")
        if bool(self.text) == bool(self.fill):
            raise ValueError(f"hostile value {self.label!r} needs exactly one of text and fill")
        if self.fill and len(self.fill) != 1:
            raise ValueError(f"hostile value {self.label!r}: fill is one character")
        if self.fill and (bool(self.cap_fraction) == bool(self.below_cap)):
            raise ValueError(
                f"hostile value {self.label!r}: fill takes one of cap_fraction and below_cap"
            )
        if self.cap_fraction and not 0.0 < self.cap_fraction < 1.0:
            raise ValueError(f"hostile value {self.label!r}: cap_fraction is between 0 and 1")
        if self.below_cap < 0:
            raise ValueError(f"hostile value {self.label!r}: below_cap is a positive byte count")
        breaks = self.text.count("\r") + self.text.count("\n") - self.text.count("\r\n")
        if breaks > 1:
            raise ValueError(f"hostile value {self.label!r}: at most one line break")
        if self.path == "MSH-10" and TOKEN not in self.text:
            # MSH-10 is how a run finds its own rows; without the fresh token a long-lived store
            # could answer with an earlier run's message.
            raise ValueError(f"hostile value {self.label!r} in MSH-10 must carry {TOKEN}")


def _separators(raw: Mapping[str, str]) -> tuple[str, str, str, str, str]:
    # Named in the data file, because the two orders in use (MSH order, and the
    # (field, component, repetition, subcomponent, escape) order reencode_with_separators takes)
    # are easy to mix up.
    return (
        raw["field"],
        raw["component"],
        raw["repetition"],
        raw["subcomponent"],
        raw["escape"],
    )


def parse_values(document: Mapping[str, Any]) -> tuple[HostileValue, ...]:
    """The hostile values a parsed data document declares, validated."""
    values: list[HostileValue] = []
    for entry in document.get("value", []):
        item = dict(entry)
        hostile_class = item.pop("class")
        seps = item.pop("separators", None)
        values.append(
            HostileValue(
                hostile_class=hostile_class,
                separators=_separators(seps) if seps is not None else None,
                **item,
            )
        )
    labels = [(v.hostile_class, v.label) for v in values]
    if len(set(labels)) != len(labels):
        raise ValueError("a hostile value label is declared twice in one class")
    return tuple(values)


@cache
def load_values(path: Path = VALUES_FILE) -> Mapping[str, tuple[HostileValue, ...]]:
    """Every hostile value in the data file, by class."""
    with path.open("rb") as handle:
        values = parse_values(tomllib.load(handle))
    by_class: dict[str, list[HostileValue]] = {}
    for value in values:
        by_class.setdefault(value.hostile_class, []).append(value)
    return MappingProxyType({k: tuple(v) for k, v in by_class.items()})


# --- building a message -------------------------------------------------------------------------


@dataclass(frozen=True)
class HostileMessage:
    """One built message: what goes on the wire and what each sink should receive."""

    value: HostileValue
    driver: str
    token: str
    payload: bytes
    control_id: str | None  # MSH-10 as the engine will read it from what it receives
    expected: bytes | None  # None: nothing may be delivered (an expected ERROR)

    @property
    def where(self) -> str:
        return f"{self.value.label} via {self.driver}"


def _base_message(token: str) -> Message:
    message = Message.parse(_core.generate_message("ADT", "A01", 1))
    message.set("MSH-10", token)
    return message


def _fill_text(value: HostileValue, message: Message) -> str:
    """The fill run, sized in BYTES of the value's encoding, since the cap is in bytes."""
    if value.cap_fraction:
        budget = int(DEFAULT_MAX_MESSAGE_BYTES * value.cap_fraction)
    else:  # below_cap: the whole message lands that many bytes under the cap
        probe = message.copy()
        probe.set(value.path, "")
        used = len(probe.encode().encode(value.encoding))
        budget = DEFAULT_MAX_MESSAGE_BYTES - value.below_cap - used
    if budget <= 0:
        raise ValueError(f"hostile value {value.label!r}: no room under the cap for the fill")
    delimiters = (message["MSH-1"] or "") + (message["MSH-2"] or "")
    if value.fill in delimiters:
        # Message.set would escape it to three bytes, and the sizing above would be wrong.
        raise ValueError(f"hostile value {value.label!r}: the fill is a delimiter")
    return value.fill * (budget // len(value.fill.encode(value.encoding)))


def split_line_break(text: str) -> tuple[str, str, str] | None:
    """``(head, break, tail)`` at the first line break in ``text``, or None without one."""
    hits = [(text.find(b), b) for b in _LINE_BREAKS if b in text]
    if not hits:
        return None
    at, brk = min(hits, key=lambda hit: (hit[0], -len(hit[1])))
    return text[:at], brk, text[at + len(brk) :]


def _with_line_break(message: Message, path: str, head: str, brk: str, tail: str) -> str:
    """The message with ``head`` at ``path`` and ``tail`` as the next segment, terminated by
    ``brk`` at that one boundary.

    :meth:`Message.set` refuses CR and LF in a value, so a bare line break inside a field can only
    exist on the wire, where it is indistinguishable from a segment boundary. The model builds the
    message (``tail`` must be one segment line); this then joins the encoded segment lines with
    their terminators, choosing ``brk`` at one boundary. It rewrites terminators BETWEEN segments
    only; no field content is sliced."""
    message.set(path, head)
    segment_id = path.split("-", 1)[0]
    position = message.segments().index(segment_id)  # 0 is MSH
    message.add_segment(tail, index=position + 1)
    lines = message.encode().split("\r")
    if lines and lines[-1] == "":
        lines.pop()
    junction = position + 1  # the injected segment's line
    return "".join(
        line + (brk if index + 1 == junction else "\r") for index, line in enumerate(lines)
    )


def build_text(value: HostileValue, token: str) -> str:
    """The HL7 text carrying ``value``, built with the parsed-message API."""
    message = _base_message(token)
    if value.separators is not None:
        message = Message.parse(reencode_with_separators(message.encode(), value.separators))
    if value.charset:
        message.set("MSH-18", value.charset)
    text = _fill_text(value, message) if value.fill else value.text.replace(TOKEN, token)
    split = split_line_break(text)
    if split is not None:
        head, brk, tail = split
        return _with_line_break(message, value.path, head, brk, tail)
    message.set(value.path, text)
    return message.encode()


def received_bytes(payload: bytes, driver: str) -> bytes:
    """What the engine receives of ``payload``: over MLLP, which has no escape, a frame ends at the
    first end-block byte wherever it falls; the File inbound reads the whole file."""
    if driver == "mllp" and _END_BLOCK in payload:
        return payload[: payload.index(_END_BLOCK)]
    return payload


def expected_delivery(payload: bytes, driver: str, encoding: str) -> bytes:
    """What the pass-through graph should deliver for ``payload`` injected via ``driver``: what it
    received, with every line ending normalized to CR (:func:`normalize`, the documented ingress
    rule). A frame cut short by an end block is delivered as the engine re-serializes that
    truncated message, which ends its last segment with CR."""
    received = received_bytes(payload, driver)
    if received != payload:
        return Message.parse(received.decode(encoding)).encode().encode(encoding)
    return normalize(payload.decode(encoding)).encode(encoding)


def build_injection(value: HostileValue, driver: str) -> HostileMessage:
    token = uuid4().hex[:16]
    payload = build_text(value, token).encode(value.encoding)
    expected = (
        None if value.expect == "error" else expected_delivery(payload, driver, value.encoding)
    )
    control_id = control_id_of(received_bytes(payload, driver))
    return HostileMessage(value, driver, token, payload, control_id, expected)


# --- checks -------------------------------------------------------------------------------------

#: Reads a record's control id; a run passes a memoizing one so a multi-megabyte payload is parsed
#: once, not once per poll per message.
ControlIdOf = Callable[[sinks.Record], str | None]


def _record_control_id(record: sinks.Record) -> str | None:
    return control_id_of(record.payload)


def escaped_files(
    out_dir: Path, names: Iterable[tuple[str | None, str]]
) -> tuple[list[Path], list[Path]]:
    """Files an UNCONFINED ``{MSH-10}.hl7`` writer would have left outside ``out_dir``, for each
    ``(control_id, token)`` in ``names``.

    The File sink sees only the inside of its directory, so an escape has to be looked for where
    it would land: the literal join of the directory and the name (which also covers an absolute
    name), and every directory a ``..`` chain could climb to, listed once, one level deep, for an
    entry carrying one of the run's tokens.

    Returns ``(found, unscanned)``: a place the check could not look in is reported, never taken as
    clean, so the check cannot pass without having looked."""
    root = out_dir.resolve()
    found: list[Path] = []
    unscanned: list[Path] = []
    tokens: list[str] = []
    climb = 1
    for control_id, token in names:
        tokens.append(token)
        if not control_id:
            continue
        climb = max(climb, control_id.count("..") + 1)
        if "\x00" in control_id:
            continue  # a name the OS cannot hold cannot have been written either
        landing = (out_dir / f"{control_id}.hl7").resolve()
        try:
            if not landing.is_relative_to(root) and landing.exists():
                found.append(landing)
        except OSError:
            unscanned.append(landing)
    for ancestor in list(root.parents)[:climb]:
        try:
            entries = list(ancestor.iterdir())
        except OSError:
            unscanned.append(ancestor)
            continue
        found.extend(p for p in entries if any(t in p.name for t in tokens) and p not in found)
    return found, unscanned


def delivery_problem(
    kind: str,
    message: HostileMessage,
    records: Sequence[sinks.Record],
    cid_of: ControlIdOf = _record_control_id,
) -> str | None:
    """None when ``records`` (one sink's) hold exactly the delivery ``message`` expects, else a
    one-line reason that names the value by label, never by content."""
    mine = [r for r in records if message.control_id and cid_of(r) == message.control_id]
    if message.expected is None:
        return f"{message.where}: an ERROR message reached the {kind} sink" if mine else None
    if not mine:
        return f"{message.where}: nothing reached the {kind} sink"
    if len(mine) > 1:
        return f"{message.where}: {len(mine)} copies reached the {kind} sink"
    record = mine[0]
    if record.payload != message.expected:
        return (
            f"{message.where}: the {kind} sink got {len(record.payload)} bytes that differ from "
            f"the {len(message.expected)} expected"
        )
    if kind == "file":
        if record.meta.get("inside") != "true":
            return f"{message.where}: the written file resolves outside its directory"
        if "/" in record.meta.get("relpath", "/"):
            return f"{message.where}: the written file is not a single name in its directory"
    return None


def foreign_problem(
    kind: str,
    messages: Sequence[HostileMessage],
    records: Sequence[sinks.Record],
    cid_of: ControlIdOf = _record_control_id,
) -> str | None:
    """A record this run did not send but caused: one with no readable control id, or one whose
    control id carries this run's token without being one of ours -- a smuggled frame. A late
    delivery left by an earlier run carries that run's token, so it is not counted here."""
    ours = {m.control_id for m in messages if m.control_id}
    tokens = [m.token for m in messages]
    foreign = 0
    for record in records:
        cid = cid_of(record)
        if cid in ours:
            continue
        if cid is None or any(token in cid for token in tokens):
            foreign += 1
    return f"{foreign} unexpected record(s) reached the {kind} sink" if foreign else None


#: The API's bound on a ``control_id`` filter (``ControlIdFilter`` in ``messagefoundry.api``).
_CONTROL_ID_FILTER_MAX = 256


def _queryable(control_id: str) -> bool:
    """Whether the API accepts ``control_id`` as a filter: it refuses (a 422) one longer than its
    bound or carrying a C0 or C1 control character, so such an id is looked for among its inbound's
    newest rows instead."""
    return len(control_id) <= _CONTROL_ID_FILTER_MAX and not any(
        ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in control_id
    )


def _status_of(client: EngineClient, message: HostileMessage) -> str | None:
    cid = message.control_id
    if not cid:
        return None
    if _queryable(cid):
        rows = client.list_messages(control_id=cid, limit=1).messages
    else:
        newest = client.list_messages(channel_id=_INBOUND_NAME[message.driver], limit=200)
        rows = [m for m in newest.messages if m.control_id == cid]
    return rows[0].status if rows else None


def _wait_dispositions(
    client: EngineClient,
    messages: Sequence[HostileMessage],
    error_baseline: Mapping[str, set[str]],
    timeout: float,
    started: float,
) -> dict[int, str]:
    """The terminal disposition of each message (by index), or what was last seen.

    A refused body (a NUL, an undecodable charset) has no control id the store records, so it is
    matched to a NEW error row with none on its inbound, received after the run began, one row per
    message. That is a match by count, not by content: other traffic refused on the same hostile
    inbound during the run could stand in for it. Over MLLP the NAK ties the refusal to the message
    directly (:func:`_nak_problem`)."""
    statuses: dict[int, str] = {}
    claimed: set[str] = set()  # error rows already matched to a message, across polls
    deadline = time.monotonic() + timeout
    while True:
        for index, message in enumerate(messages):
            if statuses.get(index) in _TERMINAL:
                continue
            if (status := _status_of(client, message)) is not None:
                statuses[index] = status
                continue
            if message.value.expect == "error":
                inbound = _INBOUND_NAME[message.driver]
                listing = client.list_messages(channel_id=inbound, status="error", limit=50)
                fresh = (
                    row.id
                    for row in listing.messages
                    if row.control_id is None
                    and row.received_at >= started
                    and row.id not in error_baseline[inbound]
                    and row.id not in claimed
                )
                if (row_id := next(fresh, None)) is not None:
                    claimed.add(row_id)
                    statuses[index] = "error"
        done = len(statuses) == len(messages) and all(s in _TERMINAL for s in statuses.values())
        if done or time.monotonic() >= deadline:
            return statuses
        time.sleep(0.2)


def _error_rows(client: EngineClient) -> dict[str, set[str]]:
    return {
        name: {
            m.id for m in client.list_messages(channel_id=name, status="error", limit=200).messages
        }
        for name in _INBOUND_NAME.values()
    }


def _nak_problem(message: HostileMessage, reply: bytes | None) -> str | None:
    """An expected-ERROR value sent over MLLP must be refused in the ACK, not accepted."""
    if message.driver != "mllp" or message.value.expect != "error":
        return None
    try:
        code = Message.parse(reply)["MSA-1"] if reply else None
    except (HL7PeekError, ValueError):
        code = None
    if code in ("AE", "AR", "CE", "CR"):
        return None
    return f"{message.where}: expected a NAK, got {code or 'no reply'}"


def health_problems(client: EngineClient) -> list[str]:
    """``/health`` must answer ok, and every hostile-graph connection must still be running:
    ``/health`` stays ok while one inbound has failed, so it alone cannot see a killed listener."""
    problems: list[str] = []
    try:
        status = client.health().status
        rows = client.connections()
    except ApiError as exc:
        return [f"the engine API stopped answering ({exc})"]
    if status != "ok":
        problems.append(f"/health answered {status!r}")
    # An outbound with no traffic yet is a standalone row keyed by its own name; after traffic it
    # is an edge row under the inbound that fed it. Either shape counts.
    ours = [
        r
        for r in rows
        if r.channel_id in _INBOUND_NAME.values() or r.destination in _OUTBOUND_NAMES
    ]
    sources = {r.channel_id for r in ours if r.role == "source"}
    if sources != set(_INBOUND_NAME.values()):
        problems.append("a hostile-graph inbound is missing from /connections")
    destinations = {r.destination for r in ours if r.role == "destination"}
    if not set(_OUTBOUND_NAMES) <= destinations:
        problems.append("a hostile-graph outbound is missing from /connections")
    problems.extend(
        f"{r.destination or r.channel_id} is {r.status}" for r in ours if r.status != "running"
    )
    return problems


# --- the scenario -------------------------------------------------------------------------------


@dataclass(frozen=True)
class HostileScenario(BaseScenario):
    """Inject every value of ``classes`` through each of ``drivers`` into the pass-through graph,
    with an MLLP and a File sink listening, and assert disposition, delivered bytes and health.

    ``mllp_refusal_ok`` also accepts a refused MLLP delivery as correct: the message ended ERROR
    and nothing of it reached the MLLP sink. That is for a value MLLP cannot frame intact."""

    name: str
    description: str
    classes: tuple[str, ...]
    drivers: tuple[str, ...] = ("mllp", "file")
    mllp_refusal_ok: bool = False
    values_file: Path = field(default=VALUES_FILE, compare=False)

    @property
    def covers(self) -> frozenset[Coverage]:
        pairs = {(kind, INBOUND) for kind in self.drivers}
        pairs |= {("mllp", OUTBOUND), ("file", OUTBOUND)}
        return frozenset(pairs)

    def values(self) -> tuple[HostileValue, ...]:
        by_class = load_values(self.values_file)
        missing = [c for c in self.classes if c not in by_class]
        if missing:
            raise KeyError(f"scenario {self.name!r}: no hostile values for class(es) {missing}")
        return tuple(v for c in self.classes for v in by_class[c])

    def messages(self) -> list[HostileMessage]:
        """Fresh messages: one per value per driver, each with its own token."""
        return [build_injection(v, d) for d in self.drivers for v in self.values()]

    def run(self, ctx: ScenarioContext) -> ScenarioResult:
        try:
            messages = self.messages()
        except (OSError, ValueError, KeyError) as exc:
            # A bad data file or a value the model refuses: a setup failure, reported, not raised.
            return ScenarioResult(self, False, f"could not build the hostile messages: {exc}")
        started = time.time()
        out_dir = Path(ctx.endpoints.value(_FILE_SINK_ENDPOINT))
        try:
            baseline = _error_rows(ctx.client)
        except ApiError as exc:
            return ScenarioResult(self, False, f"API error: {exc}")
        with (
            sinks.build("mllp", ctx.endpoints, _MLLP_SINK_ENDPOINT) as mllp_sink,
            sinks.build("file", ctx.endpoints, _FILE_SINK_ENDPOINT) as file_sink,
        ):
            problems: list[str] = []
            for message in messages:
                driver = drivers.build(
                    message.driver, ctx.endpoints, _INBOUND_ENDPOINT[message.driver]
                )
                (sent,) = driver.inject([message.payload])
                if sent.error:
                    problems.append(f"{message.where}: could not send: {sent.error}")
                elif nak := _nak_problem(message, sent.reply):
                    problems.append(nak)
            if problems:
                return ScenarioResult(self, False, "; ".join(problems))
            try:
                statuses = _wait_dispositions(ctx.client, messages, baseline, ctx.timeout, started)
            except ApiError as exc:
                return ScenarioResult(self, False, f"API error: {exc}")
            problems = self._check(messages, statuses, mllp_sink, file_sink, ctx.timeout)
            names = [(m.control_id, m.token) for m in messages]
            escaped, unscanned = escaped_files(out_dir, names)
            if escaped:
                problems.append(f"{len(escaped)} file(s) escaped the output directory")
            if unscanned:
                problems.append(f"the escape check could not look in {len(unscanned)} place(s)")
            problems.extend(health_problems(ctx.client))
        detail = f"{len(messages)} hostile message(s) across {', '.join(self.drivers)}"
        if problems:
            return ScenarioResult(self, False, detail + ": " + "; ".join(problems))
        return ScenarioResult(self, True, detail + ": dispositions, sink bytes and health held")

    def _check(
        self,
        messages: Sequence[HostileMessage],
        statuses: Mapping[int, str],
        mllp_sink: sinks.Sink,
        file_sink: sinks.Sink,
        timeout: float,
    ) -> list[str]:
        problems: list[str] = []
        refused: set[int] = set()
        for index, message in enumerate(messages):
            status = statuses.get(index, "not found")
            if self.mllp_refusal_ok and message.value.expect == "processed" and status == "error":
                refused.add(index)  # judged below by what reached the sinks
            elif status != message.value.expect:
                problems.append(f"{message.where}: {status}, expected {message.value.expect}")

        # Records stay alive in their sink for the whole run, so their ids are stable keys.
        seen: dict[int, str | None] = {}

        def cid_of(record: sinks.Record) -> str | None:
            key = id(record)
            if key not in seen:
                seen[key] = control_id_of(record.payload)
            return seen[key]

        def all_arrived(kind: str) -> Callable[[list[sinks.Record]], bool]:
            def done(records: list[sinks.Record]) -> bool:
                return all(
                    delivery_problem(kind, m, records, cid_of) is None
                    for index, m in enumerate(messages)
                    if m.expected is not None and not (kind == "mllp" and index in refused)
                )

            return done

        sink_wait = timeout if any(m.expected is not None for m in messages) else 0.0
        for kind, sink in (("mllp", mllp_sink), ("file", file_sink)):
            sink.wait_for(all_arrived(kind), sink_wait)
            # Keep listening a moment past the last expected arrival, so a late duplicate, a
            # smuggled extra record or a copy that should not be there is seen, not raced.
            time.sleep(_SETTLE_SECONDS)
            records = sink.records()
            for index, message in enumerate(messages):
                if kind == "mllp" and index in refused:
                    if any(cid_of(r) == message.control_id for r in records):
                        problems.append(f"{message.where}: refused, yet a copy reached mllp")
                    continue
                if (problem := delivery_problem(kind, message, records, cid_of)) is not None:
                    problems.append(problem)
            if (problem := foreign_problem(kind, messages, records, cid_of)) is not None:
                problems.append(problem)
        return problems


def _scenario(hostile_class: str, description: str, **kwargs: Any) -> HostileScenario:
    return HostileScenario(f"hostile_{hostile_class}", description, (hostile_class,), **kwargs)


SCENARIOS = (
    _scenario(
        "path_traversal",
        "path separators and traversal in MSH-10, which names the File outbound's file "
        "-> PROCESSED, every file a single name inside its directory, nothing outside it; "
        "a NUL -> ERROR (the ingress guard)",
    ),
    _scenario(
        "sql_metacharacters",
        "SQL metacharacters in MSH-10 and PID-5 -> PROCESSED, found by control id, bytes unchanged",
    ),
    _scenario(
        "hl7_escapes",
        "raw HL7 escape sequences carried verbatim in a whole field -> PROCESSED, bytes unchanged",
    ),
    _scenario(
        "redefined_delimiters",
        "non-default MSH-1/MSH-2 delimiters, default ones as data -> PROCESSED, bytes unchanged",
    ),
    _scenario(
        "framing_bytes",
        "MLLP start/end-block bytes in a field, sent over MLLP -> PROCESSED up to the end block, "
        "which delimits the frame (MLLP has no escape)",
        drivers=("mllp",),
    ),
    _scenario(
        "line_breaks",
        "a bare LF, CRLF or CR inside a field -> PROCESSED as a segment boundary, delivered with "
        "CR line endings (ingress normalizes them)",
    ),
    _scenario(
        "oversize_field",
        "one field at a quarter of the per-message cap, one near the cap -> PROCESSED, unchanged",
    ),
    _scenario(
        "non_ascii",
        "UTF-8 text under MSH-18 UNICODE UTF-8 -> PROCESSED unchanged; Latin-1 bytes on the UTF-8 "
        "connection -> ERROR (NAK over MLLP), never silent replacement",
    ),
    _scenario(
        "spreadsheet_formula",
        "=, +, -, @ and tab-prefixed formula values -> PROCESSED, bytes unchanged",
    ),
    _scenario(
        "markup",
        "script tags, event-handler attributes and javascript: URLs -> PROCESSED, bytes unchanged",
    ),
)


@dataclass(frozen=True)
class KnownDefect:
    """A scenario an engine defect fails today, the defect, and its signature: detail fragments of
    which EVERY reported problem must carry one, so a run failing for any other reason is told
    apart from the defect."""

    scenario: HostileScenario
    reason: str
    signature: tuple[str, ...]

    def reproduced_by(self, result: ScenarioResult) -> bool:
        """Whether ``result`` failed with this defect's signature and nothing else."""
        if result.ok or ": " not in result.detail:
            return False
        problems = result.detail.split(": ", 1)[1].split("; ")
        return bool(problems) and all(any(f in p for f in self.signature) for p in problems)


#: Scenarios that fail against the engine today because of an engine defect, kept OUT of
#: :data:`SCENARIOS` so the all-scenarios test stays green; ``tests/test_harness_hostile.py`` runs
#: each as a strict xfail on the defect's own signature, so a fix fails it: promote it then.
#: Not reachable from ``python -m harness --scenario``; run one with :func:`run_scenario`.
KNOWN_DEFECTS = (
    KnownDefect(
        HostileScenario(
            "hostile_framing_bytes_via_file",
            "MLLP framing bytes carried in by FILE and forwarded over MLLP: the MLLP delivery must "
            "be intact or refused, never truncated at the end block or split into a second frame",
            ("framing_bytes", "framing_smuggle"),
            drivers=("file",),
            mllp_refusal_ok=True,
        ),
        reason=(
            "engine defect: the MLLP outbound frames a payload that carries the MLLP end-block "
            "byte (0x1C) unescaped, so the peer ends the frame there, acknowledges a truncated "
            "message, and reads a start block after it as a second, smuggled message, while the "
            "engine records PROCESSED. On first deployment it would deliver a truncated or forged "
            "message to an MLLP partner for any such value carried in by a non-MLLP inbound"
        ),
        signature=("the mllp sink got", "unexpected record(s) reached the mllp sink"),
    ),
)
