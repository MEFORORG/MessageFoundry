# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""MFW2 — the non-executing sandbox IPC codec (ADR 0087, BACKLOG #197).

The regression suite for the pickle escape: the sandbox's whole purpose is an address-space boundary,
and a parent that ``pickle.loads`` the child's frame hands it straight back (a Handler returning an
object with a custom ``__reduce__`` executed arbitrary code IN THE ENGINE PARENT). These tests pin the
replacement wire: a closed value grammar, a strictly-sequential exactly-once segment discipline, and
fail-closed rejection of every malformed/hostile frame. Synthetic HL7 only."""

from __future__ import annotations

import datetime as dt
import json
import math
import pickle
import struct
from collections.abc import Iterator
from types import MappingProxyType
from typing import Any

import pytest

from messagefoundry.config.code_sets import CodeSet, UnmappedKind, UnmappedPolicy
from messagefoundry.config.models import ContentType
from messagefoundry.config.response import CapturedResponse
from messagefoundry.config.run_context import RunContext, run_contexts
from messagefoundry.config.state import state_get
from messagefoundry.config.wiring import (
    Send,
    SetMeta,
    SetState,
    WiringError,
    handler_result_items,
)
from messagefoundry.parsing.message import Message, RawMessage
from messagefoundry.pipeline import _sandbox_codec as codec
from messagefoundry.pipeline import sandbox
from messagefoundry.pipeline._sandbox_codec import (
    _MAX_DEPTH,
    _MAX_HEADER,
    MAX_FRAME,
    Ignored,
    SandboxCodecError,
    SandboxError,
    _Blobs,
    _dec_item,
    _Reader,
    dec_code_sets,
    dec_payload,
    dec_result,
    dec_run_context,
    dec_value,
    decode_boot,
    decode_frame,
    decode_request,
    decode_response,
    enc_code_sets,
    enc_payload,
    enc_result,
    enc_run_context,
    enc_value,
    encode_boot,
    encode_frame,
    encode_ok,
    encode_request,
)
from messagefoundry.pipeline.dryrun import _partition

RAW = "MSH|^~\\&|SEND|F|RECV|F|20240101120000||ADT^A01|MSG00001|P|2.3\rPID|1||900001||DOE^JANE\r"

# --- the __reduce__ gadget ----------------------------------------------------

#: Module-level tripwire. A gadget that executes appends to it; every test asserting "nothing ran"
#: asserts this list is still empty.
EXECUTED: list[str] = []


def _detonate(tag: str) -> str:
    EXECUTED.append(tag)
    return tag


class Gadget:
    """A perfectly ordinary object whose ``__reduce__`` runs code the moment anything unpickles it."""

    def __reduce__(self) -> tuple[Any, ...]:
        return (_detonate, ("pwned",))


@pytest.fixture(autouse=True)
def _clear_tripwire() -> Iterator[None]:
    EXECUTED.clear()
    yield
    EXECUTED.clear()


# --- frame helpers ------------------------------------------------------------


def _body(header: Any, blobs: tuple[str, ...] = ()) -> bytes:
    """A frame body from a JSON-able header object (bypasses the envelope builders on purpose)."""
    return _body_text(json.dumps(header, ensure_ascii=False, separators=(",", ":")), blobs)


def _body_text(text: str, blobs: tuple[str, ...] = ()) -> bytes:
    head = text.encode("utf-8", "surrogatepass")
    parts = [struct.pack(">I", len(head)), head]
    for blob in blobs:
        raw = blob.encode("utf-8", "surrogatepass")
        parts.append(struct.pack(">I", len(raw)))
        parts.append(raw)
    return b"".join(parts)


#: The handler/router name every frame in this module is built for. ``decode_response`` binds the whole
#: ``(id, phase, name)`` triple, so the tests have to name it too.
NAME = "h"


def _ok(
    result: Any, phase: str = "transform", request_id: str = "r:1", name: str = NAME
) -> dict[str, Any]:
    return {"v": 1, "t": "ok", "id": request_id, "phase": phase, "name": name, "result": result}


def _decode(
    body: bytes, *, request_id: str = "r:1", phase: str = "transform", name: str = NAME
) -> Any:
    """``decode_response`` with this module's default correlation triple."""
    return decode_response(body, request_id=request_id, phase=phase, name=name)


def _rt_transform(result: object) -> object:
    blobs = _Blobs()
    node = enc_result("transform", result, blobs)
    return dec_result("transform", node, _Reader(blobs.items))


# --- (1) THE REGRESSION TEST: a __reduce__ gadget never reaches the parent -----


def test_a_reduce_gadget_never_reaches_the_parent() -> None:
    """The confirmed defect, both halves.

    (a) CHILD side — describing a Handler return value never invokes ``__reduce__``: a gadget is an
    item ``_partition`` would ignore, so it is described as ``{"o": "other"}`` and the parent rebuilds
    an inert :class:`Ignored`.

    (b) PARENT side — the EXACT bytes the old child wrote (``pickle.dumps({"ok": True, "result":
    gadget})``) are fed to both codecs. ``pickle.loads`` — which is literally what the old
    ``sandbox._read_frame`` did on the reader thread, before any envelope inspection — DETONATES the
    gadget in this process. ``decode_frame`` refuses the same bytes with the tripwire untouched."""
    # (a) describing the gadget executes nothing, and the parent rebuilds an inert placeholder.
    blobs = _Blobs()
    node = enc_result("transform", Gadget(), blobs)
    assert node == {"r": "items", "shape": "one", "i": {"o": "other"}}
    assert isinstance(dec_result("transform", node, _Reader(blobs.items)), Ignored)
    assert EXECUTED == []

    # (b) the exact frame body the OLD child produced for a gadget-returning Handler.
    hostile = pickle.dumps({"ok": True, "result": Gadget()}, protocol=pickle.HIGHEST_PROTOCOL)

    # The old parent path, run here so the test is self-proving: this is the bug.
    # nosec B301 — this load is the DEFECT being regression-tested, executed here on purpose against a
    # locally-built gadget so the assertion below has something real to catch. Not a product path.
    pickle.loads(hostile)  # nosec B301
    assert EXECUTED == ["pwned"], "the gadget must actually be live for this test to mean anything"
    EXECUTED.clear()

    # The new parent path refuses it and executes nothing.
    with pytest.raises(SandboxCodecError):
        decode_frame(hostile)
    with pytest.raises(SandboxCodecError):
        _decode(hostile)
    assert EXECUTED == []

    # A hostile OBJECT GRAPH inside an otherwise well-formed frame is refused too: no wire tag can
    # name a module, a type, or a reduce callable.
    for smuggled in (
        {"__reduce__": ["tests.test_sandbox_codec", "_detonate"]},
        {"py/object": "tests.test_sandbox_codec.Gadget"},
        {"o": "send", "to": "OB", "m": {"!!python/name": "os.system"}},
    ):
        with pytest.raises(SandboxCodecError):
            _decode(_body(_ok({"r": "items", "shape": "one", "i": smuggled})))
    assert EXECUTED == []


def test_sandbox_codec_error_is_a_sandbox_error() -> None:
    """So ``route_only``/``transform_one``'s documented "raises SandboxError" — and every existing
    ``pytest.raises(SandboxError, ...)`` — keeps meaning what it says for a codec rejection."""
    assert issubclass(SandboxCodecError, SandboxError)


# --- (2) the decoder constructs only a closed set of types --------------------

_ALLOWED_TYPES = {
    Send,
    SetState,
    SetMeta,
    Ignored,
    CapturedResponse,
    Message,
    RawMessage,
    bool,
    int,
    float,
    str,
    bytes,
    list,
    tuple,
    dict,
    dt.datetime,
    dt.date,
    dt.time,
    type(None),
}


def _walk_types(obj: object, seen: set[type]) -> None:
    seen.add(type(obj))
    if isinstance(obj, dict):
        for k, v in obj.items():
            _walk_types(k, seen)
            _walk_types(v, seen)
    elif isinstance(obj, list | tuple):
        for item in obj:
            _walk_types(item, seen)
    elif isinstance(obj, Send):
        _walk_types(obj.to, seen)
        _walk_types(obj.message, seen)
    elif isinstance(obj, SetState):
        _walk_types(obj.value, seen)
    elif isinstance(obj, CapturedResponse):
        _walk_types(dict(obj.headers), seen)
        _walk_types(obj.body, seen)


def test_decoder_constructs_only_the_closed_type_set() -> None:
    corpus: list[object] = []

    # a full transform result
    corpus.append(
        _rt_transform(
            [
                Send("OB_A", "x" * 5000),
                SetState("ns", "k", {"a": [1, 2.5, True, None, ("t",)]}),
                SetMeta("mk", "mv"),
                object(),
            ]
        )
    )
    corpus.append(_rt_transform(None))
    # a router + accepts result
    for phase, result in (("router", ["h1", "h2"]), ("accepts", True)):
        blobs = _Blobs()
        corpus.append(dec_result(phase, enc_result(phase, result, blobs), _Reader(blobs.items)))
    # a run context with all three views
    rc = RunContext(
        reference_view=MappingProxyType({"codes": MappingProxyType({"A": b"\x00\x01"})}),
        state_view=MappingProxyType({("ns", "k"): [1, "two"]}),
        response_view={
            "OB_A": CapturedResponse(
                message_id="m1",
                destination_name="OB_A",
                response_seq=1,
                outcome="ok",
                detail=None,
                captured_at=1.5,
                body="MSH|",
                kind="response",
                ack_code="AA",
                ack_phase="CA",
                headers={"content-type": "text/plain"},
            )
        },
        active_environment="prod",
        ingest_time=2.0,
        message_id="m1",
        snapshot_on_send=True,
    )
    blobs = _Blobs()
    decoded_rc = dec_run_context(enc_run_context(rc, blobs), _Reader(blobs.items))
    corpus.extend([decoded_rc.reference_view, decoded_rc.state_view, decoded_rc.response_view])
    # both payload forms
    for origin in ((RAW, ContentType.HL7V2.value), (b"{}", "json")):
        blobs = _Blobs()
        corpus.append(dec_payload(enc_payload(None, origin, blobs), _Reader(blobs.items)))
    blobs = _Blobs()
    corpus.append(dec_payload(enc_payload(Message.parse(RAW), None, blobs), _Reader(blobs.items)))

    seen: set[type] = set()
    for item in corpus:
        _walk_types(item, seen)
    assert seen <= _ALLOWED_TYPES, f"decoder produced unexpected types: {seen - _ALLOWED_TYPES}"


# --- (3) the segment discipline is exactly-once and strictly sequential -------

_BIG_A = "A" * 5000
_BIG_B = "B" * 5000


def _two_sends(ref_a: Any, ref_b: Any) -> dict[str, Any]:
    return _ok(
        {
            "r": "items",
            "shape": "list",
            "i": [
                {"o": "send", "to": "OB_A", "m": ref_a},
                {"o": "send", "to": "OB_B", "m": ref_b},
            ],
        }
    )


def test_sequential_segment_references_decode() -> None:
    """The happy path the discipline has to keep working: two out-of-band bodies, in order."""
    resp = _decode(_body(_two_sends({"$": 0}, {"$": 1}), (_BIG_A, _BIG_B)))
    sends, _, _ = _partition(resp.result)  # type: ignore[arg-type]
    assert [(s.to, s.message) for s in sends] == [("OB_A", _BIG_A), ("OB_B", _BIG_B)]


@pytest.mark.parametrize(
    ("case", "body"),
    [
        ("out_of_range", _body(_two_sends({"$": 0}, {"$": 7}), (_BIG_A, _BIG_B))),
        ("duplicate", _body(_two_sends({"$": 0}, {"$": 0}), (_BIG_A, _BIG_B))),
        ("skipped", _body(_two_sends({"$": 1}, {"$": 0}), (_BIG_A, _BIG_B))),
        ("swapped", _body(_two_sends({"$": 1}, {"$": 0}), (_BIG_A, _BIG_B))),
        ("unconsumed_trailing", _body(_two_sends("inline", "inline"), (_BIG_A, _BIG_B))),
        ("partially_consumed", _body(_two_sends({"$": 0}, "inline"), (_BIG_A, _BIG_B))),
        ("non_integer_ref", _body(_two_sends({"$": "0"}, {"$": 1}), (_BIG_A, _BIG_B))),
        ("bool_ref", _body(_two_sends({"$": False}, {"$": 1}), (_BIG_A, _BIG_B))),
    ],
)
def test_blob_reference_discipline_is_exactly_once_and_sequential(case: str, body: bytes) -> None:
    """The PHI cross-wire guard. An indirection table's worst failure is silent: an off-by-one puts one
    ``Send``'s body on another ``Send``'s destination with no error at all. References are legal only
    at the cursor and every segment must be consumed, so each of these is a rejection **by
    construction** rather than by test coverage — note ``swapped`` in particular is REFUSED, not
    quietly cross-wired."""
    with pytest.raises(SandboxCodecError):
        _decode(body)


# --- (4) hostile frames fail closed ------------------------------------------


def _deep_json(depth: int) -> str:
    return "[" * depth + "]" * depth


def _too_many_blobs() -> bytes:
    header = json.dumps(_ok({"r": "items", "shape": "none"}), separators=(",", ":")).encode()
    parts = [struct.pack(">I", len(header)), header]
    parts.extend([struct.pack(">I", 0)] * 70000)
    return b"".join(parts)


_HOSTILE: list[tuple[str, bytes]] = [
    ("truncated_outer", b"\x00\x00"),
    ("truncated_header", struct.pack(">I", 4096) + b"{}"),
    ("header_over_cap", struct.pack(">I", _MAX_HEADER + 1) + b"{}"),
    ("too_many_segments", _too_many_blobs()),
    ("truncated_segment", _body(_ok({"r": "items", "shape": "none"})) + struct.pack(">I", 99)),
    ("header_not_an_object", _body([1, 2, 3])),
    (
        "bad_version",
        _body({"v": 2, "t": "ok", "id": "r:1", "phase": "transform", "name": NAME, "result": {}}),
    ),
    ("unknown_type", _body({"v": 1, "t": "nope", "id": "r:1"})),
    (
        "ok_without_result",
        _body({"v": 1, "t": "ok", "id": "r:1", "phase": "transform", "name": NAME}),
    ),
    ("id_mismatch", _body(_ok({"r": "items", "shape": "none"}, request_id="other:9"))),
    ("phase_mismatch", _body(_ok({"r": "names", "n": []}, phase="router"))),
    # The forgery that made the correlation check load-bearing: a frame for a DIFFERENT handler,
    # correctly addressed to this request otherwise. Without the name binding it would be delivered as
    # this call's answer (an attacker-chosen Send on a message the victim handler never saw).
    ("name_mismatch", _body(_ok({"r": "items", "shape": "none"}, name="h_other"))),
    ("missing_name", _body({"v": 1, "t": "ok", "id": "r:1", "phase": "transform", "result": {}})),
    (
        "unknown_value_tag",
        _body(
            _ok(
                {
                    "r": "items",
                    "shape": "one",
                    "i": {"o": "state", "ns": "n", "key": "k", "v": {"zz": 1}},
                }
            )
        ),
    ),
    (
        "two_key_wrapper",
        _body(
            _ok(
                {
                    "r": "items",
                    "shape": "one",
                    "i": {"o": "state", "ns": "n", "key": "k", "v": {"l": [], "p": []}},
                }
            )
        ),
    ),
    (
        "bare_array_value",
        _body(
            _ok(
                {"r": "items", "shape": "one", "i": {"o": "state", "ns": "n", "key": "k", "v": [1]}}
            )
        ),
    ),
    (
        "unhashable_dict_key",
        _body(
            _ok(
                {
                    "r": "items",
                    "shape": "one",
                    "i": {"o": "state", "ns": "n", "key": "k", "v": {"d": [[{"l": []}, 1]]}},
                }
            )
        ),
    ),
    (
        "invalid_base64",
        _body(
            _ok(
                {
                    "r": "items",
                    "shape": "one",
                    "i": {"o": "state", "ns": "n", "key": "k", "v": {"b": "!!!!"}},
                }
            )
        ),
    ),
    ("deep_nesting", _body_text(_deep_json(100000))),
    (
        "literal_nan",
        _body_text(
            '{"v":1,"t":"ok","id":"r:1","phase":"transform","x":NaN,"result":{"r":"items","shape":"none"}}'
        ),
    ),
    (
        "non_str_error",
        _body(
            {
                "v": 1,
                "t": "fail",
                "id": "r:1",
                "phase": "transform",
                "name": NAME,
                "kind": "error",
                "error": 12,
            }
        ),
    ),
    (
        "unknown_fail_kind",
        _body(
            {
                "v": 1,
                "t": "fail",
                "id": "r:1",
                "phase": "transform",
                "name": NAME,
                "kind": "boom",
                "error": "x",
            }
        ),
    ),
    ("unknown_item_tag", _body(_ok({"r": "items", "shape": "one", "i": {"o": "exec"}}))),
    ("unknown_shape", _body(_ok({"r": "items", "shape": "generator", "i": []}))),
    ("non_bool_accepts", _body(_ok({"r": "bool", "b": 1}, phase="transform"))),
    ("empty_body", b""),
]


@pytest.mark.parametrize(("case", "body"), _HOSTILE, ids=[c for c, _ in _HOSTILE])
def test_hostile_frames_fail_closed(case: str, body: bytes) -> None:
    with pytest.raises(SandboxCodecError):
        _decode(body)
    assert EXECUTED == []


def test_recursion_error_is_not_a_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pins the reason ``decode_frame`` catches ``RecursionError`` explicitly: it is a ``RuntimeError``,
    so a ``except ValueError`` would have let a deep-nesting rejection escape the fail-closed contract
    exactly as the old bare ``KeyError`` did.

    THE TRIGGER IS A RAISED ``RecursionError``, NOT REAL RECURSION (BACKLOG #1222). Manufacturing one by
    parsing ``"[" * 100000`` measured the RUNNER as much as the code: json's C accelerator consumes the
    C stack, which no Python-level knob reaches -- ``sys.getrecursionlimit()`` is 1000 while
    ``json.loads`` gets to ~16,900, so ``sys.setrecursionlimit`` cannot move it either. Measured: first
    raise at depth 16,913 on one box and NO raise at 100,000 on a CI runner, a 6x spread on identical
    bytes. That reddened ``main`` and two unrelated pull requests, on a file byte-identical to the one
    that had passed hours earlier.

    Do NOT "fix" a future recurrence by raising the depth: that buys a green on today's runner image,
    re-fires on the next roll, and makes the test MORE environment-coupled rather than less. What the
    contract needs is the type relationship and the handler, and neither needs a real stack overflow.
    """
    # (1) the type facts the handler's except-tuple depends on. Environment-independent.
    assert not issubclass(RecursionError, ValueError)
    assert issubclass(RecursionError, RuntimeError)

    # (2) drive the handler itself: a RecursionError out of the header parse must be converted into the
    # fail-closed SandboxCodecError. Narrowing that tuple to ValueError lets it escape, which is exactly
    # what this pins -- so this arm reds if the RecursionError is dropped from decode_frame.
    frame = encode_frame({"v": 1, "t": "ready"}, ())

    class _RecursingJson:
        """Stands in for the codec's ``json`` only for ``loads``; ``dumps`` is untouched and unused here."""

        @staticmethod
        def loads(*_args: object, **_kwargs: object) -> object:
            raise RecursionError("simulated deep nesting")

    monkeypatch.setattr(codec, "json", _RecursingJson)
    with pytest.raises(SandboxCodecError, match="RecursionError"):
        decode_frame(frame)


# --- (5) the value grammar round-trips exactly -------------------------------


def _rt_value(value: object) -> object:
    blobs = _Blobs()
    return dec_value(enc_value(value, blobs), _Reader(blobs.items))


def test_value_grammar_round_trips_exactly() -> None:
    assert _rt_value("a\udce9b") == "a\udce9b"  # a lone surrogate survives (surrogatepass)
    assert _rt_value("L" * 9000) == "L" * 9000  # and so does an out-of-band long string

    tup = _rt_value((1, "two", (3,)))
    assert tup == (1, "two", (3,)) and isinstance(tup, tuple) and isinstance(tup[2], tuple)

    keyed = _rt_value({1: "int", ("a", "b"): "tuple", None: "none", 2.5: "float"})
    assert keyed == {1: "int", ("a", "b"): "tuple", None: "none", 2.5: "float"}

    assert _rt_value(b"\x00\xff\x10") == b"\x00\xff\x10"
    assert math.isnan(_rt_value(float("nan")))  # type: ignore[arg-type]
    assert _rt_value(float("inf")) == math.inf
    assert _rt_value(float("-inf")) == -math.inf
    # tomllib produces these natively, so a .toml code set with a date value is a legitimate shape
    # plain JSON refuses.
    assert _rt_value(dt.datetime(2026, 8, 1, 12, 30, 5)) == dt.datetime(2026, 8, 1, 12, 30, 5)
    assert _rt_value(dt.date(2026, 8, 1)) == dt.date(2026, 8, 1)
    assert _rt_value(dt.time(12, 30, 5)) == dt.time(12, 30, 5)


def test_a_setstate_tuple_value_stays_a_tuple() -> None:
    """A JSON-text shortcut would flatten it to a list — a silent value-shape change mode=off does not
    make."""
    restored = _rt_transform(SetState("ns", "k", (1, 2)))
    assert isinstance(restored, SetState) and restored.value == (1, 2)
    assert isinstance(restored.value, tuple)


def test_adr0028_binary_body_is_not_double_encoded() -> None:
    """An ``mfb64:v1:<base64>`` body is ALREADY an ordinary ASCII ``str`` — it must ride as a plain
    string slot, never be re-wrapped through the bytes tag (that would break ``raw_bytes``)."""
    payload = b"\x00\x01\x02binary\xffbody"
    original = RawMessage.from_bytes(payload, "application/octet-stream")
    assert original.raw.startswith("mfb64:v1:")

    blobs = _Blobs()
    node = enc_payload(original, None, blobs)
    assert node["kind"] == "raw"
    restored = dec_payload(node, _Reader(blobs.items))
    assert isinstance(restored, RawMessage)
    assert restored.raw == original.raw  # byte-identical, NOT re-base64'd
    assert restored.raw_bytes == payload

    # and the same body carried back as a Send survives the result leg too
    out = _rt_transform(Send("OB_A", original))
    assert isinstance(out, Send) and out.message == original.raw


# --- (6) state_view tuple keys stay tuples -----------------------------------


def test_state_view_tuple_keys_round_trip() -> None:
    """``state_get`` does a dict lookup on ``(namespace, key)``; a list/joined key would turn every read
    into a SILENT miss returning its default — fail-open, inverting a suppression/dedup Handler with no
    ERROR, no dead-letter and no disposition anomaly."""
    rc = RunContext(state_view=MappingProxyType({("ns", "k"): "hit"}))
    blobs = _Blobs()
    decoded = dec_run_context(enc_run_context(rc, blobs), _Reader(blobs.items))
    with run_contexts(decoded, phase="transform"):
        assert state_get("ns", "k", "MISS") == "hit"


# --- (7) _partition parity — the codec never changes what delivers ------------


class _SubSend(Send):
    """A user subclass. ``_partition`` selects with ``isinstance``, so this DELIVERS in-process."""


def _generator_result() -> Any:
    def gen() -> Iterator[Send]:
        yield Send("OB_A", "x")

    return gen()


#: What each return shape partitions to, as ``[sends, state, meta]``. The table is the acceptance
#: criterion, asserted against BOTH modes — a shape may not partition differently across the pipe.
_PARITY: dict[str, list[int]] = {
    "none": [0, 0, 0],
    "bare_send": [1, 0, 0],
    "mixed_list": [1, 1, 1],  # the trailing `7` is unrecognised and drops
    "send_subclass": [1, 0, 0],
    "tuple_of_sends": [2, 0, 0],  # BACKLOG #341 — was [0, 0, 0]
    # >1 element on purpose — a 1-element set has only one ordering, so it cannot see _UNORDERED.
    "set_of_sends": [3, 0, 0],  # BACKLOG #341 — was [0, 0, 0]
    "bare_int": [0, 0, 0],  # not a container, not a recognised item — still DROPS
    "generator": [1, 0, 0],  # BACKLOG #341 — was [0, 0, 0]
    # THE acceptance criterion of #341 — `return []` / `return ()` must keep FILTERING, not start
    # delivering and not start raising — carried across the process boundary, not just in-process.
    "empty_list": [0, 0, 0],
    "empty_tuple": [0, 0, 0],
}

#: Cases whose container defines **no** iteration order, so parity is over the delivered MULTISET only.
#: ``Send`` is a frozen dataclass hashed on its fields and ``str`` hashing is seeded per process, so a
#: ``set``'s fan-out order differs between processes — i.e. between the sandbox child and the parent,
#: and between a first pass and a crash re-run. Asserting an order here would pin a per-process
#: accident as a contract; ADR 0087's AC-11 and `wiring.handler_result_items` say the same in prose.
_UNORDERED = {"set_of_sends"}


@pytest.mark.parametrize(
    ("case", "make"),
    [
        ("none", lambda: None),
        ("bare_send", lambda: Send("OB_A", "x")),
        ("mixed_list", lambda: [Send("OB_A", "x"), SetState("n", "k", 1), SetMeta("m", "v"), 7]),
        ("send_subclass", lambda: _SubSend("OB_A", "x")),
        ("tuple_of_sends", lambda: (Send("OB_A", "x"), Send("OB_B", "y"))),
        ("set_of_sends", lambda: {Send("OB_A", "x"), Send("OB_B", "y"), Send("OB_C", "z")}),
        ("bare_int", lambda: 7),
        ("generator", _generator_result),
        ("empty_list", list),
        ("empty_tuple", tuple),
    ],
)
def test_partition_parity_table(case: str, make: Any) -> None:
    """``[sandbox].mode`` never changes which ``Send``\\ s a Handler delivers.

    The child materialises a transform return with ``_partition``'s OWN rule
    (:func:`~messagefoundry.config.wiring.handler_result_items`), exactly as it already materialises a
    router return with ``_handler_names``' logic — so a tuple/set/generator fan-out delivers under
    ``mode=subprocess`` precisely as it does under ``mode=off`` (BACKLOG #341), an EMPTY container still
    FILTERS, a ``Send`` **subclass** still delivers, and a value neither rule recognises still drops
    (described as an ``Ignored`` slot rather than omitted, so ``_partition`` stays the SOLE filter).
    Fixing the parent's ``_partition`` alone would make the disposition MODE-DEPENDENT — in-process
    delivers while subprocess drops — which is worse than the original accept-and-drop this closes.

    **Destinations are compared, not just counts** — equal lengths would pass even if the codec swapped
    one outbound for another. For an ordered container the exact ORDER is pinned too; for a ``set``
    (``_UNORDERED``) only the multiset is, because a set has no iteration order to preserve. Note the
    scope honestly: this round-trip is **in-process**, so it cannot observe the cross-process reordering
    a real child imposes on a ``set`` — which is precisely why the contract is stated over the multiset
    rather than asserted over an order that only holds within one hash seed."""
    direct = _partition(make())
    through_codec = _partition(_rt_transform(make()))  # type: ignore[arg-type]
    assert [len(x) for x in direct] == _PARITY[case]
    assert [len(x) for x in through_codec] == _PARITY[case]
    if case == "send_subclass":
        assert len(direct[0]) == 1 and through_codec[0][0].to == "OB_A"  # still DELIVERS
    dests_direct = [s.to for s in direct[0]]
    dests_codec = [s.to for s in through_codec[0]]
    if case in _UNORDERED:
        assert sorted(dests_codec) == sorted(dests_direct)
    else:
        assert dests_codec == dests_direct
    if case in ("empty_list", "empty_tuple"):
        # The filter idiom must cross the pipe AS A CONTAINER, and `[0, 0, 0]` alone cannot see that:
        # an empty container mis-described as an *unrecognised single value* also partitions to
        # `[0, 0, 0]` (the parent rebuilds an `Ignored`). Pinning the described shape is what makes
        # this row falsifiable at all — a truthiness gate in `handler_result_items` (`and result`,
        # the natural "simplification") flips `shape` to `"one"` while every count stays green.
        assert enc_result("transform", make(), _Blobs()) == {"r": "items", "shape": "list", "i": []}


def test_handler_result_items_treats_a_str_as_a_single_value() -> None:
    """The shared materialization rule's two carve-outs, asserted directly on the rule itself.

    A ``str``/``bytes`` IS iterable but is not a container of ``Send``\\ s — iterating one would
    partition its characters. And the gate is an explicit ``__iter__`` (``isinstance(..., Iterable)``),
    never a duck-typed ``list(result)``, so a non-iterable value is a single item rather than a raise.

    An end-to-end "a ``str`` return still drops" test could NOT catch the first carve-out: characters
    are not ``Send``\\ s, so the disposition is ``[0, 0, 0]`` with or without it. Asserting on the rule
    is what makes the carve-out falsifiable at all."""
    s1, s2 = Send("OB_A", "x"), Send("OB_B", "y")
    assert handler_result_items("OB_A") is None
    assert handler_result_items(b"x") is None
    assert handler_result_items(bytearray(b"x")) is None
    assert handler_result_items(7) is None
    assert handler_result_items(None) is None
    assert handler_result_items(s1) is None  # a frozen dataclass is not iterable
    assert handler_result_items((s1, s2)) == [s1, s2]
    assert handler_result_items([s1]) == [s1]
    assert handler_result_items(()) == []
    assert _partition("OB_A") == ([], [], [])  # and a str return still DROPS end to end


# --- (8) parent-side constructor faults are wrapped --------------------------


def test_parent_rebuild_wraps_constructor_faults() -> None:
    """A forged row that trips ``SetState.__post_init__`` must surface as a codec rejection, not as a
    ``WiringError``: the child already ran that constructor successfully, so a raise here cannot be an
    authoring fault, and a ``WiringError`` would put a FALSE diagnosis in the operator's last_error."""
    with pytest.raises(SandboxCodecError) as excinfo:
        _dec_item({"o": "state", "ns": "", "key": "k", "v": 1}, _Reader(()))
    assert isinstance(excinfo.value.__cause__, WiringError)
    assert isinstance(excinfo.value, SandboxError)  # the documented contract still holds


# --- (9) the Send rebuild is a provable copy-on-Send no-op --------------------


def test_copy_on_send_rebuild_is_a_provable_no_op() -> None:
    """The parent rebuilds with the NORMAL ``Send`` constructor, inside the transform run context — so
    ``Send.__post_init__`` re-consults ADR 0104's copy-on-Send flag. Because the wire always carries a
    ``str``, ``snapshot_payload`` returns the identical object and the guard (``if snap is not
    self.message``) never rebinds: the choke point is honoured, not bypassed by an ``object.__new__``
    hack. Str-carriage is therefore a load-bearing invariant, not an optimisation."""
    blobs = [_BIG_A]
    reader = _Reader(blobs)
    with run_contexts(RunContext(snapshot_on_send=True), phase="transform"):
        item = _dec_item({"o": "send", "to": "OB_A", "m": {"$": 0}}, reader)
    assert isinstance(item, Send)
    assert item.message is blobs[0]  # identity: no snapshot copy was taken


# --- the header cap must not become a mode-dependent ceiling ------------------


def test_the_header_cap_is_the_frame_cap_and_nothing_tighter() -> None:
    """Regression for a fail-CLOSED cap sized by aesthetics rather than by traffic.

    ``_MAX_HEADER`` used to be 16 MiB, a quarter of the frame ceiling. Because the request header
    carries the whole ADR 0006 ``reference_view``, that silently capped reference tables at roughly
    700k entries: past it EVERY message on the inbound dead-lettered forever with "frame header too
    large" while ``mode=off`` served them fine, and there is no ``[sandbox]`` knob to raise it. The
    outer framing already refuses anything over :data:`MAX_FRAME` before a byte is parsed, so a
    tighter header bound bought the divergence and nothing else."""
    assert _MAX_HEADER == MAX_FRAME == sandbox._MAX_FRAME
    # A header well past the old 16 MiB cap now decodes.
    header, blobs = decode_frame(encode_frame({"v": 1, "t": "ready", "pad": "x" * 17_000_000}, ()))
    assert len(header["pad"]) == 17_000_000
    assert blobs == []


def test_a_large_reference_view_round_trips(monkeypatch: pytest.MonkeyPatch) -> None:
    """The functional half: a realistic 20k-entry crosswalk marshals and comes back intact — through
    the compact table form AND (forced here) through the general per-entry form, because both must
    produce identical results or ``mode=subprocess`` would resolve lookups differently."""
    table = {f"K{i:05d}": f"V{i:05d}" for i in range(20_000)}
    rc = RunContext(reference_view={"crosswalk": table})

    def _round_trip() -> Any:
        frame = encode_request(
            request_id="r:1",
            phase="router",
            name="r",
            payload=None,
            origin=(RAW, ContentType.HL7V2.value),
            run_context=rc,
        )
        assert len(frame) > 300_000  # the shape this has to survive
        return decode_request(frame).run_context.reference_view

    assert _round_trip() == {"crosswalk": table}
    # Force the general form by making the fast path's "short string" test fail for every entry.
    monkeypatch.setattr(codec, "_BLOB_MIN", 1)
    assert _round_trip() == {"crosswalk": table}


def _req_body(table: Any) -> bytes:
    """A hand-built ``req`` frame carrying one reference table — the frame type a lookup table rides."""
    return _body(
        {
            "v": 1,
            "t": "req",
            "id": "r:1",
            "phase": "transform",
            "name": NAME,
            "payload": {"k": "obj", "kind": "raw", "text": "x", "ct": "json"},
            "rc": {
                "reference_view": {"refs": [["codes", table]]},
                "snapshot_on_send": False,
            },
        }
    )


def test_a_forged_compact_table_is_rejected_on_the_request_frame() -> None:
    """The compact form carries its WHOLE type proof in the values, so the proof has to be exercised
    where a table actually rides: the ``req`` frame.

    This lived in the ``_HOSTILE`` response-frame table and passed for the wrong reason — a ``req``
    frame handed to ``decode_response`` is refused as an unexpected frame *type* long before any table
    is parsed, so the assertion never reached the code it was named after."""
    # The control: the same frame with a legal table decodes, so the rejections below are about the
    # value type and nothing else.
    good = decode_request(_req_body({"s": {"A": "1"}}))
    assert good.run_context.reference_view == {"codes": {"A": "1"}}
    for forged in ({"A": 1}, {"A": None}, {"A": ["x"]}, {"A": {"b": "AA=="}}):
        with pytest.raises(SandboxCodecError, match="must be a string"):
            decode_request(_req_body({"s": forged}))


def test_the_compact_table_form_is_only_an_encoding() -> None:
    """The fast path is an encoding choice, not a grammar change: the general form decodes to exactly
    the same table, and the compact form still proves every value is a ``str`` (a forged
    ``{"s": {"A": 1}}`` is rejected — see
    ``test_a_forged_compact_table_is_rejected_on_the_request_frame``)."""
    blobs = _Blobs()
    compact = codec._enc_table("t", {"A": "1", "B": "2"}, blobs)
    assert compact == {"s": {"A": "1", "B": "2"}}
    assert codec._dec_table(compact, "t", _Reader(blobs.items)) == {"A": "1", "B": "2"}
    # A mixed-type table falls back to the general per-entry form, unchanged.
    blobs = _Blobs()
    general = codec._enc_table("t", {"A": "1", "B": 2}, blobs)
    assert general == {"a": [["A", "1"], ["B", 2]]}
    assert codec._dec_table(general, "t", _Reader(blobs.items)) == {"A": "1", "B": 2}


def test_a_realistic_crosswalk_actually_takes_the_compact_form() -> None:
    """The throughput half of the same fast path, pinned structurally rather than by a wall clock.

    Describing a `str -> short str` crosswalk entry by entry costs a Python round trip per entry in
    BOTH directions, which made the `reference_view` the dominant per-message cost of
    ``mode=subprocess`` — measurably worse than the pickle it replaced. A refactor can silently route
    around the fast path without changing a single decoded value, so assert the *shape* on the wire: a
    realistic crosswalk must ride as one JSON object, not as a per-entry array."""
    table = {f"K{i:05d}": f"V{i:05d}" for i in range(2_000)}
    frame = encode_request(
        request_id="r:1",
        phase="router",
        name="r",
        payload=None,
        origin=(RAW, ContentType.HL7V2.value),
        run_context=RunContext(reference_view={"crosswalk": table}),
    )
    assert b'"s":{"K00000":"V00000"' in frame  # the compact form
    assert b'["K00000","V00000"]' not in frame  # not the per-entry form
    assert decode_request(frame).run_context.reference_view == {"crosswalk": table}


@pytest.mark.parametrize(
    ("case", "table"),
    [
        ("lone surrogate value", {"A": "lone\udcff"}),
        ("lone surrogate key", {"k\udcff": "v"}),
        ("NUL and C0 controls", {"a\x00b": "c\x01d\x7f"}),
        ("astral plane", {"\U0001f600": "\U0001f9ea"}),
        ("empty table", {}),
        ("empty strings", {"": ""}),
        ("JSON metacharacters", {'a"\\b': 'c"\\d'}),
    ],
)
def test_the_compact_form_survives_exotic_but_legal_text(case: str, table: dict[str, str]) -> None:
    """The compact form pushes keys AND values through JSON escaping instead of the segment path, so
    every text shape a real crosswalk can hold has to survive it — a mangled key is a SILENT lookup
    miss under ``mode=subprocess`` (fail-open) rather than a dead-letter."""
    blobs = _Blobs()
    node = codec._enc_table("t", table, blobs)
    assert "s" in node, case  # every case above is str -> short str, so the fast path applies
    assert codec._dec_table(node, "t", _Reader(blobs.items)) == table


# --- (10) the engine's code-set tables travel in the boot frame ---------------


def _code_sets(
    values: dict[str, Any], *, policy: UnmappedPolicy | None = None
) -> dict[str, CodeSet]:
    return {"cs": CodeSet("cs", values, policy)}


def _boot_round_trip(code_sets: object) -> Any:
    return decode_boot(
        encode_boot(
            config_dir="cfg",
            forbidden=("socket",),
            cpu_seconds=2.0,
            mem_mb=512,
            code_sets=code_sets,
        )
    ).code_sets


def test_code_sets_round_trip_through_the_boot_frame() -> None:
    """The ENGINE's tables are what the child serves, so they must survive the boot frame exactly —
    values, and the declared unmapped policy that decides what a MISS returns."""
    rebuilt = _boot_round_trip(_code_sets({"A": "1", "B": "2"}))
    assert rebuilt is not None
    assert dict(rebuilt["cs"]) == {"A": "1", "B": "2"}
    assert rebuilt["cs"].name == "cs"
    assert rebuilt["cs"].policy == UnmappedPolicy()

    flagged = _boot_round_trip(
        _code_sets({"A": "1"}, policy=UnmappedPolicy(kind=UnmappedKind.DEFAULT, default_value="D"))
    )
    assert flagged is not None
    assert flagged["cs"].translate("MISS") == "D"  # the policy, not just the table, crossed

    # A non-str value (a .toml code set) falls back to the general form and keeps its type.
    typed = _boot_round_trip(_code_sets({"A": 1, "B": dt.date(2026, 1, 1)}))
    assert typed is not None
    assert dict(typed["cs"]) == {"A": 1, "B": dt.date(2026, 1, 1)}

    # "no tables published" and "the engine has none" are DIFFERENT statements: the first leaves the
    # child on its own bootstrap load, the second tells it there are none.
    assert _boot_round_trip(None) is None
    assert _boot_round_trip({}) == {}


def test_a_deeply_nested_value_is_not_a_mode_dependent_dead_letter() -> None:
    """``mode=off`` accepts whatever ``SetState``'s own ``json.dumps`` validator accepts, so a tight
    codec depth cap was a divergence in the DELIVERING direction: a value nested 80 deep set state
    in-process and dead-lettered under ``mode=subprocess``. The cap now clears anything a real
    transform builds — while still bounding the walk, fail-closed, well short of ``RecursionError``."""
    value: Any = "leaf"
    for _ in range(200):
        value = [value]
    op = SetState("ns", "deep", value)  # constructs at mode=off, so it must cross the wire too
    rebuilt = _rt_transform(op)
    assert isinstance(rebuilt, SetState)
    assert rebuilt.value == value

    runaway: Any = "leaf"
    for _ in range(_MAX_DEPTH + 2):
        runaway = [runaway]
    with pytest.raises(SandboxCodecError, match="nesting exceeds"):
        enc_value(runaway, _Blobs())


def test_a_forged_code_set_policy_fails_closed() -> None:
    """The boot frame is decoded under the same closed contract as everything else."""
    blobs = _Blobs()
    node = enc_code_sets(_code_sets({"A": "1"}), blobs)
    node["sets"][0][1] = "not-a-kind"
    with pytest.raises(SandboxCodecError, match="invalid unmapped policy"):
        dec_code_sets(node, _Reader(blobs.items))


# --- framing round-trip ------------------------------------------------------


def test_encode_frame_round_trips_header_and_segments() -> None:
    header, blobs = decode_frame(encode_frame({"v": 1, "t": "ready"}, ("one", "two")))
    assert header == {"v": 1, "t": "ready"}
    assert blobs == ["one", "two"]


def test_encode_ok_rejects_an_undescribable_result() -> None:
    """Fail-closed at describe time: an exotic ``Send`` payload cannot silently become something else."""
    with pytest.raises(SandboxCodecError):
        encode_ok(request_id="r:1", phase="transform", name=NAME, result=Send("OB_A", object()))  # type: ignore[arg-type]
    with pytest.raises(SandboxCodecError):
        encode_ok(request_id="r:1", phase="accepts", name=NAME, result="truthy")
    with pytest.raises(SandboxCodecError):
        encode_ok(request_id="r:1", phase="router", name=NAME, result=[1, 2])
