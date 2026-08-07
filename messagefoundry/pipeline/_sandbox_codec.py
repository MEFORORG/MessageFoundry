# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""MFW2 — the non-executing IPC codec for the sandbox pipe (ADR 0087, BACKLOG #197).

**Why a codec at all.** The sandbox exists to put an OS address-space boundary between the engine
(the DEK, the tamper-evident audit chain, every live socket) and admin-authored Router/Handler code.
A codec that can *name a type* while decoding — ``pickle`` is the canonical one — hands that boundary
straight back: a Handler returning an object with a custom ``__reduce__`` executes arbitrary code in
whichever process loads the frame. So **both legs are untrusted by contract**:

* **child → parent** is untrusted because the child runs exactly the code the sandbox exists to
  distrust, and because a *grandchild* the Handler spawns inherits fd 1 (the response pipe) and can
  stage a frame while the worker is alive. (Killing the worker now reaps its whole process tree, so
  such a grandchild no longer outlives the kill — BACKLOG #342 — but that reap is best-effort process
  hygiene, not the trust control this codec provides.)
* **parent → child** is untrusted because the same reasoning read in the other direction is the only
  reason the first bullet is a boundary at all; a single schema, one review, one fuzz target.

Decoding here reduces to :func:`json.loads` plus :meth:`bytes.decode` over a **closed tag set**, then
a literal ``if``/``elif`` match that calls the ordinary constructors of a fixed handful of types.
Nothing in the decode path can name a type, import a module, or reach ``__reduce__``.

**Frame shape.** :func:`sandbox._write_frame` owns the outer ``>I length || body`` framing and the
64 MiB :data:`MAX_FRAME` ceiling (defined here, so the two layers cannot drift apart). This module owns
the *body*, which is **segmented** so a big message payload never round-trips through JSON string
escaping::

    >I header_len || header_json || ( >I blob_len || blob_bytes ) *

``header_json`` is the whole envelope; any long ``str`` slot is replaced by ``{"$": i}`` and carried
verbatim in blob ``i``. Blob references are **strictly sequential and exactly-once** — the decoder
holds a cursor, ``{"$": i}`` is legal only when ``i`` is the cursor, and decode succeeds only if every
blob was consumed. That makes the one dangerous failure mode of an indirection table (an off-by-one
silently cross-wiring one ``Send``'s body onto another ``Send``'s destination) *structurally*
unreachable rather than merely untested. The inline-vs-blob threshold is encoder-side **policy**: every
``str`` slot accepts either form, so the two ends can never disagree about it.

**Non-goal (ADR 0028).** A binary body is ALREADY an ordinary ASCII ``str`` in ``RawMessage.raw`` (the
self-describing ``mfb64:v1:<base64>`` marker). It rides this codec as a plain ``str`` slot and MUST NOT
be re-wrapped through the ``{"b": ...}`` bytes tag — double-encoding would break
:attr:`RawMessage.raw_bytes` at the far end.

**Fail-closed.** Every rejection raises :class:`SandboxCodecError`, a :class:`SandboxError` subclass,
so the caller routes it to ``ERROR``/dead-letter **post-ACK** exactly like any other isolation fault —
never a NAK, never an accept-and-drop, never a crashed connection.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import math
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from messagefoundry.config.code_sets import CodeSet, UnmappedKind, UnmappedPolicy
from messagefoundry.config.models import ContentType
from messagefoundry.config.response import CapturedResponse
from messagefoundry.config.run_context import RunContext
from messagefoundry.config.wiring import (
    Send,
    SetMeta,
    SetState,
    WiringError,
    handler_result_items,
)
from messagefoundry.parsing.message import Message, RawMessage

__all__ = [
    "MAX_FRAME",
    "SandboxError",
    "SandboxCodecError",
    "Ignored",
    "Request",
    "Response",
    "build_payload",
    "decode_boot",
    "decode_boot_reply",
    "decode_frame",
    "decode_request",
    "decode_response",
    "encode_bootfail",
    "encode_boot",
    "encode_fail",
    "encode_frame",
    "encode_ok",
    "encode_ready",
    "encode_request",
    "enc_value",
    "dec_value",
]


class SandboxError(RuntimeError):
    """A sandboxed Router/Handler was denied, timed out, crashed, or could not be marshalled.

    Raised only on the ``subprocess`` path (``off`` never raises this). The caller treats it exactly
    like any other post-ACK router/transform failure: ``ERROR``/dead-letter, no NAK.

    Defined **here**, not in :mod:`messagefoundry.pipeline.sandbox`, only because
    :class:`SandboxCodecError` must subclass it and the codec is the lower layer of the pair; the
    public name stays ``messagefoundry.pipeline.sandbox.SandboxError`` (re-exported there)."""


class SandboxCodecError(SandboxError):
    """A sandbox IPC frame was rejected: malformed, over a cap, or outside the closed value grammar.

    A :class:`SandboxError` subclass so ``route_only``/``transform_one``'s documented "raises
    SandboxError" contract keeps meaning what it says for every rejection."""


# --- caps --------------------------------------------------------------------

_LEN: Final = struct.Struct(">I")
#: The one wire ceiling, imported by :mod:`messagefoundry.pipeline.sandbox` as its ``_MAX_FRAME`` so the
#: outer framing and the body decoder cannot drift apart.
MAX_FRAME: Final = 64 * 1024 * 1024
#: Deliberately the SAME number, not a tighter one. A tighter header cap is fail-CLOSED against traffic
#: it has no business judging: a request header carries the whole ``reference_view`` (an ADR 0006
#: snapshot), so a 16 MiB header cap silently became a ~700k-entry ceiling on reference tables —
#: every message on a bigger graph dead-lettered forever, where ``mode=off`` served them fine. Since
#: :func:`sandbox._read_frame_bytes` already refuses a frame over :data:`MAX_FRAME` before a byte is
#: parsed, a separate lower bound buys no protection; it only buys a mode-dependent outage.
_MAX_HEADER: Final = MAX_FRAME
_MAX_BLOBS: Final = 65536
#: Own nesting counter for the value grammar, independent of (and below) ``RecursionError``. Each level
#: is TWO JSON levels (``{"l":[…]}``), so this must stay well under half the recursion limit — but it
#: must also clear anything ``mode=off`` accepts, since ``SetState``'s own ``json.dumps`` validator
#: tolerates deep values and a tighter cap here would be a mode-dependent dead-letter.
_MAX_DEPTH: Final = 256
#: Encoder-side POLICY only — a ``str`` at least this long travels out of band. Every ``str`` slot
#: decodes an inline string or a reference interchangeably, so the two ends cannot disagree.
_BLOB_MIN: Final = 4096

_WIRE_VERSION: Final = 1


# --- framing -----------------------------------------------------------------


def _reject_nonfinite(token: str) -> Any:
    """``json.loads(parse_constant=...)`` hook: a bare ``NaN``/``Infinity`` literal never rides the wire
    (non-finite floats travel as the explicit ``{"f": ...}`` tag instead)."""
    raise SandboxCodecError(f"non-finite JSON literal {token!r} is not allowed in a sandbox frame")


def encode_frame(header: Mapping[str, Any], blobs: Sequence[str]) -> bytes:
    """Serialize one frame body: the JSON header plus its out-of-band ``str`` segments."""
    try:
        text = json.dumps(header, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError) as exc:
        raise SandboxCodecError(f"sandbox frame header is not encodable: {exc}") from exc
    head = text.encode("utf-8", "surrogatepass")
    if len(head) > _MAX_HEADER:
        raise SandboxCodecError(f"sandbox frame header too large: {len(head)} bytes")
    if len(blobs) > _MAX_BLOBS:
        raise SandboxCodecError(f"sandbox frame carries {len(blobs)} segments (> {_MAX_BLOBS})")
    parts: list[bytes] = [_LEN.pack(len(head)), head]
    for blob in blobs:
        body = blob.encode("utf-8", "surrogatepass")
        try:
            parts.append(_LEN.pack(len(body)))
        except struct.error as exc:  # a single segment past 4 GiB
            raise SandboxCodecError(f"sandbox frame segment too large: {exc}") from exc
        parts.append(body)
    return b"".join(parts)


def decode_frame(body: bytes) -> tuple[dict[str, Any], list[str]]:
    """Parse one frame body into ``(header, blobs)``. Never constructs anything but JSON primitives."""
    try:
        if len(body) < _LEN.size:
            raise SandboxCodecError("truncated sandbox frame (no header length)")
        (head_len,) = _LEN.unpack_from(body, 0)
        if head_len > _MAX_HEADER:
            raise SandboxCodecError(f"sandbox frame header too large: {head_len} bytes")
        end = _LEN.size + head_len
        if len(body) < end:
            raise SandboxCodecError("truncated sandbox frame header")
        header = json.loads(
            body[_LEN.size : end].decode("utf-8", "surrogatepass"),
            parse_constant=_reject_nonfinite,
        )
        if not isinstance(header, dict):
            raise SandboxCodecError("sandbox frame header must be a JSON object")
        blobs: list[str] = []
        pos, total = end, len(body)
        while pos < total:
            if pos + _LEN.size > total:
                raise SandboxCodecError("truncated sandbox frame segment length")
            (blob_len,) = _LEN.unpack_from(body, pos)
            pos += _LEN.size
            if pos + blob_len > total:
                raise SandboxCodecError("truncated sandbox frame segment")
            if len(blobs) >= _MAX_BLOBS:
                raise SandboxCodecError(f"sandbox frame carries > {_MAX_BLOBS} segments")
            blobs.append(str(memoryview(body)[pos : pos + blob_len], "utf-8", "surrogatepass"))
            pos += blob_len
    except (ValueError, UnicodeDecodeError, RecursionError, struct.error) as exc:
        # RecursionError is NOT a ValueError, and it is exactly what a depth-100000 header raises;
        # without it the rejection would escape the fail-closed SandboxError contract.
        raise SandboxCodecError(f"malformed sandbox frame: {type(exc).__name__}: {exc}") from exc
    return header, blobs


class _Blobs:
    """Encoder-side segment accumulator. ``ref()`` is the ONLY thing that appends, and it appends at
    the same instant it emits the reference — so segment order IS schema walk order."""

    __slots__ = ("items",)

    def __init__(self) -> None:
        self.items: list[str] = []

    def ref(self, text: object) -> Any:
        if not isinstance(text, str):
            raise SandboxCodecError(f"expected a str slot, got {type(text).__name__}")
        if len(text) < _BLOB_MIN:
            return text
        self.items.append(text)
        return {"$": len(self.items) - 1}


class _Reader:
    """Decoder-side segment cursor enforcing the **strictly sequential, exactly-once** discipline.

    Out-of-range, duplicated, skipped and trailing-unconsumed segments are all rejected *by
    construction*: a reference is legal only at the cursor, and :meth:`finish` demands the cursor
    reached the end. That is what makes a cross-wired PHI body (one ``Send``'s payload landing on
    another ``Send``'s destination) unreachable rather than merely untested."""

    __slots__ = ("blobs", "cursor")

    def __init__(self, blobs: Sequence[str]) -> None:
        self.blobs = blobs
        self.cursor = 0

    def text(self, node: Any) -> str:
        if isinstance(node, str):
            return node
        if isinstance(node, dict) and len(node) == 1 and "$" in node:
            index = node["$"]
            if not isinstance(index, int) or isinstance(index, bool):
                raise SandboxCodecError("sandbox segment reference must be an integer")
            if index != self.cursor or index >= len(self.blobs):
                raise SandboxCodecError(
                    f"sandbox segment reference {index} is out of sequence (expected {self.cursor})"
                )
            self.cursor += 1
            return self.blobs[index]
        raise SandboxCodecError("sandbox frame slot is neither a string nor a segment reference")

    def finish(self) -> None:
        if self.cursor != len(self.blobs):
            raise SandboxCodecError(
                f"sandbox frame carries {len(self.blobs)} segments but consumed {self.cursor}"
            )


# --- the closed value grammar ------------------------------------------------


def enc_value(value: object, blobs: _Blobs, _depth: int = 0) -> Any:
    """Describe one genuinely-``Any`` value (a reference/code-set entry, a ``SetState`` value).

    Containers are **wrapped** in a single-key tag object, so a bare JSON array is illegal at value
    level and a legitimate list can never be mistaken for a tag — an unambiguous grammar with zero
    escaping. ``blobs`` is required: an "inline everything" variant would be a second encoding of the
    same value that no caller wants and nobody fuzzes."""
    if _depth > _MAX_DEPTH:
        raise SandboxCodecError(f"sandbox value nesting exceeds {_MAX_DEPTH}")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        # A tag, not a narrowing: SetState.__post_init__ validates with json.dumps' DEFAULT
        # allow_nan=True, so SetState(ns, k, float("nan")) constructs today. Refusing it here would
        # turn a working Handler into a new dead-letter purely on upgrade.
        if math.isnan(value):
            return {"f": "nan"}
        if math.isinf(value):
            return {"f": "inf" if value > 0 else "-inf"}
        return value
    if isinstance(value, str):
        return blobs.ref(value)
    if isinstance(value, bytes | bytearray):
        return {"b": base64.b64encode(bytes(value)).decode("ascii")}
    # datetime BEFORE date — datetime is a date subclass, and tomllib produces all three natively, so a
    # .toml code set with a date value is a legitimate shape plain JSON refuses.
    if isinstance(value, _dt.datetime):
        return {"D": value.isoformat()}
    if isinstance(value, _dt.date):
        return {"E": value.isoformat()}
    if isinstance(value, _dt.time):
        return {"T": value.isoformat()}
    if isinstance(value, list):
        return {"l": [enc_value(item, blobs, _depth + 1) for item in value]}
    if isinstance(value, tuple):
        # Preserved as its own tag: a JSON-array shortcut would silently flatten a tuple to a list,
        # a value-shape change mode=off does not make.
        return {"p": [enc_value(item, blobs, _depth + 1) for item in value]}
    if isinstance(value, Mapping):
        return {
            "d": [
                [enc_value(k, blobs, _depth + 1), enc_value(v, blobs, _depth + 1)]
                for k, v in value.items()
            ]
        }
    raise SandboxCodecError(
        f"value of type {type(value).__name__} cannot cross the sandbox boundary"
    )


_FLOAT_TAGS: Final[dict[str, float]] = {"nan": math.nan, "inf": math.inf, "-inf": -math.inf}


def dec_value(node: Any, reader: _Reader, _depth: int = 0) -> Any:
    """Rebuild one value from the closed grammar. A closed literal match — no getattr, no import."""
    if _depth > _MAX_DEPTH:
        raise SandboxCodecError(f"sandbox value nesting exceeds {_MAX_DEPTH}")
    if node is None or isinstance(node, bool | int | float | str):
        return node
    if isinstance(node, list):
        raise SandboxCodecError("a bare array is not a sandbox value (containers are tagged)")
    if not isinstance(node, dict) or len(node) != 1:
        raise SandboxCodecError("a sandbox value object must carry exactly one tag")
    ((tag, arg),) = node.items()
    if tag == "$":
        return reader.text(node)
    if tag == "l":
        return [dec_value(item, reader, _depth + 1) for item in _tag_list(tag, arg)]
    if tag == "p":
        return tuple(dec_value(item, reader, _depth + 1) for item in _tag_list(tag, arg))
    if tag == "d":
        out: dict[Any, Any] = {}
        for pair in _tag_list(tag, arg):
            if not isinstance(pair, list) or len(pair) != 2:
                raise SandboxCodecError("a sandbox dict entry must be a [key, value] pair")
            key = dec_value(pair[0], reader, _depth + 1)
            value = dec_value(pair[1], reader, _depth + 1)
            try:
                out[key] = value
            except (
                TypeError
            ) as exc:  # an unhashable decoded key must not escape as a bare TypeError
                raise SandboxCodecError(f"sandbox dict key is unhashable: {exc}") from exc
        return out
    if tag == "b":
        if not isinstance(arg, str):
            raise SandboxCodecError("sandbox bytes tag must carry a base64 string")
        try:
            return base64.b64decode(arg, validate=True)
        except (ValueError, TypeError) as exc:
            raise SandboxCodecError(f"sandbox bytes tag is not valid base64: {exc}") from exc
    if tag == "f":
        if not isinstance(arg, str) or arg not in _FLOAT_TAGS:
            raise SandboxCodecError(f"unknown sandbox float tag {arg!r}")
        return _FLOAT_TAGS[arg]
    if tag in ("D", "E", "T"):
        if not isinstance(arg, str):
            raise SandboxCodecError(f"sandbox {tag!r} tag must carry an ISO-8601 string")
        try:
            if tag == "D":
                return _dt.datetime.fromisoformat(arg)
            if tag == "E":
                return _dt.date.fromisoformat(arg)
            return _dt.time.fromisoformat(arg)
        except ValueError as exc:
            raise SandboxCodecError(f"sandbox {tag!r} tag is not ISO-8601: {exc}") from exc
    raise SandboxCodecError(f"unknown sandbox value tag {tag!r}")


def _tag_list(tag: str, arg: Any) -> list[Any]:
    if not isinstance(arg, list):
        raise SandboxCodecError(f"sandbox {tag!r} tag must carry an array")
    return arg


# --- small typed slot helpers -------------------------------------------------


def _req_str(node: Any, what: str) -> str:
    if not isinstance(node, str):
        raise SandboxCodecError(f"sandbox {what} must be a string")
    return node


def _opt_str(node: Any, what: str) -> str | None:
    if node is None:
        return None
    return _req_str(node, what)


def _req_int(node: Any, what: str) -> int:
    if not isinstance(node, int) or isinstance(node, bool):
        raise SandboxCodecError(f"sandbox {what} must be an integer")
    return node


def _req_float(node: Any, what: str) -> float:
    if isinstance(node, bool) or not isinstance(node, int | float):
        raise SandboxCodecError(f"sandbox {what} must be a number")
    return float(node)


def _opt_float(node: Any, what: str) -> float | None:
    if node is None:
        return None
    return _req_float(node, what)


def _req_bool(node: Any, what: str) -> bool:
    if not isinstance(node, bool):
        raise SandboxCodecError(f"sandbox {what} must be a boolean")
    return node


def _req_list(node: Any, what: str) -> list[Any]:
    if not isinstance(node, list):
        raise SandboxCodecError(f"sandbox {what} must be an array")
    return node


def _req_obj(node: Any, what: str) -> dict[str, Any]:
    if not isinstance(node, dict):
        raise SandboxCodecError(f"sandbox {what} must be an object")
    return node


# --- the payload (parent -> child) --------------------------------------------


def build_payload(raw: str | bytes, content_type: str) -> Message | RawMessage:
    """The object a Router/Handler receives (ADR 0004): a mutable HL7 :class:`Message` for ``hl7v2``,
    a verbatim :class:`RawMessage` otherwise.

    The single definition of that construction, shared by :func:`dryrun._payload` and the sandbox
    child, so the child rebuilds the **same** object the parent would have built rather than a
    look-alike that could drift. It lives here (not in ``dryrun``) because the child must not import
    ``dryrun`` — that would pull ``messagefoundry.store`` into the sandboxed process, which is exactly
    what the forbidden-import guard denies (and what "the child loads the graph, not the store"
    means)."""
    if content_type == ContentType.HL7V2.value:
        return Message.parse(raw)
    return RawMessage(raw if isinstance(raw, str) else raw.decode("utf-8"), content_type)


def enc_payload(
    payload: object, origin: tuple[str | bytes, str] | None, blobs: _Blobs
) -> dict[str, Any]:
    """Describe the Router/Handler input.

    ``origin`` is the ``(raw, content_type)`` the PARENT derived the payload from — passed only when
    the caller's own ``payload`` argument was ``None`` (all three live engine call sites), so the child
    can call the identical :func:`build_payload` and get a byte-faithful object. Otherwise the
    caller's actual object is described (``dryrun.route_message(payload=shared)`` is public API)."""
    if origin is not None:
        raw, content_type = origin
        if isinstance(raw, str):
            return {"k": "origin", "enc": "s", "raw": blobs.ref(raw), "ct": content_type}
        return {
            "k": "origin",
            "enc": "b",
            "raw": blobs.ref(base64.b64encode(raw).decode("ascii")),
            "ct": content_type,
        }
    if isinstance(payload, Message):
        return {"k": "obj", "kind": "hl7", "text": blobs.ref(payload.encode())}
    if isinstance(payload, RawMessage):
        return {
            "k": "obj",
            "kind": "raw",
            "text": blobs.ref(payload.raw),
            "ct": payload.content_type,
        }
    raise SandboxCodecError(
        f"a sandbox payload must be a Message or RawMessage, got {type(payload).__name__}"
    )


def dec_payload(node: Any, reader: _Reader) -> Message | RawMessage:
    """Rebuild the Router/Handler input in the child (see :func:`enc_payload` for the two forms)."""
    obj = _req_obj(node, "payload")
    kind = obj.get("k")
    if kind == "origin":
        text = reader.text(obj.get("raw"))
        content_type = _req_str(obj.get("ct"), "payload content type")
        enc = obj.get("enc")
        if enc == "s":
            return build_payload(text, content_type)
        if enc == "b":
            try:
                return build_payload(base64.b64decode(text, validate=True), content_type)
            except (ValueError, TypeError) as exc:
                raise SandboxCodecError(f"sandbox payload is not valid base64: {exc}") from exc
        raise SandboxCodecError(f"unknown sandbox payload encoding {enc!r}")
    if kind == "obj":
        text = reader.text(obj.get("text"))
        shape = obj.get("kind")
        if shape == "hl7":
            return Message.parse(text)
        if shape == "raw":
            return RawMessage(text, _req_str(obj.get("ct"), "payload content type"))
        raise SandboxCodecError(f"unknown sandbox payload shape {shape!r}")
    raise SandboxCodecError(f"unknown sandbox payload kind {kind!r}")


# --- the run context (parent -> child) ----------------------------------------


def enc_run_context(rc: RunContext, blobs: _Blobs) -> dict[str, Any]:
    """Describe the run-scoped views for the child.

    Snapshotting is **by construction** here: the engine's live ``MappingProxyType`` windows onto the
    store caches are walked into plain wire rows at this instant, which is exactly the read-only
    content an in-process run would have seen (and re-run stability makes a point-in-time copy the
    contract anyway). There is deliberately no second marshalling layer.

    ``code_sets`` is **absent by design** — the engine's tables ride the one-per-spawn ``boot`` frame
    instead (see :func:`enc_code_sets`). Re-sending them per dispatch was ~430 KB and ~4.6 ms of pure
    marshalling per message on a realistic crosswalk."""
    return {
        "reference_view": _enc_reference_view(rc.reference_view, blobs),
        "state_view": _enc_state_view(rc.state_view, blobs),
        "response_view": _enc_response_view(rc.response_view, blobs),
        "active_environment": rc.active_environment,
        "ingest_time": rc.ingest_time,
        "message_id": rc.message_id,
        "snapshot_on_send": bool(rc.snapshot_on_send),
    }


def dec_run_context(node: Any, reader: _Reader) -> RunContext:
    """Rebuild the child-side :class:`RunContext` (``code_sets`` stays ``None`` — the worker
    substitutes its OWN registry's tables)."""
    obj = _req_obj(node, "run context")
    # The three view slots are read in the SAME order enc_run_context wrote them: segment order is
    # schema walk order, so this ordering is load-bearing, not stylistic.
    reference_view = _dec_reference_view(obj.get("reference_view"), reader)
    state_view = _dec_state_view(obj.get("state_view"), reader)
    response_view = _dec_response_view(obj.get("response_view"), reader)
    return RunContext(
        code_sets=None,
        reference_view=reference_view,
        state_view=state_view,
        response_view=response_view,
        active_environment=_opt_str(obj.get("active_environment"), "active_environment"),
        ingest_time=_opt_float(obj.get("ingest_time"), "ingest_time"),
        message_id=_opt_str(obj.get("message_id"), "message_id"),
        snapshot_on_send=_req_bool(obj.get("snapshot_on_send"), "snapshot_on_send"),
    )


def _enc_table(what: str, table: Mapping[Any, Any], blobs: _Blobs) -> Any:
    """One lookup table (an ADR 0006 reference set, a code set), with a fast path for the shape that
    dominates real traffic.

    A crosswalk is overwhelmingly ``str -> short str``. Describing those entry by entry through
    :func:`enc_value` costs a per-entry Python round trip in BOTH directions, which made the
    ``reference_view`` the single largest per-message cost of ``mode=subprocess`` (measurably worse than
    the pickle it replaced). When every entry fits that shape the table travels as ONE plain JSON
    object and the C encoder/decoder does the walk. This is an ENCODING choice, not a grammar change:
    the decoder still proves every value is a ``str`` before it is used, and either form decodes, so the
    two ends can never disagree about which one to use."""
    if all(
        isinstance(k, str) and isinstance(v, str) and len(v) < _BLOB_MIN for k, v in table.items()
    ):
        return {"s": dict(table)}
    return {"a": [[_req_str(k, f"{what} key"), enc_value(v, blobs)] for k, v in table.items()]}


def _dec_table(node: Any, what: str, reader: _Reader) -> dict[str, Any]:
    """Rebuild one lookup table from either form (see :func:`_enc_table`)."""
    obj = _req_obj(node, what)
    if len(obj) != 1:
        # Exactly one form, like every other tagged node here — a frame carrying both would decode
        # under one of them and leave the other silently unread.
        raise SandboxCodecError(f"a {what} must carry exactly one table form")
    flat = obj.get("s")
    if flat is not None:
        entries = _req_obj(flat, what)
        # JSON object keys are strings by construction; the VALUES are what a forged frame could vary,
        # so they carry the whole type proof for this form.
        if not all(type(value) is str for value in entries.values()):
            raise SandboxCodecError(f"{what}: every compact-table value must be a string")
        return entries
    out: dict[str, Any] = {}
    for entry in _req_list(obj.get("a"), f"{what} entries"):
        kv = _req_list(entry, f"{what} entry")
        if len(kv) != 2:
            raise SandboxCodecError(f"a {what} entry must be [key, value]")
        out[_req_str(kv[0], f"{what} key")] = dec_value(kv[1], reader)
    return out


def _enc_reference_view(view: object, blobs: _Blobs) -> Any:
    if view is None:
        return None
    if not isinstance(view, Mapping):
        raise SandboxCodecError(f"reference_view must be a mapping, got {type(view).__name__}")
    rows: list[Any] = []
    for name, table in view.items():
        if not isinstance(name, str):
            raise SandboxCodecError("reference_view names must be strings")
        if not isinstance(table, Mapping):
            raise SandboxCodecError(f"reference set {name!r} must be a mapping")
        rows.append([name, _enc_table("reference set", table, blobs)])
    return {"refs": rows}


def _dec_reference_view(node: Any, reader: _Reader) -> dict[str, dict[str, Any]] | None:
    if node is None:
        return None
    rows = _req_list(_req_obj(node, "reference_view").get("refs"), "reference_view rows")
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        pair = _req_list(row, "reference_view row")
        if len(pair) != 2:
            raise SandboxCodecError("a reference_view row must be [name, entries]")
        name = _req_str(pair[0], "reference name")
        out[name] = _dec_table(pair[1], "reference set", reader)
    return out


def _enc_state_view(view: object, blobs: _Blobs) -> Any:
    if view is None:
        return None
    if not isinstance(view, Mapping):
        raise SandboxCodecError(f"state_view must be a mapping, got {type(view).__name__}")
    rows: list[Any] = []
    for key, value in view.items():
        if not (isinstance(key, tuple) and len(key) == 2 and all(isinstance(p, str) for p in key)):
            raise SandboxCodecError("state_view keys must be (namespace, key) string tuples")
        rows.append([key[0], key[1], enc_value(value, blobs)])
    return {"state": rows}


def _dec_state_view(node: Any, reader: _Reader) -> dict[tuple[str, str], Any] | None:
    if node is None:
        return None
    rows = _req_list(_req_obj(node, "state_view").get("state"), "state_view rows")
    out: dict[tuple[str, str], Any] = {}
    for row in rows:
        triple = _req_list(row, "state_view row")
        if len(triple) != 3:
            raise SandboxCodecError("a state_view row must be [namespace, key, value]")
        # The key is rebuilt as a TUPLE deliberately: state_get() does a dict lookup on
        # (namespace, key), so a list/joined key would turn every state_get into a SILENT miss
        # returning its default — fail-open, inverting a suppression/dedup Handler with no ERROR,
        # no dead-letter and no disposition anomaly.
        out[(_req_str(triple[0], "state namespace"), _req_str(triple[1], "state key"))] = dec_value(
            triple[2], reader
        )
    return out


def _enc_response_view(view: object, blobs: _Blobs) -> Any:
    if view is None:
        return None
    if not isinstance(view, Mapping):
        raise SandboxCodecError(f"response_view must be a mapping, got {type(view).__name__}")
    rows: list[Any] = []
    for dest, reply in view.items():
        if not isinstance(dest, str):
            raise SandboxCodecError("response_view destinations must be strings")
        if not isinstance(reply, CapturedResponse):
            raise SandboxCodecError(
                f"response_view[{dest!r}] must be a CapturedResponse, got {type(reply).__name__}"
            )
        rows.append(
            [
                dest,
                {
                    "message_id": reply.message_id,
                    "destination_name": reply.destination_name,
                    "response_seq": reply.response_seq,
                    "outcome": reply.outcome,
                    "detail": reply.detail,
                    "captured_at": reply.captured_at,
                    "body": None if reply.body is None else blobs.ref(reply.body),
                    "kind": reply.kind,
                    "ack_code": reply.ack_code,
                    "ack_phase": reply.ack_phase,
                    "headers": [[k, v] for k, v in reply.headers.items()],
                },
            ]
        )
    return {"replies": rows}


def _dec_response_view(node: Any, reader: _Reader) -> dict[str, CapturedResponse] | None:
    if node is None:
        return None
    rows = _req_list(_req_obj(node, "response_view").get("replies"), "response_view rows")
    out: dict[str, CapturedResponse] = {}
    for row in rows:
        pair = _req_list(row, "response_view row")
        if len(pair) != 2:
            raise SandboxCodecError("a response_view row must be [destination, reply]")
        rec = _req_obj(pair[1], "captured reply")
        headers: dict[str, str] = {}
        for entry in _req_list(rec.get("headers"), "captured reply headers"):
            kv = _req_list(entry, "captured reply header")
            if len(kv) != 2:
                raise SandboxCodecError("a captured reply header must be [name, value]")
            headers[_req_str(kv[0], "header name")] = _req_str(kv[1], "header value")
        body_node = rec.get("body")
        out[_req_str(pair[0], "response destination")] = CapturedResponse(
            message_id=_req_str(rec.get("message_id"), "reply message_id"),
            destination_name=_req_str(rec.get("destination_name"), "reply destination_name"),
            response_seq=_req_int(rec.get("response_seq"), "reply response_seq"),
            outcome=_req_str(rec.get("outcome"), "reply outcome"),
            detail=_opt_str(rec.get("detail"), "reply detail"),
            captured_at=_req_float(rec.get("captured_at"), "reply captured_at"),
            body=None if body_node is None else reader.text(body_node),
            kind=_req_str(rec.get("kind"), "reply kind"),
            ack_code=_opt_str(rec.get("ack_code"), "reply ack_code"),
            ack_phase=_opt_str(rec.get("ack_phase"), "reply ack_phase"),
            headers=headers,
        )
    return out


# --- the result (child -> parent) ---------------------------------------------


class Ignored:
    """A child result item :func:`dryrun._partition` would ignore, described rather than omitted.

    The encoder never silently drops an item it does not recognise — a silent omission would be an
    accept-and-drop (CLAUDE.md §12). Rebuilding the ignored slot keeps ``_partition`` the SOLE filter,
    so an unrecognised Handler return (a bare ``int``, a ``__reduce__`` gadget) still resolves to
    ``([], [], [])`` byte-identically to ``mode=off`` — as does an unrecognised ELEMENT inside a
    container the child materialised."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return "Ignored()"


def enc_result(phase: str, result: object, blobs: _Blobs) -> dict[str, Any]:
    """Describe a Router/Handler/predicate return value, phase-typed."""
    if phase == "accepts":
        # Strict: the caller coerces with bool() BEFORE this point (see _sandbox_worker), which is what
        # stops a truthy non-bool such as an re.Match from ever reaching the encoder.
        if not isinstance(result, bool):
            raise SandboxCodecError(f"accepts verdict must be a bool, got {type(result).__name__}")
        return {"r": "bool", "b": result}
    if phase == "router":
        # Materialise with _handler_names' OWN logic HERE, in the child: that is what makes a
        # generator Router (documented-supported, and unpicklable) work under mode=subprocess. The
        # parent's _handler_names then sees a list[str] and its list(...) is a no-op copy.
        try:
            if result is None:
                names: list[Any] = []
            elif isinstance(result, str):
                names = [result]
            else:
                names = list(result)  # type: ignore[call-overload]
        except TypeError as exc:
            raise SandboxCodecError(f"router result is not iterable: {exc}") from exc
        for item in names:
            if not isinstance(item, str):
                raise SandboxCodecError(
                    f"router returned a non-string handler name ({type(item).__name__})"
                )
        return {"r": "names", "n": names}
    if phase == "transform":
        # Materialise with _partition's OWN rule HERE, in the child — exactly what the router branch
        # above does with `_handler_names`' logic. `handler_result_items` (config.wiring) is that
        # single shared rule, so a tuple/set/generator fan-out delivers under mode=subprocess exactly
        # as it does under mode=off (BACKLOG #341); fixing only the parent's _partition would make the
        # disposition MODE-DEPENDENT, which is worse than the original accept-and-drop. A value the
        # rule does not recognise as a container stays a "one" item — the parent's unmodified
        # _partition still filters it out (and `dec_result` still returns the ITEM, not a 1-list).
        if result is None:
            return {"r": "items", "shape": "none"}
        items = handler_result_items(result)
        if items is not None:
            return {"r": "items", "shape": "list", "i": [_enc_item(it, blobs) for it in items]}
        return {"r": "items", "shape": "one", "i": _enc_item(result, blobs)}
    raise SandboxCodecError(f"unknown sandbox phase {phase!r}")


def dec_result(phase: str, node: Any, reader: _Reader) -> object:
    """Rebuild a Router/Handler/predicate return value in the parent."""
    obj = _req_obj(node, "result")
    tag = obj.get("r")
    if phase == "accepts":
        if tag != "bool":
            raise SandboxCodecError(f"expected an accepts verdict, got {tag!r}")
        return _req_bool(obj.get("b"), "accepts verdict")
    if phase == "router":
        if tag != "names":
            raise SandboxCodecError(f"expected router names, got {tag!r}")
        return [_req_str(item, "handler name") for item in _req_list(obj.get("n"), "router names")]
    if phase == "transform":
        if tag != "items":
            raise SandboxCodecError(f"expected transform items, got {tag!r}")
        shape = obj.get("shape")
        if shape == "none":
            return None
        if shape == "one":
            return _dec_item(obj.get("i"), reader)
        if shape == "list":
            return [_dec_item(it, reader) for it in _req_list(obj.get("i"), "transform items")]
        raise SandboxCodecError(f"unknown transform result shape {shape!r}")
    raise SandboxCodecError(f"unknown sandbox phase {phase!r}")


def _enc_item(item: object, blobs: _Blobs) -> dict[str, Any]:
    # isinstance, in _partition's order — NOT type identity, so a user SUBCLASS of Send still
    # delivers exactly as it does in-process.
    if isinstance(item, Send):
        # `.encode()` is called at DESCRIBE time — the same relative instant mode=off evaluates
        # dryrun.py's `send.message if isinstance(..., str) else send.message.encode()`, which is the
        # SOLE parent-side consumer of Send.message. Carrying text (never a live Message) is what makes
        # the parent's Send() rebuild a provable no-op for ADR 0104's copy-on-Send choke point.
        try:
            text = item.message if isinstance(item.message, str) else item.message.encode()
        except (AttributeError, TypeError, ValueError) as exc:
            raise SandboxCodecError(f"Send message is not encodable: {exc}") from exc
        if not isinstance(text, str):
            raise SandboxCodecError(
                f"Send message encoded to {type(text).__name__}, expected a str"
            )
        return {"o": "send", "to": _req_str(item.to, "Send destination"), "m": blobs.ref(text)}
    if isinstance(item, SetState):
        return {
            "o": "state",
            "ns": _req_str(item.namespace, "SetState namespace"),
            "key": _req_str(item.key, "SetState key"),
            "v": enc_value(item.value, blobs),
        }
    if isinstance(item, SetMeta):
        return {
            "o": "meta",
            "key": _req_str(item.key, "SetMeta key"),
            "v": blobs.ref(item.value),
        }
    return {"o": "other"}


def _dec_item(node: Any, reader: _Reader) -> object:
    obj = _req_obj(node, "transform item")
    tag = obj.get("o")
    # The NORMAL constructors over a CLOSED four-tag literal match — no getattr, no import, no
    # registry keyed by a wire string.
    try:
        if tag == "send":
            return Send(_req_str(obj.get("to"), "Send destination"), reader.text(obj.get("m")))
        if tag == "state":
            return SetState(
                _req_str(obj.get("ns"), "SetState namespace"),
                _req_str(obj.get("key"), "SetState key"),
                dec_value(obj.get("v"), reader),
            )
        if tag == "meta":
            return SetMeta(_req_str(obj.get("key"), "SetMeta key"), reader.text(obj.get("v")))
    except (WiringError, TypeError, ValueError) as exc:
        # The child ALREADY ran these constructors successfully (a Handler had to build the object to
        # return it), so a raise here cannot be an authoring fault — it is a codec bug or a forged
        # frame. Reporting it as a WiringError would put a FALSE diagnosis in the operator's last_error.
        raise SandboxCodecError(f"sandbox result item could not be rebuilt: {exc}") from exc
    if tag == "other":
        return Ignored()
    raise SandboxCodecError(f"unknown sandbox result item tag {tag!r}")


# --- the code-set tables (parent -> child, once per spawn) --------------------


def enc_code_sets(code_sets: object, blobs: _Blobs) -> Any:
    """Describe the ENGINE's live ``{name: CodeSet}`` tables for the worker's bootstrap frame.

    Sent **once per spawn**, not per dispatch: re-sending them with every message was ~430 KB and
    ~4.6 ms of pure marshalling on a realistic crosswalk. Sending them at all — rather than letting the
    child use its OWN ``load_config`` of the same directory — is what keeps ``mode=subprocess``
    byte-identical to ``mode=off``: after a transparent respawn (a wall-cap kill, a crash) the child
    re-reads ``codesets/`` from disk, so an operator who edits a crosswalk without a ``/config/reload``
    would otherwise have the child serve a value the engine never would. The engine's tables are the
    single source of truth on both sides.

    ``None`` means "the caller published no tables" and leaves the child on its own bootstrap load (the
    pre-existing behaviour for a session constructed without them); an empty mapping means "the engine
    has none", which is a different statement."""
    if code_sets is None:
        return None
    if not isinstance(code_sets, Mapping):
        raise SandboxCodecError(f"code_sets must be a mapping, got {type(code_sets).__name__}")
    rows: list[Any] = []
    for name, table in code_sets.items():
        if not isinstance(name, str):
            raise SandboxCodecError("code set names must be strings")
        if not isinstance(table, Mapping):
            raise SandboxCodecError(f"code set {name!r} must be a mapping")
        policy = getattr(table, "policy", None)
        declared = policy if isinstance(policy, UnmappedPolicy) else UnmappedPolicy()
        rows.append(
            [
                name,
                declared.kind.value,
                declared.default_value,
                _enc_table(f"code set {name!r}", table, blobs),
            ]
        )
    return {"sets": rows}


def dec_code_sets(node: Any, reader: _Reader) -> dict[str, CodeSet] | None:
    """Rebuild the engine's code-set tables in the child (the ordinary :class:`CodeSet` constructor)."""
    if node is None:
        return None
    rows = _req_list(_req_obj(node, "code_sets").get("sets"), "code_sets rows")
    out: dict[str, CodeSet] = {}
    for row in rows:
        quad = _req_list(row, "code_sets row")
        if len(quad) != 4:
            raise SandboxCodecError("a code_sets row must be [name, kind, default_value, entries]")
        name = _req_str(quad[0], "code set name")
        kind = _req_str(quad[1], "code set policy kind")
        default_value = _opt_str(quad[2], "code set policy default_value")
        entries = _dec_table(quad[3], f"code set {name!r}", reader)
        try:
            # UnmappedKind rejects an unknown kind and UnmappedPolicy.__post_init__ rejects an
            # inconsistent (kind, default_value) pair — both ValueError, both folded into the codec's
            # fail-closed contract rather than escaping as a config-layer diagnosis.
            policy = UnmappedPolicy(kind=UnmappedKind(kind), default_value=default_value)
        except ValueError as exc:
            raise SandboxCodecError(
                f"code set {name!r} carries an invalid unmapped policy: {exc}"
            ) from exc
        out[name] = CodeSet(name, entries, policy)
    return out


# --- envelopes ----------------------------------------------------------------


def _envelope(header: dict[str, Any], kind: str) -> dict[str, Any]:
    return {"v": _WIRE_VERSION, "t": kind, **header}


def _open(body: bytes, allowed: tuple[str, ...]) -> tuple[dict[str, Any], _Reader, str]:
    header, blobs = decode_frame(body)
    if header.get("v") != _WIRE_VERSION:
        raise SandboxCodecError(f"unsupported sandbox wire version {header.get('v')!r}")
    kind = header.get("t")
    if not isinstance(kind, str) or kind not in allowed:
        raise SandboxCodecError(f"unexpected sandbox frame type {kind!r}")
    return header, _Reader(blobs), kind


def encode_boot(
    *,
    config_dir: str,
    forbidden: Sequence[str],
    cpu_seconds: float,
    mem_mb: int | None,
    code_sets: object,
) -> bytes:
    """The one-per-spawn bootstrap frame.

    ``env`` is deliberately NOT marshalled: ``load_config()`` takes only a directory and the worker
    never read it — a dead field on the wire is a field nobody validates."""
    blobs = _Blobs()
    header = _envelope(
        {
            "config_dir": config_dir,
            "forbidden": list(forbidden),
            "cpu_seconds": float(cpu_seconds),
            "mem_mb": None if mem_mb is None else int(mem_mb),
            "code_sets": enc_code_sets(code_sets, blobs),
        },
        "boot",
    )
    return encode_frame(header, blobs.items)


@dataclass(frozen=True)
class Boot:
    """The decoded bootstrap frame (child side)."""

    config_dir: str
    forbidden: tuple[str, ...]
    cpu_seconds: float
    mem_mb: int | None
    code_sets: dict[str, CodeSet] | None


def decode_boot(body: bytes) -> Boot:
    header, reader, _ = _open(body, ("boot",))
    config_dir = _req_str(header.get("config_dir"), "config_dir")
    forbidden = tuple(
        _req_str(m, "forbidden module") for m in _req_list(header.get("forbidden"), "forbidden")
    )
    cpu_seconds = _req_float(header.get("cpu_seconds"), "cpu_seconds")
    mem_mb = None if header.get("mem_mb") is None else _req_int(header.get("mem_mb"), "mem_mb")
    code_sets = dec_code_sets(header.get("code_sets"), reader)
    reader.finish()
    return Boot(
        config_dir=config_dir,
        forbidden=forbidden,
        cpu_seconds=cpu_seconds,
        mem_mb=mem_mb,
        code_sets=code_sets,
    )


def encode_ready() -> bytes:
    return encode_frame(_envelope({}, "ready"), ())


def encode_bootfail(error: str) -> bytes:
    blobs = _Blobs()
    header = _envelope({"error": blobs.ref(error)}, "bootfail")
    return encode_frame(header, blobs.items)


def decode_boot_reply(body: bytes) -> tuple[bool, str]:
    """``(ready, error)`` — ``error`` is type-checked to ``str`` BEFORE the parent interpolates it, so a
    child-supplied object's ``__format__``/``__repr__`` is never invoked in the engine."""
    header, reader, kind = _open(body, ("ready", "bootfail"))
    if kind == "ready":
        reader.finish()
        return True, ""
    error = reader.text(header.get("error"))
    reader.finish()
    return False, error


def encode_request(
    *,
    request_id: str,
    phase: str,
    name: str,
    payload: object,
    origin: tuple[str | bytes, str] | None,
    run_context: RunContext,
) -> bytes:
    blobs = _Blobs()
    header = _envelope(
        {
            "id": request_id,
            "phase": phase,
            "name": name,
            "payload": enc_payload(payload, origin, blobs),
            "rc": enc_run_context(run_context, blobs),
        },
        "req",
    )
    return encode_frame(header, blobs.items)


@dataclass(frozen=True)
class Request:
    """The decoded dispatch request (child side)."""

    request_id: str
    phase: str
    name: str
    payload: Message | RawMessage
    run_context: RunContext


def decode_request(body: bytes) -> Request:
    header, reader, _ = _open(body, ("req",))
    # Walk order matches encode_request: payload BEFORE rc.
    request_id = _req_str(header.get("id"), "request id")
    phase = _req_str(header.get("phase"), "request phase")
    name = _req_str(header.get("name"), "request name")
    payload = dec_payload(header.get("payload"), reader)
    run_context = dec_run_context(header.get("rc"), reader)
    reader.finish()
    return Request(
        request_id=request_id, phase=phase, name=name, payload=payload, run_context=run_context
    )


def encode_ok(*, request_id: str, phase: str, name: str, result: object) -> bytes:
    blobs = _Blobs()
    header = _envelope(
        {
            "id": request_id,
            "phase": phase,
            "name": name,
            "result": enc_result(phase, result, blobs),
        },
        "ok",
    )
    return encode_frame(header, blobs.items)


def encode_fail(*, request_id: str, phase: str, name: str, kind: str, error: str) -> bytes:
    blobs = _Blobs()
    header = _envelope(
        {"id": request_id, "phase": phase, "name": name, "kind": kind, "error": blobs.ref(error)},
        "fail",
    )
    return encode_frame(header, blobs.items)


@dataclass(frozen=True)
class Response:
    """The decoded dispatch response (parent side)."""

    ok: bool
    result: object
    kind: str
    error: str


def decode_response(body: bytes, *, request_id: str, phase: str, name: str) -> Response:
    """Decode one response frame and check it answers the request the parent actually made.

    The whole ``(id, phase, name)`` triple is bound, so a frame produced for a *different* call can
    never be read as this one's answer. **What this is and is not:** ``request_id`` is a fresh
    :func:`secrets.token_hex` the parent mints per dispatch and reveals only inside that dispatch's
    request frame, so a frame written *before* the request — by the previous Handler, or by a grandchild
    that inherited fd 1 and outlived ``proc.kill()`` — cannot carry a matching id. It is **not** a
    defence against the code executing the current request: that code is handed the id, and it could
    equally just replace its sibling in the child's own registry. Confining one Handler from another
    inside a shared worker is not a boundary this seam draws (``mode=off`` does not draw it either);
    what it draws is the address-space boundary to the ENGINE, and the non-executing grammar below.
    :meth:`sandbox.SandboxSession.dispatch` supplies the other half — an unsolicited frame queued
    before or after a dispatch is fatal to the worker — so a pre-staged answer has no window at all."""
    header, reader, kind = _open(body, ("ok", "fail"))
    if _req_str(header.get("id"), "response id") != request_id:
        raise SandboxCodecError(
            f"sandbox response correlation mismatch (expected request {request_id!r})"
        )
    if _req_str(header.get("phase"), "response phase") != phase:
        raise SandboxCodecError(f"sandbox response phase mismatch (expected {phase!r})")
    if _req_str(header.get("name"), "response name") != name:
        raise SandboxCodecError(f"sandbox response name mismatch (expected {name!r})")
    if kind == "ok":
        if "result" not in header:
            raise SandboxCodecError("sandbox 'ok' frame carries no result")
        result = dec_result(phase, header["result"], reader)
        reader.finish()
        return Response(ok=True, result=result, kind="", error="")
    fail_kind = header.get("kind")
    if fail_kind not in ("denied", "error"):
        raise SandboxCodecError(f"unknown sandbox failure kind {fail_kind!r}")
    error = reader.text(header.get("error"))
    reader.finish()
    return Response(ok=False, result=None, kind=fail_kind, error=error)
