# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pure helpers for the per-message metadata bag (BACKLOG #150, ADR 0081).

The ``messages.metadata`` column is a single encrypted JSON object per message. It carries two kinds of
key: engine-internal keys (ADR 0013 correlation lineage — ``correlation_id`` / ``correlation_root_id`` /
``correlation_depth`` / ``passthrough_from`` / ``reingress_of_seq``) and, under a reserved ``"user"``
sub-key, the operator/handler-attached bag written by :class:`~messagefoundry.config.wiring.SetMeta`.

These two functions are the ONLY places that shape that split, shared by every store backend (so the
merge can never drift across SQLite / Postgres / SQL Server) and by the API (so the internal keys never
leak). They are pure: no I/O beyond a content-free WARNING for an unreadable cell, no crypto — the
caller decrypts before and encrypts after.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import time as _time
from collections.abc import Mapping, Sequence
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any

from messagefoundry.redaction import json_loads_or_refusal

log = logging.getLogger(__name__)


def _reference_json_default(value: Any) -> Any:
    """``json.dumps(default=)`` for a reference-snapshot value: coerce the types JSON cannot encode
    natively, and raise ``TypeError`` on anything else rather than dropping it.

    Deliberately the SAME coercions as ``transports/database.py::_json_default`` (dates to ISO-8601,
    ``Decimal`` to its exact decimal string, bytes to base64) so a value encodes identically whichever
    reference source produced it — a reader cannot tell a FILE-sourced snapshot from a DATABASE-sourced
    one, so the two must not disagree. ``transports/`` may not import ``store/`` (ADR 0154 AC-17), so
    the agreement is frozen by a test rather than by sharing the function.

    ``time`` is here and absent there because ``tomllib`` materializes a bare TOML ``09:30:00`` as
    ``datetime.time`` — a shape no DB column produces.
    """
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")
    raise _UnencodableTypeError(
        f"reference snapshot cannot serialize a {type(value).__name__} value to JSON"
    )


class _UnencodableTypeError(TypeError):
    """:func:`_reference_json_default`'s own refusal, whose message names only a type."""


def _unencodable_cause(value: Any, exc: ValueError | RecursionError) -> str:
    """A content-free name for why json could not encode a reference value (never a value or a
    key). Too deep is told by class and a non-finite float by re-encoding with NaN allowed; the
    other two kinds are read off json's own fixed message, and an unknown one stays generic."""
    if isinstance(exc, RecursionError):
        return "a value nested too deep"
    try:
        json.dumps(value, default=_reference_json_default, allow_nan=True)
    except (TypeError, ValueError, RecursionError):
        pass
    else:
        return "a non-finite float"
    text = str(exc)
    if "Circular reference" in text:
        return "a circular value"
    if "digits" in text:
        return "an oversized int"
    return "an unencodable value"


def encode_reference_value(value: Any) -> str:
    """JSON-encode ONE reference-snapshot value for the ``reference.value`` column (BACKLOG #1090).

    The sink for every reference source on every backend, so it is the one place that decides what a
    snapshot value may contain. It exists because the guard belongs at the SINK, not at one producer:
    ``_load_database_source`` coerced its cells through ``_cell`` while ``_load_file_source`` returned
    ``dict(load_code_set(path))`` uncoerced, and a bare ``json.dumps(v)`` then raised ``TypeError`` on
    an ordinary reference TOML carrying ``effective = 2026-01-01`` (``tomllib`` materializes a TOML
    date as ``datetime.date``). Measured on the pre-fix tree, both the flat and the nested-table TOML
    shapes failed. Hardening the file producer alone would have fixed that one instance and left the
    next producer — the third serialization boundary nobody has written yet — to rediscover it.

    An unencodable type still raises ``TypeError``: the sync's caller keeps the last-good snapshot
    rather than committing a set with a value silently replaced by a placeholder (ADR 0006's graceful
    degradation), which is the same never-accept-and-drop rule the rest of the store follows.

    A non-finite float (a TOML ``nan``, a DATABASE double column) raises the same ``TypeError``
    (BACKLOG #6711): ``json.dumps``' default would write the bare ``NaN`` token, which is not JSON.

    The refusal names the kind of value that failed, never the value or its key, and carries no
    json notes, cause or context. One such value refuses the whole set, by the rule above."""
    try:
        return json.dumps(value, default=_reference_json_default, allow_nan=False)
    except _UnencodableTypeError as exc:
        # Every refusal is rebuilt and raised OUTSIDE its handler: json adds notes naming the dict
        # keys on the path, and a reference key may be PHI, so neither the notes nor the original may
        # ride along. Only our own message, which names a type, is carried over.
        reason = str(exc)
    except TypeError as exc:
        # Any other TypeError's text is not ours to vouch for, so only its class is named.
        reason = (
            "reference snapshot cannot serialize this value to JSON: it holds an unencodable value"
            f" ({type(exc).__name__})"
        )
    except (ValueError, RecursionError) as exc:
        reason = (
            "reference snapshot cannot serialize this value to JSON: it holds "
            f"{_unencodable_cause(value, exc)}"
        )
    raise TypeError(reason)


def encode_response_headers(headers: Mapping[str, str] | None) -> str | None:
    """Serialize a captured allow-listed HTTP response-header map to a JSON string for the ``response``
    table's ``resp_headers`` column (BACKLOG #154), or ``None`` when there is nothing to store.

    ``None``/empty → ``None`` so the column stays ``NULL`` (byte-identical to a pre-#154 capture and to
    every non-HTTP destination). Only ``str``→``str`` entries are kept (the connector already filtered
    to the allow-list; this stays defensive). Pure: the caller encrypts the returned string at rest,
    exactly as it does ``detail``."""
    if not headers:
        return None
    clean = {str(k): str(v) for k, v in headers.items()}
    if not clean:
        return None
    return json.dumps(clean)


class MetadataTooDeepError(RuntimeError):
    """A stored metadata cell nested past json's depth limit, raised where reading it as empty would
    change an outcome (BACKLOG #6712). A ``RuntimeError``, as json's own ``RecursionError`` was on
    main, so no ``ValueError`` arm downstream turns it into "no metadata". Carries no content."""


#: A stored JSON cell's text: ``str``, or the bytes a driver may hand back for it.
type StoredJson = str | bytes | bytearray | memoryview | None

#: How long one kind of unreadable-cell WARNING is logged once. A list read over many such cells
#: would otherwise log one line per row.
_WARN_INTERVAL_S = 60.0
_warned: dict[str, float] = {}
_warned_lock = threading.Lock()


def _warn_unreadable(hint: str) -> None:
    """Log the content-free unreadable-cell WARNING for ``hint``, at most once per interval. The
    caller holds no row id, so the line names none. Throttled by the hint's kind, never its line
    and column, so the memo stays as small as the set of kinds."""
    kind = hint.split(" at ", 1)[0]
    now = _time.monotonic()
    with _warned_lock:
        last = _warned.get(kind)
        if last is not None and now - last < _WARN_INTERVAL_S:
            return
        _warned[kind] = now
    log.warning(
        "a stored JSON cell is unreadable (%s); read as empty (logged at most once per %.0f s)",
        hint,
        _WARN_INTERVAL_S,
    )


def _load_object(text: StoredJson, *, too_deep_raises: bool = True) -> dict[str, Any]:
    """The JSON object ``text`` holds, or ``{}`` for ``None``, empty, malformed or non-object text;
    text nested too deep to decode raises unless ``too_deep_raises`` is false.

    It decodes through :func:`~messagefoundry.redaction.json_loads_or_refusal`, so json's depth-limit
    ``RecursionError`` never escapes (BACKLOG #6712): it raises :class:`MetadataTooDeepError`,
    outside any handler so nothing is chained, or reads as malformed where ``too_deep_raises`` is
    false. Raising is the default because a metadata cell read as ``{}`` changes an outcome. A
    refusal that reads as empty is logged with json's content-free hint, never the text.
    ``bytes``, ``bytearray`` and ``memoryview`` decode as ``json.loads`` decodes bytes; any other
    type reads as ``{}`` and is logged by its type name."""
    if isinstance(text, (bytearray, memoryview)):
        text = bytes(text)
    if text is None:
        return {}
    if not isinstance(text, str | bytes):
        _warn_unreadable(f"not text: {type(text).__name__}")
        return {}
    if not text:
        return {}
    value, refusal = json_loads_or_refusal(text)
    if refusal is not None:
        # startswith, so a hint that ever grows a suffix still reads as too deep.
        if too_deep_raises and refusal.startswith(RecursionError.__name__):
            raise MetadataTooDeepError("a stored metadata cell is too deeply nested to decode")
        _warn_unreadable(refusal)
        return {}
    return value if isinstance(value, dict) else {}


def _dumps_or_raise(value: Any) -> str:
    """``json.dumps(value)``, or :class:`MetadataTooDeepError` when json's encoder hits its depth
    limit, raised outside the handler so nothing is chained.

    The encoder's limit sits below the decoder's, so an object :func:`_load_object` read can still
    be too deep to write back (BACKLOG #6712)."""
    try:
        return json.dumps(value)
    except RecursionError:
        pass
    raise MetadataTooDeepError("a stored metadata cell is too deeply nested to re-encode")


def decode_response_headers(headers_json: StoredJson) -> dict[str, str]:
    """Parse the decrypted ``resp_headers`` JSON back to a ``{name: value}`` map (BACKLOG #154).

    ``None``/empty/unparseable/non-object → ``{}`` (the byte-identical default), so a purged row (
    retention nulls the column) or a legacy row reads as "no captured headers". Only ``str``→``str``
    entries survive, as :func:`encode_response_headers` writes nothing else. Pure: the caller decrypts
    before calling."""
    loaded = _load_object(headers_json, too_deep_raises=False)
    return {k: v for k, v in loaded.items() if isinstance(v, str)}


def merge_user_metadata(existing_json: StoredJson, meta_ops: Sequence[tuple[str, str]]) -> str:
    """Merge ``SetMeta`` writes into a message's decrypted metadata JSON, under the reserved ``"user"``
    sub-key, and return the new JSON string.

    Any non-``user`` keys already present (ADR 0013 correlation lineage) are preserved untouched. Within
    one message the same key is last-writer-wins. ``existing_json`` may be ``None``/empty (no metadata
    yet) or a non-object (defensively treated as empty), and so may a non-object ``"user"`` bag. A
    cell too deep to decode, or one that decodes but is too deep to re-encode, raises
    :class:`MetadataTooDeepError` rather than being written back as the ops alone, which would erase
    the engine-internal keys. Caller passes decrypted JSON in and encrypts the result out — this
    function does neither."""
    parsed = _load_object(existing_json)
    existing_user = parsed.get("user")
    user: dict[str, Any] = dict(existing_user) if isinstance(existing_user, dict) else {}
    for key, value in meta_ops:
        user[key] = value
    parsed["user"] = user
    return _dumps_or_raise(parsed)


def user_metadata(metadata_json: StoredJson) -> str | None:
    """The public, read-only user bag from a message's decrypted metadata JSON: the ``"user"`` sub-key
    re-serialized as a JSON string, or ``None`` when there is none.

    The API returns the metadata column's contents through this view — it strips the engine-internal
    keys, such as the correlation lineage, so they never surface (the lineage would otherwise leak on
    pass-through / re-ingressed children). It is not the API's only READ of the column: at least
    edit-and-resubmit also reads the engine-internal refused-body record, and refuses a row stored as
    a head (``head_only_resubmit_refusal`` in ``pipeline/refused_body.py``, vault BACKLOG #2608). That
    refusal names the body's length and the head bound, never the digest or a byte of the body.

    Returns ``None`` for absent/empty/unparseable metadata or an empty user bag, so the wire field is
    ``null`` rather than ``"{}"`` when nothing was attached.

    A cell too deep to decode or re-encode raises :class:`MetadataTooDeepError` instead, at every
    caller: ``None`` would send a ``dynamic_headers`` delivery out without its headers. The delivery
    worker takes it on its internal-error arm (``InternalErrorPolicy``). The API's message summary
    takes it too, so one such cell fails the whole list, search or uploaded-file page it is on, as
    json's ``RecursionError`` did before."""
    user = _load_object(metadata_json).get("user")
    if not isinstance(user, dict) or not user:
        return None
    return _dumps_or_raise(user)
