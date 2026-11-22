# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pure helpers for the per-message metadata bag (BACKLOG #150, ADR 0081).

The ``messages.metadata`` column is a single encrypted JSON object per message. It carries two kinds of
key: engine-internal keys (at least the ADR 0013 correlation lineage — ``correlation_id`` /
``correlation_root_id`` / ``correlation_depth`` / ``passthrough_from`` / ``reingress_of_seq`` — and the
intake context under the reserved :data:`INTAKE_KEY`, vault BACKLOG #2607) and, under a reserved
``"user"`` sub-key, the
operator/handler-attached bag written by :class:`~messagefoundry.config.wiring.SetMeta`.

:func:`merge_user_metadata` and :func:`user_metadata` shape the split between the ``"user"`` bag and
the engine-internal keys, shared by every store backend (so the merge can never drift across SQLite / Postgres / SQL Server) and by the API (so the internal keys never
leak). They are pure: no I/O beyond a content-free WARNING for an unreadable cell, no crypto — the
caller decrypts before and encrypts after.
"""

from __future__ import annotations

import base64
import json
import logging
import re
from collections.abc import Mapping, Sequence
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any, Final

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


#: Prefixes of ValueErrors raised while json.dumps encodes, each mapped to a content-free kind.
_JSON_VALUE_ERRORS: Final = (
    ("Out of range float values are not JSON compliant", "a non-finite float"),
    ("Circular reference detected", "a circular value"),
    ("Exceeds the limit (", "an oversized int"),
)


def _unencodable_cause(exc_class: type[BaseException], text: str) -> str:
    """A content-free name for a refusal, from its class and the start of its message."""
    if issubclass(exc_class, RecursionError):
        return "a value nested too deep"
    for prefix, kind in _JSON_VALUE_ERRORS:
        if text.startswith(prefix):
            return kind
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

    A ``TypeError``, ``ValueError`` or ``RecursionError`` from json is replaced by a new
    ``TypeError`` whose message names a kind, never the value or its key. Any other exception
    propagates as raised. One such value refuses the whole set, by the rule above."""
    refused: tuple[type[BaseException], str] | None = None
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
        # Only the class and a plain ValueError's string argument leave the handler (read without
        # calling str(), which a subclass could override); the kind is named after it, so nothing
        # the naming could raise is chained to json's error.
        text = exc.args[0] if type(exc) is ValueError and exc.args else ""
        refused = (type(exc), text if isinstance(text, str) else "")
        reason = ""
    if refused is not None:
        reason = (
            "reference snapshot cannot serialize this value to JSON: it holds "
            f"{_unencodable_cause(*refused)}"
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

#: A row reference is cut to this many characters, as ``cell_tag`` cuts one.
_ROW_REF_LEN: Final = 12
_ROW_REF_UNSAFE: Final = re.compile(r"[^A-Za-z0-9_.:-]")


def _row_ref(row_id: object) -> str:
    """``row_id`` cut to :data:`_ROW_REF_LEN` characters, any character outside a plain id's set
    replaced with ``?``, so the line can neither grow nor be forged by it."""
    if row_id is None:
        return "unknown"
    return _ROW_REF_UNSAFE.sub("?", str(row_id)[:_ROW_REF_LEN])


def _warn_unreadable(hint: str, row_id: object) -> None:
    """Log the content-free unreadable-cell WARNING for ``hint``, naming the reference of
    ``row_id``, the id of the message the cell belongs to. Every such cell is logged."""
    log.warning(
        "a stored JSON cell of message %s is unreadable (%s); read as empty", _row_ref(row_id), hint
    )


def _load_object(
    text: StoredJson, *, too_deep_raises: bool = True, row_id: object = None
) -> dict[str, Any]:
    """The JSON object ``text`` holds, or ``{}`` for ``None``, empty, malformed or non-object text;
    text nested too deep to decode raises unless ``too_deep_raises`` is false.

    It decodes through :func:`~messagefoundry.redaction.json_loads_or_refusal`, so json's depth-limit
    ``RecursionError`` never escapes (BACKLOG #6712): it raises :class:`MetadataTooDeepError`,
    outside any handler so nothing is chained, or reads as malformed where ``too_deep_raises`` is
    false. Raising is the default because a metadata cell read as ``{}`` changes an outcome. A
    refusal that reads as empty is logged with json's content-free hint and ``row_id``'s reference,
    never the text. ``bytes``, ``bytearray`` and ``memoryview`` decode as ``json.loads`` decodes
    bytes. A released ``memoryview`` reads as ``{}`` and is logged."""
    if isinstance(text, (bytearray, memoryview)):
        try:
            text = bytes(text)
        except ValueError:
            # A released memoryview cannot be read, so it reads as {}.
            _warn_unreadable("released memoryview", row_id)
            return {}
    if text is None:
        return {}
    if not isinstance(text, str | bytes):
        _warn_unreadable(f"not text: {type(text).__name__}", row_id)
        return {}
    if not text:
        return {}
    value, refusal = json_loads_or_refusal(text)
    if refusal is not None:
        # startswith, so a hint that ever grows a suffix still reads as too deep.
        if too_deep_raises and refusal.startswith(RecursionError.__name__):
            raise MetadataTooDeepError("a stored metadata cell is too deeply nested to decode")
        _warn_unreadable(refusal, row_id)
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


def decode_response_headers(headers_json: StoredJson, *, row_id: object = None) -> dict[str, str]:
    """Parse the decrypted ``resp_headers`` JSON back to a ``{name: value}`` map (BACKLOG #154).

    ``None``/empty/unparseable/non-object → ``{}`` (the byte-identical default), so a purged row (
    retention nulls the column) or a legacy row reads as "no captured headers". Only ``str``→``str``
    entries survive, as :func:`encode_response_headers` writes nothing else. Pure: the caller decrypts
    before calling."""
    loaded = _load_object(headers_json, too_deep_raises=False, row_id=row_id)
    return {k: v for k, v in loaded.items() if isinstance(v, str)}


#: The reserved engine-internal key holding the intake context a source handed over with the body
#: (vault BACKLOG #2607): the verified certificate subject and how the peer was admitted, or a
#: poll source's path. It holds no socket address, by the owner's ruling of 2026-11-22; what it
#: can still carry is stated on :class:`~messagefoundry.transports.intake.IntakeContext`. Written once, in the ingress transaction, so a
#: future reader in the router, which nothing builds yet, would read the same value on a re-run,
#: as the purity rule requires. A message the engine made from another one (a
#: pass-through or loopback child, an operator resend or edit-and-resubmit) is written without it:
#: no peer handed that body over, and its ``correlation_root_id`` leads back to the root message,
#: which carries one where its source passed a context. :func:`user_metadata` never returns it.
INTAKE_KEY: Final = "intake"


def intake_metadata_json(fields: Mapping[str, Any] | None) -> str | None:
    """The metadata JSON a freshly received message starts with: ``fields`` under
    :data:`INTAKE_KEY`, or ``None`` when there is no context, so the cell stays ``NULL`` as before."""
    if not fields:
        return None
    return json.dumps({INTAKE_KEY: dict(fields)})


def intake_of(metadata_json: StoredJson, *, row_id: object = None) -> dict[str, Any] | None:
    """The intake context stored in a message's decrypted metadata JSON, or ``None`` when it has none."""
    intake = _load_object(metadata_json, row_id=row_id).get(INTAKE_KEY)
    return dict(intake) if isinstance(intake, dict) and intake else None


def merge_user_metadata(
    existing_json: StoredJson, meta_ops: Sequence[tuple[str, str]], *, row_id: object = None
) -> str:
    """Merge ``SetMeta`` writes into a message's decrypted metadata JSON, under the reserved ``"user"``
    sub-key, and return the new JSON string.

    Any non-``user`` keys already present (ADR 0013 correlation lineage) are preserved untouched. Within
    one message the same key is last-writer-wins. ``existing_json`` may be ``None``/empty (no metadata
    yet) or a non-object (defensively treated as empty), and so may a non-object ``"user"`` bag. A
    cell too deep to decode, or one that decodes but is too deep to re-encode, raises
    :class:`MetadataTooDeepError` rather than being written back as the ops alone, which would erase
    the engine-internal keys. Caller passes decrypted JSON in and encrypts the result out — this
    function does neither."""
    parsed = _load_object(existing_json, row_id=row_id)
    existing_user = parsed.get("user")
    user: dict[str, Any] = dict(existing_user) if isinstance(existing_user, dict) else {}
    for key, value in meta_ops:
        user[key] = value
    parsed["user"] = user
    return _dumps_or_raise(parsed)


def user_metadata(metadata_json: StoredJson, *, row_id: object = None) -> str | None:
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
    takes it too, so one such cell fails the whole response it is on, as json's ``RecursionError``
    did before: at least ``GET /messages``, ``GET`` and ``POST /messages/search``,
    ``GET /search/layered`` and ``GET /messages/{message_id}``."""
    user = _load_object(metadata_json, row_id=row_id).get("user")
    if not isinstance(user, dict) or not user:
        return None
    return _dumps_or_raise(user)
