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
    raise TypeError(f"reference snapshot cannot serialize a {type(value).__name__} value to JSON")


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
    (BACKLOG #6711): ``json.dumps``' default would write the bare ``NaN`` token, which is not JSON."""
    try:
        return json.dumps(value, default=_reference_json_default, allow_nan=False)
    except (ValueError, RecursionError):
        # Raised below, OUTSIDE this handler: json's error carries notes naming the dict keys on the
        # path, and a reference key may be PHI, so it must ride neither __cause__ nor __context__.
        # ValueError covers at least a non-finite float, a circular value and an int too long to print.
        pass
    raise TypeError(
        "reference snapshot cannot serialize this value to JSON (at least a non-finite float, a "
        "circular value, an oversized int or one nested too deep)"
    )


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


def _load_object(
    text: str | bytes | bytearray | None, *, too_deep_raises: bool = False
) -> dict[str, Any]:
    """The JSON object ``text`` holds, or ``{}`` for ``None``, empty, malformed or non-object text.

    It decodes through :func:`~messagefoundry.redaction.json_loads_or_refusal`, so json's depth-limit
    ``RecursionError`` never escapes (BACKLOG #6712): it reads as malformed, or with
    ``too_deep_raises`` it raises :class:`MetadataTooDeepError`, outside any handler so nothing is
    chained. A refusal is logged with json's content-free hint, never the text. ``bytes``/``bytearray``
    decode as ``json.loads`` decoded them before; any other type reads as ``{}``, as the
    ``TypeError`` arm this replaced did."""
    if isinstance(text, bytearray):
        text = bytes(text)
    if not isinstance(text, str | bytes) or not text:
        return {}
    value, refusal = json_loads_or_refusal(text)
    if refusal is not None:
        if too_deep_raises and refusal == RecursionError.__name__:
            raise MetadataTooDeepError("a stored metadata cell is too deeply nested to decode")
        log.warning("a stored JSON cell is unreadable (%s); read as empty", refusal)
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


def decode_response_headers(headers_json: str | None) -> dict[str, str]:
    """Parse the decrypted ``resp_headers`` JSON back to a ``{name: value}`` map (BACKLOG #154).

    ``None``/empty/unparseable/non-object → ``{}`` (the byte-identical default), so a purged row (
    retention nulls the column) or a legacy row reads as "no captured headers". Only ``str``→``str``
    entries survive, as :func:`encode_response_headers` writes nothing else. Pure: the caller decrypts
    before calling."""
    return {k: v for k, v in _load_object(headers_json).items() if isinstance(v, str)}


def merge_user_metadata(existing_json: str | None, meta_ops: Sequence[tuple[str, str]]) -> str:
    """Merge ``SetMeta`` writes into a message's decrypted metadata JSON, under the reserved ``"user"``
    sub-key, and return the new JSON string.

    Any non-``user`` keys already present (ADR 0013 correlation lineage) are preserved untouched. Within
    one message the same key is last-writer-wins. ``existing_json`` may be ``None``/empty (no metadata
    yet) or a non-object (defensively treated as empty), and so may a non-object ``"user"`` bag. An
    existing object that decodes but is too deep to re-encode raises :class:`MetadataTooDeepError`
    rather than being written back as the ops alone, which would erase the engine-internal keys.
    Caller passes decrypted JSON in and encrypts the result out — this function does neither."""
    parsed = _load_object(existing_json)
    existing_user = parsed.get("user")
    user: dict[str, Any] = dict(existing_user) if isinstance(existing_user, dict) else {}
    for key, value in meta_ops:
        user[key] = value
    parsed["user"] = user
    return _dumps_or_raise(parsed)


def user_metadata(metadata_json: str | None) -> str | None:
    """The public, read-only user bag from a message's decrypted metadata JSON: the ``"user"`` sub-key
    re-serialized as a JSON string, or ``None`` when there is none.

    The API returns the metadata column's contents through this view — it strips the engine-internal
    keys, such as the correlation lineage, so they never surface (the lineage would otherwise leak on
    pass-through / re-ingressed children). It is not the API's only READ of the column: at least
    edit-and-resubmit also reads the engine-internal refused-body record, and refuses a row stored as
    a head (``head_only_resubmit_refusal`` in ``pipeline/refused_body.py``, vault BACKLOG #2608). That
    refusal names the body's length and the head bound, never the digest or a byte of the body.

    Returns ``None`` for absent/empty/unparseable metadata or an empty user bag, so the wire field is
    ``null`` rather than ``"{}"`` when nothing was attached. A cell too deep to decode or re-encode
    raises :class:`MetadataTooDeepError` instead: ``None`` would send a ``dynamic_headers`` delivery
    out without its headers, where the error faults it and it retries, as on main."""
    user = _load_object(metadata_json, too_deep_raises=True).get("user")
    if not isinstance(user, dict) or not user:
        return None
    return _dumps_or_raise(user)
