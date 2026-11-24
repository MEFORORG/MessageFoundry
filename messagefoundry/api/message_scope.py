# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one by-id message read under ``messagefoundry/api/`` (BACKLOG #2627).

Every route that opens a message by its id used to repeat the same four lines: fetch the row, test
the caller's channel scope, audit a refusal, and answer 404. Eight routes and the export stream did
that by hand, and a ninth copy that dropped the scope test would have handed a scoped operator
another channel's message with nothing going red.

So the fetch lives here and nowhere else. :func:`get_scoped_message` returns the row or raises the
404 the routes always raised. :func:`read_scoped_message` is the same check for the export stream,
which skips a refused row rather than failing the whole response. Both audit a refusal as
``auth.channel_denied`` before they answer.

``tests/test_api_scoped_message_reads.py`` fails if any other module under ``messagefoundry/api/``
loads a ``.get_message`` or ``.message_channel_id`` attribute itself, or reaches it through
``getattr``.

Why 404 and not 403: a 403 would tell a scoped caller that a message exists in another channel. The
404 detail names only the id the caller sent.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, Final, Literal, get_args

from fastapi import HTTPException, Request

from messagefoundry.api.security import client_ip
from messagefoundry.connection_names import is_connection_name
from messagefoundry.store.cell_tag import CellTagError
from messagefoundry.store.crypto import CipherError, CipherUnavailableError, gave_no_verdict
from messagefoundry.transports.http_listener import TEMPORARY_REFUSAL_RETRY_AFTER_SECONDS

if TYPE_CHECKING:
    from messagefoundry.auth import Identity
    from messagefoundry.pipeline import Engine

_log = logging.getLogger(__name__)

#: The detail of the one 403 a channel-scoped caller gets for a connection it may not reach
#: (BACKLOG #2551). Held here, beside the audit it follows, so the API's per-name routes and the web
#: console's flag route answer with one text (BACKLOG #3378).
CONNECTION_DENIED_DETAIL: Final = "not authorized for this connection"

#: What a refused request whose row names no channel was asking for (vault BACKLOG #3748 item 7):
#: a config reload, its dry run, a reset of every statistic, a replay of every channel's dead
#: letters, a purge, and a start, stop or restart. Each value is the name of the audit action
#: that operation writes when it runs and has an effect. A row names no channel either by design or
#: because the name failed the connection-name rule, which ``"malformed_name"`` marks.
DeniedOperation = Literal[
    "config_reload",
    "config_reload_check",
    "stats_reset",
    "dead_letter_replay",
    "connection_purge",
    "connection_control",
]
_DENIED_OPERATIONS: Final[frozenset[str]] = frozenset(get_args(DeniedOperation))


async def audit_channel_denied(
    engine: Engine,
    identity: Identity,
    channel: str | None,
    client: str | None = None,
    *,
    flag_direction_not_inbound: bool = False,
    operation: DeniedOperation | None = None,
) -> None:
    """Audit a per-channel RBAC denial (mirrors auth.permission_denied).

    ``client`` (ADR 0150) is the caller's address — a denial is exactly the record an investigator
    wants a host for. It is OPTIONAL because this helper is also handed to the console seam as a bare
    callback (``audit_channel_denied=``). The console's callers pass the browser's address; a caller
    that passes none leaves it NULL rather than inheriting some other caller's address.

    A ``channel`` that fails the connection-name rule is recorded as no channel (BACKLOG #3031).
    Some callers pass a caller-chosen name, and at least the core handlers the console seam calls
    take any string, so the bound is held here, where every refusal passes: ``audit_log.channel_id``
    never holds caller text of unbounded length. The loader registers no connection under such a
    name, so it is never in a scope, and the actor and host still identify the attempt. The detail
    then carries ``"malformed_name": true``, so such a probe is told apart from a refusal that names
    no channel by design.

    ``flag_direction_not_inbound`` marks a flag request refused because its direction was not
    ``inbound``, which a scoped caller may flag only (BACKLOG #3378). The detail then carries
    ``"flag_direction_not_inbound": true``. Such a row can name an inbound inside the actor's own
    scope, and without the marker it would read like a request asked of the wrong engine shard. The
    direction itself is not recorded, since the console's form carries it as caller text.

    ``operation`` names what was refused when the row names no channel (vault BACKLOG #3748 item
    7). The detail then carries ``"operation"`` with one of the :data:`DeniedOperation` values. It
    is written only on a row that names no channel, so a row naming a channel never carries one. A
    value outside them is left out of the row and logged, rather than refusing the audit: the
    console hands this helper its keyword through an untyped seam callback. At least these rows
    name no channel and carry no operation: a refused message read whose integrity tag names no
    channel, and one whose stored row names none (:func:`read_scoped_message`)."""
    detail: dict[str, object] = {"channel": channel}
    if channel is not None and not is_connection_name(channel):
        channel = None
        detail = {"channel": None, "malformed_name": True}
    if flag_direction_not_inbound:
        detail["flag_direction_not_inbound"] = True
    if operation is not None and channel is None:
        # isinstance first: the console's value arrives untyped, and an unhashable one would
        # raise in the set test and lose the row.
        if isinstance(operation, str) and operation in _DENIED_OPERATIONS:
            detail["operation"] = operation
        else:
            _log.warning(
                "a channel denial for %s named an unknown operation; the row omits it",
                identity.username,
            )
    await engine.store.record_audit(
        "auth.channel_denied",
        actor=identity.username,
        channel_id=channel,
        detail=json.dumps(detail),
        client=client,
    )


#: What an in-scope caller is told when a message's cells fail their integrity tag (BACKLOG #2593).
#: 423, as for an upload the store cipher refuses: the message exists and needs an operator.
_INTEGRITY_REFUSED = (
    "this message's stored contents failed their integrity check and cannot be shown"
)
#: A cell the cipher refused for a reason other than its tag (BACKLOG #5969): the message exists
#: and needs an operator, as for an upload the store key cannot read.
_KEYS_REFUSED = "this message's stored contents cannot be opened with the store's keys"
#: The key service gave no verdict, so a later try may succeed (BACKLOG #3734, #5969).
_KEY_SERVICE_UNAVAILABLE = "the store's key service could not open this message. Try again shortly"


class MessageCellsRefusedError(CipherError):
    """:func:`read_scoped_message`'s refusal, for a caller that skips, of an in-scope row whose
    cells the cipher would not open for a reason other than their tag (BACKLOG #5969, #5970). Its
    own class, so the export stream tells it from a :class:`CipherError` that any other step of the
    read raised, such as the ``auth.channel_denied`` audit row's MAC, and names the real cause."""


class MessageKeyServiceUnavailableError(MessageCellsRefusedError, CipherUnavailableError):
    """:class:`MessageCellsRefusedError` where the key service gave no verdict on the cells."""


async def read_scoped_message(
    engine: Engine,
    identity: Identity,
    message_id: str,
    request: Request,
    *,
    refuse_integrity: bool = False,
) -> dict[str, Any] | None:
    """The message row, or ``None`` when it does not exist or sits outside the caller's channels.
    An in-scope row whose cells cannot be opened is ``None`` only for a failed tag and a caller
    that skips; every other refusal raises, as below.

    The channel scope is checked on the row's plaintext ``channel_id`` BEFORE any cell is opened
    (BACKLOG #5969, #5981), so an out-of-scope message decrypts nothing, and whatever its cells
    hold it reads as any other refused row: audited as ``auth.channel_denied``, then ``None``, so
    a caller that skips it (the export stream) still leaves the refusal on the record, and the
    answer never says the message exists.

    In scope, a row whose cells fail their tag, or are corrupt, was refused by the store, which
    alerts and audits drift and logs a corrupt cell (BACKLOG #2593): ``None`` for a caller that
    skips (the export stream), or, with ``refuse_integrity``, a 423. A cell the cipher refuses for
    another reason (a retired key not supplied, a Transit refusal other than the tag) is logged
    here by its error class, and is a 423 with ``refuse_integrity``, or a 503 with ``Retry-After``
    when the key service gave no verdict. A caller that skips gets a fresh
    :class:`MessageCellsRefusedError` (:class:`MessageKeyServiceUnavailableError` for the outage)
    carrying no chain, as before this check the store's own error stopped it. A
    :class:`CipherError` of any other class is not about the row's cells: at least the
    ``auth.channel_denied`` audit write can raise one, under a Transit audit MAC."""
    channel_id = await engine.store.message_channel_id(message_id)
    if channel_id is None:
        return None
    if not identity.can_access_channel(channel_id):
        await audit_channel_denied(engine, identity, channel_id, client_ip(request))
        return None
    row: dict[str, Any] | None = None
    tag_refused = False
    tag_channel: str | None = None
    # (gave no verdict, error class name) of a plain cipher refusal.
    cipher_refused: tuple[bool, str] | None = None
    try:
        row = await engine.store.get_message(message_id)
    except CellTagError as err:
        tag_refused, tag_channel = True, err.channel_id
    except CipherError as exc:
        cipher_refused = (gave_no_verdict(exc), type(exc).__name__)
    # Everything below runs after the handlers (BACKLOG #1796), so neither a refusal nor a fault in
    # the scope read or the audit chains the cipher's error. Inside a handler, even with
    # `from None`, __context__ would keep that error and, through its traceback, the store frame
    # holding the cells it had already opened.
    if tag_refused:
        # The tag is built from the channel the store read, which may not be the one checked above
        # if the row changed between the two reads; out of scope it is the uniform refusal.
        if not identity.can_access_channel(tag_channel):
            await audit_channel_denied(engine, identity, tag_channel, client_ip(request))
            return None
        if not refuse_integrity:
            return None
        raise HTTPException(423, _INTEGRITY_REFUSED)
    if cipher_refused is not None:
        # A plain cipher error names no channel, so the scope is read again: a row that changed
        # channel between the two reads is the uniform refusal, never a 423 or 503 that would say
        # it exists.
        now_in = await engine.store.message_channel_id(message_id)
        if now_in is None:
            return None
        if not identity.can_access_channel(now_in):
            await audit_channel_denied(engine, identity, now_in, client_ip(request))
            return None
        no_verdict, error_class = cipher_refused
        # The class name only: the cipher's text can echo fields cut from the stored value, and the
        # message id is the caller's, so neither the log line nor the error carries it.
        cause = f"a message could not be opened: {error_class}"
        _log.warning("%s", cause)
        if not refuse_integrity:
            # The export stream does not skip such a row: an export that leaves out rows nothing
            # records would read as complete, so it records a stop instead. A fresh error, so no
            # frame holding opened cells rides on it.
            if no_verdict:
                raise MessageKeyServiceUnavailableError(cause)
            raise MessageCellsRefusedError(cause)
        if no_verdict:
            raise HTTPException(
                503,
                _KEY_SERVICE_UNAVAILABLE,
                headers={"Retry-After": str(TEMPORARY_REFUSAL_RETRY_AFTER_SECONDS)},
            )
        raise HTTPException(423, _KEYS_REFUSED)
    if row is None:
        return None
    # Checked again on the row itself. It differs from the check above only if the row changed
    # between the two reads: an id deleted and reused, or a channel_id rewritten outside the
    # store's writers, which on a keyless store no tag refuses, so this check is the guard there.
    if not identity.can_access_channel(row["channel_id"]):
        await audit_channel_denied(engine, identity, row["channel_id"], client_ip(request))
        return None
    return row


async def get_scoped_message(
    engine: Engine, identity: Identity, message_id: str, request: Request
) -> dict[str, Any]:
    """The message row, or the 404 every by-id message route answers.

    The same 404 covers a missing message and one outside the caller's channel scope, so the answer
    never says which. The refusal is audited first, by :func:`read_scoped_message`. An in-scope
    message whose cells fail their integrity tag (BACKLOG #2593), or that the store's keys cannot
    open (BACKLOG #5969), answers 423; one the key service gave no verdict on answers 503."""
    row = await read_scoped_message(engine, identity, message_id, request, refuse_integrity=True)
    if row is None:
        raise HTTPException(404, f"no such message: {message_id}")
    return row
