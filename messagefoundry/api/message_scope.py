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
loads a ``.get_message`` attribute itself, or reaches it through ``getattr``.

Why 404 and not 403: a 403 would tell a scoped caller that a message exists in another channel. The
404 detail names only the id the caller sent.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from fastapi import HTTPException, Request

from messagefoundry.api.security import client_ip
from messagefoundry.store.cell_tag import CellTagError

if TYPE_CHECKING:
    from messagefoundry.auth import Identity
    from messagefoundry.pipeline import Engine


async def audit_channel_denied(
    engine: Engine, identity: Identity, channel: str | None, client: str | None = None
) -> None:
    """Audit a per-channel RBAC denial (mirrors auth.permission_denied).

    ``client`` (ADR 0150) is the caller's address — a denial is exactly the record an investigator
    wants a host for. It is OPTIONAL because this helper is also handed to the console seam as a bare
    callback (``audit_channel_denied=``), which has no request in hand; there it stays NULL rather than
    inheriting some other caller's address."""
    await engine.store.record_audit(
        "auth.channel_denied",
        actor=identity.username,
        channel_id=channel,
        detail=json.dumps({"channel": channel}),
        client=client,
    )


#: What an in-scope caller is told when a message's cells fail their integrity tag (BACKLOG #2593).
#: 423, as for an upload the store cipher refuses: the message exists and needs an operator.
_INTEGRITY_REFUSED = (
    "this message's stored contents failed their integrity check and cannot be shown"
)


async def read_scoped_message(
    engine: Engine,
    identity: Identity,
    message_id: str,
    request: Request,
    *,
    refuse_integrity: bool = False,
) -> dict[str, Any] | None:
    """The message row, or ``None`` when it does not exist, sits outside the caller's channels, or
    its cells fail their channel tag.

    An out-of-scope row is audited as ``auth.channel_denied`` before ``None`` comes back, so a caller
    that skips it (the export stream) still leaves the refusal on the record. A row whose cells fail
    their tag was refused, alerted and audited by the store (BACKLOG #2593). Out of scope it reads as
    any other refused row, so the answer never says the message exists. In scope it is ``None`` for
    a caller that skips (the export stream), or, with ``refuse_integrity``, a 423."""
    integrity_refused = False
    try:
        row = await engine.store.get_message(message_id)
    except CellTagError as err:
        if not identity.can_access_channel(err.channel_id):
            await audit_channel_denied(engine, identity, err.channel_id, client_ip(request))
            return None
        if not refuse_integrity:
            return None
        integrity_refused = True
    if integrity_refused:
        # Raised after the handler, so the 423 chains nothing (BACKLOG #1796). Inside it, even with
        # `from None`, __context__ would keep the CellTagError, the cipher's error under it, and
        # through their tracebacks the store frame holding the cells it had already opened.
        raise HTTPException(423, _INTEGRITY_REFUSED)
    if row is None:
        return None
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
    message whose cells fail their integrity tag answers 423 (BACKLOG #2593)."""
    row = await read_scoped_message(engine, identity, message_id, request, refuse_integrity=True)
    if row is None:
        raise HTTPException(404, f"no such message: {message_id}")
    return row
