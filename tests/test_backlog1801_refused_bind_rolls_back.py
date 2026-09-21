# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1801: a REFUSED federated-subject bind leaves no transaction open on SQLite.

``ux_users_federated_subject`` refusing ``set_user_federated_subject`` is an EXPECTED outcome: it is
how the loser of two concurrent first logins for one subject (#1256) is stopped, and
``auth/service.py`` renders it as ``federated_subject_already_bound``. sqlite3's
``isolation_level=''`` implicitly BEGINs before the UPDATE, and the writer used to take the lock and
nothing else, so the refusal left that implicit transaction open on the ONE writer connection. The
next writer through ``_writer_txn`` then failed on its own ``BEGIN`` with "cannot start a transaction
within a transaction". Under the staged pipeline that next writer can be a stage handoff, so on first
deployment a concurrent first federated login would have failed an unrelated message's handoff.

Driven against the real store, with a file database so the reads go through the pooled read
connections rather than the writer.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from messagefoundry.store.store import MessageStore

ISSUER = "https://idp.example/tenant"
SUBJECT = "S-1-1801-bound"


async def test_refused_bind_leaves_no_open_transaction(tmp_path: Path) -> None:
    store = await MessageStore.open(str(tmp_path / "store.db"))
    try:
        for uid in ("holder", "loser", "bystander"):
            await store.create_user(user_id=uid, username=uid, auth_provider="ad", now=1_000.0)
        await store.set_user_federated_subject("holder", ISSUER, SUBJECT, now=1_000.0)

        # The race loser's write. The refusal must still reach the caller, which renders it.
        with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
            await store.set_user_federated_subject("loser", ISSUER, SUBJECT, now=2_000.0)

        # 1. Nothing is left open on the writer connection.
        assert not store._db.in_transaction, "the refused bind left the writer inside a transaction"

        # 2. The next writer that opens its OWN transaction succeeds on the first try. This is the
        #    probe the defect failed: its BEGIN met the leftover one.
        await store.clear_user_federated_subject("bystander", now=3_000.0)

        # 3. The holder's binding survived, and the loser gained nothing.
        holder = await store.get_user_by_federated_subject(ISSUER, SUBJECT)
        assert holder is not None and holder.id == "holder"
        loser = await store.get_user("loser")
        assert loser is not None and loser.oidc_issuer is None and loser.oidc_subject is None
    finally:
        await store.close()
