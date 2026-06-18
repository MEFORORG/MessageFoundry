# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Durable message store + queue (SQLite WAL, transactional inbox/outbox).

The store *is* the queue: persisting an inbound message and its per-destination outbox
rows in one transaction buys at-least-once delivery, retries, and replay without a
separate broker. See :mod:`messagefoundry.store.store` and docs/ARCHITECTURE.md.
"""

from __future__ import annotations

from messagefoundry.store.base import (
    AdminStore,
    AuditStore,
    AuthStore,
    QueueStore,
    Row,
    Store,
    StoreLifecycle,
    open_store,
    sqlite_settings,
)
from messagefoundry.store.store import (
    MessageStatus,
    MessageStore,
    OutboxItem,
    OutboxStatus,
    Stage,
)

__all__ = [
    "AdminStore",
    "AuditStore",
    "AuthStore",
    "MessageStatus",
    "MessageStore",
    "OutboxItem",
    "OutboxStatus",
    "QueueStore",
    "Row",
    "Stage",
    "Store",
    "StoreLifecycle",
    "open_store",
    "sqlite_settings",
]
