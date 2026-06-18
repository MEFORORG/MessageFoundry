# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the re-run-stable ingest-time provider (config.ingest_time, ADR 0009).

The SQLite path that surfaces `OutboxItem.created_at` from the claim is exercised by the whole
pipeline suite (every claim_next_fifo builds an OutboxItem via from_row); these focus on the accessor,
the run-scoped provider wiring, the new field, and the dry-run preview. Synthetic data only.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry import current_ingest_time
from messagefoundry.config.ingest_time import activated
from messagefoundry.config.run_context import (
    ROUTER,
    TRANSFORM,
    RunContext,
    registered_providers,
    run_contexts,
)
from messagefoundry.config.wiring import MLLP, Registry, build_inbound_connection
from messagefoundry.pipeline import dryrun
from messagefoundry.store import MessageStatus
from messagefoundry.store.store import OutboxItem


def test_returns_none_with_no_active_value() -> None:
    assert current_ingest_time() is None


def test_activated_publishes_and_resets() -> None:
    with activated(1234.5):
        assert current_ingest_time() == 1234.5
    assert current_ingest_time() is None  # restored on exit — no leak


def test_provider_registered() -> None:
    assert "ingest_time" in registered_providers()


@pytest.mark.parametrize("phase", [ROUTER, TRANSFORM])
def test_run_contexts_publishes_ingest_time(phase: str) -> None:
    # Re-run-stable: it's just the RunContext value the runner passes (the row's created_at), in BOTH
    # the router and transform phases.
    with run_contexts(RunContext(ingest_time=42.0), phase=phase):
        assert current_ingest_time() == 42.0
    assert current_ingest_time() is None


def test_run_contexts_none_when_unset() -> None:
    with run_contexts(RunContext(), phase=TRANSFORM):
        assert current_ingest_time() is None


def test_outbox_item_created_at_field() -> None:
    item = OutboxItem(
        id="1",
        message_id="m",
        channel_id="c",
        destination_name=None,
        payload="p",
        attempts=0,
        stage="routed",
        created_at=99.0,
    )
    assert item.created_at == 99.0
    # Defaults to None when a backend doesn't surface it (e.g. SQL Server — no transforms).
    bare = OutboxItem(
        id="1",
        message_id="m",
        channel_id="c",
        destination_name=None,
        payload="p",
        attempts=0,
        stage="outbound",
    )
    assert bare.created_at is None


_captured: list[float | None] = []


def test_dry_run_supplies_ingest_time() -> None:
    _captured.clear()
    reg = Registry()
    reg.add_router("r", lambda msg: ["h"])  # type: ignore[no-untyped-def, arg-type]

    def handler(msg: Any) -> None:
        _captured.append(current_ingest_time())
        return None

    reg.add_handler("h", handler)  # type: ignore[arg-type]
    reg.add_inbound(build_inbound_connection("IB", MLLP(port=2599), router="r"))
    raw = "MSH|^~\\&|S|F|R|F|20260614||ADT^A01|1|P|2.5\rPID|1||M1^^^MR\r"
    result = dryrun.dry_run(reg, raw, inbound="IB")
    # Handler ran (returned None → FILTERED) and saw the preview clock dry_run passed.
    assert result.disposition is MessageStatus.FILTERED
    assert len(_captured) == 1
    assert isinstance(_captured[0], float)
