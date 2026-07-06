# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-connection DR / priority tier resolution (#61, ADR 0048 AC-1): a connection with no priority=
inherits the [delivery].priority global default; an explicit priority= overrides it. The resolution
order is per-connection override > [delivery] global default > built-in NORMAL, applied independently
on inbound + outbound (tiers are independent). The tier's explicit total order (rank) is what the DR
run-profile compares against the threshold."""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.connections_file import load_connections_file
from messagefoundry.config.models import Priority
from messagefoundry.config.wiring import (
    MLLP,
    Registry,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore


def test_priority_rank_total_order() -> None:
    # The explicit total order the run-profile threshold compares against: CRITICAL > NORMAL > LOW.
    assert Priority.CRITICAL.rank > Priority.NORMAL.rank > Priority.LOW.rank
    assert (
        Priority.CRITICAL.rank >= Priority.CRITICAL.rank
    )  # a connection runs iff resolved >= threshold


async def test_priority_inherits_then_overrides(tmp_path: Path) -> None:
    # AC-1: an inbound/outbound declaring no priority= inherits the [delivery].priority global default;
    # an explicit priority= overrides it. Resolved independently for in + out (tiers are independent).
    store = await MessageStore.open(tmp_path / "p.db")
    try:
        reg = Registry()
        reg.add_inbound(build_inbound_connection("in_default", MLLP(port=19101), router="r"))
        reg.add_inbound(
            build_inbound_connection(
                "in_critical", MLLP(port=19102), router="r", priority=Priority.CRITICAL
            )
        )
        reg.add_outbound(
            build_outbound_connection("out_default", MLLP(host="127.0.0.1", port=19201))
        )
        reg.add_outbound(
            build_outbound_connection(
                "out_low", MLLP(host="127.0.0.1", port=19202), priority=Priority.LOW
            )
        )
        reg.add_router("r", lambda m: [])

        # Global default LOW: the un-tagged connections inherit it; the explicit ones override.
        runner = RegistryRunner(reg, store, priority_default=Priority.LOW)
        assert runner.resolved_priority("in_default") is Priority.LOW  # inherits global default
        assert runner.resolved_priority("in_critical") is Priority.CRITICAL  # explicit override
        assert runner.resolved_priority("out_default") is Priority.LOW  # inherits global default
        assert runner.resolved_priority("out_low") is Priority.LOW  # explicit (== default here)

        # A different global default proves it is the inherited value, not a hard-coded NORMAL.
        runner2 = RegistryRunner(reg, store, priority_default=Priority.CRITICAL)
        assert runner2.resolved_priority("in_default") is Priority.CRITICAL
        assert runner2.resolved_priority("out_default") is Priority.CRITICAL
        assert runner2.resolved_priority("out_low") is Priority.LOW  # override still wins

        # Built-in default (no priority_default passed) is NORMAL.
        runner3 = RegistryRunner(reg, store)
        assert runner3.resolved_priority("in_default") is Priority.NORMAL
    finally:
        await store.close()


def test_priority_authored_via_connections_toml(tmp_path: Path) -> None:
    # The priority key is hand-/GUI-editable via connections.toml (ADR 0007), desugared through the same
    # factory into an identical Registry entry — on BOTH inbound and outbound.
    toml = tmp_path / "connections.toml"
    toml.write_text(
        "\n".join(
            [
                "[[inbound]]",
                'name = "IB_ACME_ADT"',
                'transport = "mllp"',
                'router = "r"',
                'priority = "critical"',
                "[inbound.settings]",
                "port = 19301",
                "",
                "[[outbound]]",
                'name = "OB_ACME"',
                'transport = "mllp"',
                'priority = "low"',
                "[outbound.settings]",
                'host = "127.0.0.1"',
                "port = 19302",
            ]
        ),
        encoding="utf-8",
    )
    reg = Registry()
    load_connections_file(toml, reg)
    assert reg.inbound["IB_ACME_ADT"].priority is Priority.CRITICAL
    assert reg.outbound["OB_ACME"].priority is Priority.LOW


def test_priority_invalid_value_in_connections_toml_rejected(tmp_path: Path) -> None:
    toml = tmp_path / "connections.toml"
    toml.write_text(
        "\n".join(
            [
                "[[inbound]]",
                'name = "IB"',
                'transport = "mllp"',
                'router = "r"',
                'priority = "urgent"',  # not a valid tier
                "[inbound.settings]",
                "port = 19401",
            ]
        ),
        encoding="utf-8",
    )
    from messagefoundry.config.wiring import WiringError

    with pytest.raises(WiringError):
        load_connections_file(toml, Registry())
