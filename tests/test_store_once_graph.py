# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The store-once-deliver-many SUT graph (``harness/config/store_once``).

Verifies the **dedup-triggering shape**: ONE handler returning ``list[Send]`` of the IDENTICAL body to
N destinations — a single ``transform_handoff`` with N deliveries carrying the same bytes, which is the
exact shape store-once-deliver-many (L2b) keys on. Contrast the load graph
(``harness/config/load``), which fans out via N separate handlers with per-destination *distinct*
bodies and therefore stores each inline (no dedup). The store-side dedup itself is covered by
``tests/test_store_once_deliver_many.py``; this asserts the *graph produces the right shape*.
"""

from __future__ import annotations

import pytest

from messagefoundry.config.wiring import load_config
from messagefoundry.generators import _core, all_types  # noqa: F401  (registers message types)
from messagefoundry.parsing import normalize
from messagefoundry.pipeline.dryrun import dry_run

_CONFIG = "harness/config/store_once"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "MEFOR_LOAD_FANOUT",
        "MEFOR_LOAD_SINK_HOST",
        "MEFOR_LOAD_SINK_PORT",
        "MEFOR_LOAD_SINK_PORTS",
        "MEFOR_LOAD_ADT_PORT",
    ):
        monkeypatch.delenv(key, raising=False)


def test_graph_loads_one_inbound_one_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_LOAD_FANOUT", "20")
    reg = load_config(_CONFIG)
    reg.validate()
    assert set(reg.inbound) == {"IB_StoreOnce"}
    # The crux: a SINGLE handler does the fan-out (one transform_handoff), NOT N handlers.
    assert set(reg.handlers) == {"fanout_identical_body"}


def test_one_handler_fans_identical_body_to_n_dests(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_LOAD_FANOUT", "20")
    reg = load_config(_CONFIG)
    msg = _core.generate_message("ADT", "A01", 1)
    result = dry_run(reg, msg, inbound="IB_StoreOnce")
    assert len(result.deliveries) == 20
    assert sorted(d.to for d in result.deliveries) == [f"OB_StoreOnce_{i:02d}" for i in range(20)]
    # The dedup key: every delivery carries the IDENTICAL body (content-addressed → store once).
    bodies = {normalize(d.payload) for d in result.deliveries}
    assert len(bodies) == 1, (
        "store-once needs identical bodies across deliveries; got distinct payloads"
    )
    assert next(iter(bodies)) == normalize(
        msg
    )  # no per-dest transform → the received body, verbatim


def test_fanout_env_controls_dest_count(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_LOAD_FANOUT", "5")
    reg = load_config(_CONFIG)
    result = dry_run(reg, _core.generate_message("ADT", "A01", 1), inbound="IB_StoreOnce")
    assert len(result.deliveries) == 5
    assert len({normalize(d.payload) for d in result.deliveries}) == 1
