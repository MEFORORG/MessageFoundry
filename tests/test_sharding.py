# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""L3 per-connection sharding: shard tag, filter_registry_for_shard, shard discovery."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.wiring import (
    MLLP,
    File,
    Registry,
    WiringError,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline.sharding import (
    DEFAULT_SHARD,
    filter_registry_for_shard,
    shard_ids,
    shard_of,
)

_LOGIC_PY = textwrap.dedent(
    """
    from messagefoundry import Send, handler, router

    @router("r")
    def route(msg):
        return ["h"]

    @handler("h")
    def handle(msg):
        return Send("OB", msg)
    """
)


def _inb(name: str, port: int, *, shard: str | None = None):
    return build_inbound_connection(name, MLLP(port=port), router="r", shard=shard)


def _registry() -> Registry:
    """A registry with inbounds spread across shards a/b plus an untagged (default) one, and SHARED
    outbound/router/handler so the filter's sharing contract can be asserted."""
    reg = Registry()
    reg.add_inbound(_inb("ib_a1", 2575, shard="a"))
    reg.add_inbound(_inb("ib_a2", 2576, shard="a"))
    reg.add_inbound(_inb("ib_b1", 2577, shard="b"))
    reg.add_inbound(_inb("ib_default", 2578))  # untagged -> default shard
    reg.add_outbound(build_outbound_connection("ob", File(directory=".")))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: None)
    return reg


def test_shard_of_normalizes_none_to_default() -> None:
    assert shard_of(None) == DEFAULT_SHARD
    assert shard_of("a") == "a"


def test_shard_field_defaults_none_and_threads_through_factory() -> None:
    assert _inb("x", 2575).shard is None
    assert _inb("y", 2576, shard="lab").shard == "lab"


def test_blank_shard_is_rejected() -> None:
    with pytest.raises(WiringError, match="shard must be a non-empty name"):
        _inb("bad", 2575, shard="   ")


def test_shard_ids_discovers_distinct_sorted_with_default() -> None:
    assert shard_ids(_registry()) == ["a", "b", DEFAULT_SHARD]


def test_shard_ids_empty_registry_is_empty() -> None:
    assert shard_ids(Registry()) == []


def test_filter_selects_only_that_shards_inbounds() -> None:
    reg = _registry()
    a = filter_registry_for_shard(reg, "a")
    assert sorted(a.inbound) == ["ib_a1", "ib_a2"]
    b = filter_registry_for_shard(reg, "b")
    assert sorted(b.inbound) == ["ib_b1"]


def test_filter_default_shard_selects_untagged() -> None:
    d = filter_registry_for_shard(_registry(), DEFAULT_SHARD)
    assert sorted(d.inbound) == ["ib_default"]


def test_filter_shares_outbound_routers_handlers() -> None:
    reg = _registry()
    a = filter_registry_for_shard(reg, "a")
    # Logic + delivery are shared across shards: same objects, not copies.
    assert a.outbound is reg.outbound
    assert a.routers is reg.routers
    assert a.handlers is reg.handlers
    assert a.code_sets is reg.code_sets
    assert a.references is reg.references
    assert a.lookups is reg.lookups


def test_filter_is_disjoint_across_shards() -> None:
    reg = _registry()
    a = set(filter_registry_for_shard(reg, "a").inbound)
    b = set(filter_registry_for_shard(reg, "b").inbound)
    d = set(filter_registry_for_shard(reg, DEFAULT_SHARD).inbound)
    assert a.isdisjoint(b) and a.isdisjoint(d) and b.isdisjoint(d)
    # The union of every shard reconstructs the whole inbound set (no message source is dropped).
    assert a | b | d == set(reg.inbound)


def test_filter_unknown_shard_yields_empty_intake_but_shared_logic() -> None:
    reg = _registry()
    empty = filter_registry_for_shard(reg, "nope")
    assert empty.inbound == {}
    assert empty.outbound is reg.outbound  # delivery still shared (not an error here)


def test_filter_does_not_mutate_source() -> None:
    reg = _registry()
    before = dict(reg.inbound)
    filter_registry_for_shard(reg, "a")
    assert reg.inbound == before


def test_connections_toml_desugars_shard(tmp_path: Path) -> None:
    # The data-authored path (connections.toml) sets the same shard tag as the code-first inbound().
    (tmp_path / "logic.py").write_text(_LOGIC_PY, encoding="utf-8")
    (tmp_path / "connections.toml").write_text(
        textwrap.dedent(
            """
            [[outbound]]
            name = "OB"
            transport = "file"
              [outbound.settings]
              directory = "."

            [[inbound]]
            name = "IB_A"
            transport = "mllp"
            router = "r"
            shard = "a"
              [inbound.settings]
              port = 2600

            [[inbound]]
            name = "IB_PLAIN"
            transport = "mllp"
            router = "r"
              [inbound.settings]
              port = 2601
            """
        ),
        encoding="utf-8",
    )
    reg = load_config(tmp_path)
    assert reg.inbound["IB_A"].shard == "a"
    assert reg.inbound["IB_PLAIN"].shard is None
    assert shard_ids(reg) == ["a", DEFAULT_SHARD]


_TWO_SHARD_CFG = textwrap.dedent(
    """
    from messagefoundry import inbound, outbound, router, handler, Send, File

    inbound('IB_A', File(directory={inbox!r}, pattern='*.hl7', poll_seconds=0.02),
            router='r', shard='a')
    inbound('IB_B', File(directory={inbox!r}, pattern='*.hl7', poll_seconds=0.02),
            router='r', shard='b')
    outbound('OB', File(directory={outdir!r}, filename='{{MSH-10}}.hl7'))

    @router('r')
    def route(msg):
        return ['h']

    @handler('h')
    def handle(msg):
        return Send('OB', msg)
    """
)


async def test_engine_reload_reapplies_shard_filter(tmp_path: Path) -> None:
    # A `serve --shard a` engine must keep owning only shard a's inbounds across a reload — the filter
    # is re-applied inside Engine.reload, not just at startup.
    from messagefoundry.pipeline import Engine

    inbox, outdir, cfg = tmp_path / "in", tmp_path / "out", tmp_path / "cfg"
    inbox.mkdir()
    outdir.mkdir()
    cfg.mkdir()
    (cfg / "c.py").write_text(
        _TWO_SHARD_CFG.format(inbox=str(inbox), outdir=str(outdir)), encoding="utf-8"
    )

    def only_a(reg: Registry) -> Registry:
        return filter_registry_for_shard(reg, "a")

    eng = await Engine.create(tmp_path / "e.db", poll_interval=0.02, registry_filter=only_a)
    try:
        eng.add_registry(only_a(load_config(cfg)))
        await eng.start()
        assert eng.registry_runner is not None
        assert set(eng.registry_runner.registry.inbound) == {"IB_A"}
        # Reload the SAME (whole) config dir — the engine must re-filter to shard a, not pick up IB_B.
        await eng.reload(cfg)
        assert set(eng.registry_runner.registry.inbound) == {"IB_A"}
        # The shared outbound is still present (delivery is shared, not partitioned).
        assert "OB" in eng.registry_runner.registry.outbound
    finally:
        await eng.stop()
