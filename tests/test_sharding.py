# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""L3 per-connection sharding: shard tag, filter_registry_for_shard, shard discovery."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.wiring import (
    MLLP,
    FhirLookupSpec,
    File,
    Registry,
    WiringError,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.config.settings import StoreBackend
from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline.sharding import (
    DEFAULT_SHARD,
    filter_registry_for_shard,
    owned_destination_set,
    owner_shard_of_destination,
    require_unified_store,
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


# --- no-split-store guard (require_unified_store, ADR 0063) ------------------


def test_require_unified_store_refuses_multi_shard_sqlite() -> None:
    with pytest.raises(ValueError, match="server-DB"):
        require_unified_store(StoreBackend.SQLITE, ["a", "b"])


def test_require_unified_store_allows_single_or_no_shard_on_sqlite() -> None:
    # One shard (or an untagged single-shard config) is one process, one store — allowed on SQLite.
    require_unified_store(StoreBackend.SQLITE, [DEFAULT_SHARD])
    require_unified_store(StoreBackend.SQLITE, ["a", "a"])  # dupes collapse to one distinct shard
    require_unified_store(StoreBackend.SQLITE, [])


def test_require_unified_store_allows_multi_shard_on_server_db() -> None:
    # Server DBs unify the store (every shard connects to the same database) — sharding is allowed.
    require_unified_store(StoreBackend.POSTGRES, ["a", "b"])
    require_unified_store(StoreBackend.SQLSERVER, ["a", "b", "c"])


def test_discover_shard_specs_runs_the_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    # discover_shard_specs must enforce the guard with the passed backend: a multi-shard SQLite config is
    # refused before any subprocess spec is built; the same config on a server DB builds specs normally.
    from messagefoundry.pipeline import supervisor

    monkeypatch.setattr(supervisor, "load_config", lambda cfg: _registry())
    with pytest.raises(ValueError, match="server-DB"):
        supervisor.discover_shard_specs(
            "cfg", store_backend=StoreBackend.SQLITE, db_base="m.db", base_port=8765
        )
    specs = supervisor.discover_shard_specs(
        "cfg", store_backend=StoreBackend.POSTGRES, db_base="m.db", base_port=8765
    )
    assert {s.shard for s in specs} == {"a", "b", DEFAULT_SHARD}


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


# --- outbound-lane ownership (owner_shard_of_destination, ADR 0073) ----------


def test_owner_is_deterministic_across_repeated_calls() -> None:
    ids = ["a", "b", "c"]
    for dest in ("OB_ACME_ADT", "OB_LAB_ORU", "ob"):
        owners = {owner_shard_of_destination(dest, ids) for _ in range(10)}
        assert len(owners) == 1  # same inputs -> same owner, every call


def test_owner_is_independent_of_universe_order_and_duplicates() -> None:
    # Rendezvous hashing must depend on the SET of shard ids, not the sequence handed in — every
    # process derives the same owner regardless of how its config happened to enumerate shards.
    base = owner_shard_of_destination("OB_ACME_ADT", ["a", "b", "c"])
    for ids in (["c", "b", "a"], ["b", "a", "c"], ["a", "a", "b", "c", "c"]):
        assert owner_shard_of_destination("OB_ACME_ADT", ids) == base


def test_owner_golden_values_pin_the_hash_scheme() -> None:
    # Hard-coded owners computed from the shipped sha256 rendezvous scheme. Ownership must be
    # restart-stable ACROSS VERSIONS (recovery + single-consumer gates key off it), so an accidental
    # change to the hash input format / algorithm must fail this test loudly.
    assert owner_shard_of_destination("OB_ACME_ADT", ["a", "b", "c"]) == "c"
    assert owner_shard_of_destination("OB_LAB_ORU", ["a", "b", "c"]) == "c"
    assert owner_shard_of_destination("ob", ["shard1", "shard2"]) == "shard1"
    assert owner_shard_of_destination("OB_UNICODE_éè☃", ["a", "b", "c", "d"]) == "b"


def test_owner_raises_on_empty_universe() -> None:
    with pytest.raises(ValueError, match="empty shard universe"):
        owner_shard_of_destination("OB", [])


def test_owner_is_total_over_arbitrary_lane_names() -> None:
    # A destination dropped from config but still draining queued rows keeps exactly one owner — the
    # function must be total over ANY string, including names in no registry and unicode.
    ids = ["a", "b"]
    assert owner_shard_of_destination("ghost-dest not in any registry", ids) == "b"
    for dest in ("", " ", "\x00weird", "éè☃", "OB|caret^tilde~"):
        assert owner_shard_of_destination(dest, ids) in ids


def _registry_with_outbounds(names: list[str]) -> Registry:
    reg = Registry()
    for name in names:
        reg.add_outbound(build_outbound_connection(name, File(directory=".")))
    return reg


def test_ownership_partitions_all_destinations_exactly_once() -> None:
    # Every outbound lane has EXACTLY one owner: the per-shard owned sets are pairwise disjoint and
    # their union covers the whole outbound map (no lane is orphaned, none double-claimed).
    ids = ["a", "b", "c"]
    names = [f"OB_{i:02d}" for i in range(20)]
    reg = _registry_with_outbounds(names)
    owned = {shard: owned_destination_set(reg, shard, ids) for shard in ids}
    for shard, dests in owned.items():
        for dest in dests:
            assert owner_shard_of_destination(dest, ids) == shard
    all_owned = sorted(d for dests in owned.values() for d in dests)
    assert all_owned == sorted(names)  # union covers everything AND no duplicates (disjoint)


def test_adding_a_destination_moves_no_other_lane() -> None:
    ids = ["a", "b", "c"]
    names = [f"OB_{i:02d}" for i in range(20)]
    before = {d: owner_shard_of_destination(d, ids) for d in names}
    # Add a destination to the registry: ownership is per-lane, so every existing lane keeps its owner.
    reg = _registry_with_outbounds([*names, "OB_BRAND_NEW"])
    for shard in ids:
        for dest in owned_destination_set(reg, shard, ids):
            if dest != "OB_BRAND_NEW":
                assert before[dest] == shard


def test_adding_a_shard_moves_only_lanes_the_new_shard_wins() -> None:
    # Minimal disruption: growing the universe from {a,b,c} to {a,b,c,d} may reassign a lane ONLY
    # to the new shard 'd' — a lane never migrates between the pre-existing shards.
    names = [f"OB_{i:02d}" for i in range(20)]
    before = {d: owner_shard_of_destination(d, ["a", "b", "c"]) for d in names}
    after = {d: owner_shard_of_destination(d, ["a", "b", "c", "d"]) for d in names}
    moved = {d for d in names if after[d] != before[d]}
    assert all(after[d] == "d" for d in moved)
    assert (
        moved
    )  # sanity: with 20 lanes, ~1/4 should move to 'd' (zero would make the test vacuous)


# --- shard identity on the filtered registry (ADR 0073) ----------------------


def test_filter_attaches_shard_identity_on_multi_shard_config() -> None:
    reg = _registry()  # shards a, b + untagged default -> 3 distinct ids
    a = filter_registry_for_shard(reg, "a")
    assert a.shard_id == "a"
    # The pinned universe is ALL ids from the UNFILTERED config, sorted, as a tuple.
    assert a.all_shard_ids == ("a", "b", DEFAULT_SHARD)
    assert filter_registry_for_shard(reg, "b").shard_id == "b"


def test_filter_attaches_identity_even_for_shard_with_no_inbounds() -> None:
    # A shard id matching no inbound still gets the identity: an empty-intake shard can still own
    # outbound lanes (recovery + delivery gates need shard_id + the full universe regardless).
    reg = _registry()
    ghost = filter_registry_for_shard(reg, "nope")
    assert ghost.inbound == {}
    assert ghost.shard_id == "nope"
    assert ghost.all_shard_ids == ("a", "b", DEFAULT_SHARD)


def test_filter_single_shard_config_attaches_no_identity() -> None:
    # Single-shard (tagged or untagged) stays byte-identical to plain `serve`: no sharded-mode
    # behaviors arm, so neither identity field is set.
    tagged = Registry()
    tagged.add_inbound(_inb("ib1", 2575, shard="only"))
    tagged.add_inbound(_inb("ib2", 2576, shard="only"))
    f = filter_registry_for_shard(tagged, "only")
    assert f.shard_id is None and f.all_shard_ids is None

    untagged = Registry()
    untagged.add_inbound(_inb("ib3", 2577))
    d = filter_registry_for_shard(untagged, DEFAULT_SHARD)
    assert d.shard_id is None and d.all_shard_ids is None


def test_source_registry_identity_defaults_none_and_is_untouched() -> None:
    reg = _registry()
    assert reg.shard_id is None and reg.all_shard_ids is None
    filter_registry_for_shard(reg, "a")
    assert reg.shard_id is None and reg.all_shard_ids is None  # filter never mutates the source


def test_filter_carries_fhir_lookups_through() -> None:
    # Regression: filter_registry_for_shard used to DROP fhir_lookups (rebuilt the Registry without
    # them), silently disarming every shard's FHIR read executor. They must ride along shared by
    # reference like the SQL lookups.
    reg = _registry()
    reg.add_fhir_lookup(FhirLookupSpec(name="clarity_fhir", settings={"url": "https://h/fhir"}))
    a = filter_registry_for_shard(reg, "a")
    assert a.fhir_lookups is reg.fhir_lookups
    assert "clarity_fhir" in a.fhir_lookups
