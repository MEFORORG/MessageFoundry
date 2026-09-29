# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Sealed read-through caches (BACKLOG #1174, ASVS 11.7.2; the in-process half of #1185's cache limb).

The transform-state and reference caches used to hold every live key's DECRYPTED value for the store's
lifetime. They now hold ciphertext under a per-process key and decrypt inside the synchronous accessor.
These tests pin the four properties the change rests on:

* no value is held in plaintext, in the unit and in a real store after writes and after a reopen;
* a read never misses (the correctness trap an evicting design falls into);
* a point-in-time snapshot and the sandbox encoder read each value at most once, never re-decrypting
  the whole table;
* the keyless-open refusal still fires at open, not inside a Handler.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
from cryptography.exceptions import InvalidTag

from messagefoundry.config.reference import activated as reference_activated
from messagefoundry.config.reference import reference
from messagefoundry.config.state import activated as state_activated
from messagefoundry.config.state import state_get
from messagefoundry.pipeline._sandbox_codec import _Blobs, _enc_table
from messagefoundry.store import sealed_cache
from messagefoundry.store.crypto import StoreKeylessError, generate_key, make_cipher
from messagefoundry.store.sealed_cache import (
    SealedDict,
    new_reference_set,
    new_state_cache,
    point_in_time,
    sealed_reference_set,
)
from messagefoundry.store.store import MessageStatus, MessageStore, Stage

RAW = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^JANE\r"
SECRET = "ANON-SECRET-7731"


def _blobs(cache: Any) -> list[bytes]:
    """The raw stored entries of a sealed cache (white box, by necessity: the property under test is
    what is resident, which no public read can show without decrypting)."""
    assert isinstance(cache, SealedDict), type(cache)
    return list(cache._data.values())


@pytest.fixture
def count_opens(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[int]]:
    """Count every decrypt the process sealer performs."""
    sealer = sealed_cache._process_sealer()
    real_open = sealer.open
    calls = [0]

    def counting_open(blob: bytes, aad: bytes) -> bytes:
        calls[0] += 1
        return real_open(blob, aad)

    monkeypatch.setattr(sealer, "open", counting_open)
    yield calls


# --- unit: the mapping itself --------------------------------------------------


def test_values_are_ciphertext_and_read_back_exactly() -> None:
    cache = new_state_cache()
    value = {"mrn": "123456789", "name": "DOE^JANE", "n": 3, "flags": [True, None]}
    cache[("ns", "k")] = value
    assert cache[("ns", "k")] == value
    blob = _blobs(cache)[0]
    assert b"123456789" not in blob and b"DOE" not in blob
    # Control: the same bytes ARE findable in the plaintext encoding, so the check above can fail.
    assert b"123456789" in json.dumps(value).encode()


def test_each_read_is_a_fresh_copy_so_a_handler_cannot_mutate_the_cache() -> None:
    cache = new_state_cache()
    cache[("ns", "k")] = {"seen": ["a"]}
    got = cache[("ns", "k")]
    got["seen"].append("tampered")
    assert cache[("ns", "k")] == {"seen": ["a"]}


def test_reads_never_miss_a_present_key() -> None:
    cache = new_state_cache()
    for i in range(500):
        cache[("ns", f"k{i}")] = i
    assert all(cache.get(("ns", f"k{i}")) == i for i in range(500))
    assert cache.get(("ns", "absent"), "dflt") == "dflt"
    with pytest.raises(KeyError):
        cache[("ns", "absent")]


def test_mapping_operations_match_a_dict() -> None:
    cache = new_state_cache()
    cache[("a", "1")] = "x"
    cache[("b", "2")] = "y"
    assert len(cache) == 2 and ("a", "1") in cache and ("z", "9") not in cache
    assert set(cache) == {("a", "1"), ("b", "2")}
    assert cache == {("a", "1"): "x", ("b", "2"): "y"}
    assert cache.setdefault(("a", "1"), "ignored") == "x"
    assert cache.setdefault(("c", "3"), "z") == "z"
    assert cache.pop(("c", "3")) == "z"
    assert cache.pop(("c", "3"), None) is None
    with pytest.raises(KeyError):
        cache.pop(("c", "3"))
    del cache[("b", "2")]
    assert dict(cache) == {("a", "1"): "x"}
    cache.clear()
    assert len(cache) == 0


def test_repr_never_carries_a_value() -> None:
    cache = new_state_cache()
    cache[("ns", "k")] = SECRET
    assert SECRET not in repr(cache)
    assert "entries=1" in repr(cache)


def test_ciphertext_is_bound_to_its_key() -> None:
    cache = new_state_cache()
    cache[("ns", "a")] = "value-a"
    cache[("ns", "b")] = "value-b"
    # Swap the two stored entries: each must now refuse to open under the other's key.
    cache._data[("ns", "a")], cache._data[("ns", "b")] = (
        cache._data[("ns", "b")],
        cache._data[("ns", "a")],
    )
    with pytest.raises(InvalidTag):
        cache[("ns", "a")]


def test_reference_sets_are_bound_to_their_set_name() -> None:
    one = new_reference_set("one")
    two = new_reference_set("two")
    one["k"] = "from-one"
    two._data["k"] = one._data["k"]
    with pytest.raises(InvalidTag):
        two["k"]


def test_every_seal_uses_a_new_nonce() -> None:
    cache = new_state_cache()
    nonces = set()
    for _ in range(200):
        cache[("ns", "k")] = "same"
        nonces.add(_blobs(cache)[0][:12])
    assert len(nonces) == 200


def test_a_forked_child_keeps_the_key_and_moves_to_a_new_nonce_space() -> None:
    sealer = sealed_cache._process_sealer()
    cache = new_state_cache()
    cache[("ns", "k")] = "before"
    prefix = sealer._prefix
    try:
        sealed_cache._after_fork_in_child()
        assert sealer._prefix != prefix
        assert cache[("ns", "k")] == "before"  # inherited entries still open
        cache[("ns", "k2")] = "after"
        assert cache[("ns", "k2")] == "after"
    finally:
        sealer._prefix = prefix


def test_sealed_reference_set_seals_pre_encoded_text() -> None:
    cache = sealed_reference_set("codes", [("A", json.dumps("1")), ("B", json.dumps({"x": 2}))])
    assert dict(cache) == {"A": "1", "B": {"x": 2}}


def test_point_in_time_copies_ciphertext_and_decrypts_nothing(count_opens: list[int]) -> None:
    cache = new_state_cache()
    for i in range(50):
        cache[("ns", f"k{i}")] = i
    snap = point_in_time(MappingProxyType(cache))
    assert count_opens[0] == 0
    cache[("ns", "k0")] = "changed-after"
    del cache[("ns", "k1")]
    assert snap[("ns", "k0")] == 0 and snap[("ns", "k1")] == 1  # frozen at the copy
    assert isinstance(snap, MappingProxyType)


def test_point_in_time_of_a_plain_mapping_is_a_dict_copy() -> None:
    plain = {("ns", "k"): 1}
    snap = point_in_time(MappingProxyType(plain))
    plain[("ns", "k")] = 2
    assert snap[("ns", "k")] == 1


def test_sandbox_table_encoder_reads_each_entry_once(count_opens: list[int]) -> None:
    table = sealed_reference_set("codes", [(f"k{i}", json.dumps(f"v{i}")) for i in range(40)])
    encoded = _enc_table("reference set", table, _Blobs())
    assert encoded == {"s": {f"k{i}": f"v{i}" for i in range(40)}}
    assert count_opens[0] == 40


# --- integration: a real SQLite store --------------------------------------------


async def _route_one_handler(store: MessageStore) -> tuple[str, str]:
    mid = await store.enqueue_ingress(channel_id="IB", raw=RAW)
    ingress = await store.claim_next_fifo("IB", stage=Stage.INGRESS.value)
    assert ingress is not None
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id="IB",
        handlers=[("h", RAW)],
        disposition=MessageStatus.ROUTED,
    )
    routed = await store.claim_next_fifo("IB", stage=Stage.ROUTED.value)
    assert routed is not None
    return mid, routed.id


async def test_store_caches_hold_no_plaintext_after_write_and_after_reopen(
    tmp_path: Path,
) -> None:
    db = tmp_path / "sealed.db"
    key = generate_key()
    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        mid, routed_id = await _route_one_handler(store)
        await store.transform_handoff(
            routed_id=routed_id,
            message_id=mid,
            channel_id="IB",
            deliveries=[("OB_A", "payload")],
            state_ops=[("patient_anon", "MRN1", SECRET)],
        )
        await store.write_reference_snapshot(
            name="providers", version="v1", rows={"NPI1": {"name": SECRET}}
        )
        for blob in _blobs(store._state_cache) + _blobs(store._reference_cache["providers"]):
            assert SECRET.encode() not in blob
        with state_activated(store.state_view()), reference_activated(store.reference_view()):
            assert state_get("patient_anon", "MRN1") == SECRET
            assert reference("providers").get("NPI1") == {"name": SECRET}
    finally:
        await store.close()

    reopened = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        for blob in _blobs(reopened._state_cache) + _blobs(reopened._reference_cache["providers"]):
            assert SECRET.encode() not in blob
        with state_activated(reopened.state_view()), reference_activated(reopened.reference_view()):
            assert state_get("patient_anon", "MRN1") == SECRET
            assert reference("providers").get("NPI1") == {"name": SECRET}
    finally:
        await reopened.close()


async def test_a_reference_value_reads_the_same_before_and_after_a_reopen(tmp_path: Path) -> None:
    """The cache used to hand back the writer's own Python object until a restart, and the JSON form
    after one. Sealing makes both reads the JSON form."""
    import datetime

    db = tmp_path / "ref.db"
    store = await MessageStore.open(db)
    try:
        rows = {"k": {"effective": datetime.date(2026, 1, 1)}}
        await store.write_reference_snapshot(name="codes", version="v1", rows=rows)
        before = store.reference_view()["codes"]["k"]
    finally:
        await store.close()
    reopened = await MessageStore.open(db)
    try:
        assert before == reopened.reference_view()["codes"]["k"] == {"effective": "2026-01-01"}
    finally:
        await reopened.close()


# --- the two server backends, offline --------------------------------------------
#
# Their live suites need a database and skip locally, so the load and converge paths this change edits
# are driven here against a fake `_fetchall` on a store built without a connection pool.


def _server_rows(cipher: Any) -> dict[str, list[dict[str, Any]]]:
    from messagefoundry.store.crypto import cell_aad

    def enc(value: Any, *aad: Any) -> str:
        return str(cipher.encrypt(json.dumps(value), aad=cell_aad(*aad)))

    return {
        "state_version": [{"namespace": "ns", "version": 2}],
        "state": [
            {"namespace": "ns", "key": "MRN1", "value": enc(SECRET, "state", "value", "ns", "MRN1")}
        ],
        "state_ns": [{"key": "MRN2", "value": enc("second", "state", "value", "ns", "MRN2")}],
        "reference": [
            {
                "name": "providers",
                "version": "v1",
                "key": "NPI1",
                "value": enc(SECRET, "reference", "value", "providers", "v1", "NPI1"),
            },
            {"name": "empty", "version": "v1", "key": None, "value": None},
        ],
    }


def _bare_server_store(backend: str, cipher: Any) -> Any:
    if backend == "postgres":
        from messagefoundry.store.postgres import PostgresStore as cls
    else:
        from messagefoundry.store.sqlserver import SqlServerStore as cls  # type: ignore[assignment]
    store = object.__new__(cls)
    store._cipher = cipher
    store._state_cache = new_state_cache()
    store._reference_cache = {}
    store._reference_versions = {}
    store._state_versions = {}
    rows = _server_rows(cipher)

    async def fake_fetchall(sql: str, *_params: Any) -> list[dict[str, Any]]:
        if "FROM reference_version" in sql:
            return rows["reference"]
        if "FROM state_version" in sql:
            return rows["state_version"]
        if "WHERE namespace" in sql:
            return rows["state_ns"]
        return rows["state"]

    store._fetchall = fake_fetchall  # type: ignore[method-assign]
    return store


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_server_backends_load_sealed_caches(backend: str) -> None:
    store = _bare_server_store(backend, make_cipher(generate_key()))
    await store._load_state_cache()
    await store._load_reference_cache()
    assert isinstance(store._state_cache, SealedDict)
    assert store._state_cache[("ns", "MRN1")] == SECRET
    assert isinstance(store._reference_cache["providers"], SealedDict)
    assert store._reference_cache["providers"]["NPI1"] == SECRET
    assert dict(store._reference_cache["empty"]) == {}  # an empty snapshot stays present
    for blob in _blobs(store._state_cache) + _blobs(store._reference_cache["providers"]):
        assert SECRET.encode() not in blob


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_server_backends_still_refuse_a_keyless_open(backend: str) -> None:
    store = _bare_server_store(backend, make_cipher(generate_key()))
    store._cipher = make_cipher(None)  # the rows were written under a key; the open has none
    with pytest.raises(StoreKeylessError):
        await store._load_state_cache()
    with pytest.raises(StoreKeylessError):
        await store._load_reference_cache()


async def test_postgres_follower_convergence_keeps_the_caches_sealed() -> None:
    store = _bare_server_store("postgres", make_cipher(generate_key()))
    assert await store.converge_state_cache() == ["ns"]
    assert await store.converge_reference_cache() == ["providers", "empty"]
    assert isinstance(store._state_cache, SealedDict)
    assert store._state_cache[("ns", "MRN2")] == "second"
    assert isinstance(store._reference_cache["providers"], SealedDict)
    assert store._reference_cache["providers"]["NPI1"] == SECRET


async def test_keyless_open_of_an_encrypted_store_still_fails_at_open(tmp_path: Path) -> None:
    db = tmp_path / "keyless.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        mid, routed_id = await _route_one_handler(store)
        await store.transform_handoff(
            routed_id=routed_id,
            message_id=mid,
            channel_id="IB",
            deliveries=[("OB_A", "payload")],
            state_ops=[("ns", "k", "v")],
        )
    finally:
        await store.close()
    with pytest.raises(StoreKeylessError, match="state"):
        await MessageStore.open(db)
