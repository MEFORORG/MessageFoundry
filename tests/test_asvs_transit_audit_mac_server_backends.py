# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""13.3.3 RIDER — the isolated-module (Vault Transit) audit MAC on the SERVER store backends.

``TransitCipher.audit_mac_key()`` returns ``None`` by design (the DEK never enters heap; the MAC is
computed inside the vault via ``audit_mac_fn``). ``open_store`` used to hand ``audit_mac_fn`` to the
SQLite backend ONLY, so a ``cipher_provider = "vault_transit"`` deployment on Postgres / SQL Server had
no keying secret in hand at all: the audit chain ran **fully unkeyed**, while the deployment posture
claimed the most isolated MAC the product offers.

This suite pins the wiring end to end without a live server. The five seams the fix has to cover are
each asserted: ``open`` accepts and stores it, ``_audit_keyed_capable`` sees it, ``load_audit_chain``
writes a fresh store's genesis row on it, ``_audit_append_mac`` prefers it, and ``verify_audit_chain`` passes
``mac=`` so a Transit-keyed chain actually verifies. Wiring ``open`` alone would produce a store that
ACCEPTS an ``audit_mac_fn`` and still writes a keyless chain — the worst outcome, because it looks fixed.

This lane does NOT claim cell 13.3.3 (it stays a register item in the #280 packet); this is the code +
tests half of the rider.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
from typing import Any

import pytest

from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.store.base import open_store
from messagefoundry.store.store import (
    AUDIT_KEY_EPOCH_ACTION,
    AUDIT_TRANSIT_KEY_ID,
    audit_active_key_id,
    audit_genesis_detail,
    audit_next_link,
    audit_row_hash,
    build_audit_mac_keys,
    load_audit_chain,
    parse_audit_genesis,
)

BACKENDS: list[str] = ["postgres", "sqlserver"]

#: A stand-in for Vault Transit's ``generate_hmac``: a distinct, recognisable MAC shape that could not
#: be produced by either the keyless SHA-256 chain or the in-heap HMAC path.
_STUB_MAC_KEY = b"transit-stub-key" * 2


def stub_transit_mac(data: bytes) -> str:
    return "vault:v1:" + hmac.new(_STUB_MAC_KEY, data, hashlib.sha256).hexdigest()


def _store_class(backend: str) -> Any:
    module = importlib.import_module(f"messagefoundry.store.{backend}")
    return getattr(module, "PostgresStore" if backend == "postgres" else "SqlServerStore")


def _bare(backend: str, *, mac_fn: Any = None, mac_key: bytes | None = None) -> Any:
    """A server store with no pool: only the audit state ``__init__`` and the open would have set.
    The chain is not yet read, so ``_audit_chain_keyed`` is False until a test sets or loads it."""
    store = object.__new__(_store_class(backend))
    store._audit_mac_key = mac_key
    store._audit_mac_fn = mac_fn
    store._audit_chain_keyed = False
    store._audit_chain_unkeyed = False
    # BACKLOG #1904: the audit keyring and the key ranges `__init__` / open would have set.
    store._audit_mac_keys = build_audit_mac_keys(None, mac_key)
    store._audit_range_key_id = audit_active_key_id(mac_key, mac_fn)
    store._audit_range_from = None
    store._audit_range_keys = []
    store._audit_ranges_trusted = True
    return store


def chained_rows(
    actions: list[tuple[str, str | None]], *, key: bytes | None = None, mac: Any = None
) -> list[dict[str, Any]]:
    """``audit_log`` rows as a backend's ``_audit_rows`` returns them: ``(action, detail)`` pairs
    chained in order from sequence number 1, hashed under ``key`` or ``mac`` (or keyless)."""
    rows: list[dict[str, Any]] = []
    prev = ""
    for seq, (action, detail) in enumerate(actions, start=1):
        row: dict[str, Any] = {
            "id": seq,
            "seq": seq,
            "ts": float(seq),
            "actor": "u",
            "action": action,
            "channel_id": None,
            "detail": detail,
            "client": None,
        }
        prev = audit_row_hash(
            prev,
            seq=seq,
            ts=row["ts"],
            actor=row["actor"],
            action=action,
            channel_id=None,
            detail=detail,
            client=None,
            key=key,
            mac=mac,
        )
        row["row_hash"] = prev
        rows.append(row)
    return rows


def serve_rows(store: Any, rows: list[dict[str, Any]]) -> None:
    """Make ``store`` read and append ``rows`` as its ``audit_log``. Both chain reads go through
    ``_fetchall``; the range-row read filters on the action, so it gets the key-epoch rows after the
    genesis row. ``record_audit`` appends to the same list, as the open's genesis write needs."""

    async def _fetchall(sql: str, *args: Any, **_kw: Any) -> list[dict[str, Any]]:
        if "WHERE action" in sql:
            return [r for r in rows if r["action"] == AUDIT_KEY_EPOCH_ACTION and int(r["seq"]) > 1]
        return rows

    async def record_audit(
        action: str,
        *,
        actor: str | None = None,
        channel_id: str | None = None,
        detail: str | None = None,
        client: str | None = None,
        now: float | None = None,
        expect_prev: str | None = None,
    ) -> None:
        """The backend's append, without its SQL: the shared link and hash, the handle's own key."""
        head = (rows[-1]["seq"], rows[-1]["row_hash"]) if rows else None
        seq, prev = audit_next_link(head, expect_prev)
        key, mac = store._audit_append_mac()
        ts = 1.0 if now is None else now
        row_hash = audit_row_hash(
            prev,
            seq=seq,
            ts=ts,
            actor=actor,
            action=action,
            channel_id=channel_id,
            detail=detail,
            client=client,
            key=key,
            mac=mac,
        )
        rows.append(
            {
                "id": seq,
                "seq": seq,
                "ts": ts,
                "actor": actor,
                "action": action,
                "channel_id": channel_id,
                "detail": detail,
                "client": client,
                "row_hash": row_hash,
            }
        )

    store._fetchall = _fetchall
    store.record_audit = record_audit


# --- seam 1: open_store threads audit_mac_fn into BOTH server backends -------


@pytest.mark.parametrize(
    ("backend", "attr", "module"),
    [
        (StoreBackend.SQLSERVER, "SqlServerStore", "messagefoundry.store.sqlserver"),
        (StoreBackend.POSTGRES, "PostgresStore", "messagefoundry.store.postgres"),
    ],
)
async def test_open_store_threads_audit_mac_fn_into_the_server_backend(
    backend: StoreBackend, attr: str, module: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rider's headline: ``open_store`` must hand the server backends the Transit MAC, not just the
    (always-``None``-under-Transit) ``audit_mac_key``."""
    seen: dict[str, Any] = {}

    class _StubTransitCipher:
        encrypts = True

        def encrypt(self, plaintext: str, *, aad: bytes | None = None) -> str:
            return plaintext

        def decrypt(self, stored: str, *, aad: bytes | None = None) -> str:
            return stored

        def is_encrypted(self, stored: str) -> bool:
            return False

        def audit_mac_key(self) -> bytes | None:
            return None  # Transit's contract: no in-heap key, ever

        def audit_mac_fn(self) -> Any:
            return stub_transit_mac

    async def _fake_open(_settings: StoreSettings, **kwargs: Any) -> object:
        seen.update(kwargs)
        return object()

    monkeypatch.setattr(
        "messagefoundry.store.base.build_store_cipher", lambda _s: _StubTransitCipher()
    )
    store_module = importlib.import_module(module)
    monkeypatch.setattr(getattr(store_module, attr), "open", _fake_open)

    # A settings object valid enough to construct; the real `.open` is stubbed out, so nothing dials.
    await open_store(
        StoreSettings(
            backend=backend, server="localhost", database="mefor_test", username="mefor_test"
        ),
        keyless_chain_refusal=None,
    )

    assert seen["audit_mac_key"] is None, (
        "Transit supplies no in-heap key — that is the whole point"
    )
    assert seen["audit_mac_fn"] is stub_transit_mac, (
        f"{attr}.open was not given the isolated-module MAC; its audit chain would run UNKEYED"
    )


# --- seams 2-5: the backend actually USES it ---------------------------------


@pytest.mark.parametrize("backend", BACKENDS)
def test_keyed_capable_is_true_on_the_transit_mac_alone(backend: str) -> None:
    # Seam 2. Gating on `_audit_mac_key is None` (the pre-fix predicate) would be False here, so the
    # fresh-store auto-key below would never fire.
    assert _bare(backend, mac_fn=stub_transit_mac)._audit_keyed_capable() is True
    assert _bare(backend, mac_key=b"k" * 32)._audit_keyed_capable() is True
    assert _bare(backend)._audit_keyed_capable() is False


@pytest.mark.parametrize("backend", BACKENDS)
def test_append_mac_prefers_the_isolated_module_over_an_in_heap_key(backend: str) -> None:
    # Seam 3. An appended row must be MAC'd inside the module, whatever the chain holds.
    store = _bare(backend, mac_fn=stub_transit_mac, mac_key=b"k" * 32)
    key, mac = store._audit_append_mac()
    assert key is None and mac is stub_transit_mac


@pytest.mark.parametrize("backend", BACKENDS)
def test_a_handle_that_holds_the_transit_mac_never_appends_a_keyless_row(backend: str) -> None:
    """The rule comes from what the handle holds, not from a row in the database (vault BACKLOG
    #2594). With the MAC in hand every append is keyed, on a chain not yet read as keyed too. The
    control is a handle with no secret on a keyless chain, which is the keyless store mode."""
    assert _bare(backend, mac_fn=stub_transit_mac)._audit_append_mac() == (None, stub_transit_mac)
    assert _bare(backend)._audit_append_mac() == (None, None)


@pytest.mark.parametrize("backend", BACKENDS)
def test_append_mac_fails_closed_when_keyed_but_no_secret_is_in_hand(backend: str) -> None:
    # A keyed chain opened writable without its key/vault must REFUSE, not append a keyless row to
    # it (which a keyed verify reports as a break).
    store = _bare(backend)
    store._audit_chain_keyed = True
    with pytest.raises(RuntimeError, match="refusing to append a keyless audit row"):
        store._audit_append_mac()


@pytest.mark.parametrize("backend", BACKENDS)
async def test_fresh_store_writes_its_genesis_row_on_the_transit_mac(backend: str) -> None:
    """Seam 4. A fresh (empty) store under vault_transit must write a genesis row, MAC'd inside the
    module, naming the Transit key.

    Pre-fix the load returned early on ``self._audit_mac_key is None`` and the chain was never keyed.
    The control is a read-only load of the same empty log, which writes nothing."""
    store = _bare(backend, mac_fn=stub_transit_mac)
    rows: list[dict[str, Any]] = []
    serve_rows(store, rows)
    await load_audit_chain(store, read_only=True)
    assert rows == [] and store._audit_chain_keyed is False  # the control: read-only writes nothing

    await load_audit_chain(store, read_only=False)
    assert len(rows) == 1, f"{backend}: a fresh Transit-keyed store must write one genesis row"
    assert rows[0]["seq"] == 1 and rows[0]["action"] == AUDIT_KEY_EPOCH_ACTION
    assert parse_audit_genesis(rows[0]["detail"]) == AUDIT_TRANSIT_KEY_ID
    assert rows[0]["row_hash"].startswith("vault:v1:")  # MAC'd inside the module
    assert store._audit_chain_keyed is True and store.audit_chain_unkeyed() is False
    assert store._audit_range_key_id == AUDIT_TRANSIT_KEY_ID and store._audit_range_from == 1

    # A second open adopts the row already there and writes nothing more.
    await load_audit_chain(store, read_only=False)
    assert len(rows) == 1
    ok, message = await store.verify_audit_chain()
    assert ok, f"{backend}: {message}"


@pytest.mark.parametrize("backend", BACKENDS)
async def test_verify_accepts_a_transit_keyed_chain(backend: str) -> None:
    """Seam 5. ``verify_audit_chain`` must pass ``mac=`` — without it the backend recomputes a keyless
    SHA-256 digest and reports every Transit-MAC'd row as tampered."""
    rows = chained_rows(
        [
            (AUDIT_KEY_EPOCH_ACTION, audit_genesis_detail(AUDIT_TRANSIT_KEY_ID)),
            ("act", None),
            ("act", None),
        ],
        mac=stub_transit_mac,
    )
    assert rows[0]["row_hash"].startswith("vault:v1:")  # genuinely the isolated-module shape

    store = _bare(backend, mac_fn=stub_transit_mac)
    store._audit_chain_keyed = True
    serve_rows(store, rows)
    ok, message = await store.verify_audit_chain()
    assert ok, f"{backend}: a Transit-keyed chain must verify — {message}"

    # ...and a forged row is still caught, so the MAC is load-bearing rather than merely accepted.
    rows[1]["row_hash"] = "vault:v1:" + "0" * 64
    ok, message = await store.verify_audit_chain()
    assert not ok and "seq=2" in (message or "")


@pytest.mark.parametrize("backend", BACKENDS)
async def test_verify_refuses_a_keyed_chain_with_no_secret_in_hand(backend: str) -> None:
    """A handle with no secret learns the chain is keyed from the chain's own genesis row, and says
    it cannot verify it. The control is the same handle on an empty log, which verifies."""
    store = _bare(backend)
    serve_rows(store, [])
    ok, message = await store.verify_audit_chain()
    assert ok, message

    rows = chained_rows(
        [(AUDIT_KEY_EPOCH_ACTION, audit_genesis_detail(AUDIT_TRANSIT_KEY_ID))],
        mac=stub_transit_mac,
    )
    serve_rows(store, rows)
    ok, message = await store.verify_audit_chain()
    assert not ok and "no store encryption key/MAC" in (message or "")


@pytest.mark.parametrize("backend", BACKENDS)
async def test_a_keyless_row_on_a_transit_keyed_store_is_a_break(backend: str) -> None:
    """A store that holds a keying secret requires every row keyed, from the first (vault BACKLOG
    #2594). A chain of plain SHA-256 rows is a reported break under the Transit MAC, and no method
    keys it in place. The control is the same rows under a handle with no secret, which verify."""
    rows = chained_rows([("act", None), ("act", None)])
    keyless = _bare(backend)
    serve_rows(keyless, rows)
    ok, message = await keyless.verify_audit_chain()
    assert ok, message

    store = _bare(backend, mac_fn=stub_transit_mac)
    serve_rows(store, rows)
    ok, message = await store.verify_audit_chain()
    assert not ok and "seq=1" in (message or "") and "genesis row" in (message or ""), message
    assert not hasattr(store, "rekey_audit_chain")


def test_rider_covers_every_shipped_server_backend() -> None:
    server = {b.value for b in StoreBackend} - {"sqlite"}
    assert server == set(BACKENDS)
