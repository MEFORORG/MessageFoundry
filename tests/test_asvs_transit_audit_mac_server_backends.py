# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""13.3.3 RIDER — the isolated-module (Vault Transit) audit MAC on the SERVER store backends.

``TransitCipher.audit_mac_key()`` returns ``None`` by design (the DEK never enters heap; the MAC is
computed inside the vault via ``audit_mac_fn``). ``open_store`` used to hand ``audit_mac_fn`` to the
SQLite backend ONLY, so a ``cipher_provider = "vault_transit"`` deployment on Postgres / SQL Server had
no keying secret in hand at all: the fresh-store watermark was never written and the audit chain ran
**fully unkeyed**, while the deployment posture claimed the most isolated MAC the product offers.

This suite pins the wiring end to end without a live server. The five seams the fix has to cover are
each asserted: ``open`` accepts and stores it, ``_audit_keyed_capable`` sees it, ``_load_audit_chain_meta``
auto-keys a fresh store on it, ``_audit_append_mac`` prefers it, and ``verify_audit_chain`` passes
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
from messagefoundry.store.store import audit_row_hash

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
    store = object.__new__(_store_class(backend))
    store._audit_mac_key = mac_key
    store._audit_mac_fn = mac_fn
    store._audit_keyed_from = None
    return store


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
        )
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
    # Seam 3. With the watermark set, an appended row must be MAC'd inside the module.
    store = _bare(backend, mac_fn=stub_transit_mac, mac_key=b"k" * 32)
    store._audit_keyed_from = 1
    key, mac = store._audit_append_mac()
    assert key is None and mac is stub_transit_mac


@pytest.mark.parametrize("backend", BACKENDS)
def test_append_mac_is_keyless_below_the_watermark(backend: str) -> None:
    assert _bare(backend, mac_fn=stub_transit_mac)._audit_append_mac() == (None, None)


@pytest.mark.parametrize("backend", BACKENDS)
def test_append_mac_fails_closed_when_keyed_but_no_secret_is_in_hand(backend: str) -> None:
    # A keyed store opened writable without its key/vault must REFUSE, not append a keyless row above
    # the watermark (which a later keyed verify would read as tampered — a false break).
    store = _bare(backend)
    store._audit_keyed_from = 5
    with pytest.raises(RuntimeError, match="refusing to append a keyless audit row"):
        store._audit_append_mac()


@pytest.mark.parametrize("backend", BACKENDS)
async def test_fresh_store_auto_keys_on_the_transit_mac(backend: str) -> None:
    """Seam 4. A fresh (empty) store under vault_transit must set the keying watermark from row 1.

    Pre-fix this returned early on ``self._audit_mac_key is None`` and the watermark was NEVER written,
    which is why the residual is "fully unkeyed", not "keyless below a watermark"."""
    store = _bare(backend, mac_fn=stub_transit_mac)
    inserted: list[str] = []

    async def _fetchone(sql: str, *_a: Any, **_kw: Any) -> Any:
        if "keyed_from_id" in sql:
            return {"keyed_from_id": None}
        return {"n": 0}  # an empty audit_log → fresh store

    store._fetchone = _fetchone

    if backend == "postgres":
        import contextlib

        class _Conn:
            async def fetchrow(self, sql: str, *_a: Any) -> Any:
                return await _fetchone(sql)

            async def execute(self, sql: str, *_a: Any) -> None:
                inserted.append(sql)

        @contextlib.asynccontextmanager
        async def _timed_acquire() -> Any:
            yield _Conn()

        store._timed_acquire = _timed_acquire
    else:
        import contextlib

        class _Cur:
            async def execute(self, sql: str, *_a: Any) -> None:
                inserted.append(sql)

        @contextlib.asynccontextmanager
        async def _acquire() -> Any:
            yield object()

        @contextlib.asynccontextmanager
        async def _cursor(_conn: Any) -> Any:
            yield _Cur()

        async def _commit(_conn: Any) -> None:
            return None

        store._acquire = _acquire
        store._cursor = _cursor
        store._commit = _commit

    await store._load_audit_chain_meta()
    assert store._audit_keyed_from == 1, f"{backend}: fresh Transit-keyed store must key from row 1"
    assert any("audit_chain_meta" in s for s in inserted)


@pytest.mark.parametrize("backend", BACKENDS)
async def test_verify_accepts_a_transit_keyed_chain(backend: str) -> None:
    """Seam 5. ``verify_audit_chain`` must pass ``mac=`` — without it the backend recomputes a keyless
    SHA-256 digest and reports every Transit-MAC'd row as tampered."""
    rows: list[dict[str, Any]] = []
    prev = ""
    for i in range(1, 4):
        row: dict[str, Any] = {
            "id": i,
            "ts": float(i),
            "actor": "u",
            "action": "act",
            "channel_id": None,
            "detail": None,
            "client": None,
        }
        prev = audit_row_hash(
            prev,
            ts=row["ts"],
            actor=row["actor"],
            action=row["action"],
            channel_id=row["channel_id"],
            detail=row["detail"],
            client=row["client"],
            mac=stub_transit_mac,
        )
        row["row_hash"] = prev
        rows.append(row)
    assert rows[0]["row_hash"].startswith("vault:v1:")  # genuinely the isolated-module shape

    store = _bare(backend, mac_fn=stub_transit_mac)
    store._audit_keyed_from = 1

    async def _fetchall(_sql: str, *_a: Any, **_kw: Any) -> list[dict[str, Any]]:
        return rows

    store._fetchall = _fetchall
    ok, message = await store.verify_audit_chain()
    assert ok, f"{backend}: a Transit-keyed chain must verify — {message}"

    # ...and a forged row is still caught, so the MAC is load-bearing rather than merely accepted.
    rows[1]["row_hash"] = "vault:v1:" + "0" * 64
    ok, message = await store.verify_audit_chain()
    assert not ok and "id=2" in (message or "")


@pytest.mark.parametrize("backend", BACKENDS)
async def test_verify_refuses_a_keyed_chain_with_no_secret_in_hand(backend: str) -> None:
    store = _bare(backend)
    store._audit_keyed_from = 1

    async def _fetchall(_sql: str, *_a: Any, **_kw: Any) -> list[dict[str, Any]]:
        return []

    store._fetchall = _fetchall
    ok, message = await store.verify_audit_chain()
    assert not ok and "no store encryption key/MAC" in (message or "")


@pytest.mark.parametrize("backend", BACKENDS)
async def test_rekey_is_available_on_the_transit_mac_alone(backend: str) -> None:
    # Pre-fix, `rekey-audit` on a vault_transit server store returned "no store encryption key
    # configured" — the operator had no route to key an existing chain at all.
    store = _bare(backend, mac_fn=stub_transit_mac)
    store._audit_keyed_from = 7
    ok, message = await store.rekey_audit_chain()
    assert ok and "already keyed" in message  # got past the capability gate

    store = _bare(backend)
    ok, message = await store.rekey_audit_chain()
    assert not ok and "no store encryption key/MAC configured" in message


def test_rider_covers_every_shipped_server_backend() -> None:
    server = {b.value for b in StoreBackend} - {"sqlite"}
    assert server == set(BACKENDS)
