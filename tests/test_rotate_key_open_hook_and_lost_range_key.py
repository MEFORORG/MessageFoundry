# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #4936 and #4934, the owner rulings of 2026-11-04.

#4936: ``rotate-key`` opens its rotation record through ``open_store``'s ``before_first_write``
hook, so a run killed inside the store open after the hook leaves any record it
opened.

#4934: ``serve``'s start refusal of a store key change the keyed audit chain cannot follow, with
``[secret_rotation].allow_lost_audit_range_key`` as its override; docs/SECURITY-LOOSENING.md
states when it fires."""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.ai_policy import SecurityEnforcement
from messagefoundry.config.settings import SecretRotationSettings, StoreSettings
from messagefoundry.pipeline.secret_rotation import (
    ROTATION_RECORD_ID,
    UnrolledStoreKeyRefused,
    dek_fingerprint,
    reconcile_rotation_meta,
    refuse_unrolled_key_change,
)
from messagefoundry.store.base import open_store
from messagefoundry.store.crypto import generate_key
from messagefoundry.store.store import (
    MessageStore,
    audit_chain_rolled,
    audit_range_key_missing,
)
from tests.test_rotate_key_rotation_record import (
    _DEK,
    _OLD_DATE,
    _env,
    _key_id,
    _open,
    _rows,
    _seed,
    _seed_keyless_chain,
)


class _Killed(Exception):
    """Stands in for a kill inside the store open, after the hook ran."""


def _kill_after_the_hook(monkeypatch: pytest.MonkeyPatch) -> None:
    async def killed(*_args: object, **_kwargs: object) -> None:
        raise _Killed("killed inside the store open")

    # The salt bind is the open's first write under the key, right after the hook.
    monkeypatch.setattr("messagefoundry.store.store.bind_store_salt", killed)


async def _reconcile(db: Path, key: str, *retired: str) -> dict[str, Any]:
    store = await _open(db, key, *retired)
    try:
        await reconcile_rotation_meta(
            store,
            SecretRotationSettings(),
            dek_key_id=_key_id(key),
            enforcement=SecurityEnforcement.WARN,
            env_values={},
            audit_rolled=audit_chain_rolled(store),
        )
        return dict(await store.get_secret_rotation_meta())
    finally:
        await store.close()


def test_a_run_killed_inside_the_open_on_a_store_with_no_keyed_chain_leaves_no_stamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """#4936 step 3. On the code before the hook no record existed at the kill, and this start
    stamped the new key, because a store with no keyed chain has nothing else to hold it."""
    monkeypatch.chdir(tmp_path)
    db, uploads, key_a, key_b = (
        tmp_path / "k.db",
        tmp_path / "uploads",
        generate_key(),
        generate_key(),
    )
    asyncio.run(_seed_keyless_chain(db, uploads, key_a))
    _env(monkeypatch, key_b, key_a, uploads)
    with monkeypatch.context() as patch:
        _kill_after_the_hook(patch)
        # run_guarded turns the uncaught kill into a failing exit.
        assert main(["rotate-key", "--db", str(db)]) != 0
    capsys.readouterr()
    rows = asyncio.run(_reconcile(db, key_b, key_a))
    assert rows[ROTATION_RECORD_ID].fingerprint == dek_fingerprint(_key_id(key_b))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_a))
    assert rows[_DEK].last_rotated == _OLD_DATE


def test_the_hook_runs_before_the_first_write_and_not_on_a_read_only_open(tmp_path: Path) -> None:
    """The hook sees the store before the salt bind and the at-rest sweep, and a read-only open
    never runs it."""
    db, key = tmp_path / "h.db", generate_key()
    asyncio.run(_seed(db, tmp_path / "uploads", key))
    seen: list[str] = []

    async def hook(store: object) -> None:
        assert isinstance(store, MessageStore)
        assert store._cipher_foreign  # the salt is not bound yet
        seen.append("hook")

    async def opened(read_only: bool) -> None:
        settings = StoreSettings(path=str(db), encryption_key=key)
        store = await open_store(
            settings, read_only=read_only, keyless_chain_refusal=None, before_first_write=hook
        )
        await store.close()

    asyncio.run(opened(False))
    assert seen == ["hook"]
    asyncio.run(opened(True))
    assert seen == ["hook"]


async def _refusal(db: Path, key: str, *retired: str, allow_lost: bool = False) -> None:
    store = await _open(db, key, *retired)
    try:
        await refuse_unrolled_key_change(
            store,
            dek_key_id=_key_id(key),
            audit_rolled=audit_chain_rolled(store),
            range_key_missing=audit_range_key_missing(store),
            allow_lost=allow_lost,
        )
    finally:
        await store.close()


def test_a_start_on_the_new_key_alone_refuses_before_any_audit_row(tmp_path: Path) -> None:
    """#4934 step 3: changed key, chain not rolled, current range key not configured."""
    db, key_a, key_b = tmp_path / "r.db", generate_key(), generate_key()
    asyncio.run(_seed(db, tmp_path / "uploads", key_a))
    with pytest.raises(UnrolledStoreKeyRefused, match="allow_lost_audit_range_key"):
        asyncio.run(_refusal(db, key_b))


@pytest.mark.parametrize("case", ["prior_key_configured", "key_unchanged", "keyless_chain"])
def test_the_refusal_needs_all_three_conditions(tmp_path: Path, case: str) -> None:
    """Each condition alone failing lets the start through."""
    db, key_a, key_b = tmp_path / "c.db", generate_key(), generate_key()
    if case == "keyless_chain":
        asyncio.run(_seed_keyless_chain(db, tmp_path / "uploads", key_a))
        asyncio.run(_refusal(db, key_b))
        return
    asyncio.run(_seed(db, tmp_path / "uploads", key_a))
    if case == "prior_key_configured":
        asyncio.run(_refusal(db, key_b, key_a))
    else:
        asyncio.run(_refusal(db, key_a))


def test_a_stamp_naming_the_key_in_use_does_not_refuse(tmp_path: Path) -> None:
    """The stamp arm alone: chain not rolled and its range key not configured, but the stamp
    already names the key in use, so the start goes through. The other cases return before the
    stamp is read."""
    db, key_a, key_b = tmp_path / "s.db", generate_key(), generate_key()
    asyncio.run(_seed(db, tmp_path / "uploads", key_a))

    async def stamp_key_b() -> None:
        store = await _open(db, key_b)
        try:
            await store.upsert_secret_rotation_meta(
                _DEK,
                fingerprint=dek_fingerprint(_key_id(key_b)),
                tracked_since=_OLD_DATE,
                last_rotated=_OLD_DATE,
            )
            assert audit_chain_rolled(store) is False
            assert audit_range_key_missing(store) is True
        finally:
            await store.close()

    asyncio.run(stamp_key_b())
    asyncio.run(_refusal(db, key_b))


def test_the_override_starts_with_a_warning_and_is_a_named_loosening(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    db, key_a, key_b = tmp_path / "o.db", generate_key(), generate_key()
    asyncio.run(_seed(db, tmp_path / "uploads", key_a))
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.secret_rotation"):
        asyncio.run(_refusal(db, key_b, allow_lost=True))
    assert "allow_lost_audit_range_key is set" in caplog.text


def _named(settings: SecretRotationSettings) -> dict[str, str]:
    from messagefoundry.config.settings import (
        AiSettings,
        AlertsSettings,
        ApiSettings,
        ApprovalsSettings,
        AuthSettings,
        BackupSettings,
        CertMonitorSettings,
        SecretsSettings,
        SecuritySettings,
        security_loosenings,
    )

    return dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            settings,
            cleartext_hops=(),
            expiry_relaxed_hops=(),
            hostname_unchecked_hops=(),
            query_credential_hops=(),
            unverified_db_hops=(),
            attested_hops=(),
            revocation_attested_hops=(),
            path_form_fhir_hops=(),
            ech_cleartext_sidecar_hops=(),
            api=ApiSettings(),
            approvals=ApprovalsSettings(),
            cert_monitor=CertMonitorSettings(),
            backup=BackupSettings(),
            secrets=SecretsSettings(),
            ai=AiSettings(),
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
            service_env=None,
        )
    )


def test_the_override_is_a_named_loosening_and_off_by_default() -> None:
    assert SecretRotationSettings().allow_lost_audit_range_key is False
    assert "allow_lost_audit_range_key" not in _named(SecretRotationSettings())
    risk = _named(SecretRotationSettings(allow_lost_audit_range_key=True))[
        "allow_lost_audit_range_key"
    ]
    assert "audit chain breaks" in risk


def test_the_range_key_answer_tells_the_states_apart(tmp_path: Path) -> None:
    keyed, keyless = tmp_path / "keyed.db", tmp_path / "keyless.db"
    key_a, key_b = generate_key(), generate_key()
    asyncio.run(_seed(keyed, tmp_path / "u1", key_a))
    asyncio.run(_seed_keyless_chain(keyless, tmp_path / "u2", key_a))

    async def answer(db: Path, key: str, *retired: str) -> bool:
        store = await _open(db, key, *retired)
        try:
            return audit_range_key_missing(store)
        finally:
            await store.close()

    assert asyncio.run(answer(keyed, key_a)) is False
    assert asyncio.run(answer(keyed, key_b, key_a)) is False
    assert asyncio.run(answer(keyed, key_b)) is True
    assert asyncio.run(answer(keyless, key_b)) is False
    assert audit_range_key_missing(object()) is False


def test_the_rows_after_a_refused_start_are_unchanged(tmp_path: Path) -> None:
    """The refusal writes nothing: the DEK stamp and the record are as the seed left them."""
    db, key_a, key_b = tmp_path / "u.db", generate_key(), generate_key()
    asyncio.run(_seed(db, tmp_path / "uploads", key_a))
    with pytest.raises(UnrolledStoreKeyRefused):
        asyncio.run(_refusal(db, key_b))
    rows = asyncio.run(_rows(db, key_b, key_a))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_a))
    assert ROTATION_RECORD_ID not in rows


def _mint_a_pair_due_for_renewal(state_dir: Path, monkeypatch: pytest.MonkeyPatch) -> bytes:
    """A real generated API pair in ``state_dir``, reported due for renewal from now on, so the
    next renewing start writes a new one. Returns the certificate's bytes as minted."""
    from messagefoundry.api import tls
    from messagefoundry.config.settings import ApiSettings

    tls.ensure_api_tls_material(ApiSettings(), state_dir=state_dir)
    monkeypatch.setattr(tls, "_renewal_due", tls._cert_facts)
    return (state_dir / "api-generated-cert.pem").read_bytes()


@pytest.mark.parametrize("allow_lost", [False, True])
def test_a_refused_supervise_start_leaves_the_api_pair_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, allow_lost: bool
) -> None:
    """#4934: the refusal runs before the renewal, so a refused fleet start renews nothing on disk
    and leaves no renewal without its audit row. Under the override the same start renews the pair
    and records it, the positive control that the pair was due."""
    from messagefoundry import __main__ as cli
    from messagefoundry.api.tls import generated_state_dir
    from messagefoundry.config.settings import ServiceSettings

    db, key_a, key_b = tmp_path / "sup.db", generate_key(), generate_key()
    asyncio.run(_seed(db, tmp_path / "uploads", key_a))
    state_dir = generated_state_dir(str(db))
    minted = _mint_a_pair_due_for_renewal(state_dir, monkeypatch)
    settings = ServiceSettings(
        store=StoreSettings(path=str(db), encryption_key=key_b),
        secret_rotation=SecretRotationSettings(allow_lost_audit_range_key=allow_lost),
    )
    before = _audit_rows(db)
    if allow_lost:
        cli._renew_api_tls_before_spawning(settings, str(db))
        assert (state_dir / "api-generated-cert.pem").read_bytes() != minted
        assert _audit_rows(db) == before + 1
        return
    with pytest.raises(UnrolledStoreKeyRefused):
        cli._renew_api_tls_before_spawning(settings, str(db))
    assert (state_dir / "api-generated-cert.pem").read_bytes() == minted
    assert _audit_rows(db) == before


def test_a_refused_serve_start_leaves_the_api_pair_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """#4934: serve mints before its lifespan opens the store, so a start that would write the
    pair takes the refusal first, exits 2 with the remedy, and renews nothing on disk."""
    db, key_a, key_b = tmp_path / "messagefoundry.db", generate_key(), generate_key()
    asyncio.run(_seed(db, tmp_path / "uploads", key_a))
    minted = _mint_a_pair_due_for_renewal(tmp_path, monkeypatch)
    started: list[object] = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key_b)
    # The enforce-only start gates (an off-box log collector, ...) are not under test here.
    monkeypatch.setenv("MEFOR_SECURITY_ENFORCEMENT", "warn")
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: started.append(k))
    (tmp_path / "messagefoundry.toml").write_text(
        "security.block_unlisted_outbound = true\n"
        "alerts.security_notifications_required = false\n"
        "security.local_access_only = true\n",
        encoding="utf-8",
    )
    samples = Path(__file__).resolve().parent.parent / "samples" / "config"
    before = _audit_rows(db)
    assert main(["serve", "--config", str(samples), "--env", "dev"]) == 2
    err = capsys.readouterr().err
    assert "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED" in err, err[-2000:]
    assert started == []
    assert (tmp_path / "api-generated-cert.pem").read_bytes() == minted
    assert _audit_rows(db) == before


def test_supervise_exits_2_with_the_remedy_on_the_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """#4934: ``supervise`` catches the refusal, prints it in full and spawns no shard."""
    from messagefoundry import __main__ as cli
    from tests.test_remote_debug_start_refusal import (
        _OFF,
        _stand_down_the_gates_before_logging,
        _supervise,
    )

    def refused(*_args: object, **_kwargs: object) -> Path:
        raise UnrolledStoreKeyRefused("refusing to start: TEST REMEDY")

    _stand_down_the_gates_before_logging(monkeypatch)
    monkeypatch.setattr(cli, "_keyless_store_gate", lambda settings: None)
    monkeypatch.setattr(cli, "_start_logging", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_renew_api_tls_before_spawning", refused)
    rc, spawned = _supervise(tmp_path, monkeypatch, _OFF)
    err = capsys.readouterr().err
    assert rc == 2 and not spawned, err[-2000:]
    assert "error: refusing to start: TEST REMEDY" in err


def _audit_rows(db: Path) -> int:
    """The audit_log row count of a synthetic test store, read without opening it as a store."""
    with closing(sqlite3.connect(db)) as conn:
        (count,) = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()
    assert isinstance(count, int)
    return count


def _app_on_the_new_key_alone(tmp_path: Path, allow_lost: bool) -> Any:
    from messagefoundry.api import create_managed_app
    from messagefoundry.config.settings import EgressSettings

    db, key_a, key_b = tmp_path / "serve.db", generate_key(), generate_key()
    asyncio.run(_seed(db, tmp_path / "uploads", key_a))
    return create_managed_app(
        store_settings=StoreSettings(path=str(db), encryption_key=key_b),
        poll_interval=0.05,
        # The seed's DEK stamp is old; the calendar refusal is not under test here.
        secret_rotation_settings=SecretRotationSettings(
            allow_lost_audit_range_key=allow_lost, enforce_store_key_expiry=False
        ),
        egress_settings=EgressSettings(deny_by_default=False),
    )


async def test_serve_refuses_a_start_on_the_new_key_alone(tmp_path: Path) -> None:
    """#4934 step 3, the wiring: the refusal aborts the serve lifespan."""
    app = await asyncio.to_thread(_app_on_the_new_key_alone, tmp_path, False)
    before = _audit_rows(tmp_path / "serve.db")
    with pytest.raises(UnrolledStoreKeyRefused):
        async with app.router.lifespan_context(app):
            pass  # pragma: no cover -- startup must not reach here
    # The point of the refusal: the refused start wrote no audit row into the unrolled range.
    assert _audit_rows(tmp_path / "serve.db") == before


async def test_serve_starts_on_the_new_key_alone_under_the_override(tmp_path: Path) -> None:
    """Positive control on the arm above: the same store starts with the override."""
    app = await asyncio.to_thread(_app_on_the_new_key_alone, tmp_path, True)
    async with app.router.lifespan_context(app):
        assert app.state.engine is not None
