# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 13.3.4 (BACKLOG #282) — the rotation watcher widened beyond the DEK: keyed-MAC fingerprints +
tracked-since stamps in store meta, auto-detected rotation, and the ENFORCE escalation arm
(pipeline/secret_rotation.py + store/crypto.py + store/store.py).

Unit-driven with a fake meta store + a fixed clock so the reconcile is deterministic; one end-to-end
test uses a real keyed :class:`MessageStore` to exercise the crypto derivation + the SQLite meta table.
PHI/secret-safe throughout — the doubles carry only identifiers, dates, and one-way keyed MACs, never a
secret value (synthetic values only)."""

from __future__ import annotations

import asyncio
import datetime

from messagefoundry.config.ai_policy import SecurityEnforcement
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import SecretRotationSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    EnvRef,
    InboundConnection,
    OutboundConnection,
    Registry,
    Soap,
    connector_secret_env_values,
    env,
)
from messagefoundry.pipeline.secret_rotation import (
    SecretRotationRunner,
    SecretStamp,
    _keyed_fingerprint,
    held_env_secret_values,
    reconcile_rotation_meta,
    secrets_from_settings_and_stamps,
)
from messagefoundry.store.crypto import generate_key, make_cipher, rotation_fingerprint_key
from messagefoundry.store.store import MessageStore, SecretRotationMetaRow

_UTC = datetime.UTC
_REF = datetime.datetime(2026, 6, 15, 12, 0, tzinfo=_UTC)
_REF_TS = _REF.timestamp()
_TODAY = _REF.date()
_DEK = "MEFOR_STORE_ENCRYPTION_KEY"


class _FakeMetaStore:
    """A stand-in for the narrow SecretRotationMetaStore: a fixed fingerprint key + an in-memory row map."""

    def __init__(
        self,
        *,
        fp_key: bytes | None = b"K" * 32,
        rows: dict[str, SecretRotationMetaRow] | None = None,
    ) -> None:
        self._fp_key = fp_key
        self.rows: dict[str, SecretRotationMetaRow] = dict(rows or {})
        self.upserts: list[tuple[str, str, str, str]] = []

    def secret_rotation_fingerprint_key(self) -> bytes | None:
        return self._fp_key

    async def get_secret_rotation_meta(self) -> dict[str, SecretRotationMetaRow]:
        return dict(self.rows)

    async def upsert_secret_rotation_meta(
        self, secret_key: str, *, fingerprint: str, tracked_since: str, last_rotated: str
    ) -> None:
        self.upserts.append((secret_key, fingerprint, tracked_since, last_rotated))
        self.rows[secret_key] = SecretRotationMetaRow(
            secret_key, fingerprint, tracked_since, last_rotated
        )


class _RecordingSink:
    """Records secret_rotation_due calls (incl. the ENFORCE `enforced` flag); other methods inert."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def __getattr__(self, _name: str):  # type: ignore[no-untyped-def]
        # Any AlertSink method other than the one under test is a no-op (keeps the double small).
        return lambda *a, **k: None

    def secret_rotation_due(
        self,
        name: str,
        *,
        secret: str,
        last_rotated: str,
        days_overdue: int,
        enforced: bool = False,
    ) -> None:
        self.calls.append(
            {
                "name": name,
                "secret": secret,
                "last_rotated": last_rotated,
                "days_overdue": days_overdue,
                "enforced": enforced,
            }
        )


def _reconcile(store: _FakeMetaStore, **kw: object) -> dict[str, object]:
    settings = kw.pop("settings", None) or SecretRotationSettings()
    return asyncio.run(
        reconcile_rotation_meta(
            store,
            settings,  # type: ignore[arg-type]
            dek_key_id=kw.pop("dek_key_id", "dekid-aaa"),  # type: ignore[arg-type]
            enforcement=kw.pop("enforcement", SecurityEnforcement.WARN),  # type: ignore[arg-type]
            alert_sink=kw.pop("alert_sink", None),  # type: ignore[arg-type]
            now=_REF_TS,
            env_values=kw.pop("env_values", {}),  # type: ignore[arg-type]
            **kw,  # type: ignore[arg-type]
        )
    )


# --- keyed MAC (binding correction a: keyed MAC, NEVER a salted hash) --------


def test_keyed_fingerprint_is_a_keyed_mac_not_the_value() -> None:
    key = b"K" * 32
    fp = _keyed_fingerprint(key, "hunter2")
    assert fp == _keyed_fingerprint(key, "hunter2")  # deterministic for a fixed key+value
    assert "hunter2" not in fp  # one-way — the value is not recoverable from the fingerprint
    assert (
        _keyed_fingerprint(b"D" * 32, "hunter2") != fp
    )  # KEYED: a different key → a different MAC


def test_rotation_fingerprint_key_none_when_keyless_and_keyed_otherwise() -> None:
    assert rotation_fingerprint_key(make_cipher(None)) is None  # identity cipher → no key material
    k1 = rotation_fingerprint_key(make_cipher(generate_key()))
    k2 = rotation_fingerprint_key(make_cipher(generate_key()))
    assert k1 is not None and len(k1) == 32
    assert k1 != k2  # DEK-derived → distinct per DEK


# --- reconcile: stamps, tracked-since floor, auto-detected rotation ----------


def test_new_class_stamps_tracked_since_today_as_age_floor() -> None:
    # Binding correction (b): a first-seen key gets a FRESH clock (tracked_since == today), never a
    # retroactive age — a pre-existing year-old key does not start alerting on upgrade.
    store = _FakeMetaStore()
    stamps = _reconcile(store)
    dek = stamps[_DEK]  # type: ignore[index]
    assert dek.tracked_since == _TODAY  # type: ignore[attr-defined]
    assert dek.last_rotated == _TODAY  # type: ignore[attr-defined]
    assert store.rows[_DEK].fingerprint == "dekid-aaa"


def test_fingerprint_change_resets_the_clock() -> None:
    # A prior stamp a year old; the DEK key-id (fingerprint) now differs → rotation auto-detected →
    # last_rotated resets to today, tracked_since (the floor) is preserved.
    prior = SecretRotationMetaRow(_DEK, "dekid-OLD", "2025-01-01", "2025-01-01")
    store = _FakeMetaStore(rows={_DEK: prior})
    stamps = _reconcile(store, dek_key_id="dekid-NEW")
    dek = stamps[_DEK]  # type: ignore[index]
    assert dek.last_rotated == _TODAY  # reset on change  # type: ignore[attr-defined]
    assert dek.tracked_since == datetime.date(
        2025, 1, 1
    )  # floor preserved  # type: ignore[attr-defined]
    assert store.rows[_DEK].fingerprint == "dekid-NEW"


def test_unchanged_class_is_not_rewritten() -> None:
    # Same fingerprint as stored → no rotation, no upsert (the stored dates are carried through).
    prior = SecretRotationMetaRow(_DEK, "dekid-SAME", "2025-01-01", "2025-03-01")
    store = _FakeMetaStore(rows={_DEK: prior})
    stamps = _reconcile(store, dek_key_id="dekid-SAME")
    assert store.upserts == []  # untouched
    dek = stamps[_DEK]  # type: ignore[index]
    assert dek.last_rotated == datetime.date(2025, 3, 1)  # type: ignore[attr-defined]


def test_reconcile_enumerates_all_held_classes() -> None:
    # The DEK + every configured secret the engine holds are all tracked (widened beyond the DEK).
    store = _FakeMetaStore()
    stamps = _reconcile(
        store,
        env_values={"MEFOR_STORE_PASSWORD": "pw", "MEFOR_AUTH_AD_BIND_PASSWORD": "bind"},
    )
    assert set(stamps) == {_DEK, "MEFOR_STORE_PASSWORD", "MEFOR_AUTH_AD_BIND_PASSWORD"}
    # The non-DEK classes carry a KEYED-MAC fingerprint of the value (not the value, not the key-id).
    assert store.rows["MEFOR_STORE_PASSWORD"].fingerprint == _keyed_fingerprint(b"K" * 32, "pw")


def test_env_classes_skipped_when_no_in_heap_key() -> None:
    # A keyless / Transit store (no fingerprint key) tracks only the DEK key-id stamp — env secrets are
    # not fingerprintable in-heap and are skipped (documented degrade), never an error.
    store = _FakeMetaStore(fp_key=None)
    stamps = _reconcile(store, env_values={"MEFOR_STORE_PASSWORD": "pw"})
    assert set(stamps) == {_DEK}


# --- per-Connection env() connector credentials (extra_values wiring) --------


def test_connector_cred_via_extra_values_is_stamped() -> None:
    # A per-Connection env() credential passed via extra_values is fingerprinted with the SAME DEK-derived
    # keyed MAC as the fixed MEFOR_* classes and gets its own stamp (tracked_since == today, the floor).
    # This is the runtime coverage the §4 doc claims — the engine resolves the graph's env() creds and
    # passes them here (see test_connector_secret_env_values_* for the resolver half).
    store = _FakeMetaStore()
    stamps = _reconcile(store, extra_values={"acme_api_key": "APIKEY-1"})
    stamp = stamps["acme_api_key"]
    assert isinstance(stamp, SecretStamp)  # narrows the object value to SecretStamp
    assert store.rows["acme_api_key"].fingerprint == _keyed_fingerprint(b"K" * 32, "APIKEY-1")
    assert stamp.tracked_since == _TODAY
    assert stamp.last_rotated == _TODAY


def test_connector_cred_value_change_resets_the_clock() -> None:
    # A changed connector-credential value (rotation) resets last_rotated to today while preserving the
    # tracked_since floor — rotation auto-detected, never operator-attested, exactly like the DEK.
    prior = SecretRotationMetaRow(
        "acme_api_key", _keyed_fingerprint(b"K" * 32, "APIKEY-OLD"), "2025-01-01", "2025-01-01"
    )
    store = _FakeMetaStore(rows={"acme_api_key": prior})
    stamps = _reconcile(store, extra_values={"acme_api_key": "APIKEY-NEW"})
    stamp = stamps["acme_api_key"]
    assert isinstance(stamp, SecretStamp)
    assert stamp.last_rotated == _TODAY  # reset on change
    assert stamp.tracked_since == datetime.date(2025, 1, 1)  # floor preserved
    assert store.rows["acme_api_key"].fingerprint == _keyed_fingerprint(b"K" * 32, "APIKEY-NEW")


def test_connector_cred_skipped_when_no_in_heap_key() -> None:
    # No fingerprint key (keyless / Transit store) → connector creds are not in-heap MAC'able either, so
    # they are skipped alongside the fixed env classes (documented degrade), never an error.
    store = _FakeMetaStore(fp_key=None)
    stamps = _reconcile(store, extra_values={"acme_api_key": "APIKEY-1"})
    assert set(stamps) == {_DEK}


def _spec(conn_type: ConnectorType, settings: dict[str, object]) -> ConnectionSpec:
    return ConnectionSpec(type=conn_type, settings=settings)


def test_connector_secret_env_values_selects_rotatable_env_refs() -> None:
    # The engine-side resolver picks ONLY rotatable connector-credential settings that are env() refs with
    # a resolvable value, keyed by their (NON-SECRET) env-value name; identifiers, non-secret settings, and
    # inline (non-env) values are excluded; a shared env key across Connections collapses to one clock.
    reg = Registry()
    reg.outbound["OB_ACME"] = OutboundConnection(
        name="OB_ACME",
        spec=_spec(
            ConnectorType.REST,
            {
                "api_key": EnvRef(key="acme_api_key"),  # rotatable secret -> included
                "credential_password": EnvRef(key="acme_pw"),  # rotatable secret -> included
                "basic_user": EnvRef(key="acme_user"),  # non-rotatable identifier -> excluded
                "host": EnvRef(key="acme_host"),  # not a secret setting -> excluded
                "token": "inline-not-env",  # secret key but not env() -> skipped
            },
        ),
    )
    reg.inbound["IB_ACME"] = InboundConnection(
        name="IB_ACME",
        spec=_spec(
            ConnectorType.MLLP, {"api_key": EnvRef(key="acme_api_key")}
        ),  # same key -> dedup
        router="r",
    )
    env_values = {
        "acme_api_key": "APIKEY-1",
        "acme_pw": "PW-1",
        "acme_user": "svc",
        "acme_host": "198.51.100.7",
    }
    assert connector_secret_env_values(reg, env_values) == {
        "acme_api_key": "APIKEY-1",
        "acme_pw": "PW-1",
    }


def test_connector_secret_env_values_skips_unresolved_and_empty() -> None:
    # A secret env() ref whose key is absent from the environment, or resolves to an empty string, has no
    # value to MAC and is skipped (never a spurious empty-value fingerprint).
    reg = Registry()
    reg.outbound["OB"] = OutboundConnection(
        name="OB",
        spec=_spec(
            ConnectorType.REST,
            {
                "api_key": EnvRef(key="present"),
                "bearer_token": EnvRef(key="absent"),  # not in env_values -> skipped
                "password": EnvRef(key="blank"),  # empty string -> skipped
            },
        ),
    )
    assert connector_secret_env_values(reg, {"present": "V", "blank": ""}) == {"present": "V"}


def test_connector_secret_env_values_includes_a_soap_body_secret() -> None:
    # BACKLOG #1009 (ADR 0015): a SOAP ``body_secrets={token: env(...)}`` desugars to a top-level
    # ``body_secret_value_<i>`` EnvRef that reaches secrecy only through the prefix branch of
    # ``_is_secret_setting`` -- it is NOT a literal ``_SECRET_SETTING_KEYS`` member. The fingerprinter
    # must resolve it (a rotation of a SOAP injected body secret would otherwise go undetected while
    # every sibling connector credential is tracked). Built from a real ``Soap()`` factory so the
    # factory -> _hoist_body_secrets -> body_secret_value_0 -> fingerprint path is exercised end to end.
    reg = Registry()
    # Synthetic placeholder matching the .gitleaks.toml ``MF_IIS_<ROLE>_<hex>`` allowlist (ADR 0015
    # amendment): a body-secret TOKEN is public by design -- it sits in committed Handler source and the
    # transport swaps in the real env() credential at send time -- not a credential. >=16 chars to satisfy
    # ``_BODY_SECRET_TOKEN_RE``.
    token = "MF_IIS_BODY_9f2c41ab3d7e"
    reg.outbound["OB_IIS"] = OutboundConnection(
        name="OB_IIS",
        spec=Soap(
            url="https://api.example.com/svc",
            body_secrets={token: env("iis_body_pw")},
        ),
    )
    assert connector_secret_env_values(reg, {"iis_body_pw": "SYNTH-VAL"}) == {
        "iis_body_pw": "SYNTH-VAL"
    }


# --- live-by-default: DEK tracked via the stamp when operator date unset -----


def _dek_stamp(last_rotated: datetime.date) -> SecretStamp:
    return SecretStamp(
        secret=_DEK,
        label="store data-encryption key",
        fingerprint="dekid-aaa",
        tracked_since=datetime.date(2025, 1, 1),
        last_rotated=last_rotated,
        max_age_days=365,
    )


def test_dek_tracked_via_stamp_when_operator_date_unset() -> None:
    # No store_key_last_rotated → the DEK is STILL tracked, off the stamp's last_rotated.
    stamps = {_DEK: _dek_stamp(datetime.date(2025, 1, 1))}
    secrets = secrets_from_settings_and_stamps(SecretRotationSettings(), stamps)
    assert [s.secret for s in secrets] == [_DEK]
    assert secrets[0].last_rotated == datetime.date(2025, 1, 1)


def test_operator_date_overrides_the_stamp() -> None:
    settings = SecretRotationSettings(store_key_last_rotated="2026-05-01")
    secrets = secrets_from_settings_and_stamps(
        settings, {_DEK: _dek_stamp(datetime.date(2025, 1, 1))}
    )
    assert secrets[0].last_rotated == datetime.date(2026, 5, 1)  # operator override wins


# --- ENFORCE escalation arm (committed) -------------------------------------


def test_enforce_escalation_fires_past_grace() -> None:
    # DEK 420 days old, 365 max + 30 grace = 395 → 25 days past grace under ENFORCE → escalated alert.
    prior = SecretRotationMetaRow(_DEK, "dekid-aaa", "2025-04-21", "2025-04-21")
    store = _FakeMetaStore(rows={_DEK: prior})
    sink = _RecordingSink()
    _reconcile(
        store,
        dek_key_id="dekid-aaa",
        enforcement=SecurityEnforcement.ENFORCE,
        alert_sink=sink,
        settings=SecretRotationSettings(store_key_max_age_days=365, enforce_grace_days=30),
    )
    assert len(sink.calls) == 1
    assert sink.calls[0]["enforced"] is True
    assert sink.calls[0]["secret"] == _DEK
    assert sink.calls[0]["days_overdue"] == 55  # 420 - 365


def test_enforce_escalation_silent_within_grace() -> None:
    # DEK 380 days old: past max (365) but within the 30-day grace → no escalation.
    prior = SecretRotationMetaRow(_DEK, "dekid-aaa", "2025-05-31", "2025-05-31")
    store = _FakeMetaStore(rows={_DEK: prior})
    sink = _RecordingSink()
    _reconcile(
        store,
        dek_key_id="dekid-aaa",
        enforcement=SecurityEnforcement.ENFORCE,
        alert_sink=sink,
        settings=SecretRotationSettings(store_key_max_age_days=365, enforce_grace_days=30),
    )
    assert sink.calls == []


def test_no_escalation_under_warn_enforcement() -> None:
    prior = SecretRotationMetaRow(_DEK, "dekid-aaa", "2024-01-01", "2024-01-01")  # very old
    store = _FakeMetaStore(rows={_DEK: prior})
    sink = _RecordingSink()
    _reconcile(
        store,
        dek_key_id="dekid-aaa",
        enforcement=SecurityEnforcement.WARN,
        alert_sink=sink,
    )
    assert sink.calls == []  # WARN never escalates at restart


# --- alert payloads are PHI/secret-free -------------------------------------


def test_alert_payloads_carry_no_secret_value_or_fingerprint() -> None:
    # Hold a secret with a distinctive value; reconcile fingerprints it, then the runner alerts on the
    # overdue DEK. Assert no secret value AND no keyed-MAC fingerprint ever reaches the alert payload.
    secret_value = "S3CR3T-VALUE-do-not-leak"
    prior = SecretRotationMetaRow(_DEK, "dekid-aaa", "2024-01-01", "2024-01-01")
    store = _FakeMetaStore(rows={_DEK: prior})
    sink = _RecordingSink()
    stamps = _reconcile(
        store,
        dek_key_id="dekid-aaa",
        enforcement=SecurityEnforcement.ENFORCE,
        alert_sink=sink,
        env_values={"MEFOR_STORE_PASSWORD": secret_value},
    )
    runner = SecretRotationRunner(
        lambda: secrets_from_settings_and_stamps(SecretRotationSettings(warn_days=14), stamps),
        SecretRotationSettings(warn_days=14),
        alert_sink=sink,
        clock=lambda: _REF_TS,
    )
    runner.run_once()
    fingerprint = store.rows["MEFOR_STORE_PASSWORD"].fingerprint
    blob = repr(sink.calls)
    assert secret_value not in blob  # never the value
    assert fingerprint not in blob  # never even the one-way keyed MAC


def test_held_env_secret_values_reads_present_nonempty_only() -> None:
    env = {"MEFOR_STORE_PASSWORD": "pw", "MEFOR_AUTH_AD_BIND_PASSWORD": "", "OTHER": "x"}
    assert held_env_secret_values(env) == {"MEFOR_STORE_PASSWORD": "pw"}


# --- end-to-end against a real keyed MessageStore ---------------------------


def test_real_store_meta_roundtrip_and_reconcile(tmp_path) -> None:  # type: ignore[no-untyped-def]
    async def _go() -> None:
        store = await MessageStore.open(tmp_path / "rot.db", cipher=make_cipher(generate_key()))
        try:
            # The real store derives a non-None keyed fingerprint key off its live DEK.
            assert store.secret_rotation_fingerprint_key() is not None
            # First reconcile: the DEK stamp is persisted with tracked_since == last_rotated == today.
            settings = SecretRotationSettings()
            stamps1 = await reconcile_rotation_meta(
                store,
                settings,
                dek_key_id=store.cipher_info().active_key_id,
                enforcement=SecurityEnforcement.WARN,
                now=_REF_TS,
                env_values={"MEFOR_STORE_PASSWORD": "pw"},
            )
            assert _DEK in stamps1 and "MEFOR_STORE_PASSWORD" in stamps1
            meta = await store.get_secret_rotation_meta()
            assert meta[_DEK].tracked_since == _TODAY.isoformat()
            # A second reconcile with the SAME inputs is a no-op (idempotent — no rewrite).
            store2 = await reconcile_rotation_meta(
                store,
                settings,
                dek_key_id=store.cipher_info().active_key_id,
                enforcement=SecurityEnforcement.WARN,
                now=_REF_TS + 86_400,  # a day later
                env_values={"MEFOR_STORE_PASSWORD": "pw"},
            )
            assert store2[_DEK].last_rotated == _TODAY  # unchanged fingerprint keeps the old date
        finally:
            await store.close()

    asyncio.run(_go())
