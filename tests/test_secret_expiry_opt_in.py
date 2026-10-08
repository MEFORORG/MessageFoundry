# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 13.3.4 / BACKLOG #1932 — the NON-DEK secret classes can now refuse on calendar expiry, opt-in.

The store DEK's calendar expiry refuses (#1004, ``tests/test_store_key_calendar_expiry.py``). Every
other fingerprinted class only alerted past ``secret_max_age_days``. ``[secret_rotation].
enforce_secret_expiry_classes`` names the classes that refuse too; it ships empty, so nothing changes
for a config that does not set it.

Arms:

1. an opted-in overdue class REFUSES, with an enforced alert, and the message names the class, its age,
   the limit and the escape;
2. a NOT-opted-in overdue class does not refuse here, and the runner still sees it (alert-only);
3. an opted-in class the engine holds with NO stamp refuses (undetermined age), but a keyless store,
   where no class can carry a stamp, does not;
4. WARN, within-grace and not-held classes are untouched;
5. the setting refuses an unknown name and the DEK's own name at load, and its accepted names match the
   watcher's class list;
6. the call is sited OUTSIDE the reconcile's blanket handler, and the refusal reaches ``Engine.start()``.

PHI/secret-safe: identifiers, dates and test-generated keys only.
"""

from __future__ import annotations

import ast
import datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.config.ai_policy import SecurityEnforcement
from messagefoundry.config.settings import (
    CONNECTOR_SECRET_EXPIRY_CLASS,
    ENFORCEABLE_SECRET_EXPIRY_CLASSES,
    STORE_DEK_SECRET_CLASS,
    EgressSettings,
    SecretRotationSettings,
)
from messagefoundry.pipeline import secret_rotation as sr
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.secret_rotation import (
    SecretRotationOverdueError,
    SecretStamp,
    StoreKeyRotationOverdueError,
    enforce_secret_expiry,
)
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore
from tests._ast_sites import call_sites

_UTC = datetime.UTC
_REF = datetime.datetime(2026, 6, 15, 12, 0, tzinfo=_UTC)
_REF_TS = _REF.timestamp()
_AD = "MEFOR_AUTH_AD_BIND_PASSWORD"
_SMTP = "MEFOR_ALERTS_EMAIL_PASSWORD"
_CONN = "ACME_SFTP_PASSWORD"  # an operator-chosen connector env() key
_OLD = datetime.date(2025, 4, 21)  # 420 days before _REF: past 365 + 30
_YOUNG = datetime.date(2026, 6, 1)
_ENGINE_PY = Path(__file__).resolve().parents[1] / "messagefoundry" / "pipeline" / "engine.py"


class _RecordingSink:
    """Records ``secret_rotation_due`` calls; every other AlertSink method is inert."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def secret_rotation_due(
        self,
        name: str,
        *,
        class_id: str,
        last_rotated: str,
        days_overdue: int,
        enforced: bool = False,
    ) -> None:
        self.calls.append(
            {
                "name": name,
                "secret": class_id,
                "last_rotated": last_rotated,
                "days_overdue": days_overdue,
                "enforced": enforced,
            }
        )

    def __getattr__(self, _name: str) -> Any:
        return lambda *a, **k: None


def _stamp(secret: str, last_rotated: datetime.date) -> SecretStamp:
    return SecretStamp(
        class_id=secret,
        label=secret,
        fingerprint="fp",
        tracked_since=datetime.date(2025, 1, 1),
        last_rotated=last_rotated,
        max_age_days=365,
    )


def _enforce(
    opted: list[str],
    stamps: dict[str, SecretStamp],
    *,
    held: set[str] | None = None,
    enforcement: SecurityEnforcement = SecurityEnforcement.ENFORCE,
    sink: _RecordingSink | None = None,
) -> None:
    enforce_secret_expiry(
        SecretRotationSettings(enforce_secret_expiry_classes=opted),
        stamps,
        enforcement=enforcement,
        held=set(stamps) if held is None else held,
        alert_sink=sink,
        now=_REF_TS,
    )


# --- ARM 1: an opted-in overdue class REFUSES -------------------------------------------------


def test_an_opted_in_overdue_class_refuses_and_alerts() -> None:
    sink = _RecordingSink()
    with pytest.raises(SecretRotationOverdueError) as exc:
        _enforce([_AD], {_AD: _stamp(_AD, _OLD)}, sink=sink)
    (refused,) = exc.value.refused
    assert refused.class_id == _AD
    assert refused.days_overdue == 55  # 420 - 365, the figure the runner's alert would report
    assert refused.last_rotated == "2025-04-21"
    text = str(exc.value)
    assert _AD in text and "55 day(s)" in text and "365-day" in text and "30-day" in text
    # The line that stops an operator must name both ways out.
    assert "enforce_secret_expiry_classes" in text and "Rotate the secret" in text
    # The alert is kept, and it is the enforced one: nothing else has alerted on this class yet.
    assert sink.calls == [
        {
            "name": _AD,
            "secret": _AD,
            "last_rotated": "2025-04-21",
            "days_overdue": 55,
            "enforced": True,
        }
    ]


def test_the_connector_token_covers_connector_credentials_only() -> None:
    stamps = {_CONN: _stamp(_CONN, _OLD), _AD: _stamp(_AD, _OLD)}
    with pytest.raises(SecretRotationOverdueError) as exc:
        _enforce([CONNECTOR_SECRET_EXPIRY_CLASS], stamps)
    assert [r.class_id for r in exc.value.refused] == [_CONN]


def test_every_opted_in_overdue_class_is_named_at_once() -> None:
    """One refusal naming all of them, so an operator does not fix one and meet the next on restart."""
    stamps = {_AD: _stamp(_AD, _OLD), _SMTP: _stamp(_SMTP, _OLD)}
    with pytest.raises(SecretRotationOverdueError) as exc:
        _enforce([_AD, _SMTP], stamps)
    assert sorted(r.class_id for r in exc.value.refused) == [_SMTP, _AD]


def test_a_broken_sink_cannot_swallow_the_refusal() -> None:
    class _BrokenSink(_RecordingSink):
        def secret_rotation_due(self, *a: Any, **k: Any) -> None:
            raise RuntimeError("notifier is down")

    with pytest.raises(SecretRotationOverdueError):
        _enforce([_AD], {_AD: _stamp(_AD, _OLD)}, sink=_BrokenSink())


# --- ARM 2: a NOT-opted-in overdue class alerts only ------------------------------------------


def test_a_not_opted_in_overdue_class_does_not_refuse() -> None:
    sink = _RecordingSink()
    _enforce([_SMTP], {_AD: _stamp(_AD, _OLD)}, sink=sink)  # must not raise
    assert sink.calls == [], "the runner owns the alert for a class that is not opted in"


def test_the_shipped_default_refuses_nothing() -> None:
    assert SecretRotationSettings().enforce_secret_expiry_classes == []
    enforce_secret_expiry(
        SecretRotationSettings(),
        {_AD: _stamp(_AD, datetime.date(2000, 1, 1))},
        enforcement=SecurityEnforcement.ENFORCE,
        held={_AD},
        now=_REF_TS,
    )


def test_the_dek_is_never_judged_here() -> None:
    """The DEK has its own refusal; the connector token must not sweep it in."""
    dek = "MEFOR_STORE_ENCRYPTION_KEY"
    _enforce([CONNECTOR_SECRET_EXPIRY_CLASS], {dek: _stamp(dek, datetime.date(2000, 1, 1))})


# --- ARM 3: an undetermined age refuses, but only where a stamp was possible ------------------


def test_a_held_opted_in_class_with_no_stamp_refuses() -> None:
    sink = _RecordingSink()
    with pytest.raises(SecretRotationOverdueError) as exc:
        _enforce([_AD], {}, held={_AD}, sink=sink)
    (refused,) = exc.value.refused
    assert refused.days_overdue is None and refused.last_rotated == "unknown"
    assert "could not be determined" in str(exc.value)
    assert sink.calls[0]["last_rotated"] == "unknown" and sink.calls[0]["enforced"] is True


def test_a_keyless_store_refuses_nothing() -> None:
    """The engine passes an empty `held` when the store cannot fingerprint, and no stamps exist."""
    _enforce([_AD, CONNECTOR_SECRET_EXPIRY_CLASS], {}, held=set())


# --- ARM 4: the conditions that must NOT refuse ----------------------------------------------


def test_within_the_grace_window_is_untouched() -> None:
    _enforce([_AD], {_AD: _stamp(_AD, datetime.date(2025, 5, 31))})  # 380 days: inside 395


def test_a_young_class_is_untouched() -> None:
    _enforce([_AD], {_AD: _stamp(_AD, _YOUNG)})


def test_no_refusal_under_warn_enforcement() -> None:
    _enforce([_AD], {_AD: _stamp(_AD, _OLD)}, enforcement=SecurityEnforcement.WARN)
    _enforce([_AD], {}, held={_AD}, enforcement=SecurityEnforcement.WARN)


def test_an_opted_in_class_the_engine_does_not_hold_is_skipped() -> None:
    _enforce([_AD], {}, held=set())
    # A stamp left from an earlier start does not make the class held again.
    _enforce([_AD], {_AD: _stamp(_AD, _OLD)}, held=set())


# --- ARM 5: the setting ----------------------------------------------------------------------


def test_an_unknown_class_name_is_rejected_at_load() -> None:
    with pytest.raises(ValidationError, match="not a tracked secret class"):
        SecretRotationSettings(enforce_secret_expiry_classes=["MEFOR_AUTH_AD_BIND_PASSWROD"])


def test_the_dek_name_is_rejected_and_pointed_at_its_own_knob() -> None:
    with pytest.raises(ValidationError, match="enforce_store_key_expiry"):
        SecretRotationSettings(enforce_secret_expiry_classes=["MEFOR_STORE_ENCRYPTION_KEY"])


def test_a_comma_string_splits_and_duplicates_collapse() -> None:
    s = SecretRotationSettings.model_validate(
        {"enforce_secret_expiry_classes": f"{_AD}, connector ,{_AD}"}
    )
    assert s.enforce_secret_expiry_classes == [_AD, "connector"]


def test_the_accepted_names_match_the_watchers_class_list() -> None:
    """The name set lives in config (config must not import the pipeline); this keeps it honest. A
    class the watcher fingerprints but the setting refused would be a class nobody could opt in."""
    watched = {name for name, _label in sr._ENV_SECRET_CLASSES}
    assert sr._DEK_CLASS_ID == STORE_DEK_SECRET_CLASS
    assert watched | {CONNECTOR_SECRET_EXPIRY_CLASS} == ENFORCEABLE_SECRET_EXPIRY_CLASSES


# --- ARM 6: the siting, and the refusal through Engine.start() --------------------------------


def _guarded_reconcile_try(tree: ast.Module) -> ast.Try:
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and call_sites(
            node, "reconcile_rotation_meta", bare_only=True
        ):
            return node
    raise AssertionError("no try/except around reconcile_rotation_meta in engine.py")


def test_the_refusal_is_sited_OUTSIDE_the_blanket_reconcile_handler() -> None:
    tree = ast.parse(_ENGINE_PY.read_text(encoding="utf-8"))
    guarded = _guarded_reconcile_try(tree)
    assert call_sites(guarded, "enforce_secret_expiry", bare_only=True) == [], (
        "enforce_secret_expiry sits inside the blanket `except Exception` that guards the reconcile; "
        "it would be logged and stepped over (BACKLOG #1932)"
    )
    assert call_sites(tree, "enforce_secret_expiry", bare_only=True), (
        "engine.py never calls enforce_secret_expiry — the gate is gone, not merely re-sited"
    )


async def _start_with_old_ad_stamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, settings: SecretRotationSettings
) -> Engine:
    """A real Engine over a real KEYED SQLite store, holding an AD bind password whose persisted stamp
    says it was last rotated in 2020. The stamp carries the SAME keyed fingerprint the reconcile will
    compute, so the reconcile keeps the old date rather than reading a rotation."""
    value = "test-only-bind-password"  # nosec B105 - a test value, never a real credential
    monkeypatch.setenv(_AD, value)
    store = await MessageStore.open(tmp_path / "expiry.db", cipher=make_cipher(generate_key()))
    fp_key = store.secret_rotation_fingerprint_key()
    assert fp_key is not None, "premise: a keyed store fingerprints secrets"
    await store.upsert_secret_rotation_meta(
        _AD,
        fingerprint=sr._keyed_fingerprint(fp_key, value),
        tracked_since="2020-01-01",
        last_rotated="2020-01-01",
    )
    engine = Engine(
        store,
        secret_rotation_settings=settings,
        security_enforcement=SecurityEnforcement.ENFORCE,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        await engine.start()
    except BaseException:
        try:
            await engine.stop()
        except Exception:  # a refused start leaves a partially wired engine; best-effort teardown
            await store.close()
        raise
    return engine


async def test_an_opted_in_overdue_class_aborts_Engine_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(SecretRotationOverdueError) as exc:
        await _start_with_old_ad_stamp(
            tmp_path, monkeypatch, SecretRotationSettings(enforce_secret_expiry_classes=[_AD])
        )
    assert [r.class_id for r in exc.value.refused] == [_AD]


async def test_a_not_opted_in_overdue_class_starts_and_is_still_alerted_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POSITIVE CONTROL on the arm above: the same stamp, no opt-in. The engine starts, and the
    reminder runner still sees the class as overdue, so the alert-only behaviour is intact."""
    engine = await _start_with_old_ad_stamp(tmp_path, monkeypatch, SecretRotationSettings())
    try:
        runner = engine._secret_rotation_runner
        assert runner is not None
        checks = {c.class_id: c for c in runner.run_once()}
        assert checks[_AD].overdue
    finally:
        await engine.stop()


async def test_an_undetermined_opted_in_class_aborts_Engine_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second-order swallow: the reconcile fails, the stamps stay empty, and a gate that only read
    them would not fire. The DEK refuses first on this path, so pin its opt-out off to reach ours."""

    async def _boom(*_a: Any, **_k: Any) -> dict[str, SecretStamp]:
        raise RuntimeError("meta store is unreachable")

    monkeypatch.setattr("messagefoundry.pipeline.engine.reconcile_rotation_meta", _boom)
    with pytest.raises(SecretRotationOverdueError) as exc:
        await _start_with_old_ad_stamp(
            tmp_path,
            monkeypatch,
            SecretRotationSettings(
                enforce_secret_expiry_classes=[_AD], enforce_store_key_expiry=False
            ),
        )
    assert exc.value.refused[0].last_rotated == "unknown"
    # And the DEK refusal is a different type, so this is not that gate firing under another name.
    assert not isinstance(exc.value, StoreKeyRotationOverdueError)


async def test_a_keyless_engine_with_an_opt_in_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Through `_expiry_enforced_held_ids`, not a hand-passed `held`: a keyless store fingerprints
    nothing, so a held, opted-in class has no stamp and that must NOT read as a failed reconcile. The
    engine starts and says the opt-in cannot fire here."""
    monkeypatch.setenv(_AD, "test-only-bind-password")
    store = await MessageStore.open(tmp_path / "keyless.db")
    assert store.secret_rotation_fingerprint_key() is None, "premise: a keyless store"
    engine = Engine(
        store,
        secret_rotation_settings=SecretRotationSettings(enforce_secret_expiry_classes=[_AD]),
        security_enforcement=SecurityEnforcement.ENFORCE,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    with caplog.at_level("WARNING", logger="messagefoundry.pipeline.engine"):
        await engine.start()
    try:
        _assert_the_line_says_nothing_alerts(engine, caplog.text)
    finally:
        await engine.stop()


def _assert_the_line_says_nothing_alerts(engine: Engine, text: str) -> None:
    """BACKLOG #2320: the line said those classes "only alert". On a store that fingerprints
    nothing the reconcile stamps no non-DEK class, so the reminder runner tracks none and nothing
    alerts. The runner's own secret list is the instrument; the log text is what is pinned."""
    assert "does not fingerprint secrets" in text
    assert "neither refuse nor alert" in text
    assert "only alert" not in text
    runner = engine._secret_rotation_runner
    assert runner is not None
    assert _AD not in {c.class_id for c in runner.run_once()}, "premise: the class is untracked"


async def test_a_vault_transit_engine_with_an_opt_in_says_nothing_alerts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #2320, the second store kind the line names. A vault_transit store keys its audit
    chain inside Transit and holds no fingerprint key, so it takes the same branch as keyless."""
    from messagefoundry.config.settings import StoreSettings
    from messagefoundry.store.base import open_store
    from tests.test_crypto_transit import _use_fake

    _use_fake(monkeypatch)
    monkeypatch.setenv(_AD, "test-only-bind-password")
    store = await open_store(
        StoreSettings(path=str(tmp_path / "transit.db"), cipher_provider="vault_transit"),
        create=True,
        keyless_chain_refusal=None,
    )
    assert isinstance(store, MessageStore)
    assert store.cipher().encrypts, "premise: an encrypting store, not a keyless one"
    assert store.secret_rotation_fingerprint_key() is None, "premise: nothing is fingerprinted"
    engine = Engine(
        store,
        secret_rotation_settings=SecretRotationSettings(enforce_secret_expiry_classes=[_AD]),
        security_enforcement=SecurityEnforcement.ENFORCE,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        with caplog.at_level("WARNING", logger="messagefoundry.pipeline.engine"):
            await engine.start()
        _assert_the_line_says_nothing_alerts(engine, caplog.text)
    finally:
        await engine.stop()


def test_the_warn_mode_line_names_when_a_class_can_alert(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """BACKLOG #2320, the sibling line: off enforce it said an expired class "only alerts", which
    is false on a store that fingerprints nothing or with the reminder off."""
    with caplog.at_level("WARNING", logger="messagefoundry.pipeline.secret_rotation"):
        _enforce([_AD], {_AD: _stamp(_AD, _OLD)}, enforcement=SecurityEnforcement.WARN)
    assert "does not refuse" in caplog.text
    assert "not keyless or vault_transit" in caplog.text
    assert "warn_days is above 0" in caplog.text
