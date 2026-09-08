# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 13.3.4 / BACKLOG #1004 — the store DEK's CALENDAR expiry now REFUSES, with a loud opt-out.

The key has two expiry axes and, before this, only one of them stopped anything. The **usage** axis
refuses unconditionally at ``2**32`` encrypts (``AesGcmCipher._count_invocation``, covered by
``tests/test_asvs_gcm_invocation_bound.py``). The **calendar** axis computed the same overdue condition
and emitted a single alert inside a try/except that logged a *sink* failure — no raise, no exit.

Five arms, and the fifth is the one that separates a control from a log line:

1. an overdue calendar age REFUSES (unit, and again through ``Engine.start()``);
2. an UNDETERMINED age REFUSES — not "alerts", and not "reads as young";
3. ``enforce_store_key_expiry = false`` disables the refusal AND is named by ``security_loosenings()``;
4. a non-overdue key is unaffected (without this arm, a gate that refused everything would pass 1-3);
5. the SITING: the refusal must not be swallowed by the blanket ``except Exception`` guarding the
   rotation-meta reconcile in ``Engine.start``. Proved two ways — an AST check that the call is not
   lexically inside that handler's ``try``, and the two engine-level tests above, which would both go
   green-by-omission (``start()`` returning normally) if the gate were moved beneath it.

PHI/secret-safe: identifiers, dates and one-way key-ids only, and every key here is generated for the
test. No message bodies are involved on this path at all.
"""

from __future__ import annotations

import ast
import datetime
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.ai_policy import SecurityEnforcement
from messagefoundry.config.settings import (
    AlertsSettings,
    AuthSettings,
    SecretRotationSettings,
    SecuritySettings,
    StoreSettings,
    security_loosenings,
)
from messagefoundry.pipeline import secret_rotation as sr
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.secret_rotation import (
    SecretStamp,
    StoreKeyRotationOverdueError,
    enforce_store_key_expiry,
)
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore

_UTC = datetime.UTC
_REF = datetime.datetime(2026, 6, 15, 12, 0, tzinfo=_UTC)
_REF_TS = _REF.timestamp()
_DEK = "MEFOR_STORE_ENCRYPTION_KEY"
_ENGINE_PY = Path(__file__).resolve().parents[1] / "messagefoundry" / "pipeline" / "engine.py"


class _RecordingSink:
    """Records ``secret_rotation_due`` calls; every other AlertSink method is inert."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

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

    def __getattr__(self, _name: str) -> Any:
        return lambda *a, **k: None


def _stamps(last_rotated: datetime.date) -> dict[str, SecretStamp]:
    return {
        _DEK: SecretStamp(
            secret=_DEK,
            label="store data-encryption key",
            fingerprint="dekid-aaa",
            tracked_since=datetime.date(2025, 1, 1),
            last_rotated=last_rotated,
            max_age_days=365,
        )
    }


def _enforce(**over: Any) -> None:
    """Run the gate at the fixed reference clock with ENFORCE + a keyed store unless overridden."""
    kw: dict[str, Any] = {
        "settings": SecretRotationSettings(),
        "stamps": _stamps(datetime.date(2025, 4, 21)),  # 420 days before _REF
        "enforcement": SecurityEnforcement.ENFORCE,
        "dek_key_id": "dekid-aaa",
        "alert_sink": None,
        "now": _REF_TS,
    }
    kw.update(over)
    enforce_store_key_expiry(
        kw.pop("settings"),
        kw.pop("stamps"),
        **kw,
    )


# --- ARM 1: an overdue calendar age REFUSES ----------------------------------------------------


def test_overdue_calendar_age_refuses() -> None:
    """420 days old, 365 max + 30 grace = 395 -> 25 days past grace. Before #1004 this only alerted."""
    with pytest.raises(StoreKeyRotationOverdueError) as exc:
        _enforce()
    assert exc.value.days_overdue == 55  # 420 - 365, the same figure the escalation alert reports
    assert exc.value.last_rotated == "2025-04-21"
    # The message must name the remedy, not just the fault: an operator meeting this at 3am needs the
    # two ways out (rotate, or accept the risk explicitly) in the line that stopped them.
    text = str(exc.value)
    assert "rotate-key" in text
    assert "enforce_store_key_expiry = false" in text


def test_the_operator_override_date_drives_the_refusal() -> None:
    """`store_key_last_rotated` wins over the stamp — the first-start trip case the item requires."""
    with pytest.raises(StoreKeyRotationOverdueError):
        _enforce(
            settings=SecretRotationSettings(store_key_last_rotated="2025-01-01"),  # 530 days
            stamps={},  # no stamp at all: a fresh install whose operator declared a real prior date
        )


def test_a_short_max_age_trips_at_first_start() -> None:
    """The other first-start trip case: shipped stamp, operator-shortened max age."""
    with pytest.raises(StoreKeyRotationOverdueError):
        _enforce(
            settings=SecretRotationSettings(store_key_max_age_days=1, enforce_grace_days=0),
            stamps=_stamps(datetime.date(2026, 6, 1)),  # 14 days old, max 1 + grace 0
        )


# --- ARM 2: an UNDETERMINED age REFUSES --------------------------------------------------------


def test_undetermined_age_refuses_and_alerts() -> None:
    """No stamp and no operator date, on a KEYED store that tracks rotation meta: the reconcile failed
    and was swallowed upstream. An undetermined age is not a young one — it refuses, and it says why."""
    sink = _RecordingSink()
    with pytest.raises(StoreKeyRotationOverdueError) as exc:
        _enforce(stamps={}, alert_sink=sink)
    assert exc.value.last_rotated == "unknown"
    assert exc.value.days_overdue is None
    assert "could not be determined" in str(exc.value)
    # The alert is required IN ADDITION, never instead — nothing else recorded WHY the engine stopped.
    assert len(sink.calls) == 1
    assert sink.calls[0]["enforced"] is True
    assert sink.calls[0]["last_rotated"] == "unknown"


def test_a_broken_sink_cannot_swallow_the_undetermined_refusal() -> None:
    """The escalation alert's own try/except catches a SINK failure. That containment must not reach the
    stop: a notifier outage that silently re-enabled an expired key would be the defect one layer down."""

    class _BrokenSink(_RecordingSink):
        def secret_rotation_due(self, *a: Any, **k: Any) -> None:
            raise RuntimeError("notifier is down")

    with pytest.raises(StoreKeyRotationOverdueError):
        _enforce(stamps={}, alert_sink=_BrokenSink())


# --- ARM 3: the opt-out disables the refusal, and announces itself -----------------------------


def test_opt_out_suppresses_the_refusal_but_keeps_the_alert() -> None:
    """`enforce_store_key_expiry = false` drops the RAISE and nothing else. The reminder still fires on
    the undetermined branch — an operator who accepted the risk still has to be told the key is stale."""
    sink = _RecordingSink()
    _enforce(  # must not raise
        settings=SecretRotationSettings(enforce_store_key_expiry=False),
        stamps={},
        alert_sink=sink,
    )
    assert len(sink.calls) == 1, "the opt-out must not also silence the reminder"


def test_opt_out_suppresses_the_overdue_refusal() -> None:
    _enforce(settings=SecretRotationSettings(enforce_store_key_expiry=False))  # must not raise


def test_the_overdue_branch_does_not_double_alert_on_the_normal_path() -> None:
    """A populated stamp map means the reconcile completed, so `_maybe_escalate_dek` has ALREADY sent
    the enforced alert on this exact condition. A second one here would train operators to ignore it."""
    sink = _RecordingSink()
    with pytest.raises(StoreKeyRotationOverdueError):
        _enforce(alert_sink=sink)  # default stamps: 420 days old, reconcile succeeded
    assert sink.calls == []


def test_the_overdue_branch_DOES_alert_when_nothing_else_has() -> None:
    """The narrow silent path: the reconcile failed (no stamps) AND the operator set
    `store_key_last_rotated`, so there is a date to judge but no escalation alert went out. With the
    opt-out ON the raise is loud enough; with it OFF this alert is the only remaining signal."""
    sink = _RecordingSink()
    _enforce(
        settings=SecretRotationSettings(
            store_key_last_rotated="2025-01-01", enforce_store_key_expiry=False
        ),
        stamps={},
        alert_sink=sink,
    )
    assert len(sink.calls) == 1, "an overdue key with the opt-out on must not start in silence"
    assert sink.calls[0]["last_rotated"] == "2025-01-01"  # a real date, not "unknown"
    assert sink.calls[0]["enforced"] is True


def test_the_opt_out_is_a_NAMED_security_loosening() -> None:
    """A silent opt-out from a refusal is indistinguishable from the refusal never having been built."""
    named = dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            SecretRotationSettings(enforce_store_key_expiry=False),
            (),
            (),
            (),
        )
    )
    assert "enforce_store_key_expiry" in named
    # The entry must say what the SITE gives up, not that a setting is off.
    risk = named["enforce_store_key_expiry"]
    assert "calendar" in risk.lower()
    assert "alert" in risk.lower()


def test_the_shipped_default_is_not_reported_as_a_loosening() -> None:
    """Non-vacuity for the arm above: at the default the registry must stay silent, or it is noise."""
    named = [
        n
        for n, _ in security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            SecretRotationSettings(),
            (),
            (),
            (),
        )
    ]
    assert named == []
    assert SecretRotationSettings().enforce_store_key_expiry is True


# --- ARM 4: a key that is NOT overdue is unaffected --------------------------------------------


def test_a_young_key_is_untouched() -> None:
    """Without this arm, a gate that refused unconditionally would pass every test above."""
    _enforce(stamps=_stamps(datetime.date(2026, 6, 1)))  # 14 days old


def test_within_the_grace_window_is_untouched() -> None:
    """Past max age but inside the enforcement grace: still an alert-only condition, as before."""
    _enforce(stamps=_stamps(datetime.date(2025, 5, 31)))  # 380 days: past 365, inside 395


def test_no_refusal_under_warn_enforcement() -> None:
    """WARN is the other dial position (there is no OFF). The gates warn and continue there, and this
    refusal follows the same dial as the ENFORCE escalation alert it rides beside."""
    _enforce(enforcement=SecurityEnforcement.WARN, stamps=_stamps(datetime.date(2024, 1, 1)))
    _enforce(enforcement=SecurityEnforcement.WARN, stamps={})  # undetermined, too


def test_a_keyless_store_has_no_dek_to_expire() -> None:
    """No local DEK (keyless, or `vault_transit`) means no calendar axis — and an undetermined age
    there is the ORDINARY state, not a swallowed failure. Refusing would break every keyless start."""
    _enforce(dek_key_id=None, stamps={})


# --- ARM 5: the SITING, which is what makes this a control ------------------------------------


def _calls_named(node: ast.AST, name: str) -> list[ast.Call]:
    return [
        n
        for n in ast.walk(node)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == name
    ]


def _guarded_reconcile_try(tree: ast.Module) -> ast.Try:
    """The ``try`` in engine.py whose body awaits ``reconcile_rotation_meta`` — the blanket handler
    whose entire body is a log call. Located by CONTENT, so it survives any line-number churn."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        if _calls_named(node, "reconcile_rotation_meta"):
            return node
    raise AssertionError(
        "no try/except around reconcile_rotation_meta in engine.py — this test's premise is gone; "
        "re-derive the siting rather than deleting the check"
    )


def test_the_reconcile_handler_is_still_the_blanket_one_this_test_guards_against() -> None:
    """POSITIVE CONTROL. Everything below is worthless if this handler stopped being a blanket
    swallow — the test would then be pinning the siting of a gate against a handler that re-raises."""
    tree = ast.parse(_ENGINE_PY.read_text(encoding="utf-8"))
    guarded = _guarded_reconcile_try(tree)
    assert guarded.handlers, "the reconcile await is no longer guarded at all"
    for handler in guarded.handlers:
        assert isinstance(handler.type, ast.Name) and handler.type.id == "Exception", (
            "the reconcile handler narrowed — re-read the siting decision"
        )
        assert not any(isinstance(n, ast.Raise) for n in ast.walk(handler)), (
            "the reconcile handler now re-raises; the swallow this test guards against is gone"
        )


def test_the_refusal_is_sited_OUTSIDE_the_blanket_reconcile_handler() -> None:
    """THE MUTATION CONTROL. Move the ``enforce_store_key_expiry`` call inside the try above and this
    goes red. A refusal beneath that handler is logged and stepped over: a traceback, not a control."""
    tree = ast.parse(_ENGINE_PY.read_text(encoding="utf-8"))
    guarded = _guarded_reconcile_try(tree)
    assert _calls_named(guarded, "enforce_store_key_expiry") == [], (
        "the store-key expiry refusal is sited INSIDE the blanket `except Exception` guarding the "
        "rotation-meta reconcile, whose entire body is a log call. It would be swallowed and the "
        "engine would start on an expired key. Site it after the handler (BACKLOG #1004, trap 1)."
    )
    # ...and it must exist somewhere, or the assertion above passes by absence.
    assert _calls_named(tree, "enforce_store_key_expiry"), (
        "engine.py never calls enforce_store_key_expiry — the gate is gone, not merely re-sited"
    )


# --- ARM 5 (behavioural): the refusal propagates out of Engine.start() -------------------------


async def _start_engine(tmp_path: Path, settings: SecretRotationSettings) -> None:
    """Start a real Engine over a real KEYED SQLite store and let any refusal escape."""
    store = await MessageStore.open(tmp_path / "expiry.db", cipher=make_cipher(generate_key()))
    engine = Engine(
        store,
        secret_rotation_settings=settings,
        security_enforcement=SecurityEnforcement.ENFORCE,
    )
    try:
        await engine.start()
    finally:
        try:
            await engine.stop()
        except (
            Exception
        ):  # a refused start leaves a partially wired engine; teardown is best-effort
            await store.close()


async def test_an_overdue_key_aborts_Engine_start(tmp_path: Path) -> None:
    """END TO END, and this is also a siting proof: sited inside the blanket handler, `start()` would
    return normally and `pytest.raises` would fail. A green here is evidence only because of that."""
    with pytest.raises(StoreKeyRotationOverdueError):
        await _start_engine(
            tmp_path,
            SecretRotationSettings(store_key_last_rotated="2020-01-01"),  # far past 365 + 30
        )


async def test_an_undetermined_age_aborts_Engine_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TRAP 1b, the second-order swallow. Force the reconcile to raise: the blanket handler eats it,
    the stamps stay empty, and a gate written to read them would silently not fire. It must refuse."""

    async def _boom(*_a: Any, **_k: Any) -> dict[str, SecretStamp]:
        raise RuntimeError("meta store is unreachable")

    monkeypatch.setattr("messagefoundry.pipeline.engine.reconcile_rotation_meta", _boom)
    with pytest.raises(StoreKeyRotationOverdueError):
        await _start_engine(tmp_path, SecretRotationSettings())


async def test_the_opt_out_lets_an_overdue_engine_start(tmp_path: Path) -> None:
    """The escape has to actually work, or it is not an opt-out."""
    await _start_engine(
        tmp_path,
        SecretRotationSettings(store_key_last_rotated="2020-01-01", enforce_store_key_expiry=False),
    )


async def test_the_opt_out_lets_an_undetermined_engine_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _boom(*_a: Any, **_k: Any) -> dict[str, SecretStamp]:
        raise RuntimeError("meta store is unreachable")

    monkeypatch.setattr("messagefoundry.pipeline.engine.reconcile_rotation_meta", _boom)
    await _start_engine(tmp_path, SecretRotationSettings(enforce_store_key_expiry=False))


async def test_a_fresh_keyed_engine_starts_on_the_shipped_defaults(tmp_path: Path) -> None:
    """ARM 4 at the engine level. The shipped configuration cannot be surprised: a first keyed start
    stamps the DEK as new (tracked_since is an age FLOOR), so nothing can trip for 395 days."""
    await _start_engine(tmp_path, SecretRotationSettings())


def test_the_gate_and_the_alert_read_the_SAME_overdue_expression() -> None:
    """One arithmetic, not two. If the refusal and the ENFORCE alert could disagree about "overdue",
    an operator would meet a stop with no matching alert — or an alert with no stop."""
    sink = _RecordingSink()
    stamps = _stamps(datetime.date(2025, 4, 21))
    sr._maybe_escalate_dek(
        SecretRotationSettings(),
        stamps,
        _REF.date(),
        enforcement=SecurityEnforcement.ENFORCE,
        alert_sink=sink,  # type: ignore[arg-type]
    )
    with pytest.raises(StoreKeyRotationOverdueError) as exc:
        _enforce(stamps=stamps)
    assert sink.calls[0]["days_overdue"] == exc.value.days_overdue
