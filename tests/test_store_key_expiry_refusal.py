# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 13.3.4 (BACKLOG #1004): a calendar-overdue store DEK must REFUSE, not merely alert.

The DEK has two expiry axes and only one of them stopped. The USAGE axis refuses unconditionally --
``AesGcmCipher`` raises at ``_GCM_MAX_INVOCATIONS`` (2**32), reads no setting, has no opt-out. The
CALENDAR axis computed the same overdue condition and emitted a single alert, so a deployment could
run a calendar-overdue key indefinitely with a log line as the only signal.

**THE SITING IS THE CONTROL, AND `test_the_refusal_is_sited_outside_the_swallowing_handler` IS THE
TEST THAT MATTERS.** ``reconcile_rotation_meta`` is awaited inside a blanket ``except Exception:``
in ``Engine.start`` whose entire body is a log call. A refusal raised beneath that await is caught,
logged and stepped over -- a traceback and a normal engine start. That is not a weaker control, it
is *no* control, and it renders identically to a working one in every green test that does not
specifically look. The 13.3.4 cell's own absence claim was previously found to have exactly this
defect: a stated reintroduction that satisfied a pattern check while describing a refusal that
refused nothing.

That test walks the AST rather than reading the source as text, because "is this raise lexically
inside that try block" is a structural question and a substring search cannot answer it. It was
mutation-proved: moving the gate inside the handler turns it red.
"""

from __future__ import annotations

import ast
import datetime
from pathlib import Path

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
from messagefoundry.pipeline.secret_rotation import (
    DekExpiryRefusal,
    SecretStamp,
    StoreKeyExpiredError,
    alert_dek_expiry_refusal,
    dek_expiry_refusal,
)

_DEK = "MEFOR_STORE_ENCRYPTION_KEY"  # nosec B105 - an env-var NAME, not a secret value
_TODAY = datetime.date(2026, 8, 14)


def _stamp(last_rotated: datetime.date) -> SecretStamp:
    return SecretStamp(
        secret=_DEK,
        label="store data-encryption key",
        fingerprint="dekid-aaa",
        tracked_since=datetime.date(2025, 1, 1),
        last_rotated=last_rotated,
        max_age_days=365,
    )


def _refuse(
    settings: SecretRotationSettings,
    *,
    stamp_age_days: int | None,
    enforcement: SecurityEnforcement = SecurityEnforcement.ENFORCE,
) -> DekExpiryRefusal | None:
    stamps = (
        {}
        if stamp_age_days is None
        else {_DEK: _stamp(_TODAY - datetime.timedelta(stamp_age_days))}
    )
    return dek_expiry_refusal(settings, stamps, _TODAY, enforcement=enforcement)


# --------------------------------------------------------------------------------------------------
# The overdue axis: refuses past max_age + grace, silent inside it, silent when not enforcing.
# --------------------------------------------------------------------------------------------------


def test_refuses_past_max_age_plus_grace() -> None:
    # 365 max + 30 grace = 395. At 420 days the key is 55 days past max age and 25 past grace.
    refusal = _refuse(SecretRotationSettings(), stamp_age_days=420)
    assert refusal is not None
    assert refusal.alerted is True  # the ENFORCE escalation already spoke for this branch
    assert "55 day(s) past" in refusal.reason
    assert "enforce_store_key_expiry = false" in refusal.reason  # names its own opt-out


@pytest.mark.parametrize("age", [0, 200, 365, 395])
def test_silent_within_max_age_and_grace(age: int) -> None:
    """395 is the boundary and must NOT refuse: the condition is ``> grace``, not ``>=``."""
    assert _refuse(SecretRotationSettings(), stamp_age_days=age) is None


def test_refuses_one_day_past_the_boundary() -> None:
    """396 must refuse. Paired with the 395 case above, this pins the boundary from both sides."""
    assert _refuse(SecretRotationSettings(), stamp_age_days=396) is not None


@pytest.mark.parametrize("enforcement", list(SecurityEnforcement))
def test_only_enforce_refuses(enforcement: SecurityEnforcement) -> None:
    """Parametrised over the LIVE enum rather than a hand-listed set.

    The item specifies "silent under WARN/OFF", but ``SecurityEnforcement`` has no ``OFF`` member --
    it is ``ENFORCE`` and ``WARN`` only. Driving this off ``list(SecurityEnforcement)`` means a member
    added later is covered automatically instead of being silently untested, which a hand-written
    list cannot promise.
    """
    refusal = _refuse(SecretRotationSettings(), stamp_age_days=420, enforcement=enforcement)
    assert (refusal is not None) is (enforcement is SecurityEnforcement.ENFORCE)


# --------------------------------------------------------------------------------------------------
# The opt-out drops the REFUSAL and never the reminder.
# --------------------------------------------------------------------------------------------------


def test_opt_out_suppresses_the_refusal() -> None:
    off = SecretRotationSettings(enforce_store_key_expiry=False)
    assert _refuse(off, stamp_age_days=420) is None
    assert _refuse(off, stamp_age_days=None) is None  # including the undetermined branch


def test_the_opt_out_does_not_touch_the_alert_arm() -> None:
    """The reminder is a separate arm and the opt-out must not reach it.

    ``_maybe_escalate_dek`` never reads ``enforce_store_key_expiry`` -- asserted here structurally so
    a future edit that wires the flag into the alert arm fails loudly. An opt-out that also silenced
    the reminder would leave an overdue key with NO signal at all, which is strictly worse than the
    alert-only posture this item replaced.
    """
    source = Path("messagefoundry/pipeline/secret_rotation.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    escalate = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "_maybe_escalate_dek"
    )
    names = {n.attr for n in ast.walk(escalate) if isinstance(n, ast.Attribute)}
    assert "enforce_store_key_expiry" not in names


def test_the_loosening_names_the_opt_out_only_when_it_is_off() -> None:
    def named(sr: SecretRotationSettings | None) -> bool:
        rows = security_loosenings(
            SecuritySettings(), StoreSettings(), AuthSettings(), AlertsSettings(), [], [], [], sr
        )
        return any(switch == "enforce_store_key_expiry" for switch, _ in rows)

    assert named(SecretRotationSettings(enforce_store_key_expiry=False)) is True
    assert named(SecretRotationSettings()) is False  # the shipped default is not a loosening
    assert named(None) is False


def test_the_setting_ships_on() -> None:
    """A default-off build would buy the setting and not the posture."""
    assert SecretRotationSettings().enforce_store_key_expiry is True


# --------------------------------------------------------------------------------------------------
# An UNDETERMINED age refuses. It is not a young one.
# --------------------------------------------------------------------------------------------------


def test_undetermined_age_refuses_and_is_not_pre_alerted() -> None:
    """No stamp and no override under ENFORCE: refuse, and say so, because nothing else will.

    This is the branch a swallowed reconcile produces. ``Engine._secret_rotation_stamps`` is assigned
    only on the successful path, so a gate treating "no stamp" as "not overdue" would be silently
    disabled by the very failure it most needs to survive.
    """
    refusal = _refuse(SecretRotationSettings(), stamp_age_days=None)
    assert refusal is not None
    assert refusal.alerted is False  # nothing has alerted for this branch -- the caller must
    assert "UNDETERMINED" in refusal.reason


def test_the_undetermined_branch_emits_its_own_alert() -> None:
    calls: list[dict[str, object]] = []

    class _Sink:
        def secret_rotation_due(self, name: str, **kw: object) -> None:
            calls.append({"name": name, **kw})

        def __getattr__(self, _n: str) -> object:  # unused AlertSink surface
            return lambda *a, **k: None

    alert_dek_expiry_refusal(_Sink(), DekExpiryRefusal(reason="r", alerted=False))  # type: ignore[arg-type]
    assert len(calls) == 1
    assert calls[0]["enforced"] is True
    assert "UNDETERMINED" in str(calls[0]["name"])

    # Already alerted by the ENFORCE escalation -> no duplicate.
    calls.clear()
    alert_dek_expiry_refusal(_Sink(), DekExpiryRefusal(reason="r", alerted=True))  # type: ignore[arg-type]
    assert calls == []


def test_a_missing_sink_never_costs_the_refusal() -> None:
    """Losing the alert must not become a start failure -- the raise is the louder half."""
    alert_dek_expiry_refusal(None, DekExpiryRefusal(reason="r", alerted=False))


# --------------------------------------------------------------------------------------------------
# First-start trip cases: the shipped config cannot be surprised, but two real ones can.
# --------------------------------------------------------------------------------------------------


def test_operator_declared_prior_rotation_trips_at_first_start() -> None:
    """An operator declaring a TRUE prior rotation date >395 days back refuses immediately.

    "No configuration can be surprised" is false; "the SHIPPED configuration cannot be surprised" is
    true, and the difference is worth a test rather than a sentence.
    """
    settings = SecretRotationSettings(store_key_last_rotated="2025-01-01")  # 590 days before _TODAY
    refusal = dek_expiry_refusal(settings, {}, _TODAY, enforcement=SecurityEnforcement.ENFORCE)
    assert refusal is not None
    assert "2025-01-01" in refusal.reason  # the override wins over the (absent) stamp

    off = SecretRotationSettings(
        store_key_last_rotated="2025-01-01", enforce_store_key_expiry=False
    )
    assert dek_expiry_refusal(off, {}, _TODAY, enforcement=SecurityEnforcement.ENFORCE) is None


def test_a_short_max_age_trips_at_first_start() -> None:
    settings = SecretRotationSettings(store_key_max_age_days=1, enforce_grace_days=0)
    assert _refuse(settings, stamp_age_days=10) is not None

    off = SecretRotationSettings(
        store_key_max_age_days=1, enforce_grace_days=0, enforce_store_key_expiry=False
    )
    assert _refuse(off, stamp_age_days=10) is None


def test_the_shipped_configuration_cannot_trip_for_395_days() -> None:
    shipped = SecretRotationSettings()
    assert shipped.store_key_max_age_days + shipped.enforce_grace_days == 395
    assert _refuse(shipped, stamp_age_days=395) is None


# --------------------------------------------------------------------------------------------------
# THE SITING. This is the test that separates a control from a decoration.
# --------------------------------------------------------------------------------------------------


def test_the_refusal_is_sited_outside_the_swallowing_handler() -> None:
    """The raise must NOT be lexically inside the try whose handler only logs.

    ``Engine.start`` awaits ``reconcile_rotation_meta`` inside a blanket ``except Exception:`` whose
    entire body is ``log.exception(...)``. A ``raise StoreKeyExpiredError`` sited within that try is
    caught there and stepped over, giving a traceback and a NORMAL ENGINE START. Every other test in
    this file would still pass, because they exercise the decision function rather than its placement
    -- which is precisely why this one exists and why it walks the AST instead of grepping.

    Mutation-proved: moving the gate inside the handler turns this red.
    """
    tree = ast.parse(Path("messagefoundry/pipeline/engine.py").read_text(encoding="utf-8"))

    def raises_store_key_expired(node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Raise) or sub.exc is None:
                continue
            call = sub.exc
            func = call.func if isinstance(call, ast.Call) else call
            if isinstance(func, ast.Name) and func.id == "StoreKeyExpiredError":
                return True
        return False

    # The raise must exist at all -- otherwise this test passes vacuously on a deleted control.
    assert raises_store_key_expired(tree), "no raise StoreKeyExpiredError in engine.py"

    # ...and must not sit inside ANY try that swallows the reconcile.
    swallowing = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Try)
        and any(
            isinstance(n, ast.Name) and n.id == "reconcile_rotation_meta"
            for stmt in node.body
            for n in ast.walk(stmt)
        )
    ]
    assert swallowing, "could not find the reconcile try block -- this test has gone stale"
    for node in swallowing:
        for stmt in node.body:
            assert not raises_store_key_expired(stmt), (
                "StoreKeyExpiredError is raised INSIDE the reconcile try, whose handler only logs. "
                "The refusal would be swallowed and the engine would start normally."
            )


def test_the_engine_imports_the_refusal_and_calls_it() -> None:
    """A decision function nobody calls is a decoration. Pin the wiring, not just the logic."""
    source = Path("messagefoundry/pipeline/engine.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    called = {
        n.func.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert "dek_expiry_refusal" in called
    assert "alert_dek_expiry_refusal" in called


def test_the_error_is_not_swallowed_by_being_too_generic() -> None:
    """It must be its own type, so a caller can distinguish it from any other start failure."""
    assert issubclass(StoreKeyExpiredError, RuntimeError)
    assert StoreKeyExpiredError is not RuntimeError
