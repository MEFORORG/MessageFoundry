# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A CI leg that weakens TLS must also stop enforcing — the two are mutually exclusive.

THE DEFECT THIS EXISTS FOR. The ``load test (smoke, sqlserver)`` legs were RED for four consecutive
nights (2026-07-27..30) on::

    ValueError: SQL Server TLS is weakened (trust_server_certificate=true or encrypt=false)

The job *did* set ``MEFOR_ALLOW_INSECURE_TLS=1``, and had since the history reset. What changed is that
ADR 0148 (GIVEN 1) remapped the built-in ``dev`` env from SYNTHETIC to **PHI** — and under an enforcing
PHI posture that escape is clamped **inert** by design (#200 / ADR 0092 decision 2,
``weakened_tls_escape_permitted``).

So the combination the job asked for is impossible on purpose::

    trust_server_certificate=true  +  enforcement=enforce   ->  REFUSED, always

Nothing caught it, because a nightly is not a PR context and the ``CI gate`` roll-up correctly treats
those PR-skipped legs as a pass. This test makes the incompatibility fail LOUDLY at PR time instead.

THE RULE, AND WHAT RE-KEYED IT. If a serve-based CI job sets
``MEFOR_STORE_TRUST_SERVER_CERTIFICATE=true`` (a self-signed service container — the only practical
option for a ``services:`` block, which starts before any step runs and so cannot be handed a cert
generated in a step), then it MUST also set ``MEFOR_SECURITY_ENFORCEMENT=warn``.

**That used to be ``MEFOR_SECURITY_HANDLES_REAL_PATIENT_DATA=false``, and BACKLOG #1279 retired it.**
The clamp reads ``enforcing`` alone now: every instance carries patient data, so declaring one
synthetic is neither possible nor, if it were, the narrow thing to do here. The replacement is
*strictly narrower* — the retired declaration silenced nineteen start-up gates, and ``warn`` downgrades
them to warnings and silences none. The clamp itself is unchanged and so is the failure it produces.

The alternative — keeping ``enforce`` — requires a REAL certificate, which means moving the job off
``services:`` onto a ``docker run`` with a generated cert mounted and trusted. Worth doing
deliberately; not as a side effect of unbreaking a nightly.
"""

from __future__ import annotations

import pytest

_TRUST = "MEFOR_STORE_TRUST_SERVER_CERTIFICATE"
_ENFORCEMENT = "MEFOR_SECURITY_ENFORCEMENT"
_RETIRED = "MEFOR_SECURITY_HANDLES_REAL_PATIENT_DATA"
_TRUTHY = {"true", "1", "yes", "on"}


def _serve_steps_with_env(workflow: str) -> list[tuple[str, str, dict]]:
    """(job key, step name, env) for every step that actually STARTS THE ENGINE.

    Scoped to ``messagefoundry serve`` deliberately, and this scoping is the whole correctness of the
    module. The posture clamp only exists when the engine builds one: ``api/app.py``'s lifespan threads
    ``hop_posture_from_ai(...)`` into ``open_store``, so a served instance gets a real ``HopPosture``.
    A **pytest** step calls ``open_store`` directly with ``posture=None``, which
    ``weakened_tls_escape_permitted`` documents as the *unclamped* fallback — byte-identical to
    pre-#200.

    Without this narrowing the first draft of this test flagged six `sqlserver-store` steps that set
    ``MEFOR_STORE_TRUST_SERVER_CERTIFICATE=true`` and are perfectly green — they run the pytest suites,
    never `serve`. Demanding a relaxation there would have been a false positive that "fixing" makes
    the repo *less* honest: those legs genuinely exercise the PHI-shaped store path.
    """
    yaml = pytest.importorskip("yaml")
    from tests._workflow_contexts import WORKFLOWS

    doc = yaml.safe_load((WORKFLOWS / workflow).read_text(encoding="utf-8"))
    out: list[tuple[str, str, dict]] = []
    for key, job in (doc.get("jobs") or {}).items():
        for step in (job or {}).get("steps") or []:
            env = (step or {}).get("env")
            run = str((step or {}).get("run") or "")
            if isinstance(env, dict) and "messagefoundry serve" in run:
                out.append((key, str((step or {}).get("name") or "<unnamed>"), env))
    return out


def test_a_weakened_tls_leg_stops_enforcing() -> None:
    """The incompatibility, made mechanical.

    While enforcing, the ``MEFOR_ALLOW_INSECURE_TLS`` escape is inert, so a leg that trusts a
    self-signed server certificate can never start. Requiring ``enforcement=warn`` alongside it turns a
    four-night silent breakage into a PR-time failure.
    """
    offenders: list[str] = []
    checked = 0
    for job, step, env in _serve_steps_with_env("ci.yml"):
        if str(env.get(_TRUST, "")).strip().lower() not in _TRUTHY:
            continue
        checked += 1
        declared = str(env.get(_ENFORCEMENT, "")).strip().lower()
        if declared != "warn":
            offenders.append(
                f"ci.yml:{job} — step {step!r} sets {_TRUST}=true but "
                f"{_ENFORCEMENT}={declared or '<unset>'}"
            )

    # Liveness: if no leg trusts a self-signed cert any more, say so rather than pass on an empty scan.
    print(
        f"[ci-leg-tls-posture] examined {checked} serve step(s) that trust a self-signed server certificate"
    )
    assert checked > 0, (
        f"no `messagefoundry serve` step in ci.yml sets {_TRUST}=true any more. If those legs were reworked onto a real "
        "certificate that is a genuine improvement — delete this guard deliberately rather than "
        "letting it pass by finding nothing."
    )
    assert not offenders, (
        "a CI leg trusts a self-signed server certificate while still enforcing:\n  "
        + "\n  ".join(offenders)
        + "\nWhile enforcing, the MEFOR_ALLOW_INSECURE_TLS escape is INERT by design (ADR 0092 "
        "decision 2), so that leg cannot start at all — it fails with 'SQL Server TLS is weakened'. "
        f"Either set {_ENFORCEMENT}=warn, or give the leg a real certificate, which means moving it "
        "off a `services:` container."
    )


def test_the_escape_alone_is_not_mistaken_for_a_fix() -> None:
    """``MEFOR_ALLOW_INSECURE_TLS`` present without the dial turned down is the exact trap.

    It reads like the fix — it is even what the error message names first — and it is what the job had
    set, unchanged, for the entire four nights it was failing. The variable is necessary but NOT
    sufficient while the instance enforces.
    """
    for job, step, env in _serve_steps_with_env("ci.yml"):
        if "MEFOR_ALLOW_INSECURE_TLS" not in env:
            continue
        if str(env.get(_TRUST, "")).strip().lower() not in _TRUTHY:
            continue
        declared = str(env.get(_ENFORCEMENT, "")).strip().lower()
        assert declared == "warn", (
            f"ci.yml:{job} — step {step!r} sets MEFOR_ALLOW_INSECURE_TLS with {_TRUST}=true but does "
            f"not set {_ENFORCEMENT}=warn. The escape is clamped inert while enforcing, so on its own "
            "it does nothing here — this is the configuration that failed silently for four nights "
            "while looking correct."
        )


def test_no_leg_still_sets_the_retired_declaration() -> None:
    """The retired key is refused at LOAD, so a leg that still sets it fails at start, not at review.

    This is the migration's own tripwire and it is deliberately wider than the two tests above: it
    covers every serve step, not only the TLS-weakened ones, because ``handles_real_patient_data`` was
    a convenience anywhere a CI box wanted a quiet start. A leg that kept it would die on
    ``[security].handles_real_patient_data was REMOVED``, which is a clear message but arrives a
    nightly too late (BACKLOG #1279).
    """
    steps = _serve_steps_with_env("ci.yml")
    assert steps, "no `messagefoundry serve` step found in ci.yml — this guard would scan nothing"
    offenders = [
        f"ci.yml:{job} — step {step!r} still sets {_RETIRED}"
        for job, step, env in steps
        if _RETIRED in env
    ]
    assert not offenders, (
        "a CI leg sets a config key the loader REFUSES:\n  "
        + "\n  ".join(offenders)
        + f"\n{_RETIRED} was removed in BACKLOG #1279 — every instance carries patient data. Set the "
        "individual switch the leg actually needs (see the refusal message, which names them)."
    )
