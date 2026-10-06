# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2131: the notice gate refuses before ``engine.start()``, not after it.

#1923 moved the construction of ``AuthService`` ahead of the start, so the OIDC revocation refusal
stops startup before any connection starts. ``auth.initialize()`` and the BACKLOG #1020 notice gate
stayed below the start. On a first run no enabled Administrator exists yet, so under ``enforce``
the gate refused only after every connection had started. Both now run before the start.

The refusal arm alone would pass against a lifespan that never reaches the start at all, so the
warn arm is its control: the same app with the dial moved, and the probe must fire there.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.pipeline.engine import Engine
from tests.test_security_notice_deliverability import _ENFORCE, _WARN, _phi_app


def _record_engine_start(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace ``Engine.start`` with a probe that records the call and fails startup, and wrap
    ``Engine.stop`` to record it. Failing lets the control arm stop before any connection starts
    while still proving the lifespan reached the start."""
    calls: list[str] = []
    real_stop = Engine.stop

    async def _probe(self: Engine) -> None:
        calls.append("engine.start")
        raise RuntimeError("PROBE: engine.start reached")

    async def _stop(self: Engine) -> None:
        calls.append("engine.stop")
        await real_stop(self)

    monkeypatch.setattr(Engine, "start", _probe)
    monkeypatch.setattr(Engine, "stop", _stop)
    return calls


async def test_the_notice_gate_refuses_before_engine_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _record_engine_start(monkeypatch)
    app = _phi_app(tmp_path, security=_ENFORCE)
    with pytest.raises(RuntimeError, match="no enabled Administrator exists"):
        async with app.router.lifespan_context(app):
            pass  # pragma: no cover -- startup must not reach here
    # Never started, and still torn down, so the store is closed and the process can exit (#1257).
    assert calls == ["engine.stop"]


async def test_the_same_app_under_warn_reaches_engine_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE CONTROL. Under warn the gate logs and returns, so the probe must fire. Without this the
    empty start above is equally consistent with a lifespan that never reaches the start."""
    calls = _record_engine_start(monkeypatch)
    app = _phi_app(tmp_path, security=_WARN)
    with pytest.raises(RuntimeError, match="PROBE: engine.start reached"):
        async with app.router.lifespan_context(app):
            pass  # pragma: no cover -- the probe fails startup
    assert calls == ["engine.start", "engine.stop"]
