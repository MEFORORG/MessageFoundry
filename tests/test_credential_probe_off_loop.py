# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The start-up credential-generation probe runs off the event loop (vault BACKLOG #3164).

``AuthService.probe_credential_generation`` runs the temporary-credential generator once at start.
A pathological ``[auth].password_extra_context_words`` list makes that generator retry its policy
screens many times, so the lifespan must not run it on the loop thread, the way the request-path
callers already do not (BACKLOG #2359). These drive the real lifespan and record where the
generator's screen ran.

Severity is conditional (CLAUDE.md section 0): zero deployments, so a held loop is what a deploying
site would meet at start, never a live exposure.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import pytest
from fastapi import FastAPI

from messagefoundry.api import create_managed_app
from messagefoundry.auth import service as service_module
from messagefoundry.auth.policy import PasswordPolicy
from messagefoundry.config.settings import (
    AlertsSettings,
    AuthSettings,
    EgressSettings,
    SecurityEnforcement,
    SecuritySettings,
    StoreSettings,
)
from messagefoundry.store.crypto import generate_key


def _app(db: Path) -> FastAPI:
    """An engine that starts on an empty store: ``warn`` lets the ADR 0167 gate pass with no
    Administrator, so the lifespan reaches the probe."""
    return create_managed_app(
        store_settings=StoreSettings(path=str(db), encryption_key=generate_key()),
        poll_interval=0.05,
        auth_settings=AuthSettings(),
        alerts_settings=AlertsSettings(
            email_smtp_host="smtp.example.invalid", email_from="alerts@example.invalid"
        ),
        security_settings=SecuritySettings(enforcement=SecurityEnforcement.WARN),
        egress_settings=EgressSettings(deny_by_default=False),
    )


async def _start(app: FastAPI) -> None:
    async with app.router.lifespan_context(app):
        pass


def test_the_lifespan_runs_the_generator_off_the_loop_thread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    on_loop: list[bool] = []

    def recording(policy: PasswordPolicy) -> str | None:
        # A worker thread has no running loop; the loop thread does.
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            on_loop.append(False)
        else:
            on_loop.append(True)
        return None

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(service_module, "credential_generation_problem", recording)
    asyncio.run(_start(_app(tmp_path / "probe.db")))
    # The count is the control: an empty list would pass the assertion below vacuously.
    assert on_loop == [False], "the probe ran once, and not on the event loop thread"


def test_a_probe_that_raises_off_the_loop_still_lets_the_start_continue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The guard still wraps the call now that it is awaited: a raise in the worker thread comes
    back through ``asyncio.to_thread`` and is logged, and the start does not refuse."""

    def broken(policy: PasswordPolicy) -> str | None:
        raise ValueError("a later policy clause raised")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(service_module, "credential_generation_problem", broken)
    with caplog.at_level(logging.ERROR, logger="messagefoundry.api.app"):
        asyncio.run(_start(_app(tmp_path / "probe.db")))  # must not raise
    assert any(
        "the credential-generation probe could not run" in r.getMessage() for r in caplog.records
    )
