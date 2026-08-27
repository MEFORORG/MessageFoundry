# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""File-endpoint alternate Windows / network-share credential (UNC/SMB) — BACKLOG #111, ADR 0132.

CI cannot stand up a real alt-credential UNC share, so the **live** ``LogonUser`` path is a
Windows-CI/manual gate. These tests cover everything that IS runnable anywhere:

* the **non-Windows clean-error** path (the one #111 note calls out as runnable) — a configured
  credential fails loud at build, never a silent no-op;
* the ``env()``-only password enforcement + secret redaction (config/wiring);
* the :class:`WindowsCredential` model;
* the :class:`CredentialContext` mechanics with the four win32 primitives monkeypatched — the
  ``LogonUser -> Impersonate -> fn -> RevertToSelf -> CloseHandle`` bracketing, the dedicated
  impersonated thread, the release-on-close, and that it **wraps** the File connectors' real
  filesystem work (send / validate_startup) rather than bypassing it;
* that ``close()`` releases the worker **without touching the event loop's shared default executor**
  and without waiting on a wedged share forever (BACKLOG #1195, ASVS 15.4.4) — the one path on which
  this module could have starved the pool it exists to stay off;
* that a logon failure rides the existing ``except OSError`` paths (DeliveryError / SourceStartupError),
  never a crash.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import (
    ConnectorType,
    Destination,
    Source,
    WindowsCredential,
)
from messagefoundry.config.wiring import EnvRef, File, WiringError, env, redacted_settings
from messagefoundry.transports import build_destination, build_source, wincred
from messagefoundry.transports.base import DeliveryError, SourceStartupError
from messagefoundry.transports.file import FileDestination, FileSource

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\r"


# --- fakes for the four win32 ctypes primitives ------------------------------


class _FakeWin32:
    """Records the order of the win32 credential primitives so a test can assert the bracketing, and
    lets a test force a logon failure. Substitutes for the real ``advapi32``/``kernel32`` calls so the
    context's mechanics are testable on any platform (no real share, no real credential)."""

    def __init__(self, *, fail_logon: bool = False) -> None:
        self.calls: list[str] = []
        self.fail_logon = fail_logon
        self.impersonate_thread: int | None = None

    def install(self, monkeypatch: pytest.MonkeyPatch) -> _FakeWin32:
        monkeypatch.setattr(wincred, "is_supported", lambda: True)  # pretend we're on win32
        monkeypatch.setattr(wincred, "_logon", self._logon)
        monkeypatch.setattr(wincred, "_impersonate", self._impersonate)
        monkeypatch.setattr(wincred, "_revert", self._revert)
        monkeypatch.setattr(wincred, "_close_handle", self._close_handle)
        return self

    def _logon(self, username: str, domain: str | None, password: str) -> object:
        if self.fail_logon:
            raise wincred.CredentialLogonError("alternate Windows credential logon failed (fake)")
        self.calls.append("logon")
        return object()  # a stand-in token handle

    def _impersonate(self, token: object) -> None:
        self.calls.append("impersonate")
        self.impersonate_thread = threading.get_ident()

    def _revert(self) -> None:
        self.calls.append("revert")

    def _close_handle(self, token: object) -> None:
        self.calls.append("close")


# --- non-Windows clean-error path (runnable here) ----------------------------


def test_ensure_supported_raises_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wincred, "is_supported", lambda: False)
    with pytest.raises(wincred.CredentialUnsupportedError) as ei:
        wincred.ensure_supported()
    # A clear, actionable message — never a silent no-op.
    assert "require Windows" in str(ei.value)
    # It is a ValueError so a connector build surfaces it as the configuration error it is.
    assert isinstance(ei.value, ValueError)


@pytest.mark.parametrize("direction", ["source", "destination"])
def test_credential_on_non_windows_fails_to_build(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, direction: str
) -> None:
    monkeypatch.setattr(wincred, "is_supported", lambda: False)
    settings: dict[str, Any] = {
        "directory": str(tmp_path),
        "credential_username": "svc",
        "credential_password": "s3cret",  # already env-resolved at this layer
    }
    with pytest.raises(wincred.CredentialUnsupportedError):
        if direction == "source":
            build_source(Source(type=ConnectorType.FILE, settings=settings))
        else:
            build_destination(Destination(name="OB", type=ConnectorType.FILE, settings=settings))


def test_no_credential_is_byte_identical(tmp_path: Path) -> None:
    # No credential_* settings => no context on either connector (the ambient-identity path is untouched).
    src = build_source(Source(type=ConnectorType.FILE, settings={"directory": str(tmp_path)}))
    dst = build_destination(
        Destination(name="OB", type=ConnectorType.FILE, settings={"directory": str(tmp_path)})
    )
    assert isinstance(src, FileSource) and src._cred_ctx is None
    assert isinstance(dst, FileDestination) and dst._cred_ctx is None


async def test_no_credential_destination_still_writes(tmp_path: Path) -> None:
    dst = build_destination(
        Destination(
            name="OB",
            type=ConnectorType.FILE,
            settings={"directory": str(tmp_path), "filename": "out.hl7"},
        )
    )
    await dst.send(ADT)
    assert (tmp_path / "out.hl7").read_bytes() == ADT.encode("utf-8")


# --- config / wiring: env()-only password, redaction -------------------------


def test_factory_password_must_be_env() -> None:
    with pytest.raises(WiringError, match="must be an env"):
        File(directory="d", credential_username="u", credential_password="inline-secret")  # type: ignore[arg-type]


def test_factory_password_env_default_and_cast_refused() -> None:
    with pytest.raises(WiringError, match="must not carry a default"):
        File(directory="d", credential_username="u", credential_password=env("pw", default="x"))
    with pytest.raises(WiringError, match="must not carry a cast"):
        File(directory="d", credential_username="u", credential_password=env("pw", cast=str))


def test_factory_username_and_password_required_together() -> None:
    with pytest.raises(WiringError, match="without credential_password"):
        File(directory="d", credential_username="u")
    with pytest.raises(WiringError, match="without credential_username"):
        File(directory="d", credential_password=env("pw"))


def test_factory_valid_credential_spec_and_absence() -> None:
    spec = File(
        directory="d",
        credential_username="CORP\\svc",
        credential_domain="CORP",
        credential_password=env("acme_pw"),
    )
    assert spec.settings["credential_username"] == "CORP\\svc"
    assert spec.settings["credential_domain"] == "CORP"
    assert isinstance(spec.settings["credential_password"], EnvRef)
    assert spec.settings["credential_password"].key == "acme_pw"
    # No credential => the settings dict carries none of the keys (byte-identical to before #111).
    plain = File(directory="d")
    assert not any(k.startswith("credential_") for k in plain.settings)


def test_credential_secrets_are_redacted() -> None:
    settings = {
        "directory": "d",
        "credential_username": env("acme_user"),
        "credential_domain": "CORP",
        "credential_password": env("acme_pw"),
    }
    red = redacted_settings(settings)
    # username + password render as {"env": key} only (no value); domain is not secret and passes through.
    assert red["credential_username"] == {"env": "acme_user"}
    assert red["credential_password"] == {"env": "acme_pw"}
    assert red["credential_domain"] == "CORP"


# --- WindowsCredential model -------------------------------------------------


def test_windows_credential_from_settings() -> None:
    assert WindowsCredential.from_settings({"directory": "d"}) is None
    cred = WindowsCredential.from_settings(
        {"credential_username": "svc", "credential_domain": "CORP", "credential_password": "pw"}
    )
    assert cred is not None
    assert (cred.username, cred.domain, cred.password) == ("svc", "CORP", "pw")
    # username without password is a config error.
    with pytest.raises(ValueError, match="without credential_password"):
        WindowsCredential.from_settings({"credential_username": "svc"})


def test_credential_logon_error_is_oserror() -> None:
    # Load-bearing: the connectors rely on `except OSError` catching a logon failure.
    assert issubclass(wincred.CredentialLogonError, OSError)


# --- CredentialContext mechanics (win32 primitives faked) --------------------


async def test_context_brackets_impersonation_on_a_dedicated_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeWin32().install(monkeypatch)
    ctx = wincred.CredentialContext(username="svc", password="pw", domain="CORP")
    main_thread = threading.get_ident()

    def op() -> str:
        fake.calls.append("op")
        assert threading.get_ident() != main_thread  # ran off the loop, on a dedicated thread
        assert (
            threading.get_ident() == fake.impersonate_thread
        )  # ...the SAME thread we impersonated
        return "done"

    result = await ctx.run(op)
    assert result == "done"
    # LogonUser -> Impersonate -> fn -> RevertToSelf -> CloseHandle, in that exact order.
    assert fake.calls == ["logon", "impersonate", "op", "revert", "close"]

    await ctx.close()
    with pytest.raises(wincred.CredentialError):
        await ctx.run(op)  # closed => refuses further work (no leaked thread reused)


async def test_context_reverts_even_when_the_op_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeWin32().install(monkeypatch)
    ctx = wincred.CredentialContext(username="svc", password="pw")

    def boom() -> None:
        fake.calls.append("op")
        raise RuntimeError("kaboom")

    with pytest.raises(RuntimeError, match="kaboom"):
        await ctx.run(boom)
    # The credential is reverted + the token closed even on an exception (no lingering impersonation).
    assert fake.calls == ["logon", "impersonate", "op", "revert", "close"]
    await ctx.close()


async def test_logon_failure_surfaces(monkeypatch: pytest.MonkeyPatch) -> None:
    _FakeWin32(fail_logon=True).install(monkeypatch)
    ctx = wincred.CredentialContext(username="svc", password="bad")
    with pytest.raises(wincred.CredentialLogonError):
        await ctx.run(lambda: "never")
    await ctx.close()


# --- close() stays OFF the shared default executor (BACKLOG #1195, ASVS 15.4.4) ----------------


def _spy_on_the_default_pool(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    """Record every dispatch to the event loop's DEFAULT executor, and return the growing list.

    Wraps the running loop's own ``run_in_executor``, which is where both routes land —
    ``asyncio.to_thread`` calls it with ``executor=None``, and so does a bare
    ``run_in_executor(None, ...)``. Deliberately NOT ``loop.set_default_executor``: this suite runs on
    ONE session-scoped loop (see ``[tool.pytest.ini_options]``), so a substitute executor installed
    here would outlive the test and a shut-down one would break every later ``to_thread`` in the
    session. ``monkeypatch`` puts the real method back."""
    loop = asyncio.get_running_loop()
    real = loop.run_in_executor
    seen: list[Any] = []

    def spy(executor: Any, func: Any, *args: Any) -> Any:
        if executor is None:
            seen.append(func)
        return real(executor, func, *args)

    monkeypatch.setattr(loop, "run_in_executor", spy)
    return seen


async def _wait_for(flag: threading.Event) -> None:
    """Await a worker-thread event from the loop without touching the default pool (which is the
    very thing these tests are counting)."""
    for _ in range(1000):
        if flag.is_set():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("the impersonated worker never started")


async def test_close_parks_no_thread_on_the_shared_default_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The whole point of the dedicated worker is that impersonated share I/O never rides the shared
    # pool. A blocking `shutdown(wait=True)` handed to `run_in_executor(None, ...)` broke that on the
    # release path: the pool thread it parked inherited the join's unbounded hold.
    _FakeWin32().install(monkeypatch)
    seen = _spy_on_the_default_pool(monkeypatch)
    ctx = wincred.CredentialContext(username="svc", password="pw")
    assert await ctx.run(lambda: "ok") == "ok"
    assert seen == [], "run() must use the context's OWN executor"
    await ctx.close()
    assert seen == [], "close() must not dispatch to the shared default executor"
    # POSITIVE CONTROL, same spy and same loop: a zero above is only evidence if this instrument can
    # see a default-pool dispatch at all.
    await asyncio.to_thread(lambda: None)
    assert len(seen) == 1


async def test_close_gives_up_on_a_wedged_worker_and_says_so(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # A UNC read on a dead share has no engine-owned timeout, so close() must not wait on it forever.
    _FakeWin32().install(monkeypatch)
    monkeypatch.setattr(wincred, "_CLOSE_DRAIN_TIMEOUT_S", 0.1)
    ctx = wincred.CredentialContext(username="svc", password="pw")
    started, release = threading.Event(), threading.Event()

    def wedged() -> None:
        started.set()
        release.wait(timeout=30)  # bounded so a FAILING test cannot wedge the suite too

    task = asyncio.create_task(ctx.run(wedged))
    await _wait_for(started)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.wincred"):
        await asyncio.wait_for(ctx.close(), timeout=10)
    assert "still running 1 filesystem call(s)" in caplog.text  # loud, never a silent give-up
    release.set()
    await task


async def test_close_still_drains_an_in_flight_call_it_can_wait_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Bounding the wait must not turn it into no wait: an ordinary call that finishes inside the
    # grace is still drained before close() returns, exactly as the blocking join used to guarantee.
    fake = _FakeWin32().install(monkeypatch)
    ctx = wincred.CredentialContext(username="svc", password="pw")
    started, release = threading.Event(), threading.Event()

    def slow() -> None:
        started.set()
        release.wait(timeout=30)
        fake.calls.append("op")

    task = asyncio.create_task(ctx.run(slow))
    await _wait_for(started)
    closing = asyncio.create_task(ctx.close())
    await asyncio.sleep(0.1)
    assert not closing.done(), "close() returned while the impersonated call was still running"
    release.set()
    await asyncio.wait_for(closing, timeout=10)
    await task
    # ...and the credential was reverted and the token closed on that worker, as always.
    assert fake.calls == ["logon", "impersonate", "op", "revert", "close"]


# --- the context WRAPS the File connectors' real filesystem work -------------


async def test_destination_write_runs_under_credential(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = _FakeWin32().install(monkeypatch)
    dst = build_destination(
        Destination(
            name="OB",
            type=ConnectorType.FILE,
            settings={
                "directory": str(tmp_path),
                "filename": "out.hl7",
                "credential_username": "svc",
                "credential_password": "pw",
            },
        )
    )
    await dst.send(ADT)
    # The write actually happened (real bytes), AND it was bracketed by impersonate/revert — i.e. the
    # credential context WRAPS _write, not bypasses it.
    assert (tmp_path / "out.hl7").read_bytes() == ADT.encode("utf-8")
    assert "impersonate" in fake.calls and "revert" in fake.calls
    await dst.aclose()  # releases the context (no leak across reconfigure)


async def test_destination_logon_failure_maps_to_delivery_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _FakeWin32(fail_logon=True).install(monkeypatch)
    dst = build_destination(
        Destination(
            name="OB",
            type=ConnectorType.FILE,
            settings={
                "directory": str(tmp_path),
                "credential_username": "svc",
                "credential_password": "bad",
            },
        )
    )
    with pytest.raises(DeliveryError):
        await dst.send(ADT)
    await dst.aclose()


async def test_source_validate_startup_runs_under_credential(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = _FakeWin32().install(monkeypatch)
    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(tmp_path),
                "validate_directory": True,
                "credential_username": "svc",
                "credential_password": "pw",
            },
        )
    )
    await src.validate_startup()  # the #114 startup probe, wrapped under the credential
    assert "impersonate" in fake.calls and "revert" in fake.calls
    await src.stop()  # releases the context


async def test_source_startup_logon_failure_isolates_connection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _FakeWin32(fail_logon=True).install(monkeypatch)
    src = build_source(
        Source(
            type=ConnectorType.FILE,
            settings={
                "directory": str(tmp_path),
                "validate_directory": True,
                "credential_username": "svc",
                "credential_password": "bad",
            },
        )
    )
    # A logon failure at startup surfaces as SourceStartupError (ADR 0031 isolates it `failed`),
    # not a crash — because CredentialLogonError is an OSError the probe path already catches.
    with pytest.raises(SourceStartupError):
        await src.validate_startup()
    await src.stop()
