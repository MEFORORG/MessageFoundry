# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0183 Amendment A, Wave 2 (BACKLOG #1136, ASVS 6.3.2): starting an engine with no Administrator.

The engine no longer creates an account on its own. So a store nobody has provisioned holds no
enabled Administrator, and each posture has to say so in words that lead to the one host command
that fixes it, ``messagefoundry provision-admin``. These pin what each posture does:

- AC-11: at the shipped posture the ADR 0167 gate refuses, names ``provision-admin``, and provisioning
  that same store lets the next start pass;
- AC-16: an Administrator with no address is refused with a message naming the offline setter,
  ``admin-set-notify-email``, and running it lets the next start pass;
- AC-12: under ``warn``, the audited waiver, or notices off, the engine starts and logs ONE WARNING
  naming ``provision-admin``; with sign-in not required it logs nothing, since no account is needed;
- AC-13: no start writes ``bootstrap-admin.txt``, and no engine code builds that file name.

These drive the real lifespan, and the one-identity AC-11 flow runs the real CLI. The two-identity
flow on a Windows service is the hosted third arm of ``windows-service-smoke``.

Severity is conditional (CLAUDE.md section 0): zero deployments, so this is what a deploying site
would meet, never a live exposure. Addresses are synthetic ``.invalid`` domains.
"""

from __future__ import annotations

import ast
import asyncio
import logging
from pathlib import Path

import pytest
from fastapi import FastAPI

from messagefoundry.__main__ import main
from messagefoundry.api import create_managed_app
from messagefoundry.config.settings import (
    AlertsSettings,
    AuthSettings,
    SecurityEnforcement,
    SecuritySettings,
    StoreSettings,
)
from messagefoundry.store.crypto import generate_key

# provision-admin's prompt stub and passphrase, imported rather than copied: that module pins them.
from tests.test_provision_first_administrator import _PASSWORD, _tty

_ADMIN = "site-admin"
_ADDRESS = "ops@example.invalid"
_PROVISION = "provision-admin"
_SETTER = "admin-set-notify-email"
_REPO = Path(__file__).resolve().parents[1]


def _app(
    db: Path,
    key: str,
    *,
    enforcement: SecurityEnforcement = SecurityEnforcement.ENFORCE,
    sign_in: bool = True,
    notices: bool = True,
    required: bool = True,
) -> FastAPI:
    """The engine at the shipped PHI posture, with one dial moved per argument.

    ``sign_in`` is ``[security].require_sign_in``, which desugars to ``[auth].enabled``.
    """
    return create_managed_app(
        store_settings=StoreSettings(path=str(db), encryption_key=key),
        poll_interval=0.05,
        auth_settings=AuthSettings(enabled=sign_in, notify_security_events=notices),
        alerts_settings=AlertsSettings(
            security_notifications_required=required,
            email_smtp_host="smtp.example.invalid",
            email_from="alerts@example.invalid",
        ),
        security_settings=SecuritySettings(enforcement=enforcement),
    )


async def _start(app: FastAPI) -> None:
    async with app.router.lifespan_context(app):
        pass


def _provision(db: Path, monkeypatch: pytest.MonkeyPatch, *extra: str) -> int:
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    return main([_PROVISION, "--username", _ADMIN, "--db", str(db), *extra])


# --- AC-11: the shipped posture refuses, and provisioning that store is the fix ----------------


def test_the_gate_refuses_an_empty_store_and_provisioning_it_lets_the_next_start_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-11 under one identity: start first, refused; provision; start again, passes.

    The order is the start-first order ADR 0163 warned about, because ``serve`` creates the store.
    Before Wave 2 the refused start had already minted an enabled Administrator, so the refusal named
    ``provision-admin`` and the command then refused too. That is the red this test was written on.
    """
    monkeypatch.chdir(tmp_path)
    key = generate_key()
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    db = tmp_path / "start-first.db"

    with pytest.raises(RuntimeError) as refused:
        asyncio.run(_start(_app(db, key)))
    message = str(refused.value)
    assert "refusing to start" in message
    assert "no enabled Administrator exists" in message
    assert f"{_PROVISION} --username" in message
    assert "bootstrap" not in message, "the refusal must not describe an account that is gone"
    assert db.exists(), "control: serve created the store, which is the order under test"

    assert _provision(db, monkeypatch, "--email", _ADDRESS) == 0
    assert "OK" in capsys.readouterr().out

    asyncio.run(_start(_app(db, key)))  # must not raise


def test_an_administrator_with_no_address_is_pointed_at_the_offline_setter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-16: the address half of the gate names ``admin-set-notify-email``, and it works.

    ``provision-admin`` cannot help here, because an enabled Administrator exists, so naming it
    would send the operator to a command that refuses.
    """
    monkeypatch.chdir(tmp_path)
    key = generate_key()
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    db = tmp_path / "no-address.db"
    assert _provision(db, monkeypatch) == 0
    capsys.readouterr()

    with pytest.raises(RuntimeError) as refused:
        asyncio.run(_start(_app(db, key)))
    message = str(refused.value)
    assert "no enabled Administrator has a notification address" in message
    assert f"{_SETTER} --username" in message
    assert "security_notifications_required=false" in message, "the audited waiver stays named"
    assert f"{_PROVISION} --username" not in message, "it would refuse: an Administrator exists"

    assert main([_SETTER, "--username", _ADMIN, "--email", _ADDRESS, "--db", str(db)]) == 0
    asyncio.run(_start(_app(db, key)))  # must not raise


# --- AC-12: the postures that start say so, once -----------------------------------------------


def _warnings_naming_provision_admin(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno >= logging.WARNING and _PROVISION in r.getMessage()
    ]


@pytest.mark.parametrize(
    "posture",
    [
        pytest.param({"enforcement": SecurityEnforcement.WARN}, id="warn"),
        pytest.param({"required": False}, id="waived-in-writing"),
        pytest.param({"notices": False}, id="notices-off"),
    ],
)
def test_a_posture_that_starts_logs_one_warning_naming_provision_admin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    posture: dict[str, object],
) -> None:
    """AC-12: it starts (so HL7 keeps flowing) and says, once, that nobody can sign in.

    Under ``warn`` the ADR 0167 gate itself logs the line. Under the waiver and with notices off the
    gate is skipped, and the skipped-gate WARNING is the one line. Exactly one either way: two lines
    for one fact are how an operator learns to skim both.
    """
    monkeypatch.chdir(tmp_path)
    key = generate_key()
    caplog.set_level(logging.WARNING)
    asyncio.run(_start(_app(tmp_path / "unprovisioned.db", key, **posture)))  # type: ignore[arg-type]
    lines = _warnings_naming_provision_admin(caplog)
    assert len(lines) == 1, lines
    assert "no enabled Administrator exists" in lines[0]


def test_with_sign_in_not_required_no_administrator_is_needed_and_nothing_is_logged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The negative arm of AC-12, and the control on the count above: a count of one is only
    evidence if the same instrument reads zero where the fact does not hold."""
    monkeypatch.chdir(tmp_path)
    caplog.set_level(logging.WARNING)
    asyncio.run(_start(_app(tmp_path / "open.db", generate_key(), sign_in=False)))
    assert _warnings_naming_provision_admin(caplog) == []


def test_a_provisioned_store_under_a_skipped_gate_logs_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The skipped-gate WARNING asks about the store, not about the posture alone."""
    monkeypatch.chdir(tmp_path)
    key = generate_key()
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    db = tmp_path / "provisioned.db"
    assert _provision(db, monkeypatch) == 0
    caplog.set_level(logging.WARNING)
    asyncio.run(_start(_app(db, key, notices=False)))
    assert _warnings_naming_provision_admin(caplog) == []


# --- AC-13: no bootstrap-admin.txt on any path -------------------------------------------------


def test_no_start_writes_a_bootstrap_credential_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-13, behaviourally: a first start on a fresh store writes no ``bootstrap-admin.txt``.

    The directory and the working directory are the same tree here, and the whole tree is searched,
    so the file cannot land beside the store or under the cwd unseen.
    """
    monkeypatch.chdir(tmp_path)
    asyncio.run(
        _start(_app(tmp_path / "fresh.db", generate_key(), enforcement=SecurityEnforcement.WARN))
    )
    assert (tmp_path / "fresh.db").exists(), "control: the start really ran against this tree"
    assert list(tmp_path.rglob("bootstrap-admin.txt")) == []


def _string_constants_outside_docstrings(tree: ast.Module) -> list[str]:
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


def test_no_engine_code_names_the_bootstrap_credential_file() -> None:
    """AC-13, statically: "any path" includes the ones no test drives.

    Every string literal in the engine package that is not a docstring is read. The one sanctioned
    hit is the scaffold's generated ``.gitignore`` line, which ADR 0183 keeps as a guard: a
    development checkout that ran ``serve`` before Wave 2 can still hold a live file.
    """
    package = _REPO / "messagefoundry"
    hits: dict[str, int] = {}
    scanned = 0
    for source in sorted(package.rglob("*.py")):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        scanned += 1
        count = sum("bootstrap-admin.txt" in s for s in _string_constants_outside_docstrings(tree))
        if count:
            hits[source.relative_to(_REPO).as_posix()] = count
    assert scanned > 100, f"control: the scan read only {scanned} files"
    assert hits == {"messagefoundry/scaffold.py": 1}, hits
