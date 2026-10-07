# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0171 Amendment B (BACKLOG #2226): ``admin-reset-totp``, the host-gated seed replacement.

The TOTP seed has no calendar lifetime (BACKLOG #1931), and revocation is the control that stands in
for one. A sole Administrator whose only factor is TOTP had no way to revoke it: the admin reset
refuses a self-target, and self-service removal refuses the last factor. The owner ruled on
2026-10-06 to answer that with this command. It enrols the new seed at the terminal, proves it, and
only then swaps it in with one conditional write, so the account never has no factor.

Severity is conditional (CLAUDE.md section 0): zero deployments, so everything here describes what a
deploying site would hit, never a live exposure. Every secret below is a synthetic test value.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.__main__ as cli
from messagefoundry.__main__ import main
from messagefoundry.auth import totp
from messagefoundry.auth.passwords import verify_password
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._admin_account import PROVISION_TOTP_SECRET, provision_totp
from tests.test_provision_first_administrator import _PASSWORD

_CMD = "admin-reset-totp"
_ADMIN = "site-admin"
_ACTION = "auth.admin_totp_reset"
#: The seed the terminal stub "generates". Synthetic, and different from the provisioned one, so a
#: test can tell which seed the row holds. Derived rather than written out, so a secret scanner
#: reading the source sees no key-shaped literal.
_NEW_SECRET = base64.b32encode(b"admin-reset-totp-new").decode("ascii")


# --- seeding and reading -----------------------------------------------------------------------


def _seed(
    db: Path,
    *,
    disabled: bool = False,
    no_totp: bool = False,
    viewer: bool = False,
    email: str | None = None,
) -> list[str]:
    """A keyless store holding one Administrator with TOTP, as ``provision-admin`` leaves it, plus a
    live session. Returns the Administrator's recovery codes."""

    async def run() -> list[str]:
        store = await MessageStore.open(db)
        try:
            settings = AuthSettings(require_mfa=not no_totp)
            outcome = await AuthService(store, settings).provision_first_administrator(
                username=_ADMIN,
                password=_PASSWORD,
                notify_email=email,
                actor="test",
                **({} if no_totp else provision_totp()),
            )
            await store.create_session(
                token_hash="synthetic-session-hash",
                user_id=outcome.user_id,
                expires_at=time.time() + 3_600,
                auth_mechanism="password",
            )
            if disabled:
                await store.set_user_disabled(outcome.user_id, disabled=True)
            if viewer:
                await store.create_user(
                    user_id="u-viewer",
                    username="viewer",
                    auth_provider="local",
                    password_hash=None,
                    password_generated=False,
                )
                await store.set_user_roles("u-viewer", [Role.VIEWER.value], assigned_by="test")
            return list(outcome.recovery_codes)
        finally:
            await store.close()

    return asyncio.run(run())


def _state(db: Path, username: str = _ADMIN) -> dict[str, Any]:
    async def read() -> dict[str, Any]:
        store = await MessageStore.open(db)
        try:
            user = await store.get_user_by_username(username)
            assert user is not None
            return {
                "enabled": user.totp_enabled,
                "secret": await store.get_totp_secret(user.id),
                "codes": await store.get_recovery_code_hashes(user.id),
                "sessions": len(await store.list_sessions(user.id)),
            }
        finally:
            await store.close()

    return asyncio.run(read())


def _audit_rows(db: Path) -> list[dict[str, Any]]:
    async def read() -> list[dict[str, Any]]:
        store = await MessageStore.open(db)
        try:
            return [dict(r) for r in await store.list_audit(limit=100, action=_ACTION)]
        finally:
            await store.close()

    return asyncio.run(read())


def _error(capsys: pytest.CaptureFixture[str]) -> str:
    return str(json.loads(capsys.readouterr().out)["error"])


class _Console:
    """Records what the command shows on the console DEVICE (``_show_on_terminal``)."""

    def __init__(self) -> None:
        self.shown: list[str] = []

    def show(self, text: str) -> None:
        self.shown.append(text)


@pytest.fixture
def console(monkeypatch: pytest.MonkeyPatch) -> _Console:
    """A terminal that enrols ``_NEW_SECRET`` with a live code, and records the console device.

    Replaces the suite-wide provision stub, which enrols the SAME secret the seed already holds and
    so could not tell a replacement from no change at all."""
    recorded = _Console()

    def enrol(*, username: str, skew_steps: int, **_wording: str) -> tuple[str, str, float]:
        at = time.time()
        return _NEW_SECRET, totp.totp(_NEW_SECRET, now=at), at

    monkeypatch.setattr(cli, "_enrol_totp_at_terminal", enrol)
    monkeypatch.setattr(cli, "_show_on_terminal", recorded.show)
    return recorded


# --- 1. the replacement ------------------------------------------------------------------------


def test_it_replaces_the_seed_and_the_codes_and_ends_every_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    console: _Console,
) -> None:
    """THE ITEM'S ACCEPTANCE CHECK. A sole Administrator, TOTP its only factor, with no second
    Administrator and ``require_mfa`` on, replaces its own seed. The old seed and the old recovery
    codes stop working, the new ones work, TOTP is still on, and the account's sessions are ended.

    The control is the seed comparison: a command that ran and wrote nothing would leave
    ``PROVISION_TOTP_SECRET`` in place and fail it."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "reset.db"
    old_codes = _seed(db)
    before = _state(db)
    assert (before["enabled"], before["secret"], before["sessions"]) == (
        True,
        PROVISION_TOTP_SECRET,
        1,
    )

    assert main([_CMD, "--username", _ADMIN, "--db", str(db)]) == 0
    out = capsys.readouterr()
    assert "OK: replaced" in out.out

    after = _state(db)
    assert after["enabled"] is True
    assert after["secret"] == _NEW_SECRET
    assert after["sessions"] == 0
    assert len(after["codes"]) == AuthSettings().mfa_recovery_code_count
    # Every stored hash is new. Then one argon2 sample each way, since a full cross-check is a
    # hundred verifies: an old code matches no new hash, and a code shown matches one.
    assert set(after["codes"]).isdisjoint(before["codes"])
    assert not any(verify_password(h, old_codes[0]) for h in after["codes"])
    shown = "".join(console.shown)
    new_codes = [line.strip() for line in shown.splitlines() if line.startswith("  ")]
    assert len(new_codes) == len(after["codes"])
    assert any(verify_password(h, new_codes[0]) for h in after["codes"])
    # Neither stream carries a code or the seed.
    for text in (out.out, out.err):
        assert _NEW_SECRET not in text
        assert not any(c in text for c in new_codes)


def test_json_output_says_where_the_secrets_went_and_carries_none(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    console: _Console,
) -> None:
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "json.db"
    _seed(db)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 0
    raw = capsys.readouterr().out
    body = json.loads(raw)
    assert body["ok"] is True
    assert body["secrets_in_output"] is False
    assert "console" in body["secrets_shown_on"]
    assert body["recovery_codes_shown"] is True
    assert body["sessions_ended"] == 1
    assert body["passkeys_kept"] is False
    assert body["holder_notice"] in {"notices_off", "no_address", "no_channel"}
    assert _NEW_SECRET not in raw


def test_it_audits_the_os_user_and_never_the_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    console: _Console,
) -> None:
    import getpass

    monkeypatch.chdir(tmp_path)
    db = tmp_path / "audit.db"
    _seed(db)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db)]) == 0
    rows = _audit_rows(db)
    assert len(rows) == 1
    assert rows[0]["actor"] == f"cli:{getpass.getuser()}"
    detail = json.loads(str(rows[0]["detail"]))
    assert detail["username"] == _ADMIN
    # The row commits with the swap, so it records that every session ended, not a count.
    assert detail["sessions_ended"] == "all"
    assert detail["provider"] == "local"
    assert detail["passkeys_kept"] is False
    # The notice runs after the row commits, so the row cannot say what became of it.
    assert "holder_notice" not in detail
    assert _NEW_SECRET not in str(rows[0]["detail"])


def test_the_proving_code_is_spent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The code typed at the terminal must not sign in afterwards: the swap records its step."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "spent.db"
    _seed(db)
    at = time.time()
    code = totp.totp(_NEW_SECRET, now=at)
    monkeypatch.setattr(cli, "_enrol_totp_at_terminal", lambda **_k: (_NEW_SECRET, code, at))
    assert main([_CMD, "--username", _ADMIN, "--db", str(db)]) == 0
    step = totp.verify_totp_step(_NEW_SECRET, code, now=at)
    assert step is not None

    async def consume() -> bool:
        store = await MessageStore.open(db)
        try:
            user = await store.get_user_by_username(_ADMIN)
            assert user is not None
            return await store.consume_totp_step(user.id, step)
        finally:
            await store.close()

    assert asyncio.run(consume()) is False, "the proving code's step was not recorded as spent"


def test_a_directory_administrator_is_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    console: _Console,
) -> None:
    """A directory Administrator's TOTP seed is engine-held state on its user row (BACKLOG #1144),
    so the replacement fits it exactly as it fits a local one."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "ad.db"
    _seed(db)

    async def add_directory_admin() -> None:
        store = await MessageStore.open(db)
        try:
            await store.create_user(
                user_id="u-ad", username="ad-admin", auth_provider="ad", password_generated=False
            )
            await store.set_user_roles("u-ad", [Role.ADMINISTRATOR.value], assigned_by="test")
            await store.set_totp_secret("u-ad", secret=PROVISION_TOTP_SECRET)
            assert await store.enable_totp("u-ad", recovery_code_hashes=[]) is True
            # The local one disabled, so the directory Administrator is the sole enabled one.
            local = await store.get_user_by_username(_ADMIN)
            assert local is not None
            await store.set_user_disabled(local.id, disabled=True)
        finally:
            await store.close()

    asyncio.run(add_directory_admin())
    assert main([_CMD, "--username", "ad-admin", "--db", str(db), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["provider"] == "ad"
    assert _state(db, "ad-admin")["secret"] == _NEW_SECRET


# --- 2. the account never has no factor --------------------------------------------------------


def _arm_zero_factor_probe(db: Path) -> None:
    """A SQLite trigger that records every write leaving the Administrator with TOTP off or no seed.
    Read with :func:`_zero_factor_writes`. The instrument for the property, not a product table."""
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE zero_factor_probe (username TEXT)")
        conn.execute(
            "CREATE TRIGGER zero_factor AFTER UPDATE ON users "
            "WHEN NEW.totp_enabled = 0 OR NEW.totp_secret IS NULL "
            "BEGIN INSERT INTO zero_factor_probe VALUES (NEW.username); END"
        )


def _zero_factor_writes(db: Path) -> int:
    with sqlite3.connect(db) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM zero_factor_probe").fetchone()[0])


def test_no_write_ever_leaves_the_account_without_a_factor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    console: _Console,
) -> None:
    """THE ZERO-FACTOR PROPERTY THE AMENDMENT ARGUES. Every UPDATE the command makes to the user row
    is watched by a trigger, and none of them leaves TOTP off or the seed empty -- not even for the
    span between two statements. The positive control below shows the probe fires on the write
    that does pass through zero factors, so its silence here is a reading and not a dead
    instrument."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "probe.db"
    _seed(db)
    _arm_zero_factor_probe(db)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db)]) == 0
    assert _zero_factor_writes(db) == 0
    assert _state(db)["secret"] == _NEW_SECRET  # the command did write

    async def positive_control() -> None:
        store = await MessageStore.open(db)
        try:
            user = await store.get_user_by_username(_ADMIN)
            assert user is not None
            await store.disable_totp(user.id)  # the route the command deliberately does not take
        finally:
            await store.close()

    asyncio.run(positive_control())
    assert _zero_factor_writes(db) == 1


def test_a_wrong_code_at_the_terminal_writes_nothing_and_the_old_seed_still_works(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The real prompt, answered with five wrong codes. Nothing is written: the old seed, the old
    codes and the session all stand, and no audit row claims a replacement."""
    from tests.test_provision_first_administrator import _Terminal

    monkeypatch.chdir(tmp_path)
    db = tmp_path / "wrong.db"
    _seed(db)
    before = _state(db)
    real = cli._enrol_totp_at_terminal.__wrapped__  # type: ignore[attr-defined]
    monkeypatch.setattr(cli, "_enrol_totp_at_terminal", real)
    monkeypatch.setattr(totp, "generate_secret", lambda: _NEW_SECRET)
    terminal = _Terminal(["000000"] * 5)
    monkeypatch.setattr("sys.stdin", terminal)
    monkeypatch.setattr(cli, "_show_on_terminal", terminal.show)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 1
    error = _error(capsys)
    assert "nothing was written" in error
    # The real prompt names this command, not provision-admin, and labels the new entry apart from
    # the old one, which carries the bare username.
    shown = "".join(terminal.shown)
    assert "NEW authenticator entry" in shown
    assert f"{_ADMIN} (replaced " in shown
    assert f"otpauth://totp/MessageFoundry:{_ADMIN}%20%28replaced%20" in shown
    assert _state(db) == before
    assert _audit_rows(db) == []


def test_without_a_terminal_it_refuses_before_showing_a_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import types

    monkeypatch.chdir(tmp_path)
    db = tmp_path / "notty.db"
    _seed(db)
    before = _state(db)
    real = cli._enrol_totp_at_terminal.__wrapped__  # type: ignore[attr-defined]
    monkeypatch.setattr(cli, "_enrol_totp_at_terminal", real)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 1
    assert "refusing to replace the authenticator seed without a terminal" in _error(capsys)
    assert _state(db) == before


# --- 3. refusals -------------------------------------------------------------------------------


def _refused_before_the_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if a refusal case ever reaches the enrolment prompt: every refusal comes first."""

    def must_not_enrol(**_k: object) -> tuple[str, str, float]:
        raise AssertionError("a refused account reached the enrolment prompt")

    monkeypatch.setattr(cli, "_enrol_totp_at_terminal", must_not_enrol)


def test_an_unknown_account_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "ghost.db"
    _seed(db)
    _refused_before_the_key(monkeypatch)
    assert main([_CMD, "--username", "ghost", "--db", str(db), "--json"]) == 1
    assert "ghost" in _error(capsys)
    assert _audit_rows(db) == []


def test_a_non_administrator_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Another account's seed is reset from the web console; here the runner would hold it."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "viewer.db"
    _seed(db, viewer=True)
    _refused_before_the_key(monkeypatch)
    assert main([_CMD, "--username", "viewer", "--db", str(db), "--json"]) == 1
    error = _error(capsys)
    assert "not an Administrator" in error and "web console" in error
    assert _audit_rows(db) == []


def test_a_disabled_administrator_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "disabled.db"
    _seed(db, disabled=True)
    before = _state(db)
    _refused_before_the_key(monkeypatch)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 1
    assert "disabled" in _error(capsys)
    assert _state(db) == before


def test_an_account_with_no_totp_is_refused_and_not_enrolled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The command replaces a seed; it never creates one, so it cannot turn TOTP on either."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "nototp.db"
    _seed(db, no_totp=True)
    _refused_before_the_key(monkeypatch)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 1
    assert "no authenticator app enrolled" in _error(capsys)
    assert _state(db)["enabled"] is False
    assert _audit_rows(db) == []


def test_a_missing_store_is_refused_rather_than_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    missing = tmp_path / "nope.db"
    # 2, could not start (vault BACKLOG #3110, item 4); it was 1, the code for an account refusal.
    assert main([_CMD, "--username", _ADMIN, "--db", str(missing), "--json"]) == 2
    assert "refusing to create one" in _error(capsys)
    assert not missing.exists()


def test_totp_turned_off_between_the_check_and_the_write_writes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The write is conditional on TOTP being on, so a removal that lands while the operator is
    typing the code is not undone by turning TOTP back on with the new seed."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "race.db"
    _seed(db)

    def enrol_while_totp_is_removed(**_k: object) -> tuple[str, str, float]:
        async def remove() -> None:
            store = await MessageStore.open(db)
            try:
                user = await store.get_user_by_username(_ADMIN)
                assert user is not None
                await store.disable_totp(user.id)
            finally:
                await store.close()

        asyncio.run(remove())
        at = time.time()
        return _NEW_SECRET, totp.totp(_NEW_SECRET, now=at), at

    monkeypatch.setattr(cli, "_enrol_totp_at_terminal", enrol_while_totp_is_removed)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 1
    assert "no authenticator app enrolled" in _error(capsys)
    after = _state(db)
    assert (after["enabled"], after["secret"]) == (False, None)
    assert _audit_rows(db) == []


def test_help_names_the_host_gate(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main([_CMD, "--help"])
    text = capsys.readouterr().out
    assert "admin-unlock" in text and "engine" in text and "stopped" in text


# --- 4. review repairs: sole administrator, compare-and-set, atomic audit, after-commit failure ---


def _with_store(db: Path, act: Any) -> Any:
    """Run ``act(store)`` against the store at ``db`` and close it."""

    async def run() -> Any:
        store = await MessageStore.open(db)
        try:
            return await act(store)
        finally:
            await store.close()

    return asyncio.run(run())


def _live_terminal(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Enrol ``_NEW_SECRET`` with a live code, and return what the console device was shown."""
    shown: list[str] = []

    def enrol(**_k: object) -> tuple[str, str, float]:
        at = time.time()
        return _NEW_SECRET, totp.totp(_NEW_SECRET, now=at), at

    monkeypatch.setattr(cli, "_enrol_totp_at_terminal", enrol)
    monkeypatch.setattr(cli, "_show_on_terminal", shown.append)
    return shown


def test_a_second_enabled_administrator_is_refused_and_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The ruling answers a SOLE Administrator. With another enabled one, that one resets this
    account's MFA from the web console, so the host command refuses before the key is shown. A
    disabled second Administrator does not count, so the control arm below goes through."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "two.db"
    _seed(db)

    async def add_admin(store: MessageStore) -> None:
        await store.create_user(
            user_id="u-second",
            username="second-admin",
            auth_provider="local",
            password_hash=None,
            password_generated=False,
        )
        await store.set_user_roles("u-second", [Role.ADMINISTRATOR.value], assigned_by="test")

    _with_store(db, add_admin)
    before = _state(db)
    _refused_before_the_key(monkeypatch)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 1
    error = _error(capsys)
    assert "not the only enabled one" in error and "second-admin" in error
    assert _state(db) == before
    assert _audit_rows(db) == []

    async def disable_second(store: MessageStore) -> None:
        await store.set_user_disabled("u-second", disabled=True)

    _with_store(db, disable_second)
    _live_terminal(monkeypatch)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 0
    assert _state(db)["secret"] == _NEW_SECRET


def test_totp_on_with_no_seed_is_refused_with_its_own_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A row flagged TOTP-on with no seed is a damaged row. The command replaces a seed and never
    creates one, so it says so before the key is shown rather than failing at the write."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "noseed.db"
    _seed(db)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE users SET totp_secret=NULL WHERE username=?", (_ADMIN,))
    _refused_before_the_key(monkeypatch)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 1
    assert "no seed stored" in _error(capsys)
    assert _audit_rows(db) == []


def test_a_re_enrolment_during_the_prompt_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """THE COMPARE-AND-SET'S FALSE BRANCH. While the operator types, the account's TOTP is removed
    and enrolled again with another seed. Every re-check passes (TOTP is on, with a seed), so only
    the enrolment instant pinned before the prompt can tell. The write matches nothing, the newer
    enrolment stands, and no audit row claims a replacement."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "reenrol.db"
    _seed(db)
    other_seed = base64.b32encode(b"enrolled-meanwhile!!").decode("ascii")

    async def re_enrol(store: MessageStore) -> None:
        user = await store.get_user_by_username(_ADMIN)
        assert user is not None
        await store.disable_totp(user.id)
        await store.set_totp_secret(user.id, secret=other_seed)
        assert await store.enable_totp(user.id, recovery_code_hashes=[], now=1.0) is True

    def enrol_while_re_enrolled(**_k: object) -> tuple[str, str, float]:
        _with_store(db, re_enrol)
        at = time.time()
        return _NEW_SECRET, totp.totp(_NEW_SECRET, now=at), at

    shown = _live_terminal(monkeypatch)
    monkeypatch.setattr(cli, "_enrol_totp_at_terminal", enrol_while_re_enrolled)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 1
    error = _error(capsys)
    assert "enrolled again while this command ran" in error
    assert "delete it: its seed was never stored" in error
    after = _state(db)
    assert (after["enabled"], after["secret"], after["sessions"]) == (True, other_seed, 1)
    assert _audit_rows(db) == []
    assert shown == [], "recovery codes were shown for a replacement that never landed"


def test_a_refused_audit_append_rolls_the_swap_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The audit row shares the swap's transaction. When the append fails, the seed, the codes and
    the sessions all stay as they were, no codes are shown, and the error says nothing was
    written -- not that the store could not be opened."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "refused.db"
    _seed(db)
    before = _state(db)

    async def refuse(*_a: object, **_k: object) -> object:
        raise RuntimeError("probe: the audit append was refused")

    shown = _live_terminal(monkeypatch)
    monkeypatch.setattr(MessageStore, "_append_audit_row", refuse)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 1
    error = _error(capsys)
    assert "nothing was written" in error and "cannot open the store" not in error
    monkeypatch.undo()  # the readers below append nothing, but use the real store
    assert _state(db) == before
    assert shown == []


def test_record_audit_raising_no_longer_leaves_an_unrecorded_seed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    console: _Console,
) -> None:
    """THE REVIEWER'S PROBE. The first build appended its audit row with ``record_audit`` AFTER the
    swap, and a ``record_audit`` that raised left the new seed live with no row and no codes shown.
    The row now commits inside the swap's own transaction, so the same probe changes nothing: the
    command succeeds, the row is there, and the codes reach the console.

    What it guards is narrow: a return to a ``record_audit`` append fails it. A return to a second
    write through some other method would not; ``test_a_refused_audit_append_rolls_the_swap_back``
    is the atomicity test."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "probe-record.db"
    _seed(db)

    async def refuse(*_a: object, **_k: object) -> None:
        raise RuntimeError("probe: record_audit refused")

    monkeypatch.setattr(MessageStore, "record_audit", refuse)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 0
    assert _state(db)["secret"] == _NEW_SECRET
    assert len(_audit_rows(db)) == 1
    assert "New recovery codes" in "".join(console.shown)


def test_a_failure_after_the_swap_still_shows_the_codes_and_says_the_seed_was_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    console: _Console,
) -> None:
    """After the commit only the store's close is left inside the store step. When it fails, the
    seed has been replaced and audited, so the operator must still get the codes, and the error
    must say the seed WAS replaced rather than read as a refusal or a store that would not open."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "after.db"
    _seed(db)
    committed: list[bool] = []
    real_replace = MessageStore.replace_totp_enrolment
    real_close = MessageStore.close

    async def replace(self: MessageStore, *a: Any, **k: Any) -> int | None:
        ended = await real_replace(self, *a, **k)
        committed.append(ended is not None)
        return ended

    async def close(self: MessageStore) -> None:
        await real_close(self)
        if committed:
            raise sqlite3.OperationalError("probe: close failed after the commit")

    monkeypatch.setattr(MessageStore, "replace_totp_enrolment", replace)
    monkeypatch.setattr(MessageStore, "close", close)
    # Exit 3, not 1: 1 is a refusal that wrote nothing.
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 3
    body = json.loads(capsys.readouterr().out)
    assert body["code"] == "replaced_then_failed" and body["replaced"] is True
    assert body["recovery_codes_shown"] is True
    assert "WAS replaced" in body["error"] and "cannot open the store" not in body["error"]
    assert "New recovery codes" in "".join(console.shown)
    monkeypatch.setattr(MessageStore, "close", real_close)
    assert _state(db)["secret"] == _NEW_SECRET
    assert len(_audit_rows(db)) == 1


def _commit_then_raise(
    monkeypatch: pytest.MonkeyPatch,
    *,
    reread_fails: bool,
    error: BaseException | None = None,
) -> None:
    """The server-backend shape a SQLite store cannot produce on its own: the swap's COMMIT lands,
    then the call raises, as a lost acknowledgment or a failed pool release would. With
    ``reread_fails`` the re-read that would say whether it landed fails too."""
    real_replace = MessageStore.replace_totp_enrolment
    real_secret = MessageStore.get_totp_secret
    committed: list[bool] = []

    async def replace(self: MessageStore, *a: Any, **k: Any) -> int | None:
        await real_replace(self, *a, **k)
        committed.append(True)
        raise error or RuntimeError("probe: the commit acknowledgment was lost")

    async def secret(self: MessageStore, user_id: str) -> str | None:
        if committed and reread_fails:
            raise RuntimeError("probe: the store stopped answering")
        return await real_secret(self, user_id)

    monkeypatch.setattr(MessageStore, "replace_totp_enrolment", replace)
    monkeypatch.setattr(MessageStore, "get_totp_secret", secret)


def test_an_error_after_a_landed_commit_is_read_back_and_reported_as_a_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    console: _Console,
) -> None:
    """An error from the swap does not by itself mean nothing was written. The command re-reads
    the seed: here it finds the new one, so it reports a replacement and shows the codes, rather
    than telling the operator the old entry still works."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "landed.db"
    _seed(db)
    _commit_then_raise(monkeypatch, reread_fails=False)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 3
    body = json.loads(capsys.readouterr().out)
    assert body["code"] == "replaced_then_failed" and "WAS replaced" in body["error"]
    assert body["sessions_ended"] == "unknown"
    assert "New recovery codes" in "".join(console.shown)
    monkeypatch.undo()
    assert _state(db)["secret"] == _NEW_SECRET


def test_an_error_whose_outcome_cannot_be_read_back_says_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    console: _Console,
) -> None:
    """When the re-read fails too, the command says the outcome is unknown, tells the operator to
    keep both entries, and still shows the codes, which a swap that landed has nowhere else."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "unknown.db"
    _seed(db)
    _commit_then_raise(monkeypatch, reread_fails=True)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 3
    body = json.loads(capsys.readouterr().out)
    assert body["code"] == "replacement_unknown" and "UNKNOWN" in body["error"]
    assert "Keep both" in body["error"]
    assert "Recovery codes for the NEW entry" in "".join(console.shown)


def test_ctrl_c_after_a_landed_commit_still_shows_the_codes_and_exits_3(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    console: _Console,
) -> None:
    """A KeyboardInterrupt that lands as the swap returns is read back like any other error: the
    seed is the new one, so the operator gets the codes and a replacement report, not a
    traceback with the old entry already dead."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "ctrl-c.db"
    _seed(db)
    _commit_then_raise(monkeypatch, reread_fails=False, error=KeyboardInterrupt())
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 3
    body = json.loads(capsys.readouterr().out)
    assert body["code"] == "replaced_then_failed" and "KeyboardInterrupt" in body["error"]
    assert "New recovery codes" in "".join(console.shown)


def test_a_store_failure_after_the_key_was_shown_says_delete_the_new_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A read that fails in the write's open, after the operator enrolled the new entry, writes
    nothing. It is no "cannot open the store" either, since the store opened once already, and
    the operator is told the new entry has no seed behind it."""
    monkeypatch.chdir(tmp_path)
    db = tmp_path / "locked.db"
    _seed(db)
    before = _state(db)
    shown = _live_terminal(monkeypatch)

    async def locked(*_a: object, **_k: object) -> bool:
        raise sqlite3.OperationalError("probe: database is locked")

    monkeypatch.setattr(MessageStore, "has_webauthn_credentials", locked)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 2
    error = _error(capsys)
    assert "OperationalError" in error and "cannot open the store" not in error
    assert "delete it: its seed was never stored" in error
    assert "database is locked" not in error  # the class only, never the driver's text
    monkeypatch.undo()
    assert _state(db) == before
    assert shown == []


def test_kept_passkeys_are_warned_about_in_text_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    console: _Console,
) -> None:
    """Passkeys are a separate factor and are kept, so the operator is told they still sign in."""
    from messagefoundry.store.store import WebAuthnCredential

    monkeypatch.chdir(tmp_path)
    db = tmp_path / "passkey.db"
    _seed(db)

    async def add_passkey(store: MessageStore) -> None:
        user = await store.get_user_by_username(_ADMIN)
        assert user is not None
        await store.add_webauthn_credential(
            WebAuthnCredential(
                credential_id_hash="synthetic-hash",
                credential_id="c3ludGhldGlj",
                user_id=user.id,
                rp_id="localhost",
                public_key="c3ludGhldGlj",
                sign_count=0,
                transports=None,
                device_type="single_device",
                backed_up=False,
                label="synthetic key",
                aaguid=None,
                created_at=1.0,
            )
        )

    _with_store(db, add_passkey)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db)]) == 0
    # A diagnostic, so stderr (BACKLOG #1673); the --json body carries passkeys_kept.
    assert "passkeys were kept" in capsys.readouterr().err


def test_a_store_key_that_cannot_be_resolved_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Could not start, as provision-admin and rotate-key exit on the same error (BACKLOG #2081)."""
    import messagefoundry.store.base as store_base
    from messagefoundry.store.keyprovider import KeyProviderError

    monkeypatch.chdir(tmp_path)
    db = tmp_path / "keyless.db"
    _seed(db)
    _refused_before_the_key(monkeypatch)

    async def unresolved(*_a: object, **_k: object) -> object:
        raise KeyProviderError("probe: the key provider is unreachable")

    monkeypatch.setattr(store_base, "open_store", unresolved)
    assert main([_CMD, "--username", _ADMIN, "--db", str(db), "--json"]) == 2
    assert "Nothing was written" in _error(capsys)
