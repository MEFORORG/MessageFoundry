# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1916 -- no command may START a keyless audit chain unless the audited opt-out applies.

#1905 closed this for ``serve`` and ``provision-admin`` with a CLI gate that each of those two
commands calls. Every other command that opens the store could still write the first audit row of a
fresh store with no key -- at least ``backup`` (its ``dr_backup`` row) and ``admin-unlock`` (its
``auth.admin_unlocked`` row) -- and a chain that starts keyless stays keyless: a later keyed open
starts a keyed chain only in an EMPTY ``audit_log``, and reports any other as broken.

The fix moves the decision into ``open_store``, the one seam every command opens through: with no
keying secret and an empty ``audit_log``, it refuses unless the caller passes the audited opt-out's
verdict. So a command that forgets to decide is refused, not waved through. These tests pin that for
every store-opening command, the opt-out arm, the existing-chain arm, and a source guard that no
product caller routes around the seam.

Also pinned: ``provision-admin`` refuses BEFORE writing when the opened store cannot take an audit row
(a keyed chain opened from a shell with no key and a stale opt-out used to write the account and then
crash on the audit row), and every command that opens a keyed store onto keyless rows says so.

Also pinned (vault BACKLOG #2725): ``audit-verify`` exits 4, not a broken chain's 1, on a keyed chain
in a shell that holds no key, and 2 when the key the settings name does not resolve.

Severity is conditional (CLAUDE.md section 0): zero deployments, so this is what a first deployment
would have inherited.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import contextlib
import json
import logging
import sqlite3
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.settings import StoreSettings
from messagefoundry.store.base import open_store
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore
from tests.test_audit_keyless_chain_flagged import _AT_REST_ENV
from tests.test_provision_first_administrator import _tty

_PASSWORD = "a-long-enough-operator-passphrase"
_REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A shell with no at-rest variables set, so a developer's own environment cannot decide these."""
    monkeypatch.chdir(tmp_path)
    for name in _AT_REST_ENV:
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def _opt_out(monkeypatch: pytest.MonkeyPatch) -> None:
    """The audited opt-out, with the second acknowledgment strict enforcement (the default) needs."""
    monkeypatch.setenv("MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI", "true")
    monkeypatch.setenv("MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI_UNDER_STRICT_ENFORCEMENT", "true")


def _fresh_store(db: Path, *, user: str | None = None, key: str | None = None) -> None:
    """A store whose schema exists and whose ``audit_log`` is EMPTY -- the state a fresh server
    database is in after anything has built its schema. Opened through the backend primitive, which
    decides nothing, so the fixture itself writes no audit row."""

    async def build() -> None:
        cipher = make_cipher(key) if key else None
        store = await MessageStore.open(
            db, cipher=cipher, audit_mac_key=cipher.audit_mac_key() if cipher else None
        )
        try:
            if user is not None:
                await store.create_user(
                    user_id="u1", username=user, auth_provider="local", password_generated=False
                )
                await store.record_login_failure("u1", failed_attempts=9, locked_until=4.0e9)
        finally:
            await store.close()

    asyncio.run(build())


def _audit_rows(db: Path) -> int:
    with sqlite3.connect(db) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0])


def _users(db: Path) -> int:
    with sqlite3.connect(db) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])


def _argv(command: str, db: Path, tmp: Path) -> list[str]:
    """Each store-opening command, pointed at ``db``, with the smallest argv it accepts."""
    if command == "backup":
        cfg = tmp / "cfg"
        cfg.mkdir(exist_ok=True)
        return [
            "backup",
            "--config",
            str(cfg),
            "--db",
            str(db),
            "--destination",
            str(tmp / "dest"),
            "--no-verify",
            "--json",
        ]
    if command == "admin-unlock":
        return ["admin-unlock", "--username", "ops", "--db", str(db), "--json"]
    if command == "audit-anchor":
        return ["audit-anchor", "--db", str(db), "--json"]
    if command == "admin-set-notify-email":
        return [
            "admin-set-notify-email",
            "--username",
            "ops",
            "--email",
            "ops@example.org",
            "--db",
            str(db),
            "--json",
        ]
    return [command, "--db", str(db)]


#: The CLI commands that open the store through ``open_store`` and can be run with the smallest argv.
#: The source guard below names every opener, including those not listed here. ``serve`` and
#: ``provision-admin`` are covered by the #1905 suite and by the ``provision-admin`` tests below;
#: ``supervise`` has its own test below; ``rotate-key`` refuses any keyless open before it opens
#: anything, so it appears in the guard, not here.
_STORE_OPENING_COMMANDS = (
    "backup",
    "admin-unlock",
    "admin-set-notify-email",
    "audit-anchor",
    "audit-verify",
)


@pytest.mark.parametrize("command", _STORE_OPENING_COMMANDS)
def test_every_store_opening_command_refuses_to_start_a_keyless_chain(
    command: str, shell: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The closing test the item names: each command, run FIRST on a fresh store with no key and no
    opt-out, refuses with exit 2 and leaves ``audit_log`` empty. Before #1916 ``backup`` and
    ``admin-unlock`` each wrote a keyless first row here -- ``backup`` even while failing, because
    its failure is audited too."""
    db = shell / "fresh.db"
    _fresh_store(db, user="ops")
    rc = main(_argv(command, db, shell))
    captured = capsys.readouterr()
    assert rc == 2, (command, captured.out, captured.err)
    assert "keyless" in (captured.out + captured.err).lower()
    assert _audit_rows(db) == 0, f"{command} wrote a keyless first audit row"


def test_backup_under_the_audited_opt_out_still_runs(
    shell: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control arm: the refusal is the opt-out's, not a blanket ban. With the audited opt-out the same
    command on the same fresh store succeeds and writes its row -- keyless, deliberately."""
    _opt_out(monkeypatch)
    # The separate archive gate: a keyless box writes a cleartext archive only under its own escape.
    monkeypatch.setenv("MEFOR_BACKUP_ALLOW_UNENCRYPTED", "true")
    db = shell / "fresh.db"
    _fresh_store(db)
    assert main(_argv("backup", db, shell)) == 0
    assert _audit_rows(db) == 1


def test_an_existing_keyless_chain_is_not_refused(shell: Path) -> None:
    """Control arm: a store whose chain ALREADY has rows is not started by this open, so a keyless
    open of it (an operator verifying a deliberately keyless store) is not refused."""
    db = shell / "existing.db"

    async def seed() -> None:
        store = await MessageStore.open(db)
        try:
            await store.record_audit("seed", actor="test")
        finally:
            await store.close()

    asyncio.run(seed())
    assert main(["audit-anchor", "--db", str(db), "--json"]) == 0
    assert _audit_rows(db) == 1


# --- the seam itself --------------------------------------------------------------------------------


def test_open_store_refuses_a_fresh_keyless_store_by_default(tmp_path: Path) -> None:
    """The default is the refusal: a caller that does not decide is refused, and the handle is closed
    (a leaked SQLite handle would hold the file open on Windows)."""
    from messagefoundry.store.base import KeylessAuditChainRefused

    db = tmp_path / "seam.db"
    _fresh_store(db)
    with pytest.raises(KeylessAuditChainRefused, match="allow_unencrypted_phi"):
        asyncio.run(open_store(StoreSettings(path=str(db))))
    db.unlink()  # proves the refused open released the file


def test_open_store_opens_a_fresh_keyless_store_when_the_opt_out_applies(tmp_path: Path) -> None:
    db = tmp_path / "seam.db"
    _fresh_store(db)

    async def run() -> None:
        store = await open_store(StoreSettings(path=str(db)), keyless_chain_refusal=None)
        await store.close()

    asyncio.run(run())


def test_open_store_never_refuses_a_keyed_store(tmp_path: Path) -> None:
    """Control arm: with a key the chain opens with its genesis row, so there is nothing to refuse."""
    db = tmp_path / "seam.db"
    key = generate_key()
    _fresh_store(db, key=key)

    async def run() -> None:
        store = await open_store(StoreSettings(path=str(db), encryption_key=key))
        await store.close()

    asyncio.run(run())


# --- provision-admin: refuse before writing -----------------------------------------------------------


def test_provision_admin_refuses_before_writing_when_the_chain_cannot_take_a_row(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A keyed store (the service created it with its key) and a shell with NO key but a stale
    opt-out. The CLI gate passes on the opt-out; before #1916 the command then wrote the account row
    and crashed on the audit row, because the keyed chain refuses a keyless append. It must refuse
    before writing anything."""
    db = shell / "keyed.db"
    _fresh_store(db, key=generate_key())  # the keyed open writes the genesis row: keyed from row 1
    _opt_out(monkeypatch)
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    rc = main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"])
    assert rc != 0
    assert "error" in json.loads(capsys.readouterr().out)
    assert _users(db) == 0, "the account was written before the audit row was refused"
    assert _audit_rows(db) == 1, "only the genesis row: the refused command appended nothing"


# --- keyless rows on a keyed store: every command says so ------------------------------------------


_REPORT = "does not open with a genesis row"


class _Records(logging.Handler):
    """Collects records straight off the store's logger. ``caplog`` hangs off the root logger, and a
    CLI run reconfigures logging, so a test that reads caplog can see nothing for a reason unrelated
    to what it asserts -- which is a silent pass for a quiet arm."""

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def _run_capturing_store_reports(argv: list[str]) -> tuple[int, list[str]]:
    handler = _Records()
    logger = logging.getLogger("messagefoundry.store.store")
    logger.addHandler(handler)
    try:
        return main(argv), [m for m in handler.messages if _REPORT in m]
    finally:
        logger.removeHandler(handler)


def test_a_command_that_opens_a_keyed_store_onto_keyless_rows_reports_them(
    shell: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No command keys those rows in place (``rekey-audit`` is deleted, vault BACKLOG #2594), and no
    open is silenced: the report names ``audit-verify`` and no remedy that does not exist. The
    control is the same store before a key is set, which opens quietly."""
    db = shell / "keyless-rows.db"

    async def seed() -> None:
        store = await MessageStore.open(db)
        try:
            await store.record_audit("seed", actor="test")
        finally:
            await store.close()

    asyncio.run(seed())
    rc, reports = _run_capturing_store_reports(["audit-anchor", "--db", str(db), "--json"])
    assert rc == 0 and not reports  # the control: keyless by the store's own mode, nothing to say

    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    rc, reports = _run_capturing_store_reports(["audit-anchor", "--db", str(db), "--json"])
    assert rc == 0
    assert reports and "audit-verify" in reports[0] and "rekey-audit" not in reports[0]
    assert main(["audit-verify", "--db", str(db)]) == 1, "a keyed verify must report the chain"


# --- vault BACKLOG #2725: a keyed chain with no key in this shell exits 4, not 1 ---------------------
#
# `audit-verify` spent exit 1, a broken chain's code, on a keyed chain verified in a shell that holds
# no key. A scheduled job reads the code and nothing else, so it would have reported tampering on an
# intact log. Measured on the unfixed code: exit 1 with "FAIL: audit chain is keyed ... but no store
# encryption key/MAC is configured to verify it". A key the settings name but that does not resolve
# went to the dispatch floor, also exit 1.


def _keyed_chain(db: Path, key: str) -> None:
    """A keyed chain of three rows: the genesis row the keyed open writes, then two actions."""

    async def build() -> None:
        cipher = make_cipher(key)
        store = await MessageStore.open(db, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
        try:
            await store.record_audit("first", actor="test")
            await store.record_audit("second", actor="test")
        finally:
            await store.close()

    asyncio.run(build())


def _write(db: Path, statement: str) -> None:
    """One out-of-band statement by a writer that holds no key."""
    with contextlib.closing(sqlite3.connect(db)) as conn:
        conn.execute(statement)
        conn.commit()


_EDIT_ROW_2 = "UPDATE audit_log SET actor = 'someone_else' WHERE seq = 2"
_DELETE_ROW_2 = "DELETE FROM audit_log WHERE seq = 2"


def test_audit_verify_exits_4_on_a_keyed_chain_with_no_key(
    shell: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The item's case: an intact keyed chain, and a shell with no key. Exit 4, and a line that says
    what the walk knows: the first row names a key, none is available, so it was NOT CHECKED. It
    must not claim the chain is keyed, call it broken, or call the result a pass."""
    db = shell / "keyed.db"
    _keyed_chain(db, generate_key())
    rc = main(["audit-verify", "--db", str(db)])
    captured = capsys.readouterr()
    out = captured.out
    assert rc == 4, out
    assert out.startswith("NOT CHECKED: ") and "first row names a store key" in out, out
    assert "audit key '" not in out, "the line quoted the key id a writer controls"
    assert "WARNING" not in captured.err, captured.err
    assert "no store encryption key/MAC" in out and "may have been changed" in out, out
    assert "it is keyed" not in out and "not a finding" not in out, out
    assert "FAIL" not in out and "broken at" not in out, out


@pytest.mark.parametrize(
    ("change", "expected"),
    [(None, 0), (_EDIT_ROW_2, 1), (_DELETE_ROW_2, 1)],
    ids=["intact", "edited-row", "deleted-row"],
)
def test_audit_verify_with_the_key_keeps_0_and_1(
    change: str | None,
    expected: int,
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Controls: with the key, an intact chain exits 0 and a tampered one exits 1. A process that
    holds a key can never be told its chain is unchecked, whatever the database holds."""
    key = generate_key()
    db = shell / "keyed.db"
    _keyed_chain(db, key)
    if change is not None:
        _write(db, change)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    rc = main(["audit-verify", "--db", str(db)])
    out = capsys.readouterr().out
    assert rc == expected, out
    assert "NOT CHECKED" not in out, out


def test_audit_verify_with_the_wrong_key_exits_1(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A key is held, just not the chain's. That is a finding about this chain and this key, so it
    stays exit 1: a shell that holds a key never gets the "not checked" code."""
    db = shell / "keyed.db"
    _keyed_chain(db, generate_key())
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    rc = main(["audit-verify", "--db", str(db)])
    out = capsys.readouterr().out
    assert rc == 1, out
    assert out.startswith("FAIL: "), out


def test_a_break_that_needs_no_key_exits_1_with_no_key(
    shell: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Tampering that a shell with no key CAN see still exits 1, not 4: a row missing from the middle
    (its sequence numbers stop matching), a row whose hash was blanked, and a tail cut off after an
    anchor was taken."""
    db = shell / "keyed.db"
    _keyed_chain(db, generate_key())
    _write(db, _DELETE_ROW_2)
    assert main(["audit-verify", "--db", str(db)]) == 1
    assert "broken at seq=2" in capsys.readouterr().out

    db = shell / "blanked.db"
    _keyed_chain(db, generate_key())
    _write(db, "UPDATE audit_log SET row_hash = '' WHERE seq = 3")
    assert main(["audit-verify", "--db", str(db)]) == 1
    assert "broken at seq=3" in capsys.readouterr().out

    db = shell / "anchored.db"
    _keyed_chain(db, generate_key())
    assert main(["audit-anchor", "--db", str(db), "--json"]) == 0
    anchor = json.loads(capsys.readouterr().out)["anchor"]
    assert main(["audit-verify", "--db", str(db), "--expected-anchor", anchor]) == 4  # the control
    capsys.readouterr()
    _write(db, "DELETE FROM audit_log WHERE seq = 3")
    assert main(["audit-verify", "--db", str(db), "--expected-anchor", anchor]) == 1
    assert "diverges from recorded anchor" in capsys.readouterr().out


def test_an_edit_a_shell_with_no_key_cannot_see_is_still_not_a_pass(
    shell: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The limit, pinned so nobody reads 4 as clean: an edited row's content shows only in its MAC,
    which needs the key. With no key the result is 4, "not checked", and never 0."""
    db = shell / "keyed.db"
    _keyed_chain(db, generate_key())
    _write(db, _EDIT_ROW_2)
    assert main(["audit-verify", "--db", str(db)]) == 4
    assert "NOT CHECKED" in capsys.readouterr().out


def test_an_edit_inside_a_closed_key_range_exits_1_with_no_key(
    shell: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A rotated chain: a range under one key, closed by a range row that carries its digest. The
    digest needs no key, so a shell with no key still sees an edit inside that range and exits 1.
    The control is the same chain untouched, which exits 4."""
    from tests.test_audit_key_rotation import _open, _rotate, _seed

    first, second = generate_key(), generate_key()
    db = shell / "rotated.db"

    async def build() -> None:
        store = await _open(db, first)
        try:
            await _seed(store, "under-first", 2)
        finally:
            await store.close()
        await _rotate(db, first, second)

    asyncio.run(build())
    assert main(["audit-verify", "--db", str(db)]) == 4  # the control
    capsys.readouterr()
    _write(db, _EDIT_ROW_2)
    assert main(["audit-verify", "--db", str(db)]) == 1
    assert "does not match the range it closes" in capsys.readouterr().out


def test_under_the_keyless_opt_out_a_chain_naming_a_key_exits_1(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The review's attack on exit 4. A deliberately keyless store, anchored. Someone edits a row
    and rewrites row 1 as a genesis row naming a key, leaving every stored hash alone, so the anchor
    still matches. Where the settings allow running keyless a chain naming a key is the anomaly, so
    it stays a broken chain, exit 1, and never "not checked". The control is the edit alone."""
    _opt_out(monkeypatch)
    db = shell / "keyless.db"

    async def seed() -> None:
        store = await MessageStore.open(db)
        try:
            for i in range(3):
                await store.record_audit(f"act{i}", actor="test")
        finally:
            await store.close()

    asyncio.run(seed())
    assert main(["audit-anchor", "--db", str(db), "--json"]) == 0
    anchor = json.loads(capsys.readouterr().out)["anchor"]
    _write(db, _EDIT_ROW_2)
    argv = ["audit-verify", "--db", str(db), "--expected-anchor", anchor]
    assert main(argv) == 1  # the control
    capsys.readouterr()
    _write(
        db,
        "UPDATE audit_log SET action = 'audit.key_epoch', "
        """detail = '{"genesis": 1, "key_id": "forged"}' WHERE seq = 1""",
    )
    rc = main(argv)
    out = capsys.readouterr().out
    assert rc == 1, out
    assert out.startswith("FAIL: audit chain broken") and "run keyless" in out, out


@pytest.mark.parametrize("command", ["audit-verify", "audit-anchor"])
def test_a_key_that_does_not_resolve_exits_2(
    command: str, shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A key the settings name that cannot be resolved stops the open before it reads a row: here
    `vault_transit` with no Transit key named. Exit 2, could not start, as `rotate-key` and
    `provision-admin` exit on the same errors. It used to reach the dispatch floor and exit 1."""
    db = shell / "keyed.db"
    _keyed_chain(db, generate_key())
    monkeypatch.setenv("MEFOR_STORE_CIPHER_PROVIDER", "vault_transit")
    rc = main(_argv(command, db, shell))
    captured = capsys.readouterr()
    assert rc == 2, (captured.out, captured.err)
    text = json.loads(captured.out)["error"] if command == "audit-anchor" else captured.err
    assert "MEFOR_STORE_TRANSIT_KEY" in text, text


def test_the_verdict_keeps_its_flag_through_a_copy() -> None:
    """`AuditVerdict` is a tuple with one extra field, so a copy or a pickle must carry the field."""
    import copy
    import pickle

    from messagefoundry.store.store import AuditVerdict

    verdict = AuditVerdict(False, "m", key_unavailable=True)
    for clone in (copy.copy(verdict), copy.deepcopy(verdict), pickle.loads(pickle.dumps(verdict))):
        assert tuple(clone) == (False, "m") and clone.key_unavailable
    assert not AuditVerdict(True, "m", key_unavailable=True).key_unavailable  # only with not-ok
    clean = AuditVerdict(True, "m", keyless_walk=True)
    assert pickle.loads(pickle.dumps(clean)).keyless_walk
    assert not AuditVerdict(False, "m", keyless_walk=True).keyless_walk  # only with ok


def _keyless_chain(db: Path) -> None:
    """A keyless chain of three rows, as a store with no key writes it. One actor value is distinctive
    so a test can show the warning never quotes a row."""

    async def seed() -> None:
        store = await MessageStore.open(db)
        try:
            for i in range(3):
                await store.record_audit(f"act{i}", actor="row-content-marker")
        finally:
            await store.close()

    asyncio.run(seed())


def test_a_keyless_chain_passing_where_the_settings_require_a_key_exits_5(
    shell: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A keyless chain walks clean in a shell whose settings forbid keyless running. Exit 5, not 0
    (vault BACKLOG #3054): the settings say verification is keyed, and a plain SHA-256 walk is not
    that, so the chain was not checked to their standard. A job reading only the code must see it.
    Not 4, which a forged first row produces, so that forgery shows as a move from 5 to 4. The
    WARNING still goes to stderr, and neither line quotes a row."""
    db = shell / "keyless.db"
    _keyless_chain(db)
    rc = main(["audit-verify", "--db", str(db)])
    captured = capsys.readouterr()
    assert rc == 5, (captured.out, captured.err)
    assert captured.out.startswith("NOT CHECKED: "), captured.out
    assert "OK" not in captured.out, captured.out
    assert "WARNING: the audit chain is keyless" in captured.err, captured.err
    assert "require a store key" in captured.err, captured.err
    assert "row-content-marker" not in captured.out + captured.err

    # A matching anchor does not change it: the walk was still not keyed, which is what the settings
    # require. Pinned, so a change that lets an anchor turn this into a pass is a decision, not drift.
    assert main(["audit-anchor", "--db", str(db)]) == 0
    anchor = capsys.readouterr().out.strip()
    assert main(["audit-verify", "--db", str(db), "--expected-anchor", anchor]) == 5
    assert capsys.readouterr().out.startswith("NOT CHECKED: ")


@pytest.mark.parametrize("allow_empty", [False, True])
def test_an_empty_log_where_the_settings_require_a_key_names_no_first_row(
    allow_empty: bool,
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Vault BACKLOG #3054, item 3. An EMPTY log has no first row, so the WARNING must not say its
    first row names no key; it says there is no first row naming one. The exit is still 5,
    --allow-empty or not: this setup never reports a pass.

    The open refuses this state first, exit 2 (#1916): an empty log with no key and no opt-out is a
    keyless chain about to start. So the verify sees it only for a log emptied between the open and
    the walk, and the test stands the open's refusal down to reach that. The first half pins the
    refusal, so a change that removed it would not leave this path untested by accident."""
    from messagefoundry.store import base as store_base

    db = shell / "empty.db"
    _fresh_store(db)
    argv = ["audit-verify", "--db", str(db), *(["--allow-empty"] if allow_empty else [])]
    assert main(argv) == 2
    assert "refusing to open" in capsys.readouterr().err

    async def _no_refusal(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(store_base, "_refuse_to_start_a_keyless_chain", _no_refusal)
    rc = main(argv)
    captured = capsys.readouterr()
    assert rc == 5, (captured.out, captured.err)
    assert captured.out.startswith("NOT CHECKED: "), captured.out
    assert "first row names" not in captured.out + captured.err, captured.err
    assert "it has no first row naming a key" in captured.err, captured.err


def test_a_keyless_chain_under_the_opt_out_does_not_warn(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Control for the warning: the same keyless chain, under the audited keyless opt-out, is what
    the settings say to expect. Exit 0 and no warning. A keyed chain verified with its key is the
    other control: it is not a keyless walk, so it does not warn either."""
    db = shell / "keyless.db"
    _keyless_chain(db)
    _opt_out(monkeypatch)
    assert main(["audit-verify", "--db", str(db)]) == 0
    assert "WARNING" not in capsys.readouterr().err

    monkeypatch.delenv("MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI")
    monkeypatch.delenv("MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI_UNDER_STRICT_ENFORCEMENT")
    key = generate_key()
    keyed = shell / "keyed.db"
    _keyed_chain(keyed, key)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    assert main(["audit-verify", "--db", str(keyed)]) == 0
    assert "WARNING" not in capsys.readouterr().err


def test_a_key_error_raised_after_the_open_is_not_reported_as_could_not_start(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Pins where the exit-2 key arm sits: around the OPEN only. Once rows are read, a key error is
    not "could not start", because a row's content might be what raised it. Here the verify itself
    raises the key error. Catching key errors around the whole run would turn this into exit 2."""
    from messagefoundry.store.keyprovider import KeyProviderError

    db = shell / "keyed.db"
    key = generate_key()
    _keyed_chain(db, key)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)

    async def raising(self: MessageStore, **kwargs: object) -> object:
        raise KeyProviderError("raised after the open")

    monkeypatch.setattr(MessageStore, "verify_audit_chain", raising)
    rc = main(["audit-verify", "--db", str(db)])
    capsys.readouterr()
    assert rc != 2, "a key error after the open was reported as could-not-start"
    assert rc != 0


_FORGE_GENESIS = (
    "UPDATE audit_log SET action = 'audit.key_epoch', "
    """detail = '{"genesis": 1, "key_id": "forged"}' WHERE seq = 1"""
)


def test_the_weaker_setup_is_pinned_a_keyless_store_from_a_shell_that_requires_a_key(
    shell: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The setup vault BACKLOG #2725 made weaker, pinned so it cannot widen unseen. A keyless store,
    verified from a shell whose settings require a key and that holds none. A writer who rewrites
    the first row to name a key and edits another row gets exit 4, where it was 1 before #2725, and
    no WARNING. Since #3054 the CLEAN chain exits 5, with the WARNING: this setup's steady state,
    never a pass. So the rewrite shows as a move from 5 to 4. The way out is to key the store or to
    set the keyless opt-out the engine runs under."""
    db = shell / "keyless.db"
    _keyless_chain(db)
    assert main(["audit-verify", "--db", str(db)]) == 5  # clean: the steady state
    assert "WARNING: the audit chain is keyless" in capsys.readouterr().err
    _write(db, _FORGE_GENESIS)
    _write(db, _EDIT_ROW_2)
    rc = main(["audit-verify", "--db", str(db)])
    captured = capsys.readouterr()
    assert rc == 4, captured.out  # forged first row: a move from 5 to 4 is the tamper sign
    assert "may have been changed" in captured.out and "WARNING" not in captured.err


def test_a_keyed_chain_rewritten_as_keyless_warns_with_no_key_and_fails_with_it(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A keyed chain that a writer with no key rewrites as keyless: row 1 made ordinary, a row
    edited, every hash recomputed as plain SHA-256. From a shell with no key it walks clean, so it
    exits 5 (#3054) and the WARNING must fire and name the rewrite as a cause. With the engine's key
    the same chain fails, exit 1."""
    from messagefoundry.store.store import _audit_row_mac

    key = generate_key()
    db = shell / "rewritten.db"
    _keyed_chain(db, key)
    # The intact keyed chain sits at 4 in this shell, so the rewrite is a move from 4 to 5 (#3054).
    assert main(["audit-verify", "--db", str(db)]) == 4
    capsys.readouterr()
    with contextlib.closing(sqlite3.connect(db)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute(
            "UPDATE audit_log SET action = 'seed', detail = NULL, actor = 'test' WHERE seq = 1"
        )
        conn.execute(_EDIT_ROW_2)
        prev = ""
        for row in conn.execute("SELECT * FROM audit_log ORDER BY seq").fetchall():
            digest = _audit_row_mac(dict(row), prev, None, None)
            assert digest is not None
            conn.execute("UPDATE audit_log SET row_hash = ? WHERE seq = ?", (digest, row["seq"]))
            prev = digest
        conn.commit()

    assert main(["audit-verify", "--db", str(db)]) == 5
    err = capsys.readouterr().err
    assert "WARNING: the audit chain is keyless" in err and "rewritten as keyless" in err, err

    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key)
    assert main(["audit-verify", "--db", str(db)]) == 1
    assert capsys.readouterr().out.startswith("FAIL: ")


def test_a_service_config_that_cannot_be_read_exits_2(
    shell: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A directory named as `--service-config` raises an OS error on load. It reached the dispatch
    floor and exited 1, a broken chain's code. It is "could not start": exit 2."""
    db = shell / "keyless.db"
    _keyless_chain(db)
    folder = shell / "a-folder"
    folder.mkdir()
    rc = main(["audit-verify", "--db", str(db), "--service-config", str(folder)])
    captured = capsys.readouterr()
    assert rc == 2, (captured.out, captured.err)
    assert captured.err.startswith("error: "), captured.err


# --- the source guard ----------------------------------------------------------------------------------

#: Product callers that may pass ``keyless_chain_refusal=None`` without computing it, and why. Each is
#: read-only against the audit log, or is not a path a service opens its store through.
_MAY_PASS_NONE = {
    # read-only: db_status() for the support bundle
    ("messagefoundry/support/bundle.py", "_db_info"),
    # read-only: open and close, or list_messages, for the deployment verifier
    ("messagefoundry/verify/smoke.py", "check_store_connectivity._open_close"),
    ("messagefoundry/verify/smoke.py", "newest_message_id._newest"),
    ("messagefoundry/verify/smoke.py", "check_smoke_disposition._poll"),
    # read-only: the lockable-account census reads users, roles and TOTP secrets and writes nothing
    # (ADR 0197 Amendment A, AC-A9); the startup twin that audits runs under serve's own open
    ("messagefoundry/verify/checks.py", "check_lockable_accounts._census"),
    # a throwaway snapshot copy, integrity-checked and deleted
    ("messagefoundry/pipeline/dr_backup.py", "_full_open_check._open"),
    # the synthetic load harness
    ("harness/load/connscale/runner.py", "_store_reader._read"),
    # serve decides whenever it passes security_settings (it always does); None is the embedding and
    # test convenience, so the verdict there is `... if security_settings is not None else None`
    ("messagefoundry/api/app.py", "create_managed_app.lifespan"),
}

#: Direct backend ``.open`` calls outside the seam, and why each is not a bypass.
_BACKEND_OPEN_OUTSIDE_THE_SEAM = {
    # the seam itself: open_store's backend dispatch
    ("messagefoundry/store/base.py", "_open_backend"),
    # Engine.create(db_path): the documented tests/embedding convenience, never the service path
    ("messagefoundry/pipeline/engine.py", "Engine.create"),
    # the load harness resetting a synthetic server store between runs
    ("harness/load/connscale/runner.py", "_reset_server_store"),
    ("harness/load/shardcert.py", "_reset_store"),
    ("harness/load/shardcert.py", "_queue_breakdown"),
}

#: The CLI commands that open the store. Each passes the shared verdict, except ``rotate-key``, which
#: refuses any open without a key before it opens anything and so keeps the refusing default.
_CLI_OPENERS = {
    "_admin_unlock.run",
    "_admin_set_notify_email.run",
    "_provision_admin.run",
    # the read-only "an Administrator exists" probe before the prompt: at the refusing default it
    # would refuse an existing empty store even under the opt-out the CLI gate already accepted
    "_provision_admin.administrator_exists",
    # the supervisor's audit of a re-minted API pair, on the verdict serve's lifespan passes
    "_renew_api_tls_before_spawning._audit",
    "_audit_verify.run",
    "_audit_anchor.run",
    "_backup.run",
}
_CLI_DEFAULT = {"_rotate_key.run"}

_BACKENDS = {"MessageStore", "SqlServerStore", "PostgresStore"}


def _calls(rel: str) -> list[tuple[str, ast.Call]]:
    """``(qualified enclosing scope, call)`` for every call in one source file."""
    tree = ast.parse((_REPO / rel).read_bytes())
    found: list[tuple[str, ast.Call]] = []

    def walk(node: ast.AST, scope: str) -> None:
        for child in ast.iter_child_nodes(node):
            inner = scope
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                inner = f"{scope}.{child.name}" if scope else child.name
            if isinstance(child, ast.Call):
                found.append((scope, child))
            walk(child, inner)

    walk(tree, "")
    return found


def _callee(call: ast.Call) -> str | None:
    """The called name, whether spelled bare (``open_store``) or through a module (``base.open_store``)."""
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _is_verdict(value: ast.expr) -> bool:
    """A call to the shared rule with its two arguments -- a store section and a security section."""
    return (
        isinstance(value, ast.Call)
        and _callee(value) == "keyless_opt_out_refusal"
        and (len(value.args) == 2 and not value.keywords)
    )


def _is_none(value: ast.expr) -> bool:
    return isinstance(value, ast.Constant) and value.value is None


def _product_files() -> list[str]:
    roots = (
        "messagefoundry",
        "messagefoundry_webconsole",
        "messagefoundry_toolkit",
        "packaging",
        "harness",
        "scripts",
        "tee",
    )
    return sorted(
        p.relative_to(_REPO).as_posix()
        for root in roots
        if (_REPO / root).is_dir()
        for p in (_REPO / root).rglob("*.py")
        if "tests" not in p.relative_to(_REPO).parts
    )


def _classify_open_store(call: ast.Call) -> str:
    """``default`` / ``verdict`` / ``none`` / ``conditional-none`` / ``other`` for one open_store call."""
    if any(kw.arg is None for kw in call.keywords):
        return "other"  # a **kwargs spread could carry anything, so it is never read as decided
    verdict = next((kw.value for kw in call.keywords if kw.arg == "keyless_chain_refusal"), None)
    if verdict is None:
        return "default"
    if _is_verdict(verdict):
        return "verdict"
    if _is_none(verdict):
        return "none"
    if isinstance(verdict, ast.IfExp) and _is_verdict(verdict.body) and _is_none(verdict.orelse):
        return "conditional-none"
    return "other"


def test_every_product_store_open_goes_through_the_seam_and_decides() -> None:
    """Enumerates every ``open_store`` call in product code and every direct backend ``.open``.

    An ``open_store`` call must leave ``keyless_chain_refusal`` at its refusing default, pass the
    shared verdict (a call to ``keyless_opt_out_refusal`` with its two arguments), or pass ``None`` --
    bare or as the other arm of a conditional verdict -- from a caller on the allow-list above, with
    its reason. A ``**kwargs`` spread counts as undecided. A direct backend ``.open`` skips the decision
    entirely, so each one must be named. A new command that opens the store therefore cannot start a
    keyless chain without deciding, or without appearing in this file's diff."""
    unreviewed_none: list[str] = []
    not_the_shared_rule: list[str] = []
    backend_opens: list[str] = []
    cli: list[tuple[str, str]] = []
    files = _product_files()
    for rel in files:
        for scope, call in _calls(rel):
            name = _callee(call)
            if name == "open_store":
                how = _classify_open_store(call)
                if rel == "messagefoundry/__main__.py":
                    cli.append((scope, how))
                if how in ("none", "conditional-none") and (rel, scope) not in _MAY_PASS_NONE:
                    unreviewed_none.append(f"{rel}:{scope}")
                elif how == "other":
                    not_the_shared_rule.append(f"{rel}:{scope}")
            if (
                name == "open"
                and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id in _BACKENDS
                and (rel, scope) not in _BACKEND_OPEN_OUTSIDE_THE_SEAM
            ):
                backend_opens.append(f"{rel}:{scope}")
    assert not unreviewed_none, (
        f"keyless_chain_refusal=None with no stated reason: {unreviewed_none}"
    )
    assert not not_the_shared_rule, (
        f"a keyless verdict not from the shared rule: {not_the_shared_rule}"
    )
    assert not backend_opens, f"a store backend opened outside open_store: {backend_opens}"
    # Positive control and completeness in one: the instrument must find exactly the CLI openers named
    # above, or its silence proves nothing. A new CLI opener fails here, and so does a second open
    # inside one of them. This checks how each opener DECIDES; what each does with a refusal is the
    # behavioural tests' job.
    assert sorted(s for s, _ in cli) == sorted(_CLI_OPENERS | _CLI_DEFAULT), sorted(cli)
    assert {s for s, how in cli if how == "verdict"} == _CLI_OPENERS
    assert {s for s, how in cli if how == "default"} == _CLI_DEFAULT
    # And it must have scanned the seam itself: the backend dispatch is the one allowed backend open.
    assert "messagefoundry/store/base.py" in files


# --- the round-1 review cases -------------------------------------------------------------------------


def test_a_KEYED_chain_opened_without_a_key_is_refused_before_any_write(
    shell: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The service keyed the store (its genesis row, nothing else yet); a shell with no key and no
    opt-out runs ``admin-unlock``. That is not a keyless START, so the seam does not claim it is. The
    handle reads from the genesis row that the chain is keyed, so the append would refuse, and the
    command must refuse before clearing the lockout rather than after."""
    db = shell / "keyed-empty.db"
    _fresh_store(db, user="ops", key=generate_key())
    rc = main(_argv("admin-unlock", db, shell))
    error = json.loads(capsys.readouterr().out)["error"]
    assert rc == 2
    assert "would be refused" in error and "would start a KEYLESS" not in error
    with sqlite3.connect(db) as conn:
        locked = conn.execute("SELECT locked_until FROM users WHERE id='u1'").fetchone()[0]
    assert locked is not None, "the lockout was cleared although its audit row could not be written"
    assert _audit_rows(db) == 1, "only the genesis row: the refused command appended nothing"


def test_backup_refuses_before_running_when_its_audit_row_would_be_refused(
    shell: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A keyed store and a shell with no key but a leftover opt-out: before, the archive was written
    and kept (and older ones pruned), then the audit append raised."""
    db = shell / "keyed.db"
    _fresh_store(db, key=generate_key())
    _opt_out(monkeypatch)
    monkeypatch.setenv("MEFOR_BACKUP_ALLOW_UNENCRYPTED", "true")
    assert main(_argv("backup", db, shell)) == 2
    assert not (shell / "dest").exists() or not any((shell / "dest").iterdir())
    assert _audit_rows(db) == 1, "only the genesis row: the refused command appended nothing"


def test_a_key_the_provider_did_not_resolve_is_refused_at_the_seam_with_its_cause(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A key named in the settings that a pinned key provider does not read. Before BACKLOG #2077 it
    passed the CLI gate and was refused at the seam; now the gate refuses it with its cause, before
    anything is opened, and ``open_store`` refuses the same case for every other command."""
    monkeypatch.setenv("MEFOR_STORE_KEY_PROVIDER", "env")
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY_FILE", str(shell / "service.key"))
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    db = shell / "unresolved.db"
    rc = main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"])
    error = json.loads(capsys.readouterr().out)["error"]
    assert rc == 2
    assert "reads only MEFOR_STORE_ENCRYPTION_KEY" in error, error
    assert not db.exists()


# --- openers that reached main after the seam ---------------------------------------------------------


def test_provision_admin_opens_an_existing_empty_store_under_the_opt_out(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The "an Administrator exists" probe opens the store before the password prompt. At the refusing
    default it would refuse an existing store with an empty audit log even under the audited opt-out
    the command's own gate has just accepted. It passes the same verdict as the write that follows."""
    db = shell / "fresh.db"
    _fresh_store(db)
    _opt_out(monkeypatch)
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    rc = main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"])
    assert rc == 0, capsys.readouterr()
    assert _users(db) == 1
    assert _audit_rows(db) == 1  # the provisioning row alone: the probe before it writes none


def _supervise_args(db: Path, root: Path) -> argparse.Namespace:
    from tests.test_api_tls import SAMPLES_CONFIG

    return argparse.Namespace(
        config=str(SAMPLES_CONFIG),
        db=str(db),
        base_port=8765,
        env="dev",
        service_config=None,
        project_root=str(root),
    )


def _run_supervise(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> tuple[int, str, list[str]]:
    """``_supervise`` with the fleet stubbed out: its return code, its stderr, and the configs it
    would have spawned. Logging setup is stubbed too, so the root handlers are not left bound to this
    test's capture buffer."""
    from messagefoundry import __main__ as cli

    spawned: list[str] = []

    async def fake_supervise(config: str, **kwargs: object) -> int:
        spawned.append(config)
        return 0

    monkeypatch.setattr("messagefoundry.pipeline.supervisor.supervise", fake_supervise)
    monkeypatch.setattr(cli, "configure_logging", lambda *args, **kwargs: None)
    rc = cli._supervise(_supervise_args(shell / "mefor.db", shell))
    return rc, capsys.readouterr().err, spawned


@pytest.mark.parametrize(
    ("opted_out", "renewal_due"), [(False, True), (False, False), (True, True)]
)
def test_supervise_applies_the_at_rest_gate_before_it_renews_or_spawns(
    opted_out: bool,
    renewal_due: bool,
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``supervise`` audits a renewed API pair in the store before it starts any shard, and each shard
    it starts runs ``serve``'s at-rest gate. With no key and no opt-out it now refuses up front with
    exit 2: before renewing, so the pair on disk is not replaced without an audit row, and whether or
    not a renewal is due, so it does not start shards that would each refuse. Under the opt-out it
    audits the renewal and starts the fleet, which shows the refusal is the gate's and not a ban."""
    from tests.test_api_tls import _plant_generated_pair

    if opted_out:
        _opt_out(monkeypatch)
    cert = None
    if renewal_due:
        cert, _key = _plant_generated_pair(shell, lived_days=300, left_days=65)
    before = cert.read_bytes() if cert is not None else None
    db = shell / "mefor.db"
    rc, err, spawned = _run_supervise(shell, monkeypatch, capsys)
    if opted_out:
        assert rc == 0, err
        assert spawned
        assert _audit_rows(db) == 1
        return
    assert rc == 2, err
    assert "keyless" in err.lower()
    assert not spawned
    assert not db.exists(), "the refusal came after the store was opened"
    if cert is not None:
        assert cert.read_bytes() == before, "the pair was replaced before the refusal"


def test_supervise_exits_2_when_a_named_key_does_not_resolve(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A named key the pinned provider does not read. Since BACKLOG #2077 the gate refuses it before
    the renewal and before any shard, and exits 2 with its cause rather than falling to the dispatch
    floor."""
    from tests.test_api_tls import _plant_generated_pair

    monkeypatch.setenv("MEFOR_STORE_KEY_PROVIDER", "env")
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY_FILE", str(shell / "service.key"))
    cert, _key = _plant_generated_pair(shell, lived_days=300, left_days=65)
    before = cert.read_bytes()
    rc, err, spawned = _run_supervise(shell, monkeypatch, capsys)
    assert rc == 2, err
    assert "reads only MEFOR_STORE_ENCRYPTION_KEY" in err, err
    assert not spawned
    assert not (shell / "mefor.db").exists()
    assert cert.read_bytes() == before, "the pair was replaced before the refusal"
