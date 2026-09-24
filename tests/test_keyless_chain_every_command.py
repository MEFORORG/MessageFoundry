# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1916 -- no command may START a keyless audit chain unless the audited opt-out applies.

#1905 closed this for ``serve`` and ``provision-admin`` with a CLI gate that each of those two
commands calls. Every other command that opens the store could still write the first audit row of a
fresh store with no key -- at least ``backup`` (its ``dr_backup`` row) and ``admin-unlock`` (its
``auth.admin_unlocked`` row) -- and a chain that starts keyless stays keyless: a later keyed open
auto-keys only an EMPTY ``audit_log``.

The fix moves the decision into ``open_store``, the one seam every command opens through: with no
keying secret and an empty ``audit_log``, it refuses unless the caller passes the audited opt-out's
verdict. So a command that forgets to decide is refused, not waved through. These tests pin that for
every store-opening command, the opt-out arm, the existing-chain arm, and a source guard that no
product caller routes around the seam.

Also pinned: ``provision-admin`` refuses BEFORE writing when the opened store cannot take an audit row
(a keyed chain opened from a shell with no key and a stale opt-out used to write the account and then
crash on the audit row), and ``rekey-audit`` no longer prints the keyless-chain WARNING it exists to
clear.

Severity is conditional (CLAUDE.md section 0): zero deployments, so this is what a first deployment
would have inherited.
"""

from __future__ import annotations

import ast
import asyncio
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
                await store.create_user(user_id="u1", username=user, auth_provider="local")
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
    return [command, "--db", str(db)]


#: Every CLI command that opens the store through ``open_store`` (the source guard below proves this
#: list is complete). ``serve`` and ``provision-admin`` are covered by the #1905 suite and by
#: ``test_provision_admin_refuses_before_writing_when_the_chain_cannot_take_a_row`` below; ``rotate-key``
#: refuses any keyless open before it opens anything, so it appears in the guard, not here.
_STORE_OPENING_COMMANDS = ("backup", "admin-unlock", "audit-anchor", "audit-verify", "rekey-audit")


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
    """Control arm: with a key the chain is keyed from row 1, so there is nothing to refuse."""
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
    _fresh_store(db, key=generate_key())  # the keyed open writes the watermark: keyed from row 1
    _opt_out(monkeypatch)
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    rc = main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"])
    assert rc != 0
    assert "error" in json.loads(capsys.readouterr().out)
    assert _users(db) == 0, "the account was written before the audit row was refused"
    assert _audit_rows(db) == 0


# --- rekey-audit: the warning it exists to clear -----------------------------------------------------


def _keyless_chain_under_a_key(db: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def seed() -> None:
        store = await MessageStore.open(db)
        try:
            await store.record_audit("seed", actor="test")
        finally:
            await store.close()

    asyncio.run(seed())
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())


_WARNING = "audit chain is KEYLESS"


class _Records(logging.Handler):
    """Collects records straight off the store's logger. ``caplog`` hangs off the root logger, and a
    CLI run reconfigures logging, so a test that reads caplog can see nothing for a reason unrelated
    to what it asserts -- which is a silent pass for the suppression arm."""

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def _run_capturing_store_warnings(argv: list[str]) -> tuple[int, list[str]]:
    handler = _Records()
    logger = logging.getLogger("messagefoundry.store.store")
    logger.addHandler(handler)
    try:
        return main(argv), [m for m in handler.messages if _WARNING in m]
    finally:
        logger.removeHandler(handler)


def test_rekey_audit_does_not_print_the_warning_it_clears(
    shell: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = shell / "rekey.db"
    _keyless_chain_under_a_key(db, monkeypatch)
    rc, warnings = _run_capturing_store_warnings(["rekey-audit", "--db", str(db)])
    assert rc == 0
    assert not warnings


def test_other_commands_still_print_the_keyless_chain_warning(
    shell: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control arm for the suppression: the same store, opened by any other command, still warns --
    so the empty list above is the suppression, not an instrument that cannot see the warning."""
    db = shell / "rekey.db"
    _keyless_chain_under_a_key(db, monkeypatch)
    rc, warnings = _run_capturing_store_warnings(["audit-anchor", "--db", str(db), "--json"])
    assert rc == 0
    assert warnings


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
    "_provision_admin.run",
    "_audit_verify.run",
    "_audit_anchor.run",
    "_rekey_audit.run",
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
    # Positive control and completeness in one: the instrument must find exactly the CLI openers the
    # behavioural tests above exercise, or its silence proves nothing. A new CLI opener fails here, and
    # so does a second open inside one of them.
    assert sorted(s for s, _ in cli) == sorted(_CLI_OPENERS | _CLI_DEFAULT), sorted(cli)
    assert {s for s, how in cli if how == "verdict"} == _CLI_OPENERS
    assert {s for s, how in cli if how == "default"} == _CLI_DEFAULT
    # And it must have scanned the seam itself: the backend dispatch is the one allowed backend open.
    assert "messagefoundry/store/base.py" in files


# --- the round-1 review cases -------------------------------------------------------------------------


def test_an_empty_KEYED_chain_opened_without_a_key_is_refused_before_any_write(
    shell: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The service keyed the store (a watermark, no rows yet); a shell with no key and no opt-out runs
    ``admin-unlock``. That is not a keyless START, so the seam does not claim it is. The append would
    refuse, so the command must refuse before clearing the lockout rather than after."""
    db = shell / "keyed-empty.db"
    _fresh_store(db, user="ops", key=generate_key())
    rc = main(_argv("admin-unlock", db, shell))
    error = json.loads(capsys.readouterr().out)["error"]
    assert rc == 2
    assert "would be refused" in error and "would start a KEYLESS" not in error
    with sqlite3.connect(db) as conn:
        locked = conn.execute("SELECT locked_until FROM users WHERE id='u1'").fetchone()[0]
    assert locked is not None, "the lockout was cleared although its audit row could not be written"
    assert _audit_rows(db) == 0


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
    assert _audit_rows(db) == 0


def test_a_key_the_provider_did_not_resolve_is_refused_at_the_seam_with_its_cause(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``provision-admin`` creates the store. A key named in the settings that the key provider does
    not resolve passes the CLI gate and is refused at the seam, which names that cause. The file the
    open created is left, deliberately: it holds no audit row and no account, so a keyed ``serve``
    still keys it from row 1, and deleting it would race a ``serve`` creating the same file."""
    monkeypatch.setenv("MEFOR_STORE_KEY_PROVIDER", "env")
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY_FILE", str(shell / "service.key"))
    _tty(monkeypatch, _PASSWORD, _PASSWORD)
    db = shell / "unresolved.db"
    rc = main(["provision-admin", "--username", "site-admin", "--db", str(db), "--json"])
    error = json.loads(capsys.readouterr().out)["error"]
    assert rc == 2
    assert "resolved no key" in error
    assert _audit_rows(db) == 0
    assert _users(db) == 0
