# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5067: ``provision-admin`` and ``admin-reset-totp`` say only what a refused store open
left behind.

Both said "nothing was written" for a server store whose live schema falls short of this build's
DDL batch (``ServerSchemaMismatchError``, BACKLOG #1720). The open rolls that batch back and writes
no schema marker. But on SQL Server under ``[store].schema_management = auto`` a writable open first
switches database options on, outside the batch (``_open_refusal_left_behind`` names them), so the
database may already have changed. Each refusal now says the batch was rolled back, and there, that the setting
may have changed. ``provision-admin``'s refusal at the write, after the key was shown, also says the
entry the operator may have added has no seed, as ``admin-reset-totp`` already did. Severity is
conditional (CLAUDE.md section 0): this is what a first deployment would have read.

Not server-gated: the store open is replaced, so no driver or server runs.
"""

from __future__ import annotations

import sqlite3
import sys
import types
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.__main__ import main
from messagefoundry.store.server_schema_verify import ServerSchemaMismatchError

# The shell, the difference and the password the #1720 tests use, shared rather than copied.
from tests.test_b1720_cli_schema_refusal_exit import _DIFFERENCE, _PASSWORD
from tests.test_b1720_cli_schema_refusal_exit import shell as shell  # noqa: F401

_RCSI = "READ_COMMITTED_SNAPSHOT and ALLOW_SNAPSHOT_ISOLATION options"
_ROLLED_BACK = "rolled its schema batch back and wrote no schema marker"
_BOUND_NO_ROW = "No account or audit row was written"
_BOUND_MAY_HAVE = "may already have changed the database"
_UNUSED_ENTRY = "If you added the entry this run showed to the authenticator app, delete it"
#: The opening every left-behind text shares (BACKLOG #5067).
_OWN_WRITES = "The change this command makes did not land"
#: Where only the refusal's class is known, the open may not have reached its writing steps.
_MAY_OR_MAY_NOT = "The open may or may not have reached its own writing steps"
_KEEP_ENTRY = "keep it for now: its seed may be stored"

#: ``(backend, schema_management)`` -> whether the refusal names the database setting.
_STORES = {
    ("sqlserver", "auto"): True,
    ("postgres", "auto"): False,
}


def _settings(tmp: Path, backend: str, management: str, *, require_mfa: bool = True) -> Path:
    """A loopback server store at ``enforce``, so the revocation guard that runs before the open at
    ``warn`` does nothing."""
    auth = "integrated" if backend == "sqlserver" else "sql"
    settings = tmp / "service.toml"
    settings.write_text(
        "[store]\n"
        f'backend = "{backend}"\n'
        'server = "127.0.0.1"\n'
        'database = "mefor"\n'
        'username = "mefor"\n'
        f'auth = "{auth}"\n'
        f'schema_management = "{management}"\n'
        "\n"
        "[security]\n"
        f"require_mfa = {'true' if require_mfa else 'false'}\n"
        'enforcement = "enforce"\n',
        encoding="utf-8",
    )
    return settings


def _refusal(backend: str) -> ServerSchemaMismatchError:
    return ServerSchemaMismatchError(backend, "mefor", [_DIFFERENCE])


def _every_open_refuses(monkeypatch: pytest.MonkeyPatch, backend: str) -> None:
    """Every store open refuses as a server store with a short schema does."""
    from messagefoundry.store import base

    async def refusing(*_args: object, **_kwargs: object) -> object:
        raise _refusal(backend)

    monkeypatch.setattr(base, "open_store", refusing)


def _refused_at_the_write(
    monkeypatch: pytest.MonkeyPatch, backend: str, refusal: Exception
) -> None:
    """The pre-check finds no store, so ``provision-admin`` prompts, shows the key and reaches the
    write's ``create=True`` open, which raises ``refusal``. A console types the password and proves
    the enrolment."""
    from messagefoundry import __main__ as cli
    from messagefoundry.config.settings import StoreBackend
    from messagefoundry.store import base

    async def opening(*_args: object, create: bool = False, **_kwargs: object) -> object:
        if not create:
            raise base.StoreNotFoundError.server_schema(StoreBackend(backend), "mefor")
        raise refusal

    monkeypatch.setattr(base, "open_store", opening)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: _PASSWORD)
    monkeypatch.setattr(
        cli, "_enrol_totp_at_terminal", lambda **_k: ("JBSWY3DPEHPK3PXP", "123456", 0.0)
    )


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> str:
    """Run the command; its output, once it exited 2, could not start."""
    code = main(argv)
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code == 2, out
    return out


def _provision(settings: Path, *extra: str) -> list[str]:
    return [
        "provision-admin",
        "--username",
        "site-admin",
        "--email",
        "ops@example.invalid",
        *extra,
        "--service-config",
        str(settings),
    ]


def _assert_left_behind(out: str, *, names_the_setting: bool) -> None:
    assert _DIFFERENCE in out, out
    assert _ROLLED_BACK in out, out
    assert "nothing was written" not in out.lower(), out
    assert (_RCSI in out) is names_the_setting, out
    assert "Traceback" not in out, out


@pytest.mark.parametrize(("backend", "management"), _STORES)
def test_provision_admin_pre_check_says_what_the_open_left(
    backend: str,
    management: str,
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The pre-check open, before the prompt. Exit 2 as before (#1720).

    Mutation: print ``_NOTHING_PROVISIONED`` again in the pre-check's arm."""
    _every_open_refuses(monkeypatch, backend)
    out = _run(_provision(_settings(shell, backend, management)), capsys)
    assert "Refusing to provision" in out, out
    _assert_left_behind(out, names_the_setting=_STORES[backend, management])
    assert _UNUSED_ENTRY not in out, "no key was shown before the pre-check"


@pytest.mark.parametrize(("backend", "management"), _STORES)
def test_provision_admin_write_says_what_the_open_left_and_names_the_entry(
    backend: str,
    management: str,
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The write's ``create=True`` open, after the key was shown: the text also names the unused
    authenticator entry.

    Mutation: drop ``after_the_key`` from the write's open-refusal arm."""
    _refused_at_the_write(monkeypatch, backend, _refusal(backend))
    out = _run(_provision(_settings(shell, backend, management)), capsys)
    _assert_left_behind(out, names_the_setting=_STORES[backend, management])
    assert _UNUSED_ENTRY in out, out


def test_provision_admin_write_names_no_entry_under_no_totp(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control on the entry: with ``--no-totp`` no key was shown, so no entry is named, and
    the hint above is not printed on every refusal."""
    _refused_at_the_write(monkeypatch, "sqlserver", _refusal("sqlserver"))
    settings = _settings(shell, "sqlserver", "auto", require_mfa=False)
    out = _run(_provision(settings, "--no-totp"), capsys)
    _assert_left_behind(out, names_the_setting=True)
    assert _UNUSED_ENTRY not in out, out


def test_provision_admin_keyless_refusal_at_the_write_names_the_entry(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A keyless refusal at the write comes after the key was shown too, and before any write.

    Mutation: drop ``after_the_key`` from the keyless arm."""
    from messagefoundry.store import base

    refusal = base.KeylessAuditChainRefused("mefor", "[store].synthetic_setting")
    _refused_at_the_write(monkeypatch, "sqlserver", refusal)
    out = _run(_provision(_settings(shell, "sqlserver", "auto")), capsys)
    assert "[store].synthetic_setting" in out, out
    assert _UNUSED_ENTRY in out, out
    # It follows a full open, so it says what that open may have changed (BACKLOG #5067).
    assert _OWN_WRITES in out and _RCSI in out, out


@pytest.mark.parametrize("kind", ["keyless", "cipher"])
def test_provision_admin_key_refusal_at_the_write_open_names_the_entry(
    kind: str, shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A key or cipher refusal at the write's ``create=True`` open comes after the key was shown
    and before any write: could not start, exit 2, with the pre-check's text and the entry named.
    It escaped to the CLI floor's exit 1 with no hint.

    Mutation: drop the write's ``(StoreKeylessError, CipherError)`` arm; the exit is then 1."""
    from messagefoundry.store.crypto import CipherError, StoreKeylessError

    refusal: Exception = (
        StoreKeylessError("table synthetic_table holds an encrypted value")
        if kind == "keyless"
        else CipherError("table synthetic_table holds a value no key opens")
    )
    _refused_at_the_write(monkeypatch, "sqlserver", refusal)
    out = _run(_provision(_settings(shell, "sqlserver", "auto")), capsys)
    assert "synthetic_table" in out, out
    # The create open may have run its writing steps first, so not "nothing was written" (#5067
    # PR 2755 open finding 2).
    assert _OWN_WRITES in out and _RCSI in out, out
    assert "nothing was written" not in out.lower(), out
    assert _UNUSED_ENTRY in out, out
    assert "Traceback" not in out, out


def _bound_refusal() -> TimeoutError:
    """A store error the open's strict invocation-bound pass re-raised as itself (BACKLOG #5608),
    carrying the bound's note, where it once arrived as a ``CipherError``."""
    from messagefoundry.store.gcm_bound import INVOCATION_BOUND_NOTE

    refusal = TimeoutError("lock request on synthetic_table timed out")
    refusal.add_note(INVOCATION_BOUND_NOTE)
    return refusal


def _assert_bound_left_behind(out: str, *, names_the_setting: bool, runs_ddl: bool = True) -> None:
    """The pass runs after the open's schema step and salt bind, so the text never says nothing
    was written: it says which rows were not, and what the open may already have changed. Under
    external schema management the open runs no DDL, so the schema is not named."""
    assert "synthetic_table" in out, out
    assert _BOUND_NO_ROW in out, out
    assert _BOUND_MAY_HAVE in out, out
    assert "the store's salt record" in out, out
    assert ("the schema, which the open creates or migrates" in out) is runs_ddl, out
    assert "nothing was written" not in out.lower(), out
    assert (_RCSI in out) is names_the_setting, out
    assert "Traceback" not in out, out


#: ``(backend, schema_management)`` -> whether the bound's text names the snapshot options, and
#: whether it names the schema the open creates or migrates.
_BOUND_STORES = {
    ("sqlserver", "auto"): (True, True),
    ("postgres", "auto"): (False, True),
    ("postgres", "external"): (False, False),
    ("sqlserver", "external"): (False, False),
}


def _open_refuses_with(monkeypatch: pytest.MonkeyPatch, refusal: Exception) -> None:
    from messagefoundry.store import base

    async def refusing(*_args: object, **_kwargs: object) -> object:
        raise refusal

    monkeypatch.setattr(base, "open_store", refusing)


@pytest.mark.parametrize(("backend", "management"), _BOUND_STORES)
def test_provision_admin_invocation_bound_store_error_at_the_pre_check_is_could_not_start(
    backend: str,
    management: str,
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The pre-check open, before the prompt, runs the same strict pass on an existing store, so
    its store error takes the write open's exit 2, not the floor's exit 1.

    Mutation: drop the pre-check's ``_raise_if_bound_refused`` call; the exit is then 1."""
    _open_refuses_with(monkeypatch, _bound_refusal())
    out = _run(_provision(_settings(shell, backend, management)), capsys)
    assert "Refusing to provision" in out, out
    assert "cannot open the store at 127.0.0.1/mefor" in out, out
    names_the_setting, runs_ddl = _BOUND_STORES[backend, management]
    _assert_bound_left_behind(out, names_the_setting=names_the_setting, runs_ddl=runs_ddl)
    assert _UNUSED_ENTRY not in out, "no key was shown before the pre-check"


def test_a_defect_carrying_the_bound_note_is_not_reported_as_could_not_start(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A bug the bound's pass re-raised is a defect, not a store that could not open, so it reaches
    the dispatch floor's exit 1. CONTROL for the arm above: without the defect check it exits 2."""
    from messagefoundry.store.gcm_bound import INVOCATION_BOUND_NOTE

    defect = NotImplementedError("synthetic defect")
    defect.add_note(INVOCATION_BOUND_NOTE)
    _open_refuses_with(monkeypatch, defect)
    assert main(_provision(_settings(shell, "postgres", "auto"))) == 1
    out = "".join(capsys.readouterr())
    assert "The open stopped where" not in out, out


def test_provision_admin_invocation_bound_store_error_at_the_write_open_names_the_entry(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """At the write's open the same error keeps the advice about the shown key's entry (#5067).

    Mutation: drop the write's ``_InvocationBoundOpenRefused`` raise; the exit is then 1."""
    _refused_at_the_write(monkeypatch, "sqlserver", _bound_refusal())
    out = _run(_provision(_settings(shell, "sqlserver", "auto")), capsys)
    _assert_bound_left_behind(out, names_the_setting=True)
    assert _UNUSED_ENTRY in out, out


def test_a_server_driver_error_at_the_bound_shows_its_class_and_sqlstate_not_its_text(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A server's text can quote a stored value, so the driver error renders as its class and
    SQLSTATE, as every other store-open error does (``_store_error_text``).

    Mutation: render the failure through ``codec_safe_str`` again; the quoted value is printed."""
    from messagefoundry.store import base
    from messagefoundry.store.gcm_bound import INVOCATION_BOUND_NOTE

    # The renderer reads a ``sqlstate`` attribute on any error, so no stand-in driver module is
    # installed: one would linger in the auth service's cached catch sets after this test.
    driver_error = type("PostgresError", (OSError,), {})

    async def refusing(*_args: object, **_kwargs: object) -> object:
        exc = driver_error("lock timeout on a row quoting synthetic-value-9")
        exc.sqlstate = "55P03"
        exc.add_note(INVOCATION_BOUND_NOTE)
        raise exc

    monkeypatch.setattr(base, "open_store", refusing)
    out = _run(_provision(_settings(shell, "postgres", "auto")), capsys)
    assert "PostgresError [SQLSTATE 55P03]" in out, out
    assert "synthetic-value-9" not in out, out


def test_the_invocation_bound_carrier_keeps_its_failure_through_str_and_pickle() -> None:
    """Built with the failure as its one argument, as ``StoreCreateBatchFailedBeforeKeyUse`` is,
    so a copy or an unpickle rebuilds it whole."""
    import pickle

    from messagefoundry.__main__ import _InvocationBoundOpenRefused

    carrier = _InvocationBoundOpenRefused(OSError("synthetic"))
    assert "synthetic" in str(carrier)
    copy = pickle.loads(pickle.dumps(carrier))
    assert isinstance(copy.failure, OSError) and str(copy.failure) == "synthetic"


def test_provision_admin_names_no_entry_once_the_write_has_started(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A refusal the write's arms catch, raised once the service's write has started, never says
    to delete the entry: the seed may then be stored, and deleting the entry would leave the
    Administrator without its factor. A real SQLite store, so the open succeeds and the write is
    reached. ``test_a_refusal_once_the_write_started_says_to_keep_the_shown_entry`` reads the
    advice it gives instead.

    Mutation: drop the ``write_started`` branch from ``after_the_key``; the hint is then
    printed."""
    from messagefoundry.auth.service import AuthService
    from messagefoundry.config.tls_policy import InsecureHopRefused

    async def refusing(*_args: object, on_first_write: Callable[[], None], **_k: object) -> object:
        on_first_write()
        raise InsecureHopRefused("synthetic hop refusal inside the write")

    monkeypatch.setattr(AuthService, "provision_first_administrator", refusing)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: _PASSWORD)
    argv = [
        "provision-admin",
        "--username",
        "site-admin",
        "--email",
        "ops@example.invalid",
        "--db",
        str(shell / "provision.db"),
    ]
    out = _run(argv, capsys)
    assert "synthetic hop refusal inside the write" in out, out
    assert _UNUSED_ENTRY not in out, out
    assert "nothing was written" not in out.lower(), out
    assert "may be missing or incomplete" in out, out


def test_provision_admin_pre_check_cipher_refusal_quotes_no_key_byte(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The pre-check's key or cipher arm prints through ``codec_safe_str`` too (BACKLOG #2532).

    Mutation: print ``_sentence(exc)`` again in that arm; the byte is then quoted."""
    from messagefoundry.store import base
    from messagefoundry.store.crypto import CipherError

    async def refusing(*_args: object, **_kwargs: object) -> object:
        try:
            b"\xe9".decode("ascii")
        except UnicodeDecodeError as exc:
            raise CipherError(exc) from exc
        raise AssertionError("unreachable")

    monkeypatch.setattr(base, "open_store", refusing)
    out = _run(_provision(_settings(shell, "sqlserver", "auto")), capsys)
    assert "xe9" not in out.lower(), out
    assert _OWN_WRITES in out, out


def test_provision_admin_names_the_os_user_before_the_key_is_shown(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A shell whose OS user cannot be named is refused before the key is shown, so no entry is
    left for a seed never stored. It was named after the key was shown, and an ``OSError`` there
    escaped with no hint.

    Mutation: name the OS user after ``_enrol_totp_at_terminal`` again; the enrolment then runs."""
    from messagefoundry import __main__ as cli

    _refused_at_the_write(monkeypatch, "sqlserver", _refusal("sqlserver"))
    shown: list[object] = []

    def enrol(**_k: object) -> tuple[str, str, float]:
        shown.append(_k)
        return ("JBSWY3DPEHPK3PXP", "123456", 0.0)

    def no_user() -> str:
        raise OSError("no user name for this shell")

    monkeypatch.setattr(cli, "_enrol_totp_at_terminal", enrol)
    monkeypatch.setattr("getpass.getuser", no_user)
    code = main(_provision(_settings(shell, "sqlserver", "auto")))
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code != 0, out
    assert not shown, "the key was shown before the OS user was named"
    # No store exists, so the pre-check opened nothing (BACKLOG #5067).
    assert "cannot name the OS user" in out and "nothing was written" in out.lower(), out
    assert "Traceback" not in out, out


@pytest.mark.parametrize(("backend", "management"), _STORES)
def test_admin_reset_totp_says_what_the_open_left(
    backend: str,
    management: str,
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``admin-reset-totp``'s first open, wrapped by ``_open_store_or_refuse``, so the schema
    refusal arrives as the cause of a ``_StoreOpenRefused``.

    Mutation: print "Nothing was written." again in ``open_refused``'s could-not-start arm."""
    _every_open_refuses(monkeypatch, backend)
    settings = _settings(shell, backend, management)
    out = _run(["admin-reset-totp", "--username", "ops", "--service-config", str(settings)], capsys)
    _assert_left_behind(out, names_the_setting=_STORES[backend, management])


def test_any_other_open_refusal_keeps_its_text() -> None:
    """The control on the helper: only the schema refusal, raised or as a cause, has more to say."""
    from messagefoundry.__main__ import _open_refusal_left_behind, _StoreOpenRefused
    from messagefoundry.config.settings import SchemaManagement, StoreBackend, StoreSettings

    store = StoreSettings(
        backend=StoreBackend.SQLSERVER,
        server="127.0.0.1",
        database="mefor",
        username="mefor",
        schema_management=SchemaManagement.AUTO,
    )
    assert _open_refusal_left_behind(RuntimeError("a hop refusal"), store) is None
    wrapped_other = _StoreOpenRefused("a key refusal")
    wrapped_other.__cause__ = RuntimeError("a key refusal")
    assert _open_refusal_left_behind(wrapped_other, store) is None
    wrapped = _StoreOpenRefused("short")
    wrapped.__cause__ = _refusal("sqlserver")
    assert _RCSI in (_open_refusal_left_behind(wrapped, store) or "")


def test_provision_admin_open_refusal_quotes_no_key_byte(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A key source's codec error at provision-admin's open does not print the byte it quotes,
    as no other store command does (BACKLOG #2532).

    Mutation: build ``_provision_open_refusal``'s text from ``str(exc)``."""
    from messagefoundry.store import base
    from messagefoundry.store.keyprovider import KeyProviderError

    async def refusing(*_args: object, **_kwargs: object) -> object:
        try:
            b"\xe9".decode("ascii")
        except UnicodeDecodeError as exc:
            raise KeyProviderError(exc) from exc
        raise AssertionError("unreachable")

    monkeypatch.setattr(base, "open_store", refusing)
    out = _run(_provision(_settings(shell, "sqlserver", "auto")), capsys)
    assert "xe9" not in out.lower(), out
    assert "nothing was written" in out, out


def test_a_cipher_refusal_once_the_write_has_started_reaches_the_floor(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The write's key or cipher arm re-raises a refusal once the write has started (engine PR
    2755 open finding 3, BACKLOG #5067): one from the write itself may follow a row it wrote, so it
    must not be reported as could not start, with "nothing was written" and the advice to delete
    the entry. A real SQLite store, so the open succeeds and the write is reached.

    Mutation: drop the ``if write_started: raise`` branch from that arm; the run then exits 2,
    which the exit-code assertion catches."""
    from messagefoundry.auth.service import AuthService
    from messagefoundry.store.crypto import CipherError

    async def refusing(*_args: object, on_first_write: Callable[[], None], **_k: object) -> object:
        on_first_write()
        raise CipherError("synthetic cipher refusal inside the write")

    monkeypatch.setattr(AuthService, "provision_first_administrator", refusing)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: _PASSWORD)
    argv = [
        "provision-admin",
        "--username",
        "site-admin",
        "--email",
        "ops@example.invalid",
        "--db",
        str(shell / "provision.db"),
    ]
    code = main(argv)
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code == 1, out
    assert _UNUSED_ENTRY not in out, out
    assert "nothing was written" not in out.lower(), out


# Engine PR 2755 open findings 1 and 2, and closing step 2 (BACKLOG #5067).


def _provision_sqlite(shell: Path, *extra: str) -> list[str]:
    """``provision-admin`` against a real SQLite store, so the open succeeds and the write is
    reached."""
    return [
        "provision-admin",
        "--username",
        "site-admin",
        "--email",
        "ops@example.invalid",
        *extra,
        "--db",
        str(shell / "provision.db"),
    ]


def _service_raises(monkeypatch: pytest.MonkeyPatch, refusal: Exception, *, wrote: bool) -> None:
    """The service's provision raises ``refusal``, after its first write when ``wrote``, or from a
    read before any write. A console types the password and proves the enrolment."""
    from messagefoundry import __main__ as cli
    from messagefoundry.auth.service import AuthService

    async def refusing(*_args: object, on_first_write: Callable[[], None], **_k: object) -> object:
        if wrote:
            on_first_write()
        raise refusal

    monkeypatch.setattr(AuthService, "provision_first_administrator", refusing)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: _PASSWORD)
    monkeypatch.setattr(
        cli, "_enrol_totp_at_terminal", lambda **_k: ("JBSWY3DPEHPK3PXP", "123456", 0.0)
    )


def test_a_cipher_refusal_from_a_read_before_the_write_is_could_not_start(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A cipher refusal from the service's reads before its first write (finding 1) is could not
    start, exit 2, with the advice to delete the shown entry, as at the open. The CLI marked the
    write started before those reads, so it reached the dispatch floor's exit 1.

    Mutation: set ``write_started`` before the service call again; the exit is then 1."""
    from messagefoundry.store.crypto import CipherError

    _service_raises(monkeypatch, CipherError("table synthetic_table holds a value"), wrote=False)
    out = _run(_provision_sqlite(shell), capsys)
    assert "synthetic_table" in out, out
    assert _UNUSED_ENTRY in out, out
    assert "The write had started" not in out, out


def test_a_refusal_once_the_write_started_says_to_keep_the_shown_entry(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Closing step 2: once the write has started, the refusal names the shown entry, and says
    to keep it until a later run completes, never to delete it now.

    Mutation: drop the shown-key sentence from ``after_the_key``'s write-started branch."""
    from messagefoundry.config.tls_policy import InsecureHopRefused

    _service_raises(monkeypatch, InsecureHopRefused("synthetic hop refusal"), wrote=True)
    out = _run(_provision_sqlite(shell), capsys)
    assert "The write had started" in out, out
    assert _KEEP_ENTRY in out and "Once a later run of this command completes" in out, out
    assert _UNUSED_ENTRY not in out, out


def test_a_refusal_once_the_write_started_names_no_entry_under_no_totp(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control: with ``--no-totp`` no key was shown, so no entry is named."""
    from messagefoundry.config.tls_policy import InsecureHopRefused

    _service_raises(monkeypatch, InsecureHopRefused("synthetic hop refusal"), wrote=True)
    settings = shell / "service.toml"
    settings.write_text("[security]\nrequire_mfa = false\n", encoding="utf-8")
    out = _run(_provision_sqlite(shell, "--no-totp", "--service-config", str(settings)), capsys)
    assert "The write had started" in out, out
    assert _KEEP_ENTRY not in out and _UNUSED_ENTRY not in out, out


async def test_the_service_calls_on_first_write_after_its_reads_and_before_its_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``on_first_write`` fires once, after the pre-write reads and once the fresh row's INSERT
    has returned, so a read's or a refused INSERT's refusal is reported as raised before any
    account write (finding 1).

    Mutation: call ``on_first_write`` at the top of the method; the refused read then fires it."""
    from messagefoundry.auth.service import AuthService
    from messagefoundry.config.settings import AuthSettings
    from messagefoundry.store.crypto import CipherError
    from messagefoundry.store.store import MessageStore
    from tests._admin_account import PROVISION_EMAIL, provision_totp

    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        fired: list[str] = []
        create_user = store.create_user

        async def recording_create(*args: Any, **kwargs: Any) -> Any:
            fired.append("create_user")
            return await create_user(*args, **kwargs)

        monkeypatch.setattr(store, "create_user", recording_create)

        async def refused_read(*_a: object, **_k: object) -> object:
            raise CipherError("synthetic read refusal")

        with monkeypatch.context() as patched:
            patched.setattr(service, "_lookup_by_username", refused_read)
            with pytest.raises(CipherError):
                await service.provision_first_administrator(
                    username="site-admin",
                    password=_PASSWORD,
                    notify_email=PROVISION_EMAIL,
                    actor="test",
                    on_first_write=lambda: fired.append("first write"),
                    **provision_totp(),
                )
        assert fired == [], fired

        await service.provision_first_administrator(
            username="site-admin",
            password=_PASSWORD,
            notify_email=PROVISION_EMAIL,
            actor="test",
            on_first_write=lambda: fired.append("first write"),
            **provision_totp(),
        )
        assert fired == ["create_user", "first write"], fired
    finally:
        await store.close()


#: ``(backend, schema_management, refusal kind)`` -> what the text names: the schema step, the
#: snapshot options, the salt record, the genesis record; ``None`` where it names none of them and
#: says only that the open's own steps may have written, never that nothing was written.
_STEPS: dict[tuple[str, str, str], tuple[bool, bool, bool, bool] | None] = {
    ("sqlserver", "auto", "cipher"): (True, True, True, True),
    ("postgres", "auto", "keyless"): (True, False, False, False),
    ("postgres", "external", "cipher"): (False, False, True, True),
    ("postgres", "external", "keyless"): None,
}
_MAY_HAVE_WRITTEN = "the open's own steps may already have written to the database"
_MAY_HAVE_CHANGED = "the database may or may not have changed"


def _steps_refusal(kind: str) -> Exception:
    from messagefoundry.store.crypto import CipherError, StoreKeylessError

    if kind == "cipher":
        return CipherError("table synthetic_table holds a value no key opens")
    return StoreKeylessError("table synthetic_table holds an encrypted value")


def _assert_steps(out: str, expected: tuple[bool, bool, bool, bool] | None) -> None:
    assert "synthetic_table" in out, out
    assert "nothing was written" not in out.lower(), out
    if expected is None:
        assert _MAY_HAVE_CHANGED in out and "at least" not in out, out
        return
    schema, options, salt, genesis = expected
    assert _OWN_WRITES in out, out
    assert ("the audit chain's genesis record" in out) is genesis, out
    assert ("the schema, which the open creates or migrates" in out) is schema, out
    assert (_RCSI in out) is options, out
    assert ("the store's salt record" in out) is salt, out


@pytest.mark.parametrize(("backend", "management", "kind"), _STEPS)
def test_provision_admin_write_open_key_refusal_says_what_the_open_may_have_changed(
    backend: str,
    management: str,
    kind: str,
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Finding 2: a key or cipher refusal at the write's ``create=True`` open can follow the
    open's own writing steps, so the text names them rather than say nothing was written. A
    keyless open binds no salt, and under ``external`` the open runs no DDL.

    Mutation: return ``None`` from ``_open_refusal_left_behind`` for these classes again."""
    _refused_at_the_write(monkeypatch, backend, _steps_refusal(kind))
    out = _run(_provision(_settings(shell, backend, management)), capsys)
    _assert_steps(out, _STEPS[backend, management, kind])
    assert _UNUSED_ENTRY in out, out


@pytest.mark.parametrize(("backend", "management", "kind"), _STEPS)
def test_provision_admin_pre_check_key_refusal_says_what_the_open_may_have_changed(
    backend: str,
    management: str,
    kind: str,
    shell: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Finding 2 at the pre-check: an existing store's open, migrations included, comes first.

    Mutation: print "Nothing was written" again in the pre-check's key or cipher arm."""
    _open_refuses_with(monkeypatch, _steps_refusal(kind))
    out = _run(_provision(_settings(shell, backend, management)), capsys)
    _assert_steps(out, _STEPS[backend, management, kind])


def test_provision_admin_pre_check_key_probe_of_an_absent_store_wrote_nothing(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control: with no SQLite store yet, the pre-check only resolves the key and opens
    nothing, so its refusal still says nothing was written."""
    from messagefoundry.store import base

    def refusing(*_a: object, **_k: object) -> object:
        raise _steps_refusal("cipher")

    monkeypatch.setattr(base, "build_store_cipher", refusing)
    out = _run(_provision_sqlite(shell), capsys)
    assert "synthetic_table" in out and "Nothing was written" in out, out
    assert _OWN_WRITES not in out, out


def test_admin_reset_totp_keyless_chain_refusal_says_what_the_open_may_have_changed(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Finding 2 at ``admin-reset-totp``: a keyless-chain refusal comes after a full open, which
    under ``auto`` may have migrated the schema and switched the snapshot options on.

    Mutation: return ``None`` from ``_open_refusal_left_behind`` for this class again."""
    from messagefoundry.store import base

    _open_refuses_with(monkeypatch, base.KeylessAuditChainRefused("mefor", "[store].synthetic"))
    settings = _settings(shell, "sqlserver", "auto")
    out = _run(["admin-reset-totp", "--username", "ops", "--service-config", str(settings)], capsys)
    assert "[store].synthetic" in out, out
    assert _OWN_WRITES in out and _RCSI in out, out
    assert "nothing was written" not in out.lower(), out


def test_a_key_refusal_from_a_read_after_the_write_open_says_what_the_open_may_have_changed(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A key-resolution refusal from the service's reads, before its first account write, comes
    after the write's ``create=True`` open has returned, which may have created the store. So the
    text names that, and still says the entry's seed was never stored.

    Mutation: pass ``opened=False`` from the write's key-resolution arm; it then says nothing was
    written."""
    from messagefoundry.store.keyprovider import KeyProviderError

    _service_raises(monkeypatch, KeyProviderError("synthetic key service refusal"), wrote=False)
    out = _run(_provision_sqlite(shell), capsys)
    assert "synthetic key service refusal" in out, out
    assert _OWN_WRITES in out and "the schema, which the open creates or migrates" in out, out
    assert "nothing was written" not in out.lower(), out
    assert _UNUSED_ENTRY in out, out


def test_an_integrity_refusal_once_the_write_started_says_to_keep_the_shown_entry(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Closing step 2 at the integrity arm, which any write can reach: the shown entry is named,
    with the advice to keep it. Exit 1, this command's refusal.

    Mutation: drop the ``keep_the_entry`` call from ``refused_write``."""
    _service_raises(monkeypatch, sqlite3.IntegrityError("synthetic constraint"), wrote=True)
    code = main(_provision_sqlite(shell))
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code == 1, out
    assert "the store refused one of this command's writes (IntegrityError)" in out, out
    assert _KEEP_ENTRY in out and _UNUSED_ENTRY not in out, out


async def test_the_service_calls_on_first_write_before_a_repair_clears_the_factors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The repair branch: ``on_first_write`` fires before the earlier holder's factors are
    cleared, the branch's first account write.

    Mutation: move the repair branch's ``on_first_write`` call below ``disable_totp``."""
    from messagefoundry.auth.identity import AuthProvider
    from messagefoundry.auth.service import AuthService
    from messagefoundry.config.settings import AuthSettings
    from messagefoundry.store.store import MessageStore
    from tests._admin_account import PROVISION_EMAIL, provision_totp

    store = await MessageStore.open(":memory:")
    try:
        # A roleless local row, which the command takes over.
        await store.create_user(
            user_id="u-roleless",
            username="site-admin",
            auth_provider=AuthProvider.LOCAL.value,
            display_name=None,
            email=None,
            password_hash=None,
            must_change_password=True,
            password_generated=False,
            audits=(),
        )
        service = AuthService(store, AuthSettings())
        fired: list[str] = []
        disable_totp = store.disable_totp

        async def recording_disable(*args: Any, **kwargs: Any) -> Any:
            fired.append("disable_totp")
            return await disable_totp(*args, **kwargs)

        monkeypatch.setattr(store, "disable_totp", recording_disable)
        outcome = await service.provision_first_administrator(
            username="site-admin",
            password=_PASSWORD,
            notify_email=PROVISION_EMAIL,
            actor="test",
            on_first_write=lambda: fired.append("first write"),
            **provision_totp(),
        )
        assert outcome.repaired is True
        assert fired[:2] == ["first write", "disable_totp"], fired
        assert fired.count("first write") == 1, fired
    finally:
        await store.close()


def test_a_keyless_store_open_names_no_salt_record() -> None:
    """A keyless open binds no salt, so a refusal after a keyless open does not name the salt
    record; a keyed one does, and the v1 writer (``aad_bind = false``) binds none either.

    Mutation: pass ``salt=True`` in ``_provision_open_refusal``'s opened branch again."""
    from messagefoundry.__main__ import _invocation_bound_left_behind, _provision_open_refusal
    from messagefoundry.config.settings import StoreSettings
    from messagefoundry.store.keyprovider import KeyProviderError

    store = StoreSettings(path="synthetic.db")
    refusal = KeyProviderError("synthetic")
    keyless = _provision_open_refusal(refusal, store, opened=True, keyed=False)
    keyed = _provision_open_refusal(refusal, store, opened=True, keyed=True)
    assert _OWN_WRITES in keyless and "salt record" not in keyless, keyless
    assert "the store's salt record" in keyed, keyed
    v1 = StoreSettings(path="synthetic.db", aad_bind=False)
    assert "salt record" not in _invocation_bound_left_behind(v1)


# Manager follow-up on w7-cli open findings 1 to 3 (BACKLOG #5067).


def test_a_refused_first_insert_says_the_shown_entry_has_no_seed(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A fresh run whose first INSERT the store refuses, with no row holding the name, wrote no
    account and no seed, so the integrity arm says to delete the shown entry, not to keep it.

    Mutation: call ``on_first_write`` before ``create_user`` again; the run then says to keep
    it."""
    from messagefoundry import __main__ as cli
    from messagefoundry.store.store import MessageStore

    async def refused_insert(*_a: object, **_k: object) -> object:
        raise sqlite3.IntegrityError("synthetic constraint")

    monkeypatch.setattr(MessageStore, "create_user", refused_insert)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: _PASSWORD)
    monkeypatch.setattr(
        cli, "_enrol_totp_at_terminal", lambda **_k: ("JBSWY3DPEHPK3PXP", "123456", 0.0)
    )
    monkeypatch.setattr("messagefoundry.auth.totp.verify_totp_step", lambda *_a, **_k: 1)
    code = main(_provision_sqlite(shell))
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code == 1, out
    assert "before this command's first account write landed (IntegrityError)" in out, out
    assert "so no account was written" in out and "partly written account" not in out, out
    assert "delete it: its seed was never stored." in out and _KEEP_ENTRY not in out, out


def test_a_refusal_after_the_pre_check_open_says_what_the_open_may_have_changed(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A key-resolution refusal from the pre-check's reads comes after its open returned, which
    may have migrated the store, so it does not say nothing was written.

    Mutation: pass ``opened=False`` from the pre-check's key-resolution arm."""
    from messagefoundry.auth.service import AuthService
    from messagefoundry.store import base
    from messagefoundry.store.keyprovider import KeyProviderError

    class _Opened:
        async def close(self) -> None:
            return None

    async def opening(*_a: object, **_k: object) -> object:
        return _Opened()

    async def refusing(*_a: object, **_k: object) -> object:
        raise KeyProviderError("synthetic key service refusal in a read")

    monkeypatch.setattr(base, "open_store", opening)
    monkeypatch.setattr(AuthService, "provision_refusal", refusing)
    out = _run(_provision(_settings(shell, "sqlserver", "auto")), capsys)
    assert "synthetic key service refusal in a read" in out, out
    assert _OWN_WRITES in out and _RCSI in out, out
    assert "nothing was written" not in out.lower(), out


def test_an_open_that_names_no_step_still_never_says_nothing_was_written() -> None:
    """Where the list names nothing, the text says the open's own steps may have written; a keyed
    open names the genesis record it may write to an empty chain.

    Mutation: return ``None`` from ``_open_steps_left_behind`` for an empty list again."""
    from messagefoundry.__main__ import (
        _open_refusal_left_behind,
        _open_steps_left_behind,
        _UnauditableWrite,
    )
    from messagefoundry.config.settings import SchemaManagement, StoreBackend, StoreSettings

    store = StoreSettings(
        backend=StoreBackend.POSTGRES,
        server="127.0.0.1",
        database="mefor",
        username="mefor",
        schema_management=SchemaManagement.EXTERNAL,
        cipher_provider="vault_transit",
    )
    assert _MAY_HAVE_WRITTEN in _open_steps_left_behind(store, keyed=False, returned=True)
    assert _MAY_HAVE_CHANGED in _open_steps_left_behind(store, keyed=False)
    keyed = _open_steps_left_behind(store, keyed=True)
    assert "the audit chain's genesis record" in keyed and "salt record" not in keyed, keyed
    # A refused audit row of the command's own follows a full open too.
    assert _open_refusal_left_behind(_UnauditableWrite("synthetic"), store) is not None


def test_admin_reset_totp_unauditable_write_says_what_the_open_may_have_changed(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``_UnauditableWrite`` follows a full open in admin-reset-totp too.

    Mutation: return ``None`` from ``_open_refusal_left_behind`` for ``_UnauditableWrite``."""
    from messagefoundry.__main__ import _UnauditableWrite

    _open_refuses_with(monkeypatch, _UnauditableWrite("synthetic unauditable write"))
    settings = _settings(shell, "sqlserver", "auto")
    out = _run(["admin-reset-totp", "--username", "ops", "--service-config", str(settings)], capsys)
    assert "synthetic unauditable write" in out, out
    assert _OWN_WRITES in out and "nothing was written" not in out.lower(), out


# Manager follow-up on round-9210f623f2 findings 1 to 4 (BACKLOG #5067).


@pytest.mark.parametrize("wrote", [True, False], ids=["write-started", "before-the-write"])
def test_a_locked_store_after_the_write_open_is_no_cannot_open(
    wrote: bool, shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A "database is locked" from the service, after the write's open returned, is no "cannot
    open the store": once the write started it says so and to keep the entry; before it, to delete
    it. Exit 2, as main exited on this arm.

    Mutation: send that arm to ``_emit_store_open_error`` again; it then says cannot open."""
    _service_raises(monkeypatch, sqlite3.OperationalError("database is locked"), wrote=wrote)
    # Exit 2, as main exited on this arm.
    out = _run(_provision_sqlite(shell), capsys)
    assert "the store failed after it opened (OperationalError)" in out, out
    assert "cannot open the store" not in out, out
    if wrote:
        assert "The write had started" in out and _KEEP_ENTRY in out, out
    else:
        assert _UNUSED_ENTRY in out and _OWN_WRITES in out, out


def test_a_transit_keyed_open_names_the_genesis_record(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Under ``vault_transit`` with no local key the store is keyed in Vault, so a refusal after
    the pre-check's open names the genesis record a keyed open may write.

    Mutation: read "keyed" from ``_store_key_configured`` alone again."""
    from messagefoundry.__main__ import _open_is_keyed, _opened_left_behind
    from messagefoundry.config.settings import ServiceSettings, StoreSettings
    from messagefoundry.store.keyprovider import KeyProviderError

    transit = ServiceSettings(
        store=StoreSettings(path="synthetic.db", cipher_provider="vault_transit")
    )
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    assert _open_is_keyed(transit)
    left = _opened_left_behind(
        KeyProviderError("synthetic"), transit.store, keyed=_open_is_keyed(transit)
    )
    assert "the audit chain's genesis record" in left, left


# Manager rulings on round-d8699b00a1 (BACKLOG #5067).


def test_a_cipher_refusal_at_the_open_asserts_no_write(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A cipher refusal the open raised may come before it connects (the cipher build), so the
    text says the open may or may not have reached its writing steps and names a change only as a
    possibility.

    Mutation: word the class-inferred text as "may already have changed" again."""
    from messagefoundry.store.crypto import CipherError

    _open_refuses_with(monkeypatch, CipherError("synthetic cipher build refusal"))
    out = _run(_provision(_settings(shell, "sqlserver", "auto")), capsys)
    assert _MAY_OR_MAY_NOT in out and "if it did, it may have changed at least" in out, out
    assert "may already have changed" not in out, out


def test_the_create_open_s_own_database_error_names_the_shown_entry(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The write's create open raising a ``sqlite3.DatabaseError`` itself, after the key was
    shown, says to delete the entry, and exits 2 as main did.

    Mutation: send that case to ``_emit_store_open_error`` again; the advice is then missing."""
    from messagefoundry import __main__ as cli
    from messagefoundry.store import base

    async def opening(*_args: object, create: bool = False, **_kwargs: object) -> object:
        if not create:
            raise base.StoreNotFoundError("synthetic: no store yet")
        raise sqlite3.OperationalError("unable to open database file")

    monkeypatch.setattr(base, "open_store", opening)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: _PASSWORD)
    monkeypatch.setattr(
        cli, "_enrol_totp_at_terminal", lambda **_k: ("JBSWY3DPEHPK3PXP", "123456", 0.0)
    )
    out = _run(_provision_sqlite(shell), capsys)
    assert "cannot open the store at" in out and "unable to open database file" in out, out
    assert _UNUSED_ENTRY in out, out


def test_a_close_that_fails_after_a_committed_provision_keeps_the_result(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The store closes quietly once the run has its result, so a close that fails after the
    grant committed still shows the recovery codes and sends the administrator_granted page, and
    the run exits 0 with a warning.

    Mutation: close with a bare ``await store.close()`` in ``run()`` again; the run then fails."""
    from messagefoundry import __main__ as cli
    from messagefoundry.store.store import MessageStore

    real_close = MessageStore.close
    shown: list[object] = []
    paged: list[str] = []

    async def failing_close(self: MessageStore) -> None:
        await real_close(self)
        raise sqlite3.OperationalError("synthetic close failure")

    def show(codes: object, **_k: object) -> bool:
        shown.append(codes)
        return True

    async def page(*_a: object, username: str, **_k: object) -> bool:
        paged.append(username)
        return True

    monkeypatch.setattr(MessageStore, "close", failing_close)
    monkeypatch.setattr(cli, "_show_recovery_codes_once", show)
    monkeypatch.setattr(cli, "_raise_offline_administrator_granted", page)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: _PASSWORD)
    monkeypatch.setattr(
        cli, "_enrol_totp_at_terminal", lambda **_k: ("JBSWY3DPEHPK3PXP", "123456", 0.0)
    )
    monkeypatch.setattr("messagefoundry.auth.totp.verify_totp_step", lambda *_a, **_k: 1)
    code = main(_provision_sqlite(shell))
    captured = capsys.readouterr()
    assert code == 0, captured.out + captured.err
    assert shown and paged == ["site-admin"], (shown, paged)
    assert "closing the store failed (OperationalError)" in captured.err


def test_a_totp_refusal_after_the_pre_check_open_says_what_it_may_have_changed(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Over an existing store the pre-check's open returned before the enrolment, so a refused
    enrolment does not say nothing was written; over no store it still does, since the pre-check
    opened nothing.

    Mutation: print the enrolment refusal alone again in provision-admin's arm."""
    from messagefoundry import __main__ as cli
    from messagefoundry.auth.service import AuthService
    from messagefoundry.store import base

    class _Opened:
        async def close(self) -> None:
            return None

    async def opening(*_a: object, **_k: object) -> object:
        return _Opened()

    async def no_refusal(*_a: object, **_k: object) -> None:
        return None

    def refused(**_k: object) -> tuple[str, str, float]:
        raise cli._PasswordEntryRefused("3 codes did not match. Check the app")

    monkeypatch.setattr(base, "open_store", opening)
    monkeypatch.setattr(AuthService, "provision_refusal", no_refusal)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: _PASSWORD)
    monkeypatch.setattr(cli, "_enrol_totp_at_terminal", refused)
    code = main(_provision(_settings(shell, "sqlserver", "auto")))
    captured = capsys.readouterr()
    out = captured.out + captured.err
    assert code != 0, out
    assert "codes did not match" in out and _OWN_WRITES in out, out
    assert "nothing was written" not in out.lower(), out


def test_the_enrolment_refusals_leave_what_was_written_to_their_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_enrol_totp_at_terminal``'s refusals no longer say nothing was written: each caller knows
    whether a store open came first.

    Mutation: say "; nothing was written" again in the empty-code refusal."""
    from messagefoundry import __main__ as cli

    monkeypatch.setattr(cli, "_show_on_terminal", lambda _text: None)
    monkeypatch.setattr(
        sys, "stdin", types.SimpleNamespace(isatty=lambda: True, readline=lambda: "\n")
    )
    with pytest.raises(cli._PasswordEntryRefused) as refused:
        # The real prompt; tests/conftest.py stubs the name for every other test.
        cli._enrol_totp_at_terminal.__wrapped__(username="site-admin", skew_steps=1)  # type: ignore[attr-defined]
    assert str(refused.value) == "empty authenticator code"


def test_a_key_refusal_at_the_write_open_over_an_existing_store_names_the_pre_check_open(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Over an existing store the pre-check's open returned, and may have written, before the
    write's open is refused, so the refusal does not say nothing was written.

    Mutation: pass ``opened=store_opened`` alone from the write's key-resolution arm."""
    from messagefoundry import __main__ as cli
    from messagefoundry.auth.service import AuthService
    from messagefoundry.store import base
    from messagefoundry.store.keyprovider import KeyProviderError

    class _Opened:
        async def close(self) -> None:
            return None

    async def opening(*_a: object, create: bool = False, **_k: object) -> object:
        if create:
            raise KeyProviderError("synthetic key service refusal at the write")
        return _Opened()

    async def no_refusal(*_a: object, **_k: object) -> None:
        return None

    monkeypatch.setattr(base, "open_store", opening)
    monkeypatch.setattr(AuthService, "provision_refusal", no_refusal)
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: _PASSWORD)
    monkeypatch.setattr(
        cli, "_enrol_totp_at_terminal", lambda **_k: ("JBSWY3DPEHPK3PXP", "123456", 0.0)
    )
    out = _run(_provision(_settings(shell, "sqlserver", "auto")), capsys)
    assert "synthetic key service refusal at the write" in out, out
    assert _OWN_WRITES in out and "nothing was written" not in out.lower(), out
    assert _UNUSED_ENTRY in out, out


# PR 3162 hold finding 1 (BACKLOG #5067): the three refusals raised only after a full open.

_CERTAIN = "may already have changed the database before this refusal: at least"
_SALT = "the store's salt record"
_GENESIS = "the audit chain's genesis record"
_ADMIN_ARGV: dict[str, list[str]] = {
    "admin-unlock": ["admin-unlock", "--username", "ops"],
    "admin-set-notify-email": [
        "admin-set-notify-email",
        "--username",
        "ops",
        "--email",
        "ops@example.org",
    ],
    "admin-reset-totp": ["admin-reset-totp", "--username", "ops"],
}


def _after_full_open(kind: str) -> Exception:
    from messagefoundry.__main__ import _KeylessProvisionRefused, _UnauditableWrite
    from messagefoundry.store.base import KeylessAuditChainRefused

    if kind == "unauditable":
        return _UnauditableWrite("synthetic unauditable write")
    if kind == "keyless-provision":
        return _KeylessProvisionRefused("synthetic keyless provision")
    return KeylessAuditChainRefused("mefor", "[store].synthetic")


@pytest.mark.parametrize("kind", ["unauditable", "keyless-provision", "keyless-chain"])
def test_a_refusal_raised_after_a_full_open_says_so_with_certainty(kind: str) -> None:
    """Each of the three is raised only after a full open, so the text says the open may already
    have changed the database, never that it may or may not have reached its writing steps. None
    names the salt record or the genesis record, keyed settings or not: the keyless two follow a
    keyless open, and ``_UnauditableWrite`` refuses only a keyless open, since a keyed handle keys
    its audit rows under the active key when the chain's own key is not held (PR 3162 hold 3
    item 4).

    Mutation: word these three as ``returned=False`` again, or pass ``keyed=True`` for
    ``_UnauditableWrite``."""
    from messagefoundry.__main__ import _opened_left_behind
    from messagefoundry.config.settings import StoreSettings

    store = StoreSettings(path="synthetic.db")
    left = _opened_left_behind(_after_full_open(kind), store, keyed=True)
    assert _CERTAIN in left and _MAY_OR_MAY_NOT not in left, left
    assert _SALT not in left and _GENESIS not in left, left


@pytest.mark.parametrize("command", sorted(_ADMIN_ARGV))
def test_an_unauditable_write_names_no_salt_record_under_keyed_settings(
    command: str, shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """At each admin command's could-not-start arm, an ``_UnauditableWrite`` under settings that
    name a key names no salt record, with the certain wording: it follows only a keyless open
    (PR 3162 hold 3 item 4). The open is replaced, so the refusal is raised from it; the text is
    what is under test.

    Mutation: classify ``_UnauditableWrite`` as keyed again."""
    from messagefoundry import __main__ as cli

    monkeypatch.setattr(cli, "_open_is_keyed", lambda _settings: True)
    _open_refuses_with(monkeypatch, _after_full_open("unauditable"))
    settings = _settings(shell, "sqlserver", "auto")
    out = _run([*_ADMIN_ARGV[command], "--service-config", str(settings)], capsys)
    assert "synthetic unauditable write" in out, out
    assert _CERTAIN in out and _MAY_OR_MAY_NOT not in out, out
    assert _SALT not in out and _GENESIS not in out, out


def test_provision_admin_unauditable_write_at_the_write_names_no_salt_record(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``provision-admin``'s arm for the three after-open refusals names no salt record for an
    ``_UnauditableWrite`` under settings that name a key: it follows only a keyless open (PR 3162
    hold 3 item 4).

    Mutation: classify ``_UnauditableWrite`` as keyed again."""
    from messagefoundry import __main__ as cli

    monkeypatch.setattr(cli, "_open_is_keyed", lambda _settings: True)
    _refused_at_the_write(monkeypatch, "sqlserver", _after_full_open("unauditable"))
    out = _run(_provision(_settings(shell, "sqlserver", "auto")), capsys)
    assert "synthetic unauditable write" in out, out
    assert _CERTAIN in out and _MAY_OR_MAY_NOT not in out, out
    assert _SALT not in out and _GENESIS not in out, out


def test_admin_unlock_keyless_chain_refusal_says_so_with_certainty(
    shell: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A keyless-chain refusal follows a keyless full open: certain wording, no salt or genesis.

    Mutation: word ``KeylessAuditChainRefused`` as ``returned=False`` again."""
    _open_refuses_with(monkeypatch, _after_full_open("keyless-chain"))
    settings = _settings(shell, "sqlserver", "auto")
    out = _run([*_ADMIN_ARGV["admin-unlock"], "--service-config", str(settings)], capsys)
    assert "[store].synthetic" in out, out
    assert _CERTAIN in out and _MAY_OR_MAY_NOT not in out, out
    assert _SALT not in out and _GENESIS not in out, out
