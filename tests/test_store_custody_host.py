# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``host`` key provider wired into the engine (vault BACKLOG #3411, key custody S3 part B3b).

The mint with its recovery-key read-back, the handoff conversion and its crash rule, the store id
pin at every open, the precedence refusals, the account rules and the loosenings, and that no key
material reaches a log, an exception message, argv or the environment on the mint and conversion
paths. A host file is written under user-scope DPAPI on Windows and as a mode-0600 file on Linux,
so the cases that write one run on those two; the decisions run everywhere. The handoff cases are
Windows only."""

from __future__ import annotations

import base64
import functools
import logging
import os
import re
import sys
import types
from collections.abc import Iterator
from pathlib import Path

import pytest

from messagefoundry import custody_posture, restricted_file
from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.custody_posture import KeyCustodyPosture, key_custody_loosenings
from messagefoundry.store import custody, custody_host
from messagefoundry.store.base import open_store
from messagefoundry.store.custody import HostBlob, MasterKey, RecoveryKey, StoreId
from messagefoundry.store.custody_host import (
    HostCustodyMissing,
    HostCustodyRefused,
    foreign_custody_refusal,
    host_store_key,
    load_host_custody,
    mint_host_custody,
    mint_target,
    store_pin,
)
from messagefoundry.store.keyprovider import KeyProviderError
from messagefoundry.store.store import (
    StoreIdPinRefused,
    StorePin,
    audit_genesis_detail,
    parse_audit_genesis_store_id,
    store_pin_problem,
)

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="the handoff is Windows-only")
#: A host file is written on Windows (DPAPI) and Linux (a mode-0600 file) only.
host_file_platforms = pytest.mark.skipif(
    sys.platform not in {"win32", "linux"}, reason="a host file is kept on Windows and Linux only"
)

_RECOVERY_TEXT = re.compile(r"(?:[0-9A-Z]{4}-){13}[0-9A-Z]{4}")


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """No store key or secrets directory from the shell, the engine's own account read as local
    (so a domain-joined box runs the cases), and no observation left for the next test."""
    for name in (
        "MEFOR_STORE_ENCRYPTION_KEY",
        "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED",
        "MEFOR_SECRETS_DIRECTORY",
    ):
        monkeypatch.delenv(name, raising=False)
    if sys.platform == "win32":
        sid = custody_host._engine_sid()
        if sid is not None and sid.upper().startswith("S-1-5-21-"):
            domain = sid.rpartition("-")[0]
            monkeypatch.setattr(restricted_file, "local_account_domain_sid", lambda: domain)
    custody_posture.record_key_custody(None)
    yield
    custody_posture.record_key_custody(None)


@pytest.fixture
def tmp_path(tmp_path: Path) -> Path:
    """pytest's own, skipped on Linux where ``/tmp`` is not a file system a host file may sit on
    (tmpfs, the default on some distributions), as the custody primitives' tests do."""
    if sys.platform == "linux":
        fd = os.open(tmp_path, os.O_RDONLY)
        try:
            magic = restricted_file.linux_file_system_type(fd)
        finally:
            os.close(fd)
        if magic not in restricted_file.LINUX_HOST_FILE_SYSTEMS:
            pytest.skip(f"the temporary directory is on file system type {magic:#010x}")
    return tmp_path


def _settings(tmp_path: Path, **update: object) -> StoreSettings:
    return StoreSettings(path=str(tmp_path / "store.db"), key_provider="host").model_copy(
        update=update
    )


class _Console:
    """A terminal that records what it was shown and enters back whatever ``answer`` returns."""

    def __init__(self, *answers: str | None) -> None:
        self.shown: list[str] = []
        self._answers = list(answers)

    def show(self, text: str) -> None:
        self.shown.append(text)

    def shown_key(self) -> str:
        match = _RECOVERY_TEXT.search("".join(self.shown))
        assert match is not None
        return match.group(0)

    def read(self) -> str:
        answer = self._answers.pop(0) if self._answers else None
        return self.shown_key() if answer is None else answer


def _mint(settings: StoreSettings, console: _Console | None = None) -> HostBlob:
    blob, _path = mint_host_custody(
        settings, service_account=None, enforcing=True, terminal=console or _Console()
    )
    return blob


def _leaks(text: str, blob: HostBlob, recovery: str | None = None) -> list[str]:
    """Each rendering of the blob's key material, or the recovery key text, found in ``text``."""
    material = blob.master_key.material()
    forms = [material.hex(), material.hex().upper(), repr(material)[2:-1], host_store_key(blob)]
    forms.append(base64.b64encode(material).decode())
    if recovery is not None:
        forms += [recovery, recovery.replace("-", "")]
    return [form for form in forms if form in text]


async def _genesis_store_id(settings: StoreSettings, blob: HostBlob) -> bytes | None:
    store = await open_store(settings, custody=blob)
    try:
        row = await store._audit_genesis_row()  # type: ignore[attr-defined]
        assert row is not None
        label = parse_audit_genesis_store_id(row["detail"])
        assert label is not None
        return label.store_id
    finally:
        await store.close()


# --- where the blob lives, and what it may not sit beside ----------------------------------------


def test_the_custody_directory_is_the_secrets_directory_or_the_data_directory(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    assert custody_host.custody_directory(settings, environ={}) == tmp_path.resolve()
    secrets = tmp_path / "secrets"
    assert (
        custody_host.custody_directory(settings, environ={"MEFOR_SECRETS_DIRECTORY": str(secrets)})
        == secrets
    )
    with pytest.raises(HostCustodyRefused, match="absolute path"):
        custody_host.custody_directory(settings, environ={"MEFOR_SECRETS_DIRECTORY": "rel"})
    memory = settings.model_copy(update={"path": ":memory:"})
    assert custody_host.custody_directory(memory, environ={}) is None
    server = settings.model_copy(update={"backend": StoreBackend.POSTGRES})
    assert custody_host.custody_directory(server, environ={}) is None
    with pytest.raises(HostCustodyRefused, match="MEFOR_SECRETS_DIRECTORY"):
        load_host_custody(server, enforcing=True, environ={})


@pytest.mark.parametrize(
    ("update", "environ", "named"),
    [
        ({"encryption_key": "x"}, {}, "MEFOR_STORE_ENCRYPTION_KEY"),
        ({"encryption_key_file": "k.bin"}, {}, r"\[store\].encryption_key_file"),
        ({}, {"MEFOR_STORE_ENCRYPTION_KEY": "x"}, "MEFOR_STORE_ENCRYPTION_KEY"),
        ({}, {"MEFOR_STORE_ENCRYPTION_KEYS_RETIRED": "x"}, "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED"),
        ({"cipher_provider": "vault_transit"}, {}, "cipher_provider"),
    ],
)
def test_a_host_blob_is_never_read_beside_another_key_source(
    tmp_path: Path, update: dict[str, object], environ: dict[str, str], named: str
) -> None:
    settings = _settings(tmp_path, **update)
    with pytest.raises(HostCustodyRefused, match=named):
        load_host_custody(settings, enforcing=True, environ=environ)
    with pytest.raises(HostCustodyRefused, match=named):
        mint_target(settings, service_account=None, enforcing=True, environ=environ)


@pytest.mark.parametrize("name", ["master.key", "handoff.key"])
async def test_a_host_blob_refuses_every_other_key_provider(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_bytes(b"not read")
    settings = _settings(tmp_path, key_provider="auto", encryption_key_file="k.bin")
    refusal = foreign_custody_refusal(settings, environ={})
    assert refusal is not None and name in refusal and "'auto'" in refusal
    with pytest.raises(HostCustodyRefused, match=name):
        await open_store(settings, create=True)
    assert not (tmp_path / "store.db").exists()


def test_no_host_blob_and_no_handoff_names_provision_admin(tmp_path: Path) -> None:
    with pytest.raises(HostCustodyMissing, match="provision-admin"):
        load_host_custody(_settings(tmp_path), enforcing=True, environ={})
    assert isinstance(HostCustodyMissing("x"), KeyProviderError)


# --- the mint -------------------------------------------------------------------------------------


@host_file_platforms
def test_the_mint_shows_the_recovery_key_and_writes_only_once_it_is_entered_back(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    console = _Console()
    blob, path = mint_host_custody(
        settings, service_account=None, enforcing=True, terminal=console, now=lambda: 1_800_000_000
    )
    assert path == tmp_path.resolve() / "master.key"
    assert blob.recovery_proved_at == 1_800_000_000
    assert blob.earlier_store_ids == ()
    assert custody.read_host_file(path) == blob
    # The entry opened the recovery wrap: the key shown is the one the blob was minted with.
    RecoveryKey.parse(console.shown_key())


@host_file_platforms
def test_a_mistyped_entry_is_asked_again_and_a_right_one_then_proves_it(tmp_path: Path) -> None:
    console = _Console("not a key", RecoveryKey.mint().text())  # then the right one
    blob = _mint(_settings(tmp_path), console)
    assert blob.recovery_proved_at is not None
    said = "".join(console.shown)
    assert "Try again" in said and "not the one shown above" in said


@host_file_platforms
def test_a_recovery_key_never_entered_back_writes_nothing(tmp_path: Path) -> None:
    console = _Console("wrong", "wrong", "wrong")
    with pytest.raises(HostCustodyRefused, match="nothing was written"):
        _mint(_settings(tmp_path), console)
    assert not (tmp_path / "master.key").exists()


@host_file_platforms
@pytest.mark.parametrize("name", ["master.key", "handoff.key"])
def test_a_second_mint_over_an_existing_file_is_file_exists(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_bytes(b"there")
    console = _Console()
    with pytest.raises(FileExistsError, match=name):
        _mint(_settings(tmp_path), console)
    assert console.shown == []  # refused before anything was minted or shown


@windows_only
@pytest.mark.parametrize("account", ["Administrators", "*S-1-5-18"])
def test_a_handoff_grantee_the_write_would_refuse_is_refused_before_the_mint(
    tmp_path: Path, account: str
) -> None:
    console = _Console()
    with pytest.raises(HostCustodyRefused, match="no store key was minted"):
        mint_host_custody(
            _settings(tmp_path), service_account=account, enforcing=True, terminal=console
        )
    assert console.shown == []  # nothing minted, nothing shown
    assert not (tmp_path / "handoff.key").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="the handoff is written on Windows")
def test_a_handoff_is_refused_off_windows(tmp_path: Path) -> None:
    with pytest.raises(HostCustodyRefused, match="service user itself"):
        mint_target(_settings(tmp_path), service_account="svc", enforcing=True, environ={})


@host_file_platforms
async def test_no_key_material_reaches_a_log_an_error_argv_or_the_environment_on_the_mint(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    settings = _settings(tmp_path)
    console = _Console("wrong")
    blob = _mint(settings, console)
    recovery = console.shown_key()
    store = await open_store(settings, create=True, custody=blob)
    await store.close()
    # A refused second mint and a refused open, whose texts must carry nothing either.
    errors: list[str] = []
    for attempt in (
        lambda: _mint(settings),
        lambda: load_host_custody(
            settings, enforcing=True, environ={"MEFOR_STORE_ENCRYPTION_KEY": "x"}
        ),
    ):
        try:
            attempt()
        except (FileExistsError, HostCustodyRefused) as exc:
            errors.append(f"{exc!r} {exc}")
    assert len(errors) == 2
    for text in (caplog.text, *errors, " ".join(sys.argv), repr(dict(os.environ)), repr(blob)):
        assert not _leaks(text, blob, recovery)
    # Only the console was shown the recovery key.
    assert recovery in "".join(console.shown)


# --- the store id pin -----------------------------------------------------------------------------


def _genesis(store_id: bytes | None) -> dict[str, object]:
    from messagefoundry.store.crypto import NO_STORE_ID

    return {"detail": audit_genesis_detail("k1", NO_STORE_ID if store_id is None else store_id)}


def test_the_pin_accepts_the_current_and_an_earlier_id_and_refuses_the_rest() -> None:
    current, earlier, other = b"\x01" * 16, b"\x02" * 16, b"\x03" * 16
    pin = StorePin(current, frozenset({current, earlier}))
    assert store_pin_problem(_genesis(current), pin) is None
    assert store_pin_problem(_genesis(earlier), pin) is None
    problem = store_pin_problem(_genesis(other), pin)
    assert problem is not None and other.hex() in problem and "another store" in problem
    assert "names no store id" in (store_pin_problem(_genesis(None), pin) or "")
    assert "no genesis record" in (store_pin_problem(None, pin) or "")
    assert "not a genesis record" in (store_pin_problem({"detail": "{}"}, pin) or "")
    assert "refuses" in (
        store_pin_problem({"detail": '{"genesis": 1, "key_id": "k", "store_id": "zz"}'}, pin) or ""
    )


def test_store_pin_names_every_id_the_blob_holds() -> None:
    blob = HostBlob(MasterKey(bytes(32)), StoreId(b"\x01" * 16), (StoreId(b"\x02" * 16),))
    assert store_pin(blob) == StorePin(b"\x01" * 16, frozenset({b"\x01" * 16, b"\x02" * 16}))


@host_file_platforms
async def test_a_new_store_records_the_blob_store_id_and_every_open_checks_it(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    blob = _mint(settings)
    store = await open_store(settings, create=True, custody=blob)
    await store.close()
    # Reopened from the host file, as every later command and start does.
    assert await _genesis_store_id(settings, blob) == blob.store_id.value
    store = await open_store(settings)
    await store.close()
    assert custody_posture.observed_key_custody() == KeyCustodyPosture(recovery_key_proved=True)


@host_file_platforms
async def test_a_host_blob_of_another_store_is_refused_at_open(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    blob = _mint(settings)
    store = await open_store(settings, create=True, custody=blob)
    await store.close()
    # The same key under another store id: the blob is not this store's, whatever key it holds.
    stranger = HostBlob(blob.master_key, StoreId.mint(), (), blob.recovery_proved_at)
    with pytest.raises(StoreIdPinRefused, match="belongs to another store") as excinfo:
        await open_store(settings, custody=stranger)
    assert isinstance(excinfo.value, KeyProviderError)
    assert not _leaks(str(excinfo.value), blob)
    # A blob that carries the store's id as an earlier one (a restore under a new id) opens it.
    restored = HostBlob(blob.master_key, StoreId.mint(), (blob.store_id,), blob.recovery_proved_at)
    store = await open_store(settings, custody=restored)
    await store.close()


@host_file_platforms
async def test_a_store_created_without_a_store_id_is_refused_under_the_host_provider(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    blob = _mint(settings)
    # A store created keyed but under another provider has no genesis record naming a store id.
    auto = settings.model_copy(
        update={"key_provider": "auto", "encryption_key": host_store_key(blob)}
    )
    (tmp_path / "master.key").rename(tmp_path / "aside.key")
    store = await open_store(auto, create=True)
    await store.close()
    (tmp_path / "aside.key").rename(tmp_path / "master.key")
    with pytest.raises(StoreIdPinRefused, match="names no store id"):
        await open_store(settings)


# --- the account ----------------------------------------------------------------------------------


def test_a_non_local_account_is_refused_under_enforce_and_named_outside_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(restricted_file, "local_account_domain_sid", lambda: "S-1-5-21-1-2-3")
    domain_user = lambda: "S-1-5-21-9-9-9-1104"  # noqa: E731
    with pytest.raises(HostCustodyRefused, match="enforcement = enforce refuses it"):
        custody_host.non_local_account_reading(enforcing=True, sid_of=domain_user)
    reading = custody_host.non_local_account_reading(enforcing=False, sid_of=domain_user)
    assert reading is not None and "not an account of this host" in reading
    for local in ("S-1-5-21-1-2-3-1001", "S-1-5-80-1-2-3-4-5"):
        assert (
            custody_host.non_local_account_reading(
                enforcing=True, sid_of=functools.partial(str, local)
            )
            is None
        )
    with pytest.raises(HostCustodyRefused, match="could not be read"):
        custody_host.non_local_account_reading(enforcing=True, sid_of=lambda: None)


def test_the_non_local_decision() -> None:
    problem = restricted_file.custody_non_local_account_problem
    assert problem("S-1-5-80-1-2-3-4-5", None) is None
    assert problem("S-1-5-21-1-2-3-500", "S-1-5-21-1-2-3") is None
    assert problem("s-1-5-21-1-2-3-500", "S-1-5-21-1-2-3") is None
    assert problem("S-1-5-21-1-2-4-500", "S-1-5-21-1-2-3") is not None  # another domain
    assert problem("S-1-5-21-1-2-3-500", None) is not None  # the host's own domain unread
    assert problem("S-1-5-82-1-2", "S-1-5-21-1-2-3") is not None


def test_a_linux_engine_as_root_or_nobody_keeps_no_custody_file() -> None:
    decide = custody._posix_engine_account_problem
    assert "root" in (decide(0, "root") or "")
    assert "nobody" in (decide(65534, None) or "")
    assert "nobody" in (decide(4242, "nobody") or "")
    assert decide(1001, "mefor") is None


@pytest.mark.skipif(sys.platform != "linux", reason="the Linux account check")
def test_a_linux_host_file_is_not_written_or_read_as_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    blob = HostBlob(MasterKey(bytes(32)), StoreId(b"\x01" * 16))
    with pytest.raises(custody.CustodyError, match="runs as root"):
        custody.write_host_file(tmp_path / "master.key", blob)
    with pytest.raises(custody.CustodyError, match="runs as root"):
        custody.read_host_file(tmp_path / "master.key")


# --- the loosenings -------------------------------------------------------------------------------


def test_the_custody_loosenings() -> None:
    def names(**kw: object) -> list[str]:
        return [n for n, _ in key_custody_loosenings(**kw)]  # type: ignore[arg-type]

    assert names(key_provider="vault", cipher_provider="aesgcm", observed=None) == [
        "store_id_not_pinned"
    ]
    assert names(key_provider="auto", cipher_provider="vault_transit", observed=None) == [
        "store_id_not_pinned"
    ]
    assert names(key_provider="auto", cipher_provider="aesgcm", observed=None) == []
    unproved = KeyCustodyPosture(recovery_key_proved=False, non_local_account="a domain user")
    assert names(key_provider="host", cipher_provider="aesgcm", observed=unproved) == [
        "recovery_key_unproved",
        "key_custody_non_local_account",
    ]
    # An observation from a host blob says nothing about a store under another provider.
    assert names(key_provider="auto", cipher_provider="aesgcm", observed=unproved) == []
    proved = KeyCustodyPosture(recovery_key_proved=True)
    assert names(key_provider="host", cipher_provider="aesgcm", observed=proved) == []


@host_file_platforms
async def test_an_unproved_blob_is_observed_at_open(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    blob = _mint(settings)
    store = await open_store(settings, create=True, custody=blob)
    await store.close()
    unproved = HostBlob(blob.master_key, blob.store_id)
    (tmp_path / "master.key").unlink()
    custody.write_host_file(tmp_path / "master.key", unproved)
    store = await open_store(settings, posture=HopPosture(enforcing=False))
    await store.close()
    observed = custody_posture.observed_key_custody()
    assert observed is not None and not observed.recovery_key_proved


# --- the handoff: first-start conversion and the crash rule (Windows) -----------------------------


def _handoff(path: Path, blob: HostBlob) -> None:
    """A handoff as ``write_handoff_file`` writes it, but for and owned by this account, which any
    token may make, so these cases run off-admin too (the custody tests' own helper)."""
    from messagefoundry.secrets_dpapi import dpapi_protect

    restricted_file.write_restricted_file(
        path,
        dpapi_protect(blob.serialize(), machine_scope=True),
        read_grants=[f"*{custody_host._engine_sid()}"],
        creator_access=False,
        read_delete=True,
    )


def _proved_blob() -> HostBlob:
    return HostBlob(MasterKey.mint(), StoreId.mint(), (), 1_800_000_000)


@windows_only
async def test_the_first_start_converts_the_handoff_and_deletes_it(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    settings = _settings(tmp_path)
    blob = _proved_blob()
    _handoff(tmp_path / "handoff.key", blob)
    store = await open_store(settings, create=True)
    await store.close()
    assert not (tmp_path / "handoff.key").exists()
    assert custody.read_host_file(tmp_path / "master.key") == blob
    assert await _genesis_store_id(settings, blob) == blob.store_id.value
    assert not _leaks(caplog.text, blob)


@windows_only
async def test_a_read_only_open_does_not_convert_a_handoff(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _handoff(tmp_path / "handoff.key", _proved_blob())
    with pytest.raises(HostCustodyRefused, match="has not been converted"):
        load_host_custody(settings, enforcing=True, convert=False, environ={})
    assert (tmp_path / "handoff.key").exists() and not (tmp_path / "master.key").exists()


@windows_only
def test_a_handoff_that_cannot_be_converted_refuses_and_stays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blob = _proved_blob()
    _handoff(tmp_path / "handoff.key", blob)

    def _refuse(path: Path, written: HostBlob) -> None:
        raise custody.CustodyError("the host file was not written: a stand-in refusal")

    monkeypatch.setattr(custody, "write_host_file", _refuse)
    with pytest.raises(HostCustodyRefused, match="rather than run from it") as excinfo:
        load_host_custody(_settings(tmp_path), enforcing=True, environ={})
    assert (tmp_path / "handoff.key").exists() and not (tmp_path / "master.key").exists()
    assert not _leaks(f"{excinfo.value!r} {excinfo.value}", blob)


@windows_only
def test_the_crash_rule_deletes_a_handoff_naming_the_host_file_store_id(tmp_path: Path) -> None:
    blob = _proved_blob()
    custody.write_host_file(tmp_path / "master.key", blob)
    _handoff(tmp_path / "handoff.key", blob)
    assert load_host_custody(_settings(tmp_path), enforcing=True, environ={}) == blob
    assert not (tmp_path / "handoff.key").exists()


@windows_only
def test_the_crash_rule_refuses_a_handoff_naming_another_store(tmp_path: Path) -> None:
    blob = _proved_blob()
    custody.write_host_file(tmp_path / "master.key", blob)
    other = _proved_blob()
    _handoff(tmp_path / "handoff.key", other)
    with pytest.raises(HostCustodyRefused, match="not this store's") as excinfo:
        load_host_custody(_settings(tmp_path), enforcing=True, environ={})
    assert (tmp_path / "handoff.key").exists()
    assert not _leaks(str(excinfo.value), blob) and not _leaks(str(excinfo.value), other)


# --- provision-admin --------------------------------------------------------------------------


@host_file_platforms
def test_provision_admin_mints_the_key_and_creates_the_store_pinned_to_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import asyncio

    from messagefoundry import __main__ as cli
    from messagefoundry.__main__ import main

    monkeypatch.chdir(tmp_path)
    (tmp_path / "messagefoundry.toml").write_text('[store]\nkey_provider = "host"\n')
    password = "a long and unremarkable passphrase 7"
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    queued = [password, password]
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: queued.pop(0))
    consoles: list[_Console] = []

    def _console() -> _Console:
        consoles.append(_Console("wrong"))
        return consoles[-1]

    monkeypatch.setattr(cli, "_RecoveryKeyConsole", _console)
    db = tmp_path / "provision.db"
    argv = ["provision-admin", "--username", "site-admin", "--email", "ops@example.invalid"]
    assert main([*argv, "--db", str(db)]) == 0
    captured = capsys.readouterr()
    blob = custody.read_host_file(tmp_path / "master.key")
    recovery = consoles[0].shown_key()
    assert not _leaks(captured.out + captured.err, blob, recovery)
    settings = _settings(tmp_path).model_copy(update={"path": str(db)})
    assert asyncio.run(_genesis_store_id(settings, blob)) == blob.store_id.value
    # The store exists, so a second run mints nothing and asks no recovery key.
    assert main([*argv, "--db", str(db), "--service-account", "x"]) != 0
    assert len(consoles) == 1
