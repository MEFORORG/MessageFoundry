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
from typing import Any

import pytest

from messagefoundry import custody_posture, restricted_file
from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.custody_posture import KeyCustodyPosture, key_custody_loosenings
from messagefoundry.store import custody, custody_host
from messagefoundry.store.base import Store, open_store
from messagefoundry.store.custody import (
    HostBlob,
    MasterKey,
    RecoveryKey,
    StoreId,
    unwrap_master_key,
    wrap_master_key,
)
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


#: The wrap each blob ``_mint`` made was minted with, by store id, for the store it creates.
_WRAPS: dict[bytes, bytes] = {}


def _mint(settings: StoreSettings, console: _Console | None = None) -> HostBlob:
    minted = mint_host_custody(
        settings, service_account=None, enforcing=True, terminal=console or _Console()
    )
    _WRAPS[minted.blob.store_id.value] = minted.recovery_wrap
    return minted.blob


async def _create(settings: StoreSettings, blob: HostBlob) -> None:
    """Create the store a minted blob is for, as provision-admin does, with its recovery wrap."""
    store = await open_store(
        settings, create=True, custody=blob, recovery_wrap=_WRAPS[blob.store_id.value]
    )
    await store.close()


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
    # PR 2804 sixth hold: the setting-only fix first, then the fallback, which leaves the file.
    assert f"set [store].key_provider = 'host' and {_KEY_SETTINGS_OUT}" in refusal, refusal
    assert "Keep a copy of each key setting's value first" in refusal, refusal
    assert not _advises_changing(refusal, allowed=(_KEY_SETTINGS_OUT,)), refusal
    assert custody_host.keep_the_key_step(settings, new_store=False) in refusal, refusal
    assert "mints this store's key" not in refusal, refusal  # only the host provider mints
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
    blob, path, wrap = mint_host_custody(
        settings, service_account=None, enforcing=True, terminal=console, now=lambda: 1_800_000_000
    )
    assert path == tmp_path.resolve() / "master.key"
    assert blob.recovery_proved_at == 1_800_000_000
    assert blob.earlier_store_ids == ()
    assert custody.read_host_file(path) == blob
    # The entry opened the recovery wrap: the key shown is the one the blob was minted with.
    assert unwrap_master_key(wrap, RecoveryKey.parse(console.shown_key()), blob.store_id) == (
        blob.master_key
    )
    # The screen was cleared after the copy was confirmed and before the key was asked for.
    said = "".join(console.shown)
    assert said.index(console.shown_key()) < said.index("\x1b[2J") < said.rindex("Enter the")


@host_file_platforms
def test_a_mistyped_entry_is_asked_again_and_a_right_one_then_proves_it(tmp_path: Path) -> None:
    console = _Console("", "not a key", RecoveryKey.mint().text())  # then the right one
    blob = _mint(_settings(tmp_path), console)
    assert blob.recovery_proved_at is not None
    said = "".join(console.shown)
    assert "Try again" in said and "not the one shown above" in said


@host_file_platforms
def test_a_recovery_key_never_entered_back_writes_nothing(tmp_path: Path) -> None:
    console = _Console("", "wrong", "wrong", "wrong")
    with pytest.raises(HostCustodyRefused, match="nothing was written"):
        _mint(_settings(tmp_path), console)
    assert not (tmp_path / "master.key").exists()


@host_file_platforms
@pytest.mark.parametrize("name", ["master.key", "handoff.key"])
def test_a_second_mint_over_an_existing_file_is_file_exists(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_bytes(b"there")
    console = _Console()
    with pytest.raises(FileExistsError, match=name) as refused:
        _mint(_settings(tmp_path), console)
    assert console.shown == []  # refused before anything was minted or shown
    # PR 2804 fourth hold, item 5: a way on that keeps the file, which may be another store's key.
    text = str(refused.value)
    assert not _advises_changing(text) and "leaves it in place" in text, text
    assert custody_host.keep_the_key_step(_settings(tmp_path), new_store=False) in text, text


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
    console = _Console("", "wrong")
    blob = _mint(settings, console)
    recovery = console.shown_key()
    await _create(settings, blob)
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
    await _create(settings, blob)
    # Reopened from the host file, as every later command and start does.
    assert await _genesis_store_id(settings, blob) == blob.store_id.value
    store = await open_store(settings)
    await store.close()
    assert custody_posture.observed_key_custody() == KeyCustodyPosture(recovery_key_proved=True)


@host_file_platforms
async def test_a_host_blob_of_another_store_is_refused_at_open(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    blob = _mint(settings)
    await _create(settings, blob)
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
    await _create(settings, blob)
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
    # provision-admin creates the store with the blob it minted, then writes the handoff.
    _WRAPS[blob.store_id.value] = wrap_master_key(
        blob.master_key, RecoveryKey.mint(), blob.store_id
    )
    await _create(settings, blob)
    _handoff(tmp_path / "handoff.key", blob)
    store = await open_store(settings)  # the service's first start
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
    # PR 2804 sixth hold: the stray handoff moves out of the custody directory, so the secrets
    # directory's name check never sees it, to a path that does not exist yet, so it overwrites
    # nothing. The guard allows that one sentence and nothing else.
    text = str(excinfo.value)
    move = f"move it out of {tmp_path} to a path outside that directory that does not exist yet"
    assert move in text and ".aside" not in text, text
    # A move across volumes is a copy, which takes the destination's access list.
    assert "on the same volume and in a directory readable by no one but administrators" in text
    assert not _advises_changing(text, allowed=(move,)), text
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
        consoles.append(_Console("", "wrong"))
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


# --- review round one: the wrap, an unauthenticated genesis, read-only, conversion, resolve -------


@host_file_platforms
async def test_the_new_store_keeps_the_recovery_wrap_the_recovery_key_opens(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    console = _Console()
    blob = _mint(settings, console)
    await _create(settings, blob)
    store = await open_store(settings)
    try:
        row = await store._audit_genesis_row()  # type: ignore[attr-defined]
    finally:
        await store.close()
    label = parse_audit_genesis_store_id(row["detail"])
    assert label is not None and label.recovery_wrap is not None
    opened = unwrap_master_key(
        label.recovery_wrap, RecoveryKey.parse(console.shown_key()), blob.store_id
    )
    assert opened == blob.master_key


def test_a_genesis_recovery_wrap_is_held_to_its_shape() -> None:
    from messagefoundry.store import store as store_module

    sid = b"\x01" * 16
    wrap = b"\x02" * custody._WRAP_BYTES
    assert store_module._AUDIT_RECOVERY_WRAP_HEX.pattern == f"[0-9a-f]{{{2 * custody._WRAP_BYTES}}}"
    label = parse_audit_genesis_store_id(audit_genesis_detail("k", sid, wrap))
    assert label is not None and label.recovery_wrap == wrap and label.store_id == sid
    with pytest.raises(ValueError, match="65 bytes"):
        audit_genesis_detail("k", sid, wrap[:-1])
    with pytest.raises(ValueError, match="beside a store id"):
        audit_genesis_detail("k", b"", wrap)
    good = audit_genesis_detail("k", sid, wrap)
    for planted in (
        good.replace(wrap.hex(), "zz"),
        good.replace(f', "store_id": "{sid.hex()}"', ""),
    ):
        parsed = parse_audit_genesis_store_id(planted)
        assert parsed is not None and parsed.refused, planted


@host_file_platforms
async def test_a_genesis_record_the_blob_key_does_not_verify_is_refused(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    blob = _mint(settings)
    await _create(settings, blob)
    # The store's id under another key: the record names the id, and is not this key's.
    impostor = HostBlob(MasterKey.mint(), blob.store_id, (), blob.recovery_proved_at)
    with pytest.raises(StoreIdPinRefused, match="does not verify"):
        await open_store(settings, custody=impostor)


def test_every_key_resolve_refuses_a_host_blob_beside_another_provider(tmp_path: Path) -> None:
    from messagefoundry.store.keyprovider import resolve_key_provider

    (tmp_path / "master.key").write_bytes(b"not read")
    settings = _settings(tmp_path, key_provider="env", encryption_key="x")
    with pytest.raises(HostCustodyRefused, match="master.key"):
        resolve_key_provider(settings)


@windows_only
def test_a_read_that_may_not_convert_leaves_a_handoff_beside_the_host_file(
    tmp_path: Path,
) -> None:
    blob = _proved_blob()
    custody.write_host_file(tmp_path / "master.key", blob)
    _handoff(tmp_path / "handoff.key", _proved_blob())  # another store's: refused if settled
    assert load_host_custody(_settings(tmp_path), enforcing=True, convert=False, environ={}) == blob
    assert (tmp_path / "handoff.key").exists()


@windows_only
def test_the_crash_rule_refuses_a_handoff_of_this_store_under_another_key(tmp_path: Path) -> None:
    blob = _proved_blob()
    custody.write_host_file(tmp_path / "master.key", blob)
    _handoff(tmp_path / "handoff.key", HostBlob(MasterKey.mint(), blob.store_id))
    with pytest.raises(HostCustodyRefused, match="another key"):
        load_host_custody(_settings(tmp_path), enforcing=True, environ={})
    assert (tmp_path / "handoff.key").exists()


@windows_only
def test_a_conversion_whose_read_back_differs_removes_the_host_file_it_wrote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _handoff(tmp_path / "handoff.key", _proved_blob())
    calls: list[Path] = []

    def _read(path: Path) -> HostBlob:
        calls.append(path)
        if len(calls) == 1:  # the open's first look finds no host file
            raise FileNotFoundError(path)
        return _proved_blob()  # the read-back after the write opens to another blob

    monkeypatch.setattr(custody, "read_host_file", _read)
    with pytest.raises(HostCustodyRefused, match="does not open to the handoff"):
        load_host_custody(_settings(tmp_path), enforcing=True, environ={})
    assert (tmp_path / "handoff.key").exists() and not (tmp_path / "master.key").exists()


def test_no_blob_is_reported_missing_before_the_account_is_judged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _refuse(**kw: object) -> None:
        raise AssertionError("the account was judged before the files were looked for")

    monkeypatch.setattr(custody_host, "non_local_account_reading", _refuse)
    with pytest.raises(HostCustodyMissing):
        load_host_custody(_settings(tmp_path), enforcing=True, environ={})


# --- review round two -----------------------------------------------------------------------------


@windows_only
def test_a_shared_account_is_refused_before_the_mint_with_its_own_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(custody_host, "_engine_sid", lambda: "S-1-5-18")
    console = _Console()
    with pytest.raises(HostCustodyRefused, match="many services share") as excinfo:
        _mint(_settings(tmp_path), console)
    assert "domain" not in str(excinfo.value)
    assert console.shown == []


@host_file_platforms
async def test_an_empty_store_file_is_built_under_the_host_provider(tmp_path: Path) -> None:
    # The pin is checked once the schema is in place, so a file the open must still build opens.
    settings = _settings(tmp_path)
    (tmp_path / "store.db").write_bytes(b"")
    blob = _mint(settings)
    await _create(settings, blob)
    assert await _genesis_store_id(settings, blob) == blob.store_id.value


# --- held-PR repair round (PR 2804): unrepaired items 1, 2, 3, 9 and 10 ---------------------------


@host_file_platforms
async def test_a_chain_is_never_started_without_the_recovery_wrap(tmp_path: Path) -> None:
    # Item 1: a store whose minting create-open failed before its genesis record would otherwise be
    # started by the next open with no wrap, while the blob still says the recovery key is proved.
    settings = _settings(tmp_path)
    blob = _mint(settings)
    with pytest.raises(StoreIdPinRefused, match="recovery wrap"):
        await open_store(settings, create=True, custody=blob)  # no recovery_wrap
    with pytest.raises(StoreIdPinRefused, match="recovery wrap"):
        await open_store(settings)  # a later start, from the host file
    # A read-only open writes nothing, so it may read the empty chain.
    store = await open_store(settings, read_only=True)
    try:
        assert await store._audit_genesis_row() is None  # type: ignore[attr-defined]
    finally:
        await store.close()


async def test_a_store_with_data_and_an_empty_chain_is_not_absent(tmp_path: Path) -> None:
    # Item 2: provision-admin's server probe read an empty audit chain as no store at all.
    from messagefoundry.store.custody_host import store_holds_data

    settings = StoreSettings(path=str(tmp_path / "keyless.db"))
    store = await open_store(settings, create=True, keyless_chain_refusal=None)
    try:
        assert not await store_holds_data(store)
        await store.create_user(
            user_id="u1",
            username="operator",
            auth_provider="local",
            password_generated=False,
            audits=(),
        )
        assert await store_holds_data(store)
    finally:
        await store.close()


async def _keyless_store(path: Path) -> Store:
    return await open_store(StoreSettings(path=str(path)), create=True, keyless_chain_refusal=None)


async def test_a_connection_event_alone_makes_a_store_hold_data(tmp_path: Path) -> None:
    # PR 2804 hold (A): the probe counted messages, message events, audit rows and users only, so
    # a store with an empty chain and data in any other table read as absent.
    from messagefoundry.store.custody_host import store_holds_data

    store = await _keyless_store(tmp_path / "keyless.db")
    try:
        assert not await store_holds_data(store)
        await store.record_connection_event(
            connection="IB_TEST_ADT", transport="mllp", direction="inbound", kind="established"
        )
        assert await store_holds_data(store)
    finally:
        await store.close()


async def test_a_row_in_a_table_the_store_never_made_holds_data(tmp_path: Path) -> None:
    # PR 2804 hold (A): the tables are read from the database's own catalog, so a table this build
    # does not know of still counts, and a table added later cannot be missed by a hand-kept list.
    import sqlite3

    from messagefoundry.store.custody_host import store_holds_data

    path = tmp_path / "keyless.db"
    store = await _keyless_store(path)
    await store.close()
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE added_later (x INTEGER)")
        conn.execute("INSERT INTO added_later (x) VALUES (1)")
    conn.close()
    store = await open_store(StoreSettings(path=str(path)), keyless_chain_refusal=None)
    try:
        occupancy = await store.table_occupancy()
        assert occupancy["added_later"] is True
        assert await store_holds_data(store)
    finally:
        await store.close()


async def test_a_fresh_store_holds_only_the_bookkeeping_it_seeds(tmp_path: Path) -> None:
    # The negative arm of the census: every table but the named bookkeeping is empty on a store
    # nothing has used, so the exclusion list is what keeps a fresh store absent.
    from messagefoundry.store.custody_host import SCHEMA_BOOKKEEPING_TABLES

    store = await _keyless_store(tmp_path / "keyless.db")
    try:
        occupancy = await store.table_occupancy()
    finally:
        await store.close()
    assert {"messages", "message_events", "audit_log", "users", "connection_event"} <= set(
        occupancy
    )
    assert {name for name, held in occupancy.items() if held} <= SCHEMA_BOOKKEEPING_TABLES


def test_every_row_a_schema_build_seeds_is_named_bookkeeping() -> None:
    # A VALUES seed added to any backend's schema batch would make every fresh server store read
    # as holding data, and refuse every mint, so each seeded table must be bookkeeping or have its
    # seed filtered by the census. The control is that the pattern finds the one seed every backend
    # has. It reads only `INSERT ... (cols) VALUES` in the batch, not a seed written elsewhere.
    from messagefoundry.store import postgres, sqlserver
    from messagefoundry.store import store as sqlite_store
    from messagefoundry.store.base import SCHEMA_SEED_FILTERS
    from messagefoundry.store.custody_host import SCHEMA_BOOKKEEPING_TABLES

    seed = re.compile(r"\bINSERT\s+(?:OR\s+\w+\s+)?INTO\s+(\w+)\s*\([^)]*\)\s*VALUES\b", re.I)
    for ddl in (postgres._SCHEMA, sqlserver._SCHEMA, [sqlite_store._SCHEMA]):
        seeded = {table for statement in ddl for table in seed.findall(statement)}
        assert "global_session_epoch" in seeded
        assert seeded <= SCHEMA_BOOKKEEPING_TABLES | set(SCHEMA_SEED_FILTERS)


def _seeded(path: Path, *statements: str) -> None:
    """Run ``statements`` on the SQLite file at ``path`` directly, outside the store."""
    import sqlite3

    conn = sqlite3.connect(path)
    try:
        with conn:
            for statement in statements:
                conn.execute(statement)
    finally:
        conn.close()


async def _holds_data(path: Path) -> bool:
    from messagefoundry.store.custody_host import store_holds_data

    store = await open_store(StoreSettings(path=str(path)), keyless_chain_refusal=None)
    try:
        return await store_holds_data(store)
    finally:
        await store.close()


async def test_a_virtual_table_whose_module_is_not_loaded_is_skipped(tmp_path: Path) -> None:
    # PR 2804 hold, finding 13: probing a virtual table raised "no such module". A virtual table
    # and its shadow tables belong to a module, not to the store, so the census skips them.
    path = tmp_path / "keyless.db"
    await (await _keyless_store(path)).close()
    _seeded(
        path,
        "PRAGMA writable_schema = ON",
        "INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql) VALUES"
        " ('table', 'vt', 'vt', 0, 'CREATE VIRTUAL TABLE vt USING no_such_module(x)')",
    )
    assert not await _holds_data(path)


async def test_an_exact_case_lookalike_of_a_bookkeeping_table_holds_data(tmp_path: Path) -> None:
    # PR 2804 hold, finding 4: names were compared casefolded, so U+017F (long s), which casefolds
    # to "s", made this table read as schema_meta and its row as bookkeeping.
    path = tmp_path / "keyless.db"
    await (await _keyless_store(path)).close()
    _seeded(
        path,
        'CREATE TABLE "\u017fchema_meta" (x INTEGER)',
        'INSERT INTO "\u017fchema_meta" (x) VALUES (1)',
    )
    assert await _holds_data(path)


async def test_a_census_whose_core_table_differs_in_case_holds_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # PR 2804 hold, finding 4: "USERS" is not the store's users table on a case-sensitive server,
    # so a census that lists only it did not see the store's own.
    from messagefoundry.store.custody_host import store_holds_data

    store = await _keyless_store(tmp_path / "keyless.db")
    try:

        async def _lookalike() -> dict[str, bool]:
            return {"messages": False, "message_events": False, "audit_log": False, "USERS": False}

        monkeypatch.setattr(store, "table_occupancy", _lookalike)
        assert await store_holds_data(store)
    finally:
        monkeypatch.undo()
        await store.close()


async def test_a_raised_session_epoch_holds_data(tmp_path: Path) -> None:
    # PR 2804 hold, finding 8: global_session_epoch was excluded whatever it held. Its seed row (id
    # 1, epoch 0) is not data; an epoch a revoke-all raised is.
    path = tmp_path / "keyless.db"
    await (await _keyless_store(path)).close()
    assert not await _holds_data(path)
    _seeded(path, "UPDATE global_session_epoch SET epoch = 1 WHERE id = 1")
    assert await _holds_data(path)


@host_file_platforms
async def test_a_mint_that_failed_before_its_genesis_record_can_run_again(tmp_path: Path) -> None:
    # PR 2804 hold, finding 2: a server mint whose create-open committed the salt, the counter and
    # the markers, then failed before the genesis record, with its key file removed. Those tables
    # hold no operator data, so the probe reads the store as absent and a fresh mint takes it.
    from messagefoundry.store.custody_host import store_holds_data

    settings = _settings(tmp_path)
    await _failed_mint_leftovers(Path(settings.path), tmp_path)
    throwaway = HostBlob(MasterKey.mint(), StoreId.mint())
    probe = await open_store(settings, read_only=True, custody=throwaway)
    try:
        occupancy = await probe.table_occupancy()
        assert occupancy["store_salt"] and occupancy["keyed_surface"]
        assert not occupancy["audit_log"]
        assert not await store_holds_data(probe)
    finally:
        await probe.close()
    blob = _mint(settings)
    await _create(settings, blob)
    assert await _genesis_store_id(settings, blob) == blob.store_id.value


async def test_a_census_that_cannot_see_the_store_tables_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Fail closed: a catalog read that misses the store's own tables (a schema the connection does
    # not resolve to, a permission that hides them) holds data, and a query error is never empty.
    import sqlite3

    from messagefoundry.store.custody_host import store_holds_data

    store = await _keyless_store(tmp_path / "keyless.db")
    try:
        seen = dict(await store.table_occupancy())
        assert not await store_holds_data(store)  # the control: the real census reads absent

        async def _blind() -> dict[str, bool]:
            return {}

        async def _partial() -> dict[str, bool]:
            return {name: held for name, held in seen.items() if name != "users"}

        async def _broken() -> dict[str, bool]:
            raise sqlite3.OperationalError("no such table: stand-in")

        for census in (_blind, _partial):
            monkeypatch.setattr(store, "table_occupancy", census)
            assert await store_holds_data(store)
        monkeypatch.setattr(store, "table_occupancy", _broken)
        with pytest.raises(sqlite3.OperationalError):
            await store_holds_data(store)
    finally:
        monkeypatch.undo()
        await store.close()


async def _failed_mint_leftovers(path: Path, tmp_path: Path) -> None:
    """A keyless store at ``path`` holding the salt, counter and markers a keyed open commits
    before its genesis record, copied from a keyed store made beside it."""
    await (await _keyless_store(path)).close()
    keyed = tmp_path / "keyed.db"
    store = await open_store(
        StoreSettings(path=str(keyed), encryption_key=base64.b64encode(os.urandom(32)).decode()),
        create=True,
    )
    await store.close()
    _seeded(
        path,
        f"ATTACH DATABASE '{keyed}' AS keyed",
        "INSERT INTO store_salt SELECT * FROM keyed.store_salt",
        "INSERT INTO cipher_meta SELECT * FROM keyed.cipher_meta",
        "INSERT INTO keyed_surface SELECT * FROM keyed.keyed_surface",
    )


@pytest.mark.parametrize(
    ("census", "refusal"),
    [
        ("connection event", "the store already holds data"),
        ("incomplete", "does not hold the view definition permission"),
        ("unreadable", "could not be read (OperationalError)"),
        ("unreachable", "could not be read (ConnectionRefusedError)"),
    ],
)
def test_provision_admin_refuses_a_mint_over_a_server_store_it_cannot_show_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    census: str,
    refusal: str,
) -> None:
    # PR 2804 hold (A), end to end: the server probe opens a store with an empty chain whose only
    # data is a connection event, or whose census cannot be shown complete, and the mint is refused
    # before any prompt or key file, with a text that names the cause.
    import asyncio

    from messagefoundry.__main__ import main
    from messagefoundry.store import base

    held = tmp_path / "held.db"

    async def _seed() -> None:
        store = await _keyless_store(held)
        try:
            if census == "connection event":
                await store.record_connection_event(
                    connection="IB_TEST_ADT",
                    transport="mllp",
                    direction="inbound",
                    kind="established",
                )
        finally:
            await store.close()

    asyncio.run(_seed())
    real_open = base.open_store
    probes: list[bool] = []

    async def _incomplete() -> dict[str, bool]:
        raise base.TableCensusIncomplete(
            "this login does not hold the view definition permission on schema 'app' (stand-in)"
        )

    # A driver's text can quote a cell value, so the refusal names the class and never this text.
    driver_text = "permission denied for table stand_in"

    async def _unreadable() -> dict[str, bool]:
        import sqlite3

        raise sqlite3.OperationalError(driver_text)

    async def _unreachable() -> dict[str, bool]:
        raise ConnectionRefusedError(driver_text)

    async def _open(settings: StoreSettings, **kwargs: object) -> Store:
        if kwargs.get("custody") is not None:  # the server probe, under its throwaway blob
            probes.append(bool(kwargs.get("read_only")))
            store = await real_open(
                StoreSettings(path=str(held)), read_only=True, keyless_chain_refusal=None
            )
            if census == "incomplete":
                monkeypatch.setattr(store, "table_occupancy", _incomplete)
            elif census == "unreadable":
                monkeypatch.setattr(store, "table_occupancy", _unreadable)
            elif census == "unreachable":
                monkeypatch.setattr(store, "table_occupancy", _unreachable)
            return store
        raise HostCustodyMissing("no host blob and no handoff here (stand-in)")

    monkeypatch.setattr(base, "open_store", _open)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "messagefoundry.toml").write_text(
        '[store]\nbackend = "postgres"\nkey_provider = "host"\n'
        'server = "db.invalid"\ndatabase = "mefor"\nusername = "mefor"\n'
    )
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    if sys.platform != "win32":
        # provision-admin refuses a secrets directory others can read before it reaches the census.
        secrets.chmod(0o700)
    monkeypatch.setenv("MEFOR_SECRETS_DIRECTORY", str(secrets))
    # No terminal: a mint that went ahead would stop at the terminal check, not this refusal.
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: False))
    argv = ["provision-admin", "--username", "site-admin", "--email", "ops@example.invalid"]
    assert main(argv) != 0
    err = capsys.readouterr().err
    assert probes == [True], err  # the server probe ran, under a read-only open
    assert refusal in err and "Traceback" not in err
    if census == "connection event":
        # PR 2804 fifth hold: the census just proved rows, so the text says so, and the way on
        # leaves the store in place.
        assert "the store already holds data" in err and not _advises_changing(err), err
        assert "cannot tell whether the store holds anything" not in err, err
        flat = " ".join(err.split())
        assert "run with the custody directory that holds the store's host blob" in flat, err
        # A server backend: the other secret files are carried over, and the external schema is
        # provisioned first.
        assert "new, empty" not in flat and "Copy into it every secret file" in flat, err
        assert "a new database, whose schema a DDL-capable login provisions first" in flat, err
    assert driver_text not in err
    assert list(secrets.iterdir()) == []  # no host blob, no handoff


async def _sqlserver_occupancy(
    monkeypatch: pytest.MonkeyPatch, anchor: dict[str, object] | None
) -> tuple[dict[str, bool], list[str]]:
    """``SqlServerStore.table_occupancy`` over a stand-in fetch, with no server: the anchor query
    answers ``anchor``, the catalog lists ``messages``, and every probe finds no row. Returns the
    census and each SQL text it sent."""
    from messagefoundry.store.sqlserver import SqlServerStore

    store = object.__new__(SqlServerStore)
    asked: list[str] = []

    async def _fetchall(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        asked.append(sql)
        if "HAS_PERMS_BY_NAME" in sql:
            return [] if anchor is None else [dict(anchor)]
        if "sys.tables" in sql:
            return [{"t": "messages"}]
        return []

    monkeypatch.setattr(store, "_fetchall", _fetchall)
    return await store.table_occupancy(), asked


async def test_the_sqlserver_census_reads_a_schema_this_login_may_view(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The control for the two refusals below: view definition alone, with no schema select.
    occupancy, asked = await _sqlserver_occupancy(monkeypatch, {"s": "app", "vd": 1, "sel": 0})
    assert occupancy == {"messages": False}
    assert "N'VIEW DEFINITION'" in asked[0]
    assert any("FROM [app].[messages]" in sql for sql in asked)


async def test_the_sqlserver_census_refuses_when_the_server_does_not_answer_the_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # PR 2804 N4, the NULL arm. The text is matched: with the arm gone the grant arm still
    # refuses, but naming a grant the login may hold.
    from messagefoundry.store.base import TableCensusIncomplete

    with pytest.raises(TableCensusIncomplete, match="did not answer"):
        await _sqlserver_occupancy(monkeypatch, {"s": "app", "vd": None, "sel": 1})


@pytest.mark.parametrize("schema_select", [0, 1])
async def test_the_sqlserver_census_refuses_without_view_definition_on_the_schema(
    monkeypatch: pytest.MonkeyPatch, schema_select: int
) -> None:
    # PR 2804 N4, the grant arm, and hold 3: select (db_datareader grants it on the database) does
    # not stand in for view definition, since a table-level DENY of select hides a table from
    # sys.tables under select alone.
    from messagefoundry.store.base import TableCensusIncomplete

    with pytest.raises(TableCensusIncomplete, match="does not hold the view definition permission"):
        await _sqlserver_occupancy(monkeypatch, {"s": "app", "vd": 0, "sel": schema_select})


_CHANGING = re.compile(
    r"\.aside|\bput (?:it |them )?back\b|\brm\b|\boverwritten\b"
    r"|\b(?:mov|renam|remov|delet|overwrit|replac|eras|wip)(?:e|es|ed|ing)\b"
    r"|\b(?:drop|unlink)(?:s|ped|ping|ed|ing)?\b|\bmv\b"
    r"|\b(?:removal|deletion|replacement|discard|purge|truncat|relocat)\w*",
    re.IGNORECASE,
)


async def _keyless_closed(path: Path) -> None:
    await (await _keyless_store(path)).close()


async def _never_started_pin_text(directory: Path) -> str:
    """What a pinned writable open says over a chain never started: the pin refusal's text."""
    from messagefoundry.store.store import StoreChainNeverStarted

    settings = _settings(directory)
    await _keyless_closed(Path(settings.path))
    blob = _mint(settings)
    with pytest.raises(StoreChainNeverStarted) as refused:
        await open_store(settings, custody=blob)
    return str(refused.value)


#: Phrases the guard takes out first: one reports what failed, and one changes only a setting.
_NOT_CHANGING_WHAT_EXISTS = ("could not be removed",)

#: foreign_custody_refusal's own remedy, which changes settings only. Allowed for that text alone.
_KEY_SETTINGS_OUT = "remove every other store key setting"


def _advises_changing(text: str, *, allowed: tuple[str, ...] = ()) -> bool:
    """Whether ``text`` advises moving, renaming, removing, deleting or overwriting something
    (PR 2804 fifth hold), passive forms included. The phrases in ``_NOT_CHANGING_WHAT_EXISTS``,
    and a caller's own provably safe step in ``allowed``, are taken out first."""
    for phrase in (*_NOT_CHANGING_WHAT_EXISTS, *allowed):
        text = text.replace(phrase, "")
    return _CHANGING.search(text) is not None


def test_the_keep_the_key_step_names_the_variable_the_engine_reads(tmp_path: Path) -> None:
    # The step writes the variable's name as a literal (CodeQL alert 315), so pin it to the
    # constant the engine reads.
    from messagefoundry.engine_secrets import SECRETS_DIRECTORY_VARIABLE

    step = custody_host.keep_the_key_step(_settings(tmp_path), new_store=True)
    assert f"named by {SECRETS_DIRECTORY_VARIABLE} here" in step


@pytest.mark.parametrize("backend", [StoreBackend.SQLITE, StoreBackend.POSTGRES])
def test_the_fallback_step_fits_the_backend_and_the_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: StoreBackend
) -> None:
    # PR 2804 sixth hold, item 2: no backend is told to empty its secrets directory, a server
    # backend under external schema management is told to provision the schema first, the
    # command keeps --service-account, a Windows run is told about it, and the recovery key is
    # paired with its key file.
    settings = _settings(tmp_path).model_copy(update={"backend": backend})
    step = custody_host.keep_the_key_step(
        settings, new_store=True, service_account="NT SERVICE\\MessageFoundry"
    )
    assert "empty directory" not in step and "new, empty" not in step
    assert "Copy into it every secret file" in step, step
    # Quoted, since a service account name can hold a space.
    command = (
        "run `messagefoundry provision-admin` again with the same arguments, "
        '--service-account "NT SERVICE\\MessageFoundry" among them'
    )
    assert command in step, step
    assert "restricted and writable by the service as a secrets directory must be" in step, step
    assert "The new store starts empty" in step, step
    assert "other than master.key and handoff.key" in step, step
    assert "recovery key shown when an existing key file was minted goes with that file" in step
    schema = "whose schema a DDL-capable login provisions first"
    assert (schema in step) is (backend is StoreBackend.POSTGRES), step
    assert ("a new database" in step) is (backend is StoreBackend.POSTGRES), step
    monkeypatch.setattr(sys, "platform", "win32")
    windows = custody_host.keep_the_key_step(settings, new_store=False)
    assert "add --service-account with that account" in windows, windows
    assert "Point [store]" not in windows, windows
    auto = custody_host.keep_the_key_step(
        settings.model_copy(update={"key_provider": "auto"}), new_store=False
    )
    assert "provision-admin" not in auto and "run the command again" in auto, auto
    # No key is minted there, so no new key or recovery key is spoken of.
    assert "recovery key" not in auto and "new key" not in auto, auto


@host_file_platforms
def test_no_keep_the_key_text_advises_changing_what_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # PR 2804 fifth hold, the proof: the texts the one helper's callers emit advise changing
    # nothing that exists. The positive control is the fourth hold's own text. Rendered here are
    # at least the existing-store refusal, the pin refusal, the never-started refusal,
    # foreign_custody_refusal, mint_target's refusal and both failed-mint warnings. Not here: the
    # crash rule's handoff refusal, which its own Windows-only test checks, and the pin refusal's
    # race backstop in _load_audit_chain, which prints the same _PIN_NEEDS_THE_WRAP text.
    import asyncio

    from messagefoundry import __main__ as cli
    from messagefoundry.store.store import StoreIdPinRefusedBeforeWrite

    old = (
        "The engine cannot tell whose key is in master.key, and it may be another store's only "
        "key, so keep it. If no other store uses it, move the store file store.db to "
        "store.db.aside, and move master.key to master.key.aside"
    )
    assert _advises_changing(old) and _advises_changing("Remove it before running again")
    for advice in (
        "put back the host blob it was made with",
        "the key file must be deleted first",
        "replace the host blob",
        "drop the database",
        "moving the store aside",
        "removing the key file",
        "the key file needs removal first",
        "discard the old store",
    ):
        assert _advises_changing(advice), advice
    assert not _advises_changing("the key file could not be removed (Access is denied).")
    # The existing-store refusal: a SQLite store here with no key for it.
    existing = tmp_path / "existing"
    existing.mkdir()
    asyncio.run(_keyless_closed(existing / "store.db"))
    assert _run_provision_admin(existing, monkeypatch, existing / "store.db") == 2
    refused = capsys.readouterr().err
    assert "the store already exists" in refused, refused
    texts = [refused]
    pinned = tmp_path / "pinned"
    pinned.mkdir()
    texts.append(asyncio.run(_never_started_pin_text(pinned)))
    settings = _settings(tmp_path)
    (tmp_path / custody_host.HOST_FILE_NAME).write_bytes(b"not read")
    foreign = custody_host.foreign_custody_refusal(
        settings.model_copy(update={"key_provider": "auto", "encryption_key_file": "k.bin"}),
        environ={},
    )
    assert foreign is not None
    texts += [cli._never_started_refusal(settings, None), foreign]
    with pytest.raises(FileExistsError) as exists:
        custody_host.mint_target(settings, service_account=None, enforcing=False, environ={})
    texts.append(str(exists.value))
    server = StoreSettings().model_copy(
        update={"backend": StoreBackend.POSTGRES, "key_provider": "host"}
    )
    kept = tmp_path / "kept.key"
    kept.write_bytes(b"k")
    cli._discard_minted_custody(kept, server, StoreIdPinRefused("after the salt bind"))

    def _held(self: Path, missing_ok: bool = False) -> None:
        raise PermissionError(13, "Access is denied")

    texts.append(capsys.readouterr().err)
    with monkeypatch.context() as patched:
        patched.setattr(Path, "unlink", _held)
        cli._discard_minted_custody(kept, server, StoreIdPinRefusedBeforeWrite("before"))
    held = capsys.readouterr().err
    assert "could not be removed" in held, held
    # PR 2804 sixth hold: this run minted that key and nothing was written under it.
    assert "This run minted it and nothing was written under it" in held, held
    assert "cannot tell whose key" not in held, held
    texts.append(held)
    assert all(text.count("WARNING:") == 1 for text in texts[-2:]), texts[-2:]
    offending = [
        text
        for text in texts
        if _advises_changing(text, allowed=(_KEY_SETTINGS_OUT,) if text is foreign else ())
    ]
    assert not offending, offending
    # Every text names its own way on, in the order rendered above. The existing-store text
    # names provision-admin through the missing-key text it quotes, so its marker is the fallback.
    fallback = "To go on without it"
    markers = [
        (fallback, "run with the custody directory that holds the store's host blob"),
        ("which names the way on",),
        (fallback,),
        (fallback, "set [store].key_provider = 'host'"),
        (fallback, "leaves it in place"),
        ("Keep that file and run the command again",),
        (fallback, "This run minted it and nothing was written under it"),
    ]
    assert len(markers) == len(texts)
    for text, needed in zip(texts, markers, strict=True):
        flat = " ".join(text.split())
        assert all(marker in flat for marker in needed), (needed, text)


async def _failed_create(
    settings: StoreSettings, blob: HostBlob, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The create a mint makes, under ``blob``'s own key, stopped once its salt, invocation counter
    and markers are committed and before its genesis record: what a failed mint leaves."""
    from messagefoundry.store import store as store_module

    async def _stopped(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("stopped before the genesis record (stand-in)")

    with monkeypatch.context() as patched:
        patched.setattr(store_module, "load_audit_chain", _stopped)
        with pytest.raises(RuntimeError, match="stand-in"):
            await _create(settings, blob)


def _run_provision_admin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store_path: Path) -> int:
    """provision-admin against the SQLite store at ``store_path`` under the host key provider, with
    no terminal: its exit code. Read stderr from ``capsys``."""
    from messagefoundry.__main__ import main

    monkeypatch.chdir(tmp_path)
    (tmp_path / "messagefoundry.toml").write_text('[store]\nkey_provider = "host"\n')
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: False))
    argv = ["provision-admin", "--username", "site-admin", "--email", "ops@example.invalid"]
    return main([*argv, "--db", str(store_path)])


@host_file_platforms
@pytest.mark.parametrize("shape", ["failed mint", "foreign key", "holds data", "never keyed"])
def test_a_rerun_over_a_chain_never_started_keeps_the_key_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    shape: str,
) -> None:
    # PR 2804 hold 2 and fourth hold, items 1 and 3: a mint that failed before its genesis record
    # keeps its key file, and the re-run never names it for removal. The engine cannot tell its own
    # failed mint (leftovers under the minted blob's key) from a blob another store owns (leftovers
    # under a foreign key, or none), so every shape keeps the key and names the one way on.
    import asyncio

    settings = _settings(tmp_path)
    store_path = Path(settings.path)

    async def _unstarted() -> None:
        # Made before the key: a keyless open refuses a directory that holds a host blob.
        store = await _keyless_store(store_path)
        try:
            if shape == "holds data":
                await store.record_connection_event(
                    connection="IB_TEST_ADT",
                    transport="mllp",
                    direction="inbound",
                    kind="established",
                )
        finally:
            await store.close()
        if shape != "never keyed":
            await _failed_mint_leftovers(store_path, tmp_path)  # under an unrelated key

    if shape != "failed mint":
        asyncio.run(_unstarted())
    blob = _mint(settings)
    if shape == "failed mint":
        asyncio.run(_failed_create(settings, blob, monkeypatch))
    kept = tmp_path / custody_host.HOST_FILE_NAME
    assert kept.exists()
    code = _run_provision_admin(tmp_path, monkeypatch, store_path)
    assert code == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert kept.exists()
    # PR 2804 fifth hold: the one way on, which creates only new things.
    assert not _advises_changing(err), err
    step = custody_host.keep_the_key_step(settings, new_store=True)
    assert " ".join(step.split()) in " ".join(err.split()), err
    assert "leaves it and the store in place" in err, err


@host_file_platforms
def test_a_shared_secrets_directory_never_names_another_stores_key_for_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # PR 2804 fourth hold: store A is live under the key in a shared secrets directory, and store B
    # beside it was never started. provision-admin for B opens with A's key and must keep it.
    import asyncio

    secrets = tmp_path / "secrets"
    secrets.mkdir()
    if sys.platform != "win32":
        secrets.chmod(0o700)
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    b_path = tmp_path / "b" / "store.db"

    async def _b() -> None:
        await (await _keyless_store(b_path)).close()

    asyncio.run(_b())  # before the key exists: a keyless open refuses a directory holding one
    monkeypatch.setenv("MEFOR_SECRETS_DIRECTORY", str(secrets))
    a_settings = _settings(tmp_path / "a")
    blob = _mint(a_settings)
    asyncio.run(_create(a_settings, blob))
    kept = secrets / custody_host.HOST_FILE_NAME
    code = _run_provision_admin(tmp_path, monkeypatch, b_path)
    assert code == 2
    err = capsys.readouterr().err
    assert not _advises_changing(err) and "leaves it and the store in place" in err, err
    assert "named by MEFOR_SECRETS_DIRECTORY here" in " ".join(err.split()), err
    assert kept.exists()
    # B's pre-check was refused before its first write, so nothing was bound under A's key.
    import sqlite3

    with sqlite3.connect(b_path) as db:
        assert db.execute("SELECT COUNT(*) FROM store_salt").fetchone() == (0,)

    async def _a_still_opens() -> None:
        await (await open_store(a_settings)).close()

    asyncio.run(_a_still_opens())


@host_file_platforms
def test_the_way_on_a_never_started_refusal_names_lets_the_mint_go_ahead(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # PR 2804 fifth hold, item 4: follow the refusal's one way on, a new, empty custody directory
    # and a new store location, and the re-run mints this store's key there through mint_target
    # and provisions it. The key file and the store left in place are untouched.
    import asyncio

    from messagefoundry import __main__ as cli
    from messagefoundry.__main__ import main

    settings = _settings(tmp_path)
    store_path = Path(settings.path)

    async def _unstarted() -> None:
        await (await _keyless_store(store_path)).close()

    asyncio.run(_unstarted())
    _mint(settings)
    kept = tmp_path / custody_host.HOST_FILE_NAME
    assert _run_provision_admin(tmp_path, monkeypatch, store_path) == 2
    assert "named by MEFOR_SECRETS_DIRECTORY here" in " ".join(capsys.readouterr().err.split())
    left = {path: path.read_bytes() for path in (kept, store_path)}
    secrets = tmp_path / "new-secrets"
    secrets.mkdir()
    if sys.platform != "win32":
        secrets.chmod(0o700)
    monkeypatch.setenv("MEFOR_SECRETS_DIRECTORY", str(secrets))
    new_store = tmp_path / "new-store.db"
    minted: list[Path] = []
    real_target = custody_host.mint_target

    def _target(store: StoreSettings, **kwargs: Any) -> Path:
        minted.append(real_target(store, **kwargs))
        return minted[-1]

    monkeypatch.setattr(custody_host, "mint_target", _target)
    password = "a long and unremarkable passphrase 7"
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    queued = [password, password]
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: queued.pop(0))
    monkeypatch.setattr(cli, "_RecoveryKeyConsole", lambda: _Console("", "wrong"))
    argv = ["provision-admin", "--username", "site-admin", "--email", "ops@example.invalid"]
    assert main([*argv, "--db", str(new_store)]) == 0, capsys.readouterr().err
    assert minted and set(minted) == {secrets / custody_host.HOST_FILE_NAME}, minted
    assert minted[0].exists()
    assert new_store.exists()
    assert {path: path.read_bytes() for path in left} == left


@host_file_platforms
async def test_a_pinned_open_over_a_chain_never_started_removes_nothing(tmp_path: Path) -> None:
    # PR 2804 fourth hold, item 4: serve and every other command print this text for the state
    # provision-admin decides, so it names nothing for removal and sends the operator there.
    from messagefoundry.store.store import StoreChainNeverStarted

    settings = _settings(tmp_path)
    await (await _keyless_store(Path(settings.path))).close()
    blob = _mint(settings)
    with pytest.raises(StoreChainNeverStarted) as refused:
        await open_store(settings, custody=blob)
    text = str(refused.value)
    assert not _advises_changing(text) and "provision-admin" in text, text
    assert "keep it and the store" in text, text


@host_file_platforms
async def test_a_pin_refusal_before_any_write_is_told_apart_from_one_after(
    tmp_path: Path,
) -> None:
    # Item 3: a refusal raised after the salt bind must not read as "nothing written".
    from messagefoundry.store.store import StoreChainNeverStarted, StoreIdPinRefusedBeforeWrite

    settings = _settings(tmp_path)
    blob = _mint(settings)
    await _create(settings, blob)
    stranger = HostBlob(blob.master_key, StoreId.mint(), (), blob.recovery_proved_at)
    with pytest.raises(StoreIdPinRefusedBeforeWrite) as refused:
        await open_store(settings, custody=stranger)
    # Another store's blob is not a never-started chain, whose refusal keeps the key file and
    # names the way on.
    assert not isinstance(refused.value, StoreChainNeverStarted)


def test_a_minted_key_is_kept_when_the_pin_refused_after_a_write(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from messagefoundry import __main__ as cli
    from messagefoundry.store.store import StoreIdPinRefusedBeforeWrite

    server = StoreSettings().model_copy(update={"backend": StoreBackend.POSTGRES})
    kept = tmp_path / "kept.key"
    kept.write_bytes(b"k")
    cli._discard_minted_custody(kept, server, StoreIdPinRefused("after the salt bind"))
    assert kept.exists()
    # PR 2804 fourth and sixth holds: whether the store holds anything under the key is not
    # proved here, so the text keeps it and sends the operator to the re-run in place, which
    # carries on with a store started under it or names a way on. This run minted the key, so the
    # text does not call it possibly another store's.
    warning = capsys.readouterr().err
    assert str(kept) in warning and "run the command again" in warning.lower(), warning
    assert "remove" not in warning.lower(), warning
    assert "another store's" not in warning, warning
    assert not _advises_changing(warning) and "cannot tell whose key" not in warning, warning
    removed = tmp_path / "removed.key"
    removed.write_bytes(b"k")
    cli._discard_minted_custody(removed, server, StoreIdPinRefusedBeforeWrite("before"))
    assert not removed.exists()


def test_a_minted_key_that_cannot_be_removed_is_named_as_this_runs_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # PR 2804 sixth hold: nothing was written under the key this run minted, so the warning says
    # so rather than that the engine cannot tell whose key it is, and gives the fallback way on.
    from messagefoundry import __main__ as cli
    from messagefoundry.store.store import StoreIdPinRefusedBeforeWrite

    server = StoreSettings().model_copy(
        update={"backend": StoreBackend.POSTGRES, "key_provider": "host"}
    )
    kept = tmp_path / "kept.key"
    kept.write_bytes(b"k")

    def _held(self: Path, missing_ok: bool = False) -> None:
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr(Path, "unlink", _held)
    cli._discard_minted_custody(kept, server, StoreIdPinRefusedBeforeWrite("before"))
    warning = capsys.readouterr().err
    assert "This run minted it and nothing was written under it" in warning, warning
    assert "the recovery key shown opens nothing" in warning, warning
    assert "cannot tell whose key" not in warning and not _advises_changing(warning), warning
    assert "Copy into it every secret file" in " ".join(warning.split()), warning


@host_file_platforms
def test_end_of_input_at_the_recovery_prompt_is_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Item 9: getpass raises EOFError at end of input (Ctrl-D, Ctrl-Z), which is not an OSError.
    from messagefoundry import __main__ as cli
    from messagefoundry.__main__ import main

    monkeypatch.chdir(tmp_path)
    (tmp_path / "messagefoundry.toml").write_text('[store]\nkey_provider = "host"\n')
    password = "a long and unremarkable passphrase 7"
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    queued = [password, password]
    monkeypatch.setattr("getpass.getpass", lambda *_a, **_k: queued.pop(0))

    class _Gone(_Console):
        def read(self) -> str:
            raise EOFError

    monkeypatch.setattr(cli, "_RecoveryKeyConsole", _Gone)
    argv = ["provision-admin", "--username", "site-admin", "--email", "ops@example.invalid"]
    assert main([*argv, "--db", str(tmp_path / "p.db")]) == 2
    err = capsys.readouterr().err
    assert "recovery key" in err and "Traceback" not in err
    assert not (tmp_path / "master.key").exists() and not (tmp_path / "p.db").exists()


@windows_only
def test_a_cleanup_that_cannot_remove_the_host_file_keeps_the_original_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Item 10: the unlink in the conversion's cleanup replaced the read-back's own error.
    _handoff(tmp_path / "handoff.key", _proved_blob())
    calls: list[Path] = []

    def _read(path: Path) -> HostBlob:
        calls.append(path)
        if len(calls) == 1:  # the open's first look finds no host file
            raise FileNotFoundError(path)
        raise custody.CustodyError("the read-back stand-in refusal")

    def _no_unlink(self: Path, missing_ok: bool = False) -> None:
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr(custody, "read_host_file", _read)
    monkeypatch.setattr(Path, "unlink", _no_unlink)
    with pytest.raises(HostCustodyRefused) as excinfo:
        load_host_custody(_settings(tmp_path), enforcing=True, environ={})
    text = str(excinfo.value)
    assert "the read-back stand-in refusal" in text and "could not be removed" in text
