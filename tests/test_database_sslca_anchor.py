# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A generic DATABASE connection's ``odbc_params`` ``sslca`` is a lane trust anchor (vault BACKLOG
#3090, steps 7 and 8).

Before this the file was checked once, when the connection was built, for an encryption header
and a private key, and for nothing else: no check of who could write it, no audited fingerprint,
and no check once the lane was up. Now the lane check reads it as it reads a dialling
``tls_ca_file`` (``auth.trust_anchors``, module item 12), and refuses a swapped file that names an
encryption header. Step 8 lowers the build's read cap from 16 MiB to 1 MiB.

Synthetic certificates only. Nothing here hands a file to a driver.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import keywrap
from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.trust_anchors import (
    AUDIT_ACTION,
    ENCRYPTION_HEADER_SCOPE,
    PRIVATE_KEY_SCOPE,
    TrustAnchorError,
)
from messagefoundry.config import wiring
from messagefoundry.config.wiring import Registry, load_config
from messagefoundry.pipeline import wiring_runner
from messagefoundry.store import MessageStore
from messagefoundry.transports import database
from messagefoundry.transports.database import _build_odbc_dsn, generic_odbc_param
from tests.test_foreign_tls_ca_encryption_header import _certificate, _headered
from tests.test_trust_anchors import _block, _path_ok

_OUT = "OB_DB_GEN"
_IN = "IB_DB_GEN"


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "audit.db")
    yield s
    await s.close()


@pytest.fixture(autouse=True)
def _isolated_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wiring, "_active", Registry())


@pytest.fixture
def judged(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ACL and path read as owner-only, so a test varies only what it is about."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)


def _ca(tmp_path: Path, body: bytes = b"db-ca", name: str = "db-ca.pem") -> Path:
    path = tmp_path / name
    path.write_bytes(_block(body))
    return path


def _settings(ca: Path | str, **params: str) -> dict[str, Any]:
    """A generic DATABASE connection's settings, as the lane check reads them once resolved."""
    return {
        "dialect": "generic",
        "odbc_driver": "MySQL ODBC 9.1 Unicode Driver",
        "server": "db.synthetic.test",
        "odbc_params": {"SSLMODE": "VERIFY_IDENTITY", "SSLCA": str(ca), **params},
    }


async def _rows(store: MessageStore, label: str) -> list[dict[str, Any]]:
    rows = await store.list_audit(action=AUDIT_ACTION, limit=200)
    out = [json.loads(r["detail"]) for r in rows]
    return [d for d in out if d.get("label") == label]


# --- the spec ------------------------------------------------------------------------------------


@pytest.mark.parametrize("spelling", ["sslca", "SSLCA", "SslCa"])
def test_a_generic_database_lane_names_its_sslca_as_its_anchor(
    tmp_path: Path, spelling: str
) -> None:
    """The keyword matches in any case, as the build matches it. The hop reads the file by path,
    so the spec carries ``loads_verified_bytes=False`` and asks for the encryption-header check.
    Red with ``database_ca_anchor_spec`` taken out of ``lane_anchor_spec``: no spec."""
    ca = _ca(tmp_path)
    settings = _settings(ca)
    settings["odbc_params"] = {"SSLMODE": "VERIFY_IDENTITY", spelling: str(ca)}
    assert ta.lane_anchor_spec("outbound", _OUT, settings) == ta.AnchorSpec(
        f"outbound:{_OUT}",
        f"outbound connection '{_OUT}' odbc_params sslca",
        str(ca),
        loads_verified_bytes=False,
        refuses_encryption_header=True,
    )
    inbound = ta.lane_anchor_spec("inbound", _IN, settings)
    assert inbound is not None and inbound.label == f"inbound:{_IN}"
    assert inbound.setting == f"inbound connection '{_IN}' odbc_params sslca"


@pytest.mark.parametrize("mode", ["disable", "DISABLED", " Disable "])
def test_a_ca_the_driver_never_reads_under_sslmode_disable_is_not_checked(
    tmp_path: Path, mode: str
) -> None:
    """``sslmode=disable`` builds no TLS context, so the CA is not read and not checked. The
    control is the same file under a verifying mode, which is checked."""
    ca = _ca(tmp_path)
    off = _settings(ca, SSLMODE=mode)
    assert (
        ta.unread_ca_reason(off) == "odbc_params sslmode turns TLS off, so the driver reads no CA"
    )
    assert ta.lane_anchor_spec("outbound", _OUT, off) is None
    assert ta.unread_ca_reason(_settings(ca)) is None
    assert ta.lane_anchor_spec("outbound", _OUT, _settings(ca)) is not None


@pytest.mark.parametrize("mode", ["allow", "prefer", "PREFERRED", "require"])
def test_a_mode_that_may_still_use_tls_keeps_the_check(tmp_path: Path, mode: str) -> None:
    assert ta.lane_anchor_spec("outbound", _OUT, _settings(_ca(tmp_path), SSLMODE=mode))


def test_a_value_that_names_no_regular_file_is_left_to_the_driver(tmp_path: Path) -> None:
    """The build leaves a missing file and a directory to the driver, and so does the lane check:
    ``evaluate_anchor`` reads the whole file, so only a regular file is handed to it."""
    assert ta.lane_anchor_spec("outbound", _OUT, _settings(tmp_path / "no-such.pem")) is None
    assert ta.lane_anchor_spec("outbound", _OUT, _settings(tmp_path)) is None


def test_a_padded_value_is_checked_at_the_spelling_that_names_a_file(tmp_path: Path) -> None:
    """The build checks the value as sent and trimmed; the spec takes the spelling that names a
    regular file, so a padded value still gets the lane check."""
    ca = _ca(tmp_path)
    spec = ta.lane_anchor_spec("outbound", _OUT, _settings(f" {ca} "))
    assert spec is not None and spec.path == str(ca)


def test_the_sqlserver_preset_and_a_plain_tls_ca_lane_are_unchanged(tmp_path: Path) -> None:
    """The SQL Server preset sends no ``odbc_params``. A ``tls_ca_file`` lane keeps its own spec."""
    ca = _ca(tmp_path)
    preset = _settings(ca) | {"dialect": "sqlserver"}
    assert ta.lane_anchor_spec("outbound", _OUT, preset) is None
    spec = ta.lane_anchor_spec("outbound", "OUT", {"tls_ca_file": str(ca)})
    assert spec is not None and spec.setting == "outbound connection 'OUT' tls_ca_file"
    assert spec.refuses_encryption_header is False


def test_the_registry_collects_the_database_outbound_and_poller(tmp_path: Path) -> None:
    """Through the public factories and a loaded graph, as ``serve`` loads one."""
    ca = _ca(tmp_path)
    params = {"SSLMODE": "VERIFY_IDENTITY", "SSLCA": str(ca)}
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "feed.py").write_text(
        "from messagefoundry import Database, DatabasePoll, Send, handler, inbound, outbound\n"
        "from messagefoundry import router\n"
        f"inbound({_IN!r}, DatabasePoll(server='db.synthetic.test', dialect='generic', "
        "odbc_driver='MySQL ODBC 9.1 Unicode Driver', poll_statement='SELECT 1', "
        f"odbc_params={params!r}), router='r')\n"
        "inbound('IB_DB_PLAIN', DatabasePoll(server='db.synthetic.test', dialect='generic', "
        "odbc_driver='MySQL ODBC 9.1 Unicode Driver', poll_statement='SELECT 1', "
        "odbc_params={'SSLMODE': 'VERIFY_IDENTITY'}), router='r')\n"
        f"outbound({_OUT!r}, Database(server='db.synthetic.test', dialect='generic', "
        "odbc_driver='MySQL ODBC 9.1 Unicode Driver', statement='INSERT INTO t VALUES (:a)', "
        f"odbc_params={params!r}))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        f"    return Send({_OUT!r}, msg)\n",
        encoding="utf-8",
    )
    registry = load_config(cfg)
    labels = {s.label for s in ta.registry_anchor_specs(registry, {}, lanes=True)}
    assert labels == {f"outbound:{_OUT}", f"inbound:{_IN}"}
    # The start leaves both to the runner's lane check.
    assert ta.registry_anchor_specs(registry, {}, lanes=False) == []
    poller = registry.inbound[_IN]
    assert wiring_runner._inbound_lane_reads_ca(poller)
    assert ta.lane_ca_setting(poller.spec.settings) == "odbc_params sslca"
    # The control: a poller with no sslca has no lane CA, and a tls_ca_file line keeps its name.
    assert not wiring_runner._inbound_lane_reads_ca(registry.inbound["IB_DB_PLAIN"])
    assert ta.lane_ca_setting({"tls_ca_file": str(ca)}) == "tls_ca_file"


def test_a_poller_whose_dialect_is_an_env_value_still_counts_its_sslca(tmp_path: Path) -> None:
    """An ``env()`` dialect may resolve to ``generic``, so the poller's sslca goes to the lane
    check, which resolves it and decides. Red with ``inbound_lane_reads_ca`` reading the unresolved
    dialect: the poller is never checked, while an outbound with the same dialect is."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import EnvRef

    settings = {**_settings(_ca(tmp_path)), "dialect": EnvRef("DB_DIALECT")}
    assert ta.inbound_lane_reads_ca(ConnectorType.DATABASE, settings)
    assert ta.lane_ca_setting(settings) == "odbc_params sslca"
    # The controls: no sslca, a literal SQL Server preset, and a blank sslca count for nothing.
    del settings["odbc_params"]["SSLCA"]
    assert not ta.inbound_lane_reads_ca(ConnectorType.DATABASE, settings)
    preset = {**_settings(_ca(tmp_path)), "dialect": "sqlserver"}
    assert not ta.inbound_lane_reads_ca(ConnectorType.DATABASE, preset)
    blank = _settings("")
    assert not ta.inbound_lane_reads_ca(ConnectorType.DATABASE, blank)
    assert ta.lane_ca_setting(blank) == "tls_ca_file"


def test_a_path_object_names_the_anchor_as_its_text_does(tmp_path: Path) -> None:
    """A code-first ``Path`` value builds, since the build reads ``str(value)``, so the lane
    check takes it too. Red with the ``os.fspath`` step removed: no spec, so no check."""
    ca = _ca(tmp_path)
    settings = _settings(ca)
    settings["odbc_params"]["SSLCA"] = ca
    spec = ta.lane_anchor_spec("outbound", _OUT, settings)
    assert spec is not None and spec.path == str(ca)
    assert generic_odbc_param(settings, "sslca") == ca


# --- the lane check ------------------------------------------------------------------------------


async def test_a_writable_sslca_refuses_the_lane_at_enforce_and_warns_at_warn(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A CA another account can write lets that account choose which server the driver trusts.
    Red with ``database_ca_anchor_spec`` taken out of ``lane_anchor_spec``: both checks pass with
    no row."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    settings = _settings(_ca(tmp_path))
    enforce = ta.make_lane_anchor_check(store, enforcing=True)
    with pytest.raises(TrustAnchorError, match="is writable by a non-owner") as refused:
        await enforce("outbound", _OUT, settings)
    assert f"outbound connection '{_OUT}' odbc_params sslca" in str(refused.value)
    await ta.make_lane_anchor_check(store, enforcing=False)("outbound", _OUT, settings)
    events = [r for r in await _rows(store, f"outbound:{_OUT}") if r["event"] == "acl_insecure"]
    assert [r["enforcing"] for r in events] == [False, True]  # most recent first


async def test_a_writable_sslca_on_a_poller_refuses_that_inbound(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: False)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)
    check = ta.make_lane_anchor_check(store, enforcing=True)
    with pytest.raises(TrustAnchorError, match="is writable by a non-owner"):
        await check("inbound", _IN, _settings(_ca(tmp_path)))
    assert await _rows(store, f"inbound:{_IN}")


async def test_a_swapped_sslca_with_an_encryption_header_is_refused_at_the_next_check(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The build checked the file once. A file swapped since is read at the next lane check,
    compared with the audited fingerprint, and refused for the header the build refuses. Red with
    the header check taken out of ``_refuse_by_path_content``: the swapped file passes."""
    ca = _ca(tmp_path)
    settings = _settings(ca)
    check = ta.make_lane_anchor_check(store, enforcing=True)
    await check("outbound", _OUT, settings)
    before = hashlib.sha256(ca.read_bytes()).hexdigest()
    swapped = _headered(_certificate())
    ca.write_bytes(swapped.encode("ascii"))
    with pytest.raises(TrustAnchorError, match=re.escape(ENCRYPTION_HEADER_SCOPE)) as refused:
        await check("outbound", _OUT, settings)
    message = str(refused.value)
    assert f"outbound connection '{_OUT}' odbc_params sslca" in message
    assert "AES-256-CBC" not in message  # the header's value is content, never echoed
    rows = await _rows(store, f"outbound:{_OUT}")
    assert [r["event"] for r in rows] == ["pem_refused", "changed", "observed"]
    assert rows[1]["previous"] == before


async def test_a_swapped_sslca_with_a_private_key_is_refused_at_the_next_check(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    ca = _ca(tmp_path)
    settings = _settings(ca)
    check = ta.make_lane_anchor_check(store, enforcing=True)
    await check("outbound", _OUT, settings)
    label = "PRIVATE" + " KEY"  # split, so a secret scanner does not read a real key
    ca.write_bytes(
        _block(b"db-ca") + f"-----BEGIN {label}-----\nAAAA\n-----END {label}-----\n".encode()
    )
    with pytest.raises(TrustAnchorError, match=re.escape(PRIVATE_KEY_SCOPE)):
        await check("outbound", _OUT, settings)


async def test_an_unchanged_sslca_passes_every_check_with_one_baseline(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The control for the swap: the same file checked twice writes one ``observed`` row."""
    check = ta.make_lane_anchor_check(store, enforcing=True)
    settings = _settings(_ca(tmp_path))
    await check("outbound", _OUT, settings)
    await check("outbound", _OUT, settings)
    assert [r["event"] for r in await _rows(store, f"outbound:{_OUT}")] == ["observed"]


async def test_the_encryption_header_check_stays_off_for_a_tls_ca_file(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """A ``tls_ca_file`` hop loads with Python's ``ssl`` by path, which was measured refusing an
    encrypted block at once, so its lane check keeps only the private-key refusal."""
    ca = tmp_path / "ca.pem"
    ca.write_text(_certificate() + "# DEK-Info: noted\n", encoding="ascii")
    await ta.make_lane_anchor_check(store, enforcing=True)(
        "outbound", "OUT", {"tls_ca_file": str(ca)}
    )


# --- step 8: the build's read cap ----------------------------------------------------------------


def test_the_build_reads_at_most_one_mib_the_key_file_cap() -> None:
    """Step 8 keeps the capped read in the constructor and lowers it to the key-file cap."""
    assert database._MAX_DRIVER_CA_FILE_BYTES == 1 << 20 == keywrap._MAX_KEY_FILE_BYTES


def test_an_sslca_file_one_byte_past_one_mib_is_refused(tmp_path: Path) -> None:
    """Red at the old 16 MiB cap: a file of 1 MiB and one byte would build. The control is a file
    of exactly 1 MiB, read whole, which builds."""
    cert = _certificate().encode("ascii")
    at_cap = tmp_path / "at-cap.pem"
    at_cap.write_bytes(cert + b"#" * ((1 << 20) - len(cert)))
    over = tmp_path / "over.pem"
    over.write_bytes(at_cap.read_bytes() + b"#")
    assert "SSLCA=" in _build_odbc_dsn(_settings(at_cap), connection=_OUT)
    with pytest.raises(ValueError, match="larger than the 1 MiB"):
        _build_odbc_dsn(_settings(over), connection=_OUT)


# --- a pipe never makes the check wait ------------------------------------------------------------


async def test_a_ca_that_is_not_a_regular_file_at_read_time_is_refused_not_read(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The spec is chosen by a ``stat``; a pipe swapped in before the check reads the file would
    make a plain read wait. ``evaluate_anchor`` judges its own descriptor, so a file that is not
    regular there is an anchor it cannot read. Runs on every platform: the descriptor is reported
    as a pipe. Red with the regular-file test taken out of ``_read_regular_file``."""
    ca = _ca(tmp_path)
    settings = _settings(ca)
    spec = ta.lane_anchor_spec("outbound", _OUT, settings)
    assert spec is not None
    real_fstat = os.fstat

    def as_pipe(fd: int) -> Any:
        fields = list(real_fstat(fd))
        fields[0] = stat.S_IFIFO | 0o600
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", as_pipe)
    with pytest.raises(OSError, match="not a regular file"):
        ta.evaluate_anchor(spec)
    with pytest.raises(TrustAnchorError, match="could not read the trust anchor"):
        await ta.make_lane_anchor_check(store, enforcing=True)("outbound", _OUT, settings)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes need POSIX mkfifo")
def test_a_real_pipe_is_refused_without_waiting(tmp_path: Path) -> None:
    pipe = tmp_path / "ca.pipe"
    os.mkfifo(pipe)
    with pytest.raises(OSError, match="not a regular file"):
        ta.evaluate_anchor(ta.AnchorSpec("outbound:X", "setting", str(pipe)))


@pytest.mark.parametrize(
    "remote", ["//db-ca.invalid/share/ca.pem", "\\\\db-ca.invalid\\share\\ca.pem"]
)
def test_a_value_that_can_name_another_host_is_never_opened(
    remote: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lane check runs before the build at a start, and the build refuses a remote spelling,
    so the spec must not stat or open it first: on Windows that would dial the host over SMB. Red
    with the remote screen taken out of ``driver_file_spellings``."""

    touched: list[object] = []

    def recording(p: object) -> bool:
        touched.append(p)
        return True  # as if the remote file were there

    with monkeypatch.context() as patched:
        patched.setattr(os.path, "exists", recording)
        patched.setattr(os.path, "isdir", lambda _p: False)
        spec = ta.lane_anchor_spec("outbound", _OUT, _settings(remote))
    assert touched == [] and spec is None


def test_a_device_named_as_sslca_is_refused_unread(tmp_path: Path) -> None:
    """A pipe or device in place before the check is not left unjudged: the spec names it, and
    the read refuses it. ``os.devnull`` is a device on every platform. Red with the spec built only
    for a regular file: no spec, so nothing checks who can write the path."""
    spec = ta.lane_anchor_spec("outbound", _OUT, _settings(os.devnull))
    assert spec is not None and spec.path == os.devnull
    with pytest.raises(OSError, match="not a regular file"):
        ta.evaluate_anchor(spec)


# --- a refused descriptor is closed ---------------------------------------------------------------


def _recording_descriptors(monkeypatch: pytest.MonkeyPatch) -> tuple[list[int], list[int]]:
    """Record every descriptor ``os.open`` hands out and every one ``os.close`` closes."""
    opened: list[int] = []
    closed: list[int] = []
    real_open, real_close = os.open, os.close

    def opening(*args: Any, **kwargs: Any) -> int:
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def closing(fd: int) -> None:
        closed.append(fd)
        real_close(fd)

    monkeypatch.setattr(os, "open", opening)
    monkeypatch.setattr(os, "close", closing)
    return opened, closed


def test_a_descriptor_fdopen_refuses_is_closed_by_the_anchor_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``os.fdopen`` does not close a descriptor it refuses, as it refuses a POSIX directory, so
    the read closes it. Runs on every platform. Red with ``_read_regular_file`` back on
    ``os.fdopen(os.open(...))``: the descriptor stays open, one per lane check."""
    path = str(_ca(tmp_path))
    opened, closed = _recording_descriptors(monkeypatch)

    def refusing(*_args: Any, **_kwargs: Any) -> Any:
        raise IsADirectoryError(errno.EISDIR, "Is a directory")

    monkeypatch.setattr(os, "fdopen", refusing)
    with pytest.raises(IsADirectoryError):
        ta.evaluate_anchor(ta.AnchorSpec("outbound:X", "setting", path))
    assert opened
    assert set(opened) <= set(closed)


@pytest.mark.parametrize("reader", ["anchor", "driver"])
def test_a_directory_leaves_no_descriptor_open(
    reader: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory is judged by its stat and never opened, so no descriptor is left open. Red on
    POSIX with either reader back on ``os.fdopen(os.open(...))`` and no stat first."""
    opened, closed = _recording_descriptors(monkeypatch)
    if reader == "anchor":
        with pytest.raises(OSError):
            ta.evaluate_anchor(ta.AnchorSpec("outbound:X", "setting", str(tmp_path)))
    else:
        assert f"SSLCA={{{tmp_path}}}" in _build_odbc_dsn(_settings(tmp_path), connection=_OUT)
    assert set(opened) <= set(closed)


def test_a_path_like_value_is_checked_at_the_text_the_driver_is_sent(tmp_path: Path) -> None:
    """The build sends ``str(value)``, so the check reads that file, and the remote screen judges
    that text. Red with ``driver_file_spellings`` back on ``os.fspath``: the check reads a
    different file from the one the driver is told to load."""
    sent = str(_ca(tmp_path, name="sent.pem"))

    class Split(os.PathLike[str]):
        def __fspath__(self) -> str:
            return str(tmp_path / "other.pem")

        def __str__(self) -> str:
            return sent

    assert database.driver_file_spellings(Split()) == (sent,)
