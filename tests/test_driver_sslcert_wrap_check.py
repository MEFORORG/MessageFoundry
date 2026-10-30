# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A generic DATABASE connection's ``odbc_params`` ``sslcert`` takes the key-wrap check ``sslkey``
takes (vault BACKLOG #3090, step 5).

``sslcert`` names a client certificate the driver loads with its own TLS library, and a PEM there
may carry the private key. A certificate-chain load is the one that can prompt for a passphrase,
so before this an encrypted key in that file, with no ``sslpassword``, reached a driver that could
wait on a prompt nobody sees. The check reads the file as the ``sslca`` check reads it: a pipe is
never read, and a missing file is left to the driver.

Synthetic keys and certificates only.
"""

from __future__ import annotations

import datetime
import errno
import os
import stat
from pathlib import Path
from typing import Any, NamedTuple

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry import keywrap
from messagefoundry.keywrap import KeyWrapRefused
from messagefoundry.transports import database
from messagefoundry.transports.database import _build_odbc_dsn
from tests.test_keywrap import _PASSPHRASE, _legacy_pem, _pkcs8

_CONNECTION = "OB_DB_GEN"


class _Client(NamedTuple):
    cert_pem: bytes
    cert_der: bytes
    plain_key: bytes
    approved_key: bytes
    legacy_key: bytes


@pytest.fixture(scope="module")
def client() -> _Client:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client.synthetic.test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    plain = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return _Client(
        cert.public_bytes(serialization.Encoding.PEM),
        cert.public_bytes(serialization.Encoding.DER),
        plain,
        _pkcs8(key, prf="sha256", iterations=600_000),
        _legacy_pem(key),
    )


def _write(tmp_path: Path, data: bytes, name: str = "client.pem") -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def _build(
    cert: str,
    *,
    sslpassword: str | None = None,
    spelling: str = "sslcert",
    extra: dict[str, str] | None = None,
) -> str:
    params: dict[str, str] = {"SSLmode": "verify-full", spelling: cert, **(extra or {})}
    if sslpassword is not None:
        params["sslpassword"] = sslpassword
    settings: dict[str, Any] = {
        "dialect": "generic",
        "odbc_driver": "MySQL ODBC 9.1 Unicode Driver",
        "server": "db.synthetic.test",
        "odbc_params": params,
    }
    return _build_odbc_dsn(settings, connection=_CONNECTION)


@pytest.mark.parametrize("spelling", ["sslcert", "SSLCERT"])
def test_an_encrypted_key_in_sslcert_with_no_sslpassword_is_refused(
    tmp_path: Path, client: _Client, spelling: str
) -> None:
    """Red with the ``_refuse_weak_driver_cert`` call taken out of ``_build_odbc_dsn``: the build
    hands the path on. The refusal names the setting, and never the key or the path."""
    path = _write(tmp_path, client.cert_pem + client.approved_key)
    with pytest.raises(KeyWrapRefused, match="Set odbc_params sslpassword") as refused:
        _build(path, spelling=spelling)
    message = str(refused.value)
    assert _CONNECTION in message and "odbc_params sslcert" in message
    assert path not in message and "ENCRYPTED" not in message


def test_the_same_key_with_its_sslpassword_builds(tmp_path: Path, client: _Client) -> None:
    """The control: an approved wrap with its passphrase set goes to the driver unchanged."""
    path = _write(tmp_path, client.cert_pem + client.approved_key)
    assert f"sslcert={{{path}}}" in _build(path, sslpassword=_PASSPHRASE)


def test_a_legacy_proc_type_key_is_refused_even_with_its_sslpassword(
    tmp_path: Path, client: _Client
) -> None:
    """A ``Proc-Type: 4,ENCRYPTED`` key is derived with MD5 at one iteration, so ``keywrap``
    refuses it with or without a passphrase, as it does under ``sslkey``."""
    path = _write(tmp_path, client.cert_pem + client.legacy_key)
    for password in (None, _PASSPHRASE):
        with pytest.raises(KeyWrapRefused, match="legacy OpenSSL PEM encryption"):
            _build(path, sslpassword=password)


def test_a_plain_pem_certificate_builds(tmp_path: Path, client: _Client) -> None:
    path = _write(tmp_path, client.cert_pem)
    assert f"sslcert={{{path}}}" in _build(path)


def test_a_der_certificate_builds(tmp_path: Path, client: _Client) -> None:
    """A DER certificate has no PEM block, so ``keywrap`` reads it as bare DER. Its outer
    SEQUENCE has three parts, not the two of an EncryptedPrivateKeyInfo, so ``_der_problem`` reads
    it as no encrypted key, and it builds."""
    assert keywrap._der_problem(client.cert_der, known_encrypted=False) == (False, None)
    path = _write(tmp_path, client.cert_der, "client.der")
    assert f"sslcert={{{path}}}" in _build(path)


def test_a_certificate_with_its_plain_key_builds(tmp_path: Path, client: _Client) -> None:
    """The private-key-label refusal an ``sslca`` file takes (BACKLOG #3745) is not applied: a
    client certificate file may hold its own key."""
    path = _write(tmp_path, client.cert_pem + client.plain_key)
    assert f"sslcert={{{path}}}" in _build(path)


def test_a_missing_sslcert_is_left_to_the_driver(tmp_path: Path) -> None:
    path = str(tmp_path / "no-such-client.pem")
    assert f"sslcert={{{path}}}" in _build(path)


def test_a_padded_value_is_checked_as_a_driver_may_trim_it(tmp_path: Path, client: _Client) -> None:
    path = _write(tmp_path, client.cert_pem + client.approved_key)
    with pytest.raises(KeyWrapRefused, match="Set odbc_params sslpassword"):
        _build(f" {path} ")


def test_a_file_that_is_not_regular_is_not_read(
    tmp_path: Path, client: _Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file the open handle reports as a pipe is never read, so a pipe cannot hold the build.
    Runs on every platform; the POSIX test below opens a real pipe. Red with the descriptor's
    regular-file test taken out of ``trust_anchors.read_if_regular``, which ``_read_driver_file``
    reads through: the encrypted key behind it is read and refused."""
    path = _write(tmp_path, client.cert_pem + client.approved_key)
    real_fstat = os.fstat
    handles: set[int] = set()
    real_open = os.open

    def opening(name: Any, *args: Any, **kwargs: Any) -> int:
        fd = real_open(name, *args, **kwargs)
        if str(name) == path:
            handles.add(fd)
        return fd

    def as_pipe(fd: int) -> Any:
        result = real_fstat(fd)
        if fd not in handles:
            return result
        fields = list(result)
        fields[0] = stat.S_IFIFO | 0o600
        return os.stat_result(fields)

    monkeypatch.setattr(os, "open", opening)
    monkeypatch.setattr(os, "fstat", as_pipe)
    assert f"sslcert={{{path}}}" in _build(path)
    assert handles
    # The same pipe named as sslkey is refused unread, as keywrap refused what it could not read.
    with pytest.raises(KeyWrapRefused, match="not a regular file"):
        _build(_write(tmp_path, client.cert_pem, "plain.pem"), extra={"sslkey": path})


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes need POSIX mkfifo")
def test_a_pipe_named_as_sslcert_is_left_to_the_driver_unread(tmp_path: Path) -> None:
    """Reading a pipe with no writer would wait, which is what the check exists to prevent."""
    pipe = tmp_path / "client.pipe"
    os.mkfifo(pipe)
    assert f"sslcert={{{pipe}}}" in _build(str(pipe))


def test_an_sslcert_past_the_read_cap_is_refused(
    tmp_path: Path, client: _Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The read is capped as the ``sslca`` read is, and an over-cap file is refused, not read in
    part, since a key past the cut would pass unseen."""
    data = client.cert_pem + client.approved_key
    path = _write(tmp_path, data)
    monkeypatch.setattr(database, "_MAX_DRIVER_CA_FILE_BYTES", len(data) - 1)
    with pytest.raises(ValueError, match="certificate file is larger than"):
        _build(path, sslpassword=_PASSPHRASE)


class _WindowsReadError(OSError):
    """An ``OSError`` carrying a Win32 code on any platform, as CPython raises one on Windows."""

    winerror: int = 0


class _WindowsNotFound(FileNotFoundError):
    """A ``FileNotFoundError`` carrying a Win32 code on any platform."""

    winerror: int = 0


def _read_failure(shape: str) -> OSError:
    """One failure ``read_if_regular`` can raise, by the shape a test names."""
    kind, _, code = shape.partition(":")
    if kind == "einval" and not code:
        # A CRT or POSIX EINVAL: winerror is None on Windows and absent on POSIX.
        return OSError(errno.EINVAL, "Invalid argument")
    if kind == "einval":
        einval = _WindowsReadError(errno.EINVAL, "Invalid argument")
        einval.winerror = int(code)
        return einval
    if not code:
        return FileNotFoundError(errno.ENOENT, "No such file or directory")
    missing = _WindowsNotFound(errno.ENOENT, "No such file or directory")
    missing.winerror = int(code)
    return missing


@pytest.mark.parametrize(
    ("shape", "refused"),
    [
        ("einval", True),
        ("einval:1920", True),
        ("einval:1117", True),
        ("einval:123", False),
        ("notfound:53", True),
        ("notfound:67", True),
        ("notfound", False),
    ],
)
def test_a_read_failure_that_names_no_file_is_the_only_one_left_to_the_driver(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str, refused: bool
) -> None:
    """CPython maps every Win32 error it has no errno for to EINVAL, so a real failure to read the
    key (1920, ERROR_CANT_ACCESS_FILE; 1117, ERROR_IO_DEVICE) arrives as EINVAL, as a CRT or POSIX
    EINVAL does, and is refused. Only 123, ERROR_INVALID_NAME, names no file. A share Windows could
    not reach (53, 67) arrives as FileNotFoundError, and is refused too, since the driver may reach
    the file later. Red with ``_read_driver_file`` leaving any EINVAL, or any FileNotFoundError, to
    the driver: the unreadable key is never checked."""
    path = _write(tmp_path, b"unread")
    error = _read_failure(shape)

    def failing(*_args: Any) -> bytes | None:
        raise error

    monkeypatch.setattr(database, "read_if_regular", failing)
    plain = _write(tmp_path, b"plain", "plain.pem")
    if refused:
        with pytest.raises(KeyWrapRefused, match="could not be read"):
            _build(plain, extra={"sslkey": path})
    else:
        assert f"sslkey={{{path}}}" in _build(plain, extra={"sslkey": path})


def _record_looks(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The paths anything stats, through the ``os`` and ``os.path`` calls that look at a path."""
    looked: list[str] = []
    for owner, name in (
        (os, "stat"),
        (os, "lstat"),
        (os.path, "exists"),
        (os.path, "lexists"),
        (os.path, "isdir"),
        (os.path, "isfile"),
    ):
        real = getattr(owner, name)

        def look(target: Any, *args: Any, _real: Any = real, **kwargs: Any) -> Any:
            if isinstance(target, (str, os.PathLike)):
                looked.append(os.fspath(target))
            return _real(target, *args, **kwargs)

        monkeypatch.setattr(owner, name, look)
    return looked


@pytest.mark.parametrize(
    ("shape", "refused"),
    [("notfound:53", True), ("notfound", False), ("einval:1231", True)],
)
def test_a_failed_read_is_judged_from_the_first_error_with_no_second_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str, refused: bool
) -> None:
    """Only a failure a directory swapped in can cause is looked at again. On a share Windows
    could not reach, a second look waits out the same network timeout on the event loop, whether
    the share's failure arrives as a missing name or as an EINVAL (1231,
    ERROR_NETWORK_UNREACHABLE). Red with ``os.path.isdir`` asked after every failure: it is called
    for the path.

    Only the looks AFTER the failed read count. Before it, the remote-path screen walks the path's
    own components (BACKLOG #2705), which is a first look, and it never stats anything on a share
    or a network drive: it stops at either before reading it."""
    path = _write(tmp_path, b"unread")
    error = _read_failure(shape)
    looked = _record_looks(monkeypatch)

    def failing(*_args: Any) -> bytes | None:
        looked.clear()
        raise error

    monkeypatch.setattr(database, "read_if_regular", failing)
    if refused:
        with pytest.raises(ValueError, match="could not be read"):
            _build(path, spelling="sslca")
    else:
        assert f"sslca={{{path}}}" in _build(path, spelling="sslca")
    assert path not in looked


@pytest.mark.parametrize("mode", ["disable", "DISABLED"])
def test_an_unreachable_sslca_the_driver_never_reads_does_not_fail_the_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    """Under a mode that turns TLS off the driver reads no CA (``generic_odbc_tls_off``), so a
    share that cannot be reached at build time is not a reason to refuse. Red with the
    unreachable-share refusal applied whatever the mode. The control: the same share under
    ``verify-full``, where the driver reads the CA, is refused."""
    path = _write(tmp_path, b"unread")
    error = _read_failure("notfound:67")

    def failing(*_args: Any) -> bytes | None:
        raise error

    monkeypatch.setattr(database, "read_if_regular", failing)
    assert f"sslca={{{path}}}" in _build(path, spelling="sslca", extra={"SSLmode": mode})
    with pytest.raises(ValueError, match="could not be read"):
        _build(path, spelling="sslca")


@pytest.mark.parametrize(("spelling", "left"), [("sslca", True), ("sslkey", False)])
def test_a_directory_swapped_in_that_fails_the_open_is_judged_as_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spelling: str, left: bool
) -> None:
    """On Windows a directory swapped in after the stat fails the open with PermissionError, so
    that failure alone is looked at again: a directory is left to the driver, and refused unread
    as ``sslkey``. Red with ``PermissionError`` dropped from the failures re-checked: the CA
    directory is refused as unreadable, and the key as unreadable rather than as no file."""
    folder = tmp_path / "swapped"
    folder.mkdir()

    def failing(*_args: Any) -> bytes | None:
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(database, "read_if_regular", failing)
    if left:
        assert f"{spelling}={{{folder}}}" in _build(str(folder), spelling=spelling)
    else:
        with pytest.raises(KeyWrapRefused, match="not a regular file"):
            _build(_write(tmp_path, b"plain"), extra={spelling: str(folder)})


def test_an_unreachable_sslca_under_tls_off_is_read_at_one_spelling_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A padded value has two spellings on one share. Once the first is left to the driver as
    unreached, the trimmed one is not read, since it would wait out the same timeout again. Red
    with the loop going on to the next spelling: two reads."""
    path = _write(tmp_path, b"unread")
    error = _read_failure("notfound:53")
    reads: list[str] = []

    def failing(target: str, *_args: Any) -> bytes | None:
        reads.append(target)
        raise error

    monkeypatch.setattr(database, "read_if_regular", failing)
    padded = path + "  "
    assert "sslca=" in _build(padded, spelling="sslca", extra={"SSLmode": "disable"})
    assert reads == [padded]


@pytest.mark.parametrize(
    ("spelling", "shape", "refusal"),
    [
        ("sslkey", "notfound:53", KeyWrapRefused),
        ("sslcert", "notfound:67", KeyWrapRefused),
        ("sslca", "einval:1920", ValueError),
    ],
)
def test_tls_off_leaves_only_an_unreached_sslca_to_the_driver(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    spelling: str,
    shape: str,
    refusal: type[ValueError],
) -> None:
    """The carve-out is the CA's alone, and only for a share that was not reached: an unreached
    ``sslkey`` or ``sslcert``, and a CA that failed to read in any other way, are still refused
    under ``disable``. Red with the carve-out widened to either."""
    path = _write(tmp_path, b"unread")
    error = _read_failure(shape)

    def failing(*_args: Any) -> bytes | None:
        raise error

    monkeypatch.setattr(database, "read_if_regular", failing)
    with pytest.raises(refusal, match="could not be read"):
        _build(path, spelling=spelling, extra={"SSLmode": "disable"})


def test_a_readable_sslca_is_still_checked_when_tls_is_off(tmp_path: Path) -> None:
    """Only the unreachable share is left to a driver that reads no CA. A CA file the engine can
    read is checked as before, so an encrypted block in it is refused under ``disable`` too."""
    path = _write(tmp_path, b"-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n", "ca.pem")
    with pytest.raises(ValueError, match="encryption header"):
        _build(path, spelling="sslca", extra={"SSLmode": "disable"})


def test_with_sslkey_set_sslcert_is_not_read(tmp_path: Path, client: _Client) -> None:
    """With ``sslkey`` set the driver takes the key from that file, so an encrypted key left in a
    combined ``sslcert`` export is never loaded. ``refuse_weak_cert_chain_key`` follows the same
    rule. Red with the ``sslkey`` test taken out of ``_refuse_weak_driver_cert``."""
    cert = _write(tmp_path, client.cert_pem + client.approved_key)
    key = _write(tmp_path, client.plain_key, "client.key")
    dsn = _build(cert, extra={"sslkey": key})
    assert f"sslcert={{{cert}}}" in dsn and f"sslkey={{{key}}}" in dsn
    # The control: the same sslcert alone is refused.
    with pytest.raises(KeyWrapRefused, match="Set odbc_params sslpassword"):
        _build(cert)


def test_a_padded_sslkey_is_checked_as_a_driver_may_trim_it(
    tmp_path: Path, client: _Client
) -> None:
    """``sslkey`` is read the way ``sslcert`` and ``sslca`` are, so a padded value is checked at
    its trimmed spelling too. Red with ``_refuse_weak_driver_key`` back on ``refuse_weak_key_file``:
    the raw spelling names no file, and the encrypted key passes."""
    key = _write(tmp_path, client.approved_key, "client.key")
    with pytest.raises(KeyWrapRefused, match="Set odbc_params sslpassword"):
        _build(_write(tmp_path, client.cert_pem), extra={"sslkey": f" {key} "})


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes need POSIX mkfifo")
def test_a_pipe_named_as_sslkey_is_refused_without_waiting(tmp_path: Path, client: _Client) -> None:
    """``sslkey`` keeps keywrap's refusal of a file it cannot read, so a real pipe is refused, and
    the open does not wait for a writer."""
    pipe = tmp_path / "client.key.pipe"
    os.mkfifo(pipe)
    with pytest.raises(KeyWrapRefused, match="not a regular file"):
        _build(_write(tmp_path, client.cert_pem), extra={"sslkey": str(pipe)})


def test_a_blank_sslkey_does_not_turn_off_the_sslcert_check(
    tmp_path: Path, client: _Client
) -> None:
    """A blank ``sslkey`` names no key file, so a driver that trims it takes the key from
    ``sslcert``. Red with the ``.strip()`` taken out of ``_refuse_weak_driver_cert``."""
    cert = _write(tmp_path, client.cert_pem + client.approved_key)
    with pytest.raises(KeyWrapRefused, match="Set odbc_params sslpassword"):
        _build(cert, extra={"sslkey": " "})


def test_a_directory_named_as_sslkey_is_still_refused(tmp_path: Path, client: _Client) -> None:
    """``keywrap.refuse_weak_key_file`` refused a directory as unreadable, and ``sslkey`` keeps
    that. ``sslcert`` leaves one to the driver, as ``sslca`` does."""
    cert = _write(tmp_path, client.cert_pem)
    with pytest.raises(KeyWrapRefused, match="not a regular file"):
        _build(cert, extra={"sslkey": str(tmp_path)})
    assert f"sslcert={{{tmp_path}}}" in _build(str(tmp_path))
