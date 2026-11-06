# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A CA file the engine hands to another TLS stack is refused if it holds an encryption header
(BACKLOG #3090, item 3).

A ``Proc-Type: 4,ENCRYPTED`` block can send a TLS library to a password prompt. Python's ``ssl`` was
measured refusing such a CA file at once (``tests/test_encrypted_pem_cafile_pin.py``). A driver
that loads the file with its own library was not measured, so the engine checks the file first
wherever it hands a CA FILE path to one:

* ``[store].ssl_root_cert`` on SQL Server, sent as the ODBC ``ServerCertificate`` pin. The engine
  parses it first, but ``cryptography``'s parser accepts a certificate block with the headers, so
  the parse was not a refusal. :func:`messagefoundry.pki.load_pinned_server_certificate` now checks.
* ``odbc_params`` ``sslca`` on a generic DATABASE connection, which MySQL's ODBC driver loads.
* libpq's own root certificate on a psqlODBC connection, ``PGSSLROOTCERT`` or libpq's default
  ``root.crt``, which the engine never hands over but libpq reads from its environment (step 3).

A CA DIRECTORY handed to a driver is not changed: ``sslcapath`` is pinned here as still building.

Nothing here hands an encrypted block to a TLS library. Synthetic data only.
"""

from __future__ import annotations

import copy
import errno
import functools
import os
import re
import sys
import types
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from messagefoundry import pki
from messagefoundry.auth.trust_anchors import ENCRYPTION_HEADER_SCOPE, PRIVATE_KEY_SCOPE
from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.redaction import safe_exc
from messagefoundry.transports import database
from messagefoundry.transports.database import _build_odbc_dsn
from tests._encrypted_pem_probe import ENCRYPTION_HEADERS as _HEADERS

_CONNECTION = "OB_DB_GEN"
_KEY_LABEL = "RSA PRIVATE" + " KEY"  # split, so a secret scanner does not read a real key


@functools.cache
def _certificate() -> str:
    """One synthetic server certificate per run: key generation is the slow part."""
    return pki.make_self_signed("db.synthetic.test", [], 30)[0].decode("ascii")


def _headered(pem: str) -> str:
    begin, rest = pem.split("\n", 1)
    return f"{begin}\n{_HEADERS}{rest}"


def _shapes() -> list[Any]:
    cert = _certificate()
    return [
        pytest.param(_headered(cert), id="certificate with both headers"),
        pytest.param(
            cert + f"-----BEGIN {_KEY_LABEL}-----\n{_HEADERS}AAAA\n-----END {_KEY_LABEL}-----\n",
            id="certificate then an encrypted key block",
        ),
        # The check errs wide on purpose, as anchor_cadata's does (#3105).
        pytest.param(cert + "# DEK-Info: noted\n", id="header name after the last END"),
    ]


def _write(tmp_path: Path, text: str, name: str = "synthetic.pem") -> str:
    path = tmp_path / name
    # Bytes, so the file holds exactly ``text`` on every platform, with no CRLF translation.
    path.write_bytes(text.encode("ascii"))
    return str(path)


def _body_of(text: str) -> str:
    """One full line of the certificate's base64 body, which no refusal may echo."""
    return next(line for line in text.splitlines() if len(line) == 64)


# --- [store].ssl_root_cert, the SQL Server ServerCertificate pin --------------------------------


def _sqlserver(pin: str) -> StoreSettings:
    return StoreSettings(
        backend=StoreBackend.SQLSERVER,
        server="db.synthetic.test",
        database="mefor",
        username="mefor",
        ssl_root_cert=pin,
    )


@pytest.mark.parametrize("text", _shapes())
def test_a_sqlserver_pin_with_an_encryption_header_is_refused_at_load(
    tmp_path: Path, text: str
) -> None:
    """Red with the header check removed from ``load_pinned_server_certificate``: each shape is a
    single server certificate ``cryptography`` parses, so the load validator would pass it to the
    driver."""
    pin = _write(tmp_path, text)
    with pytest.raises(ValidationError, match=r"\[store\]\.ssl_root_cert") as refused:
        _sqlserver(pin)
    message = str(refused.value)
    assert ENCRYPTION_HEADER_SCOPE in message
    assert "AES-256-CBC" not in message and _body_of(text) not in message
    # The store's own open-time check reads the file through the same function.
    reason = pki.read_pinned_server_certificate(pin)
    assert isinstance(reason, str) and reason.startswith("is not a usable SQL Server pin: it names")


def test_cryptography_alone_would_accept_the_headered_pin(tmp_path: Path) -> None:
    """Why the parse was not already a refusal: the certificate under the headers parses."""
    from cryptography import x509

    text = _headered(_certificate())
    assert len(x509.load_pem_x509_certificates(text.encode("ascii"))) == 1


def test_a_plain_sqlserver_pin_still_loads(tmp_path: Path) -> None:
    """The control: the same certificate without the headers is accepted."""
    pin = _write(tmp_path, _certificate())
    assert _sqlserver(pin).ssl_root_cert == pin
    assert not isinstance(pki.read_pinned_server_certificate(pin), str)


# --- odbc_params sslca, a generic DATABASE connection's CA file ---------------------------------


def _build_generic(driver: str, params: dict[str, Any]) -> str:
    settings = {
        "dialect": "generic",
        "odbc_driver": driver,
        "server": "db.synthetic.test",
        "odbc_params": params,
    }
    return _build_odbc_dsn(settings, connection=_CONNECTION)


def _build(**params: Any) -> str:
    return _build_generic("MySQL ODBC 9.1 Unicode Driver", {"SSLMODE": "VERIFY_IDENTITY", **params})


@pytest.mark.parametrize("spelling", ["sslca", "SSLCA"])
@pytest.mark.parametrize("text", _shapes())
def test_an_sslca_file_with_an_encryption_header_is_refused(
    tmp_path: Path, text: str, spelling: str
) -> None:
    """Red with ``_refuse_encrypted_driver_ca`` removed: the builder would hand the path on."""
    ca = _write(tmp_path, text)
    with pytest.raises(ValueError, match="odbc_params sslca") as refused:
        _build(**{spelling: ca})
    message = str(refused.value)
    assert _CONNECTION in message
    assert ENCRYPTION_HEADER_SCOPE in message
    assert "AES-256-CBC" not in message and _body_of(text) not in message


def test_a_plain_sslca_file_still_builds(tmp_path: Path) -> None:
    """The control: the same certificate without the headers goes to the driver unchanged."""
    ca = _write(tmp_path, _certificate())
    assert f"SSLCA={ca};" in _build(SSLCA=ca)


#: BACKLOG #3745: a key block with no encryption header, PKCS#8 encrypted and plain.
_KEY_SHAPES = [
    pytest.param("ENCRYPTED PRIVATE" + " KEY", id="PKCS#8 encrypted"),
    pytest.param("PRIVATE" + " KEY", id="plain"),
]


def _with_key(label: str) -> str:
    return _certificate() + f"-----BEGIN {label}-----\nAAAA\n-----END {label}-----\n"


@pytest.mark.parametrize("label", _KEY_SHAPES)
def test_a_sqlserver_pin_with_a_private_key_is_refused_at_load(tmp_path: Path, label: str) -> None:
    """Red with the private-key check removed from ``load_pinned_server_certificate``:
    ``cryptography`` parses the one certificate and skips the key block."""
    pin = _write(tmp_path, _with_key(label))
    with pytest.raises(ValidationError, match=r"\[store\]\.ssl_root_cert") as refused:
        _sqlserver(pin)
    assert PRIVATE_KEY_SCOPE in str(refused.value)
    assert "AAAA" not in str(refused.value)


@pytest.mark.parametrize("label", _KEY_SHAPES)
def test_an_sslca_file_with_a_private_key_is_refused(tmp_path: Path, label: str) -> None:
    """Red with the private-key check removed from ``_refuse_encrypted_driver_ca``."""
    ca = _write(tmp_path, _with_key(label))
    with pytest.raises(ValueError, match=re.escape(f"the CA file {PRIVATE_KEY_SCOPE}")) as refused:
        _build(sslca=ca)
    assert _CONNECTION in str(refused.value) and "AAAA" not in str(refused.value)


def test_a_missing_sslca_file_is_left_to_the_driver(tmp_path: Path) -> None:
    ca = str(tmp_path / "no-such-ca.pem")
    assert f"sslca={ca};" in _build(sslca=ca)


def test_an_sslca_file_the_check_cannot_read_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca = _write(tmp_path, _certificate())

    real_open = os.open

    def unreadable(path: Any, *args: Any, **kwargs: Any) -> int:
        if str(path) == ca:
            raise PermissionError(13, "Permission denied")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", unreadable)
    with pytest.raises(ValueError, match="could not be read to check it") as refused:
        _build(sslca=ca)
    assert "Permission denied" in str(refused.value)


def test_an_sslca_file_past_the_read_cap_is_refused_not_read_in_part(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A header past a partial read would pass unseen, so an over-cap file is refused."""
    text = _certificate() + "# DEK-Info: noted\n"
    ca = _write(tmp_path, text)
    monkeypatch.setattr(database, "_MAX_DRIVER_CA_FILE_BYTES", len(text) - 5)
    with pytest.raises(ValueError, match="larger than"):
        _build(sslca=ca)
    # At exactly the cap the whole file is read, so the header refusal fires, not the size one.
    monkeypatch.setattr(database, "_MAX_DRIVER_CA_FILE_BYTES", len(text))
    with pytest.raises(ValueError, match=re.escape(f"the CA file {ENCRYPTION_HEADER_SCOPE}")):
        _build(sslca=ca)


def test_a_padded_sslca_value_is_refused(tmp_path: Path) -> None:
    """BACKLOG #2705: values are sent unbraced, and a driver may trim a padded one or keep it, so
    a padded value is refused at build, whatever the file holds."""
    ca = _write(tmp_path, _headered(_certificate()))
    with pytest.raises(ValueError, match="must not be empty, blank, or start or end with a space"):
        _build(sslca=f" {ca} ")
    plain = _write(tmp_path, _certificate(), "plain.pem")
    with pytest.raises(ValueError, match="must not be empty, blank, or start or end with a space"):
        _build(sslca=f" {plain} ")
    # The control: the same file unpadded builds.
    assert f"sslca={plain};" in _build(sslca=plain)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes need POSIX mkfifo")
def test_a_pipe_named_as_sslca_is_not_opened(tmp_path: Path) -> None:
    """Opening a pipe with no writer would wait, which is what the check exists to prevent."""
    pipe = tmp_path / "ca.pipe"
    os.mkfifo(pipe)
    assert f"sslca={pipe};" in _build(sslca=str(pipe))


def test_a_ca_directory_still_reaches_the_driver(tmp_path: Path) -> None:
    """The stated remainder: a directory is not changed, whether it is named as ``sslcapath``,
    where it belongs, or as ``sslca``. Each holds an encrypted block, and each still builds."""
    _write(tmp_path, _headered(_certificate()), "0a1b2c3d.0")
    assert f"sslcapath={tmp_path};" in _build(sslcapath=str(tmp_path))
    assert f"sslca={tmp_path};" in _build(sslca=str(tmp_path))


# --- libpq's own root certificate, which psqlODBC's libpq reads from the environment -----------


def _build_psql(sslmode: str = "verify-full") -> str:
    return _build_generic("PostgreSQL Unicode", {"SSLmode": sslmode})


@pytest.fixture
def _no_libpq_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A libpq home with no ``root.crt`` and no ``PGSSLROOTCERT``, so nothing reads the runner's
    own; the home is returned for a test to fill."""
    monkeypatch.delenv("PGSSLROOTCERT", raising=False)
    home = tmp_path / "libpq-home"
    home.mkdir()
    monkeypatch.setattr(database, "_libpq_home", lambda: str(home))
    return home


@pytest.mark.usefixtures("_no_libpq_root")
@pytest.mark.parametrize("text", _shapes())
def test_a_pgsslrootcert_with_an_encryption_header_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, text: str
) -> None:
    """BACKLOG #3090, step 3. Red with ``_refuse_encrypted_libpq_root_cert`` removed: the builder
    would build, and libpq would load the file at the first connect."""
    monkeypatch.setenv("PGSSLROOTCERT", _write(tmp_path, text))
    with pytest.raises(ValueError, match="libpq root certificate PGSSLROOTCERT") as refused:
        _build_psql()
    message = str(refused.value)
    assert _CONNECTION in message and ENCRYPTION_HEADER_SCOPE in message
    # A stored build failure goes through safe_exc, whose name-run scrub must leave the setting.
    assert "PGSSLROOTCERT" in safe_exc(refused.value)
    assert "AES-256-CBC" not in message and _body_of(text) not in message


@pytest.mark.parametrize("sslmode", ["verify-full", "verify-ca", "require", "prefer", "allow"])
def test_libpqs_default_root_certificate_with_an_encryption_header_is_refused(
    _no_libpq_root: Path, sslmode: str
) -> None:
    """With no ``PGSSLROOTCERT``, libpq reads ``root.crt`` under its home directory.

    Red with ``_refuse_encrypted_libpq_root_cert`` removed."""
    _write(_no_libpq_root, _headered(_certificate()), "root.crt")
    with pytest.raises(ValueError, match="DATABASE libpq's default root certificate") as refused:
        _build_psql(sslmode)
    assert ENCRYPTION_HEADER_SCOPE in str(refused.value)


@pytest.mark.parametrize("label", _KEY_SHAPES)
def test_libpqs_root_certificate_with_a_private_key_is_refused(
    _no_libpq_root: Path, label: str
) -> None:
    _write(_no_libpq_root, _with_key(label), "root.crt")
    with pytest.raises(ValueError, match=re.escape(f"the CA file {PRIVATE_KEY_SCOPE}")) as refused:
        _build_psql()
    assert "AAAA" not in str(refused.value)


def test_libpqs_root_certificate_controls_still_build(
    _no_libpq_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The controls: a plain root certificate builds; an encrypted one is not read under
    ``sslmode=disable``, by a driver that is not psqlODBC, or when ``PGSSLROOTCERT`` says
    ``system``; and a missing file is left to libpq."""
    assert "SSLmode=verify-full;" in _build_psql()  # no file at all
    _write(_no_libpq_root, _certificate(), "root.crt")
    assert "SSLmode=verify-full;" in _build_psql()
    _write(_no_libpq_root, _headered(_certificate()), "root.crt")
    assert "SSLmode=disable;" in _build_psql("disable")
    assert "SSLMODE=VERIFY_IDENTITY;" in _build()  # MySQL's driver reads no libpq root
    monkeypatch.setenv("PGSSLROOTCERT", "system")
    assert "SSLmode=verify-full;" in _build_psql()


@pytest.mark.usefixtures("_no_libpq_root")
def test_a_pgsslrootcert_on_another_host_is_refused_unread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Red with the ``names_another_host`` branch dropped: the build would read a share on the
    event loop. The refusal names the way out."""
    monkeypatch.setenv("PGSSLROOTCERT", "//db.synthetic.test/share/root.crt")
    with pytest.raises(ValueError, match="not a plain local path") as refused:
        _build_psql()
    assert "set PGSSLROOTCERT to a local path" in str(refused.value)


@pytest.mark.parametrize("source", ["default", "PGSSLROOTCERT"])
def test_libpqs_root_certificate_the_check_cannot_read_is_refused(
    _no_libpq_root: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    """A file libpq can ``stat`` but not open fails every connect in libpq too, where
    ``SSL_CTX_load_verify_locations`` refuses it; the engine refuses it at build."""
    root = _write(_no_libpq_root, _certificate(), "root.crt")
    if source == "PGSSLROOTCERT":
        monkeypatch.setenv("PGSSLROOTCERT", root)
    real_open = os.open

    def unreadable(path: Any, *args: Any, **kwargs: Any) -> int:
        if str(path) == root:
            raise PermissionError(13, "Permission denied")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", unreadable)
    with pytest.raises(ValueError, match="root certificate file could not be read to check it"):
        _build_psql()


@pytest.mark.skipif(os.name == "nt", reason="libpq reads HOME and the password file off Windows")
def test_libpqs_home_falls_back_to_the_password_file_for_an_empty_home(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """libpq 15 and later treat an empty ``HOME`` as unset; ``expanduser`` would give ``/``."""
    import pwd

    monkeypatch.setenv("HOME", "")
    expected = os.path.join(pwd.getpwuid(os.geteuid()).pw_dir, ".postgresql")
    assert database._libpq_home() == expected


@pytest.mark.skipif(os.name != "nt", reason="the shell folder is read on Windows only")
def test_libpqs_home_on_windows_is_the_shell_roaming_folder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """libpq asks the shell, so an unset ``APPDATA`` does not hide the default file."""
    monkeypatch.delenv("APPDATA", raising=False)
    home = database._libpq_home()
    assert home is not None and home.endswith(os.sep + "postgresql")


def _refuse_lookup() -> tuple[str, str] | None:
    raise AssertionError("the root certificate was looked up")


@pytest.mark.parametrize(
    "params",
    [
        pytest.param({}, id="no keyword"),
        pytest.param({"port": "5432"}, id="no TLS keyword"),
        pytest.param({"SSLmode": "disable"}, id="disable"),
    ],
)
def test_libpqs_root_certificate_is_not_looked_up_when_psqlodbc_sends_disable(
    monkeypatch: pytest.MonkeyPatch, params: dict[str, Any]
) -> None:
    """With no ``SSLmode`` psqlODBC sends ``disable`` to libpq (``DEFAULT_SSLMODE`` in its
    ``dlg_specific.h``), so libpq attempts no TLS and loads no root certificate. Red before the
    check keyed on the build's own ``sslmode``: an unset mode looked the file up."""
    monkeypatch.setattr(database, "_libpq_root_cert", _refuse_lookup)
    assert _build_generic("PostgreSQL Unicode", params).startswith("DRIVER={PostgreSQL Unicode};")


class _ShareNotReached(FileNotFoundError):
    """``ERROR_BAD_NETPATH``, as Windows reports a share it could not reach."""

    winerror = 53


#: CPython's class and errno for each Win32 code below, as ``OSError(None, "", None, code)``
#: maps them on Windows 11.
_WINDOWS_MAPPED: dict[int, tuple[type[OSError], int]] = {
    2: (FileNotFoundError, errno.ENOENT),
    3: (FileNotFoundError, errno.ENOENT),
    5: (PermissionError, errno.EACCES),
    15: (FileNotFoundError, errno.ENOENT),
    21: (PermissionError, errno.EACCES),
    23: (PermissionError, errno.EACCES),
    31: (PermissionError, errno.EACCES),
    32: (PermissionError, errno.EACCES),
    33: (PermissionError, errno.EACCES),
    59: (OSError, errno.EINVAL),
    64: (OSError, errno.EINVAL),
    65: (PermissionError, errno.EACCES),
    67: (FileNotFoundError, errno.ENOENT),
    121: (OSError, errno.EINVAL),
    123: (OSError, errno.EINVAL),
    161: (FileNotFoundError, errno.ENOENT),
    206: (FileNotFoundError, errno.ENOENT),
    267: (NotADirectoryError, errno.ENOTDIR),
    1231: (OSError, errno.EINVAL),
    1921: (OSError, errno.EINVAL),
}


def _windows_stat_failure(winerror: int) -> OSError:
    """A ``stat`` failure as Windows raises it, on any platform: ``winerror`` set, and the class
    and ``errno`` CPython maps it to."""
    base, mapped = _WINDOWS_MAPPED[winerror]
    failure_type = type(f"_WinError{winerror}", (base,), {"winerror": winerror})
    return cast(OSError, failure_type(mapped, f"Windows error {winerror}"))


def _win(winerror: int, refused: bool) -> Any:
    return pytest.param(_windows_stat_failure(winerror), refused, id=f"win-{winerror}")


@pytest.mark.skipif(sys.platform != "win32", reason="CPython maps Win32 codes on Windows only")
def test_the_windows_rows_match_cpythons_own_mapping() -> None:
    """The table the Windows rows are built from is what this CPython raises for each code."""
    for code, (base, mapped) in _WINDOWS_MAPPED.items():
        made = OSError(None, "", None, code)
        assert (type(made), made.errno) == (base, mapped), code


@pytest.mark.parametrize("source", ["default", "PGSSLROOTCERT"])
@pytest.mark.parametrize(
    ("failure", "refused"),
    [
        # Left: no file is there, or libpq, as the same identity, cannot stat it either.
        pytest.param(FileNotFoundError(errno.ENOENT, "No such file"), False, id="ENOENT"),
        pytest.param(NotADirectoryError(errno.ENOTDIR, "Not a directory"), False, id="ENOTDIR"),
        pytest.param(OSError(errno.ENAMETOOLONG, "File name too long"), False, id="ENAMETOOLONG"),
        pytest.param(OSError(errno.ELOOP, "Too many levels of symbolic links"), False, id="ELOOP"),
        pytest.param(PermissionError(errno.EACCES, "Permission denied"), False, id="EACCES"),
        pytest.param(PermissionError(errno.EPERM, "Not permitted"), False, id="EPERM"),
        pytest.param(ValueError("embedded null byte"), False, id="NUL"),
        *(_win(code, False) for code in (2, 3, 5, 15, 123, 161, 206, 267, 1921)),
        # Refused: a fault that may clear before a later connect, when libpq loads the file.
        pytest.param(OSError(errno.EIO, "Input/output error"), True, id="EIO"),
        pytest.param(OSError(errno.ETIMEDOUT, "Timed out"), True, id="ETIMEDOUT"),
        pytest.param(OSError(errno.ESTALE, "Stale file handle"), True, id="ESTALE"),
        pytest.param(OSError(errno.ENOTCONN, "Not connected"), True, id="ENOTCONN"),
        pytest.param(_ShareNotReached(errno.ENOENT, "No network path"), True, id="share"),
        *(_win(code, True) for code in (59, 64, 67, 121, 1231)),
        # A PermissionError on Windows other than ERROR_ACCESS_DENIED: an I/O, sharing, lock or
        # network fault, which may clear before a later connect.
        *(_win(code, True) for code in (21, 23, 31, 32, 33, 65)),
    ],
)
def test_a_root_certificate_the_engine_cannot_stat(
    _no_libpq_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    failure: Exception,
    refused: bool,
) -> None:
    """libpq 17's ``initialize_SSL`` loads the root file only when its ``stat`` succeeds; any
    other ``stat`` result skips the file, or fails a ``verify`` connect, without loading it. So a
    ``stat`` failure that says no file is there, or that libpq could not ``stat`` it either, is
    left to libpq. Red before ``leave_unstatable``: the failure refused the build. The sampled
    others are refused, an unreached share or an I/O fault, since libpq stats again at each
    connect and may load the file once the fault clears, when the check does not run again. Red
    on the I/O rows before the allowed set: the stat branch left every failure but 53 and 67."""
    root = _write(_no_libpq_root, _headered(_certificate()), "root.crt")
    if source == "PGSSLROOTCERT":
        monkeypatch.setenv("PGSSLROOTCERT", root)
    real_stat = os.stat

    def unstatable(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if str(path) == root:
            raise copy.copy(failure)  # a fresh one, so no traceback carries over between runs
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", unstatable)
    if refused:
        with pytest.raises(ValueError, match="root certificate file could not be read to check"):
            _build_psql()
    else:
        assert "SSLmode=verify-full;" in _build_psql()


def test_a_refused_stat_failure_takes_no_second_look(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Windows ``PermissionError`` outside the left set is refused at once, even on a
    directory: ``os.path.isdir`` would wait out the same device or network fault again, on the
    event loop, and its answer would leave the file. Red when the read's directory look ran."""
    target = str(tmp_path)
    real_stat = os.stat

    def faulting(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if str(path) == target:
            raise _windows_stat_failure(32)
        return real_stat(path, *args, **kwargs)

    def no_second_look(path: Any) -> bool:
        raise AssertionError("the path was looked at again after its stat failed")

    monkeypatch.setattr(os, "stat", faulting)
    monkeypatch.setattr(os.path, "isdir", no_second_look)
    with pytest.raises(ValueError, match="could not be read to check it"):
        database._read_driver_file(target, "setting", "file", "it", leave_unstatable=True)


def test_a_directory_swapped_in_after_a_passing_stat_is_still_left(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the test above: when the stat passes and the open then fails with a
    ``PermissionError`` on what is now a directory, the read's directory look still runs and leaves
    it. Red when a passing stat also skipped that look."""
    target = str(tmp_path)

    def swapped(path: Any, limit: int) -> bytes | None:
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(database, "read_if_regular", swapped)
    assert (
        database._read_driver_file(target, "setting", "file", "it", leave_unstatable=True) is None
    )


def test_an_unreached_share_at_the_stat_still_honours_leave_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refused ``stat`` failure is judged as a failed read is, so ``leave_unreachable`` still
    turns a share Windows could not reach into :class:`_UnreachedShare`, not a refusal. Red when
    the stat branch raised the refusal itself."""
    target = str(tmp_path / "root.crt")
    real_stat = os.stat

    def unreached(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
        if str(path) == target:
            raise _ShareNotReached(errno.ENOENT, "No network path")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", unreached)
    with pytest.raises(database._UnreachedShare):
        database._read_driver_file(
            target, "setting", "file", "it", leave_unstatable=True, leave_unreachable=True
        )


@pytest.mark.skipif(sys.platform == "win32", reason="libpq reads the password file off Windows")
def test_libpqs_home_for_an_empty_password_file_home_is_the_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """libpq builds the path as ``'%s/%s'``, so an empty home names ``/.postgresql``
    (``pqGetHomeDirectory``, libpq 17). Red when an empty home gave ``None``, which read nothing.
    The control: no password-file entry names no home, as libpq names none."""
    import pwd

    monkeypatch.setenv("HOME", "")
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: types.SimpleNamespace(pw_dir=""))
    assert database._libpq_home() == os.path.join(os.sep, ".postgresql")

    def no_entry(uid: int) -> Any:
        raise KeyError(uid)

    monkeypatch.setattr(pwd, "getpwuid", no_entry)
    assert database._libpq_home() is None


@pytest.mark.skipif(sys.platform != "win32", reason="the shell folder is read on Windows only")
def test_libpqs_home_for_an_empty_shell_folder_is_the_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """libpq builds ``'%s/postgresql'``, so an empty folder names ``/postgresql`` on the current
    drive (``pqGetHomeDirectory``, libpq 17). Red when an empty folder gave ``None``. The
    control: a failed shell call names no home, as libpq names none."""
    monkeypatch.setattr(database, "_windows_roaming_appdata", lambda: "")
    assert database._libpq_home() == os.path.join(os.sep, "postgresql")
    monkeypatch.setattr(database, "_windows_roaming_appdata", lambda: None)
    assert database._libpq_home() is None


def test_a_libpq_home_the_engine_cannot_name_refuses_the_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A shell call the engine cannot make is a refusal that names the way out, never an
    ``OSError`` out of the builder, and never a check that read nothing."""
    monkeypatch.delenv("PGSSLROOTCERT", raising=False)

    def unnamed() -> str | None:
        raise OSError("synthetic: shell32 did not load")

    monkeypatch.setattr(database, "_libpq_home", unnamed)
    with pytest.raises(ValueError, match="root certificate: set PGSSLROOTCERT to a local path"):
        _build_psql()


@pytest.mark.skipif(sys.platform != "win32", reason="shell32 is loaded on Windows only")
@pytest.mark.parametrize("failure", ["load", "export"])
def test_a_shell32_failure_is_an_oserror_the_build_refuses(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    """Red before the load was caught: ``WinDLL``'s ``OSError`` and a missing export's
    ``AttributeError`` escaped the builder as themselves."""
    import ctypes

    def broken(name: str, *args: Any, **kwargs: Any) -> object:
        if failure == "load":
            raise OSError("synthetic: shell32 did not load")
        return object()  # no SHGetFolderPathW on it

    monkeypatch.setattr(ctypes, "WinDLL", broken)
    with pytest.raises(OSError, match="SHGetFolderPathW could not be loaded"):
        database._windows_roaming_appdata()
    monkeypatch.delenv("PGSSLROOTCERT", raising=False)
    with pytest.raises(ValueError, match="set PGSSLROOTCERT to a local path"):
        _build_psql()


@pytest.mark.parametrize("keyword", ["sslrootcert", "sslcrl", "sslcrldir", "ServerCertificate"])
def test_other_drivers_ca_keywords_never_reach_a_driver(keyword: str) -> None:
    """Inventory evidence: psqlODBC's CA and CRL keywords, and SQL Server's pin keyword, are off the
    generic dialect's list, so this connector never hands their paths to a driver."""
    with pytest.raises(ValueError, match="must not set"):
        _build(**{keyword: "/etc/ssl/synthetic.pem"})
