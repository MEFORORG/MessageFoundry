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
    Runs on every platform; the POSIX test below opens a real pipe. Red with the regular-file test
    taken out of ``_read_driver_file``: the encrypted key behind it is read and refused."""
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
def test_a_pipe_named_as_sslcert_is_not_opened(tmp_path: Path) -> None:
    """Opening a pipe with no writer would wait, which is what the check exists to prevent."""
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
def test_a_pipe_named_as_sslkey_is_not_opened(tmp_path: Path, client: _Client) -> None:
    pipe = tmp_path / "client.key.pipe"
    os.mkfifo(pipe)
    assert f"sslkey={{{pipe}}}" in _build(
        _write(tmp_path, client.cert_pem), extra={"sslkey": str(pipe)}
    )


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
