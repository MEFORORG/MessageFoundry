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

A CA DIRECTORY handed to a driver is not changed: ``sslcapath`` is pinned here as still building.

Nothing here hands an encrypted block to a TLS library. Synthetic data only.
"""

from __future__ import annotations

import functools
import os
import re
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry import pki
from messagefoundry.auth.trust_anchors import ENCRYPTION_HEADER_SCOPE, PRIVATE_KEY_SCOPE
from messagefoundry.config.settings import StoreBackend, StoreSettings
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


def _build(**params: Any) -> str:
    settings = {
        "dialect": "generic",
        "odbc_driver": "MySQL ODBC 9.1 Unicode Driver",
        "server": "db.synthetic.test",
        "odbc_params": {"SSLMODE": "VERIFY_IDENTITY", **params},
    }
    return _build_odbc_dsn(settings, connection=_CONNECTION)


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


@pytest.mark.parametrize("keyword", ["sslrootcert", "sslcrl", "sslcrldir", "ServerCertificate"])
def test_other_drivers_ca_keywords_never_reach_a_driver(keyword: str) -> None:
    """Inventory evidence: psqlODBC's CA and CRL keywords, and SQL Server's pin keyword, are off the
    generic dialect's list, so this connector never hands their paths to a driver."""
    with pytest.raises(ValueError, match="must not set"):
        _build(**{keyword: "/etc/ssl/synthetic.pem"})
