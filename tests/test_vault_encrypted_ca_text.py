# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Vault hop refuses CA text with an encryption header before any TLS load (BACKLOG #3090).

``NarrowedHTTPSConnection`` loads a ``str`` ``ca_cert_data`` as PEM text, and an encrypted block
in that text makes OpenSSL wait for a password. ``tests/test_encrypted_pem_cafile_pin.py`` measures
that with the real library, in a child process. Nothing here runs a real load of such text: the TLS
context is a stand-in, and so is the socket, so a regression fails at once and cannot hang the
suite. ``tests/test_trust_anchors.py`` does the same for BACKLOG #2270.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import requests
import urllib3.exceptions
from urllib3._base_connection import ProxyConfig
from urllib3.util import parse_url

from messagefoundry.transports.strict_requests import StrictReplyAdapter, _narrowed_pool_classes

_HEADERS = "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n\n"
_BEGIN = "-----BEGIN CERTIFICATE-----\n"
#: A body that is not a certificate. Nothing here hands it to OpenSSL.
_PLAIN = _BEGIN + "SYNTHETICBODYMARKER\n-----END CERTIFICATE-----\n"


class _Stopped(Exception):
    """Raised by the stand-in socket, so ``connect`` ends once the CA has been dealt with."""


class _RecordingContext:
    """Stands in for the TLS context, and records what it was asked to load."""

    def __init__(self) -> None:
        self.loads: list[tuple[object, ...]] = []

    def load_verify_locations(self, *args: object) -> None:
        self.loads.append(args)


class _NoTlsLoad:
    """Stands in for the TLS context: a refusal must come before it is handed the text."""

    def load_verify_locations(self, *args: object) -> None:
        raise AssertionError("the TLS library was handed an encrypted block")


def _contexts(kind: type) -> tuple[list[Any], Any]:
    """A context factory that builds ``kind``, and the list of every context it built."""
    made: list[Any] = []

    def factory() -> Any:
        made.append(kind())
        return made[-1]

    return made, factory


def _connection(factory: Any, *, proxied: bool, **ca: Any) -> Any:
    """A narrowed connection that opens no socket, to Vault directly or through an https proxy."""
    cls = _narrowed_pool_classes(factory, connector="Vault test hop")["https"].ConnectionCls
    conn: Any
    if proxied:
        conn = cls(
            "vault.test",
            8200,
            proxy=parse_url("https://proxy.test:3128"),
            proxy_config=ProxyConfig(None, False, None, None),
            **ca,
        )
        conn.set_tunnel("vault.test", 8200, scheme="https")
    else:
        conn = cls("vault.test", 8200, **ca)

    def no_socket() -> None:
        raise _Stopped

    conn._new_conn = no_socket
    return conn


@pytest.mark.parametrize("proxied", [True, False], ids=["through an https proxy", "direct"])
@pytest.mark.parametrize(
    "text",
    [
        pytest.param(_PLAIN.replace(_BEGIN, _BEGIN + _HEADERS), id="Proc-Type and DEK-Info"),
        pytest.param(
            _PLAIN.replace(_BEGIN, _BEGIN + "DEK-Info: AES-256-CBC,0011\n\n"), id="DEK-Info"
        ),
        pytest.param(
            _PLAIN.replace(_BEGIN, _BEGIN + "proc-type: 4,ENCRYPTED\n\n"), id="lower case"
        ),
        pytest.param(_PLAIN + _PLAIN.replace(_BEGIN, _BEGIN + _HEADERS), id="second block"),
    ],
)
def test_encrypted_ca_text_is_refused_before_any_tls_load(proxied: bool, text: str) -> None:
    """Red under: the ``_refuse_encrypted_ca_text`` call removed from ``connect``. Through a proxy
    the stand-in context then raises its ``AssertionError``, and direct the stand-in socket raises
    ``_Stopped``. The refusal is the type a failed CA load raises, with fixed text."""
    made, factory = _contexts(_NoTlsLoad)
    conn = _connection(factory, proxied=proxied, ca_cert_data=text)
    with pytest.raises(urllib3.exceptions.SSLError, match="encryption header") as refusal:
        conn.connect()
    assert made == [], "a TLS context was built for CA text the hop refuses"
    assert "Vault test hop" in str(refusal.value)
    assert "SYNTHETICBODYMARKER" not in str(refusal.value), "the refusal echoed the CA text"
    assert "AES-256-CBC" not in str(refusal.value), "the refusal echoed the CA text"


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(_PLAIN, id="plain text"),
        pytest.param("Proc-Type: 4,ENCRYPTED\n" + _PLAIN, id="header above the first block"),
        pytest.param(b"\x30\x03\x02\x01\x01", id="DER bytes"),
        pytest.param(
            _PLAIN.replace(_BEGIN, _BEGIN + _HEADERS).encode("ascii"), id="bytes, read as DER"
        ),
    ],
)
def test_other_ca_data_still_reaches_the_proxy_leg_load(data: str | bytes) -> None:
    """The control: the check refuses only flagged text, and everything else is loaded as before.
    A header above the first block passes, as it does in ``anchor_cadata``, because OpenSSL skips
    every line outside a block. ``bytes`` are never checked: the load reads them as DER."""
    made, factory = _contexts(_RecordingContext)
    conn = _connection(factory, proxied=True, ca_cert_data=data)
    with pytest.raises(_Stopped):
        conn.connect()
    assert made[0].loads == [(None, None, data)], "the proxy leg did not load the CA data"
    assert conn.proxy_config.ssl_context is made[0]


def test_a_ca_directory_reaches_the_proxy_leg_and_is_not_refused(tmp_path: Path) -> None:
    """Why ``_refuse_encrypted_ca_text`` does not refuse a directory: requests passes one on.

    hvac hands ``VAULT_CAPATH`` to requests as ``verify``, and requests reads ``REQUESTS_CA_BUNDLE``
    and ``CURL_CA_BUNDLE`` the same way. This drives requests' own pool builder with a directory as
    ``verify``, so it pins the hand-off and not a copy of it. Red under: a refusal of a set
    ``ca_cert_dir``, which would stop a hop that works today."""
    made, factory = _contexts(_RecordingContext)
    adapter = StrictReplyAdapter(connector="Vault test hop", ssl_context_factory=factory)
    request = requests.Request("GET", "https://vault.test:8200/v1/sys/health").prepare()
    pool = adapter.get_connection_with_tls_context(
        request, str(tmp_path), proxies={"https": "https://proxy.test:3128"}
    )
    conn: Any = pool._new_conn()
    assert conn.ca_cert_dir == str(tmp_path) and conn.ca_certs is None
    conn.set_tunnel("vault.test", 8200, scheme="https")

    def no_socket() -> None:
        raise _Stopped

    conn._new_conn = no_socket
    with pytest.raises(_Stopped):
        conn.connect()
    assert made[0].loads == [(None, str(tmp_path), None)]
