# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A Vault CA the proxy leg's load refuses gives a fixed reason, not ``ProxyError`` (BACKLOG #3090).

``NarrowedHTTPSConnection._narrow_the_proxy_leg`` loads the hop's CA onto the context for the TLS
leg to an ``https://`` proxy. A load that raised used to come out of requests as a ``ProxyError``,
and ``vault_failure_text`` gave the providers only that type name. It now raises the hop's marked
``VaultHopRefused`` with fixed text, which reaches the caller as it is.

**No encrypted block is loaded by the real TLS library here.** ``tests/_encrypted_pem_probe.py``
says why such a load runs only in a child process the parent can kill, and
``tests/test_encrypted_pem_cafile_pin.py`` measures that a path load of one raises ``PEM lib`` at
once. So an encrypted file meets a stand-in context that raises what was measured. The real
library is driven with a CA file that holds no encryption header and no certificate, which it
refuses the same way, as an ``ssl.SSLError``, with nothing to wait for.

**The direct path, with no proxy, is measured and left as it was.** urllib3 loads the CA for the
Vault leg itself and wraps a refusal as its ``SSLError``, which requests reports as
``requests.exceptions.SSLError``. ``vault_failure_text`` gives that type name.

Synthetic data only: the CA files hold no real certificate.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.auth.trust_anchors import has_encryption_header
from tests._encrypted_pem_probe import ENCRYPTION_HEADERS as _HEADERS
from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed

pytestmark = pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)

_CONNECTOR = "Vault test hop"
_BEGIN = "-----BEGIN CERTIFICATE-----\n"
#: A body that is not a certificate, so a real load of it refuses with no header to act on.
_NOT_A_CERTIFICATE = _BEGIN + "SYNTHETICBODYMARKER\n-----END CERTIFICATE-----\n"
_ENCRYPTED = _NOT_A_CERTIFICATE.replace(_BEGIN, _BEGIN + _HEADERS)
#: The kind of error the load raised for an encrypted block in ``test_encrypted_pem_cafile_pin.py``.
_PEM_LIB = "[X509] PEM lib"
_PROXY = "https://127.0.0.1:9"
_URL = "https://127.0.0.1:9/v1/sys/health"


class _Stopped(Exception):
    """Raised where the connection would open a socket, so a CA the load took ends there."""


class _MeasuredPathLoad:
    """Stands in for the TLS context. A CA file with an encryption header raises what the real
    load raised for one; anything else is recorded as loaded."""

    def __init__(self) -> None:
        self.loads: list[tuple[object, ...]] = []

    def load_verify_locations(self, *args: object) -> None:
        cafile = args[0]
        if isinstance(cafile, str) and has_encryption_header(Path(cafile).read_text("ascii")):
            raise ssl.SSLError(9, _PEM_LIB)
        self.loads.append(args)


def _strict() -> Any:
    from messagefoundry.transports import strict_requests

    return strict_requests


def _fixed_reason(reason: str = "_UNLOADABLE_PROXY_LEG_CA") -> str:
    strict = _strict()
    return f"{_CONNECTOR}: {getattr(strict, reason)} {strict._PROXY_LEG_CA_LEVER}"


def _ca_file(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "synthetic-vault-ca.pem"
    path.write_text(text, encoding="ascii")
    return path


def _session(factory: Callable[[], Any], new_conn: Callable[[Any], Any]) -> Any:
    """A requests session on the hop's adapter, whose connections open ``new_conn``'s socket."""
    import requests

    adapter = _strict().StrictReplyAdapter(
        connector=_CONNECTOR,
        ssl_context_factory=factory,
        revocation_attested=True,
        attestation_section="secrets",
    )
    # The pool classes are this adapter's own, so the replacement reaches no other test.
    adapter._pool_classes["https"].ConnectionCls._new_conn = new_conn
    session = requests.Session()
    session.trust_env = False
    session.mount("https://", adapter)
    return session


def _no_socket(conn: Any) -> Any:
    raise _Stopped


def _contexts(kind: Callable[[], Any]) -> tuple[list[Any], Callable[[], Any]]:
    made: list[Any] = []

    def factory() -> Any:
        made.append(kind())
        return made[-1]

    return made, factory


def test_each_fixed_reason_says_only_what_its_exception_type_shows() -> None:
    """The refusals below equal these constants exactly, so their wording is pinned once, here.
    Content the library refused may be an encrypted block; a file it could not read was not
    loaded at all, so that text does not mention encryption."""
    strict = _strict()
    assert "encrypted" in strict._UNLOADABLE_PROXY_LEG_CA
    assert "could not be opened or read" in strict._UNREADABLE_PROXY_LEG_CA
    assert "encrypt" not in strict._UNREADABLE_PROXY_LEG_CA


class _UnreadableLoad:
    """Stands in for the TLS context: the load fails to read the file, as an ``OSError`` that is
    not an ``ssl.SSLError``."""

    def load_verify_locations(self, *args: object) -> None:
        raise PermissionError(13, "Permission denied")


def test_a_ca_file_the_load_cannot_read_gives_the_unreadable_reason(tmp_path: Path) -> None:
    ca = _ca_file(tmp_path, _NOT_A_CERTIFICATE)
    _, factory = _contexts(_UnreadableLoad)
    session = _session(factory, _no_socket)
    with pytest.raises(_strict().VaultHopRefused) as refusal:
        session.get(_URL, verify=str(ca), proxies={"https": _PROXY}, timeout=5)
    assert _strict().vault_failure_text(refusal.value) == _fixed_reason("_UNREADABLE_PROXY_LEG_CA")
    assert isinstance(refusal.value.__cause__, PermissionError)


def test_an_encrypted_ca_file_on_the_proxy_leg_gives_the_fixed_reason(tmp_path: Path) -> None:
    """Red under the old arm, ``raise urllib3.exceptions.SSLError(exc)``: requests then raises a
    ``ProxyError``, ``pytest.raises`` below does not match it, and ``vault_failure_text`` would
    have given ``"ProxyError"``."""
    ca = _ca_file(tmp_path, _ENCRYPTED)
    made, factory = _contexts(_MeasuredPathLoad)
    session = _session(factory, _no_socket)
    with pytest.raises(_strict().VaultHopRefused) as refusal:
        session.get(_URL, verify=str(ca), proxies={"https": _PROXY}, timeout=5)
    assert _strict().vault_failure_text(refusal.value) == _fixed_reason()
    # The cause is kept for a traceback; only the text is fixed.
    assert isinstance(refusal.value.__cause__, ssl.SSLError)
    assert len(made) == 1 and made[0].loads == [], "the proxy leg's context loaded the block"


def test_a_plain_ca_file_on_the_proxy_leg_is_loaded_and_not_refused(tmp_path: Path) -> None:
    """The control: the same request with a CA file the load takes gets past the load, and stops
    at the socket, for a reason that is not the fixed one."""
    ca = _ca_file(tmp_path, _NOT_A_CERTIFICATE)
    made, factory = _contexts(_MeasuredPathLoad)
    session = _session(factory, _no_socket)
    with pytest.raises(_Stopped):
        session.get(_URL, verify=str(ca), proxies={"https": _PROXY}, timeout=5)
    assert made[0].loads == [(str(ca), None, None)], "the proxy leg did not load the CA file"


def test_a_ca_file_the_real_library_refuses_gives_the_fixed_reason(tmp_path: Path) -> None:
    """The real TLS library, on a file it refuses with no encryption header in it. The refusal is
    the same fixed text, whatever the library's own words were."""
    ca = _ca_file(tmp_path, _NOT_A_CERTIFICATE)
    session = _session(ssl.create_default_context, _no_socket)
    with pytest.raises(_strict().VaultHopRefused) as refusal:
        session.get(_URL, verify=str(ca), proxies={"https": _PROXY}, timeout=5)
    assert _strict().vault_failure_text(refusal.value) == _fixed_reason()
    assert isinstance(refusal.value.__cause__, ssl.SSLError)


def _socketpair_end(pairs: list[tuple[socket.socket, socket.socket]]) -> Callable[[Any], Any]:
    """A ``_new_conn`` that hands urllib3 one end of a local socket pair, so the Vault leg gets as
    far as urllib3's own CA load with no network."""

    def new_conn(conn: Any) -> socket.socket:
        pairs.append(socket.socketpair())
        return pairs[-1][0]

    return new_conn


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        pytest.param(_ENCRYPTED, _MeasuredPathLoad, id="encrypted, measured stand-in"),
        pytest.param(_NOT_A_CERTIFICATE, ssl.create_default_context, id="real library"),
    ],
)
def test_the_direct_path_still_gives_requests_ssl_error(
    tmp_path: Path, text: str, kind: Callable[[], Any]
) -> None:
    """The measurement for the direct path, left as it was: urllib3's own Vault-leg load wraps the
    refusal as its ``SSLError``, and requests reports ``requests.exceptions.SSLError``. Pinned so a
    change on either side shows here."""
    import requests

    ca = _ca_file(tmp_path, text)
    pairs: list[tuple[socket.socket, socket.socket]] = []
    _, factory = _contexts(kind)
    session = _session(factory, _socketpair_end(pairs))
    try:
        with pytest.raises(requests.exceptions.SSLError) as failure:
            session.get(_URL, verify=str(ca), timeout=5)
    finally:
        for pair in pairs:
            for end in pair:
                end.close()
    assert pairs, "urllib3 never asked for a socket, so its CA load was not reached"
    assert _strict().vault_failure_text(failure.value) == "SSLError"
