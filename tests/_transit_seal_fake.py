# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A local stand-in for Vault/OpenBao Transit that row seals can run against (BACKLOG #2592).

Deliberately **extra-free**, like the seal contracts: it imports neither ``hvac`` nor a database
driver, so the live PostgreSQL and SQL Server suites can import it on legs that install only their
own driver extra.

It does what the row seal needs Transit to do, faithfully enough to fail where Transit fails:
``generate_hmac`` MACs under a per-version secret held "inside the module" and names that version in
its ``vault:v<N>:`` string; ``verify_signed_data`` checks the string at the version it names, never
the latest, and refuses a version it does not hold the way Transit does, with an HTTP 400, whether
newer than ``latest`` or below ``min_decryption``; ``read_key`` reports both numbers, as Transit's
key metadata does; ``down`` makes every call fail the way an unreachable Vault does; and
``verify_denied`` makes the verify call fail the way a token without that capability does. Encrypt and decrypt are real
AES-GCM with the cell's associated data, so a store opened on it works end to end.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_lib
import os
import threading
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from messagefoundry.store.crypto_transit import TransitCipher

#: The data key and the audit key the fake holds; the row seal runs under the audit key.
DATA_KEY = "mefor-store"
AUDIT_KEY = "mefor-audit"


class TransitRefusal(Exception):
    """What the fake raises for a request Transit would answer with HTTP 400. A test that has the
    ``[vault]`` extra swaps in hvac's ``InvalidRequest``, which is what the engine tells apart."""


class FakeTransit:
    """The fake Transit engine. It holds key versions 1 to ``latest``; ``rotate`` moves ``latest``
    on."""

    def __init__(self) -> None:
        self._aes = AESGCM(b"\x00" * 32)
        self.latest = 1
        self.min_decryption = 1
        self.down = False
        self.verify_denied = False
        self.refusal: type[Exception] = TransitRefusal
        self.verify_calls = 0
        #: The thread of every Transit call, so a test can show none ran on the event loop.
        self.threads: set[int] = set()

    def rotate(self) -> None:
        self.latest += 1

    def _gate(self) -> None:
        self.threads.add(threading.get_ident())
        if self.down:
            raise ConnectionError("synthetic Vault outage")

    @staticmethod
    def _secret(name: str, version: int) -> bytes:
        return hashlib.sha256(f"synthetic transit secret/{name}/{version}".encode()).digest()

    def _mac(self, name: str, version: int, hash_input: str) -> str:
        digest = hmac_lib.new(
            self._secret(name, version), base64.b64decode(hash_input), hashlib.sha256
        ).digest()
        return f"vault:v{version}:" + base64.b64encode(digest).decode("ascii")

    def read_key(self, *, name: str, **_: Any) -> dict[str, Any]:
        self._gate()
        return {
            "data": {
                "name": name,
                "type": "aes256-gcm96",
                "latest_version": self.latest,
                "min_decryption_version": self.min_decryption,
            }
        }

    def generate_hmac(
        self, *, name: str, hash_input: str, key_version: int | None = None, **_: Any
    ) -> dict[str, Any]:
        self._gate()
        version = self.latest if key_version is None else key_version
        if not 1 <= version <= self.latest:
            raise self.refusal("synthetic: key version not held")
        return {"data": {"hmac": self._mac(name, version, hash_input)}}

    def verify_signed_data(
        self, *, name: str, hash_input: str, hmac: str | None = None, **_: Any
    ) -> dict[str, Any]:
        self._gate()
        if self.verify_denied:
            raise PermissionError("synthetic: permission denied on transit/verify")
        self.verify_calls += 1
        text, _sep, _body = (hmac or "").removeprefix("vault:v").partition(":")
        if not text.isdigit():
            raise self.refusal("synthetic: not a Transit HMAC")
        version = int(text)
        if not self.min_decryption <= version <= self.latest:
            raise self.refusal("synthetic: key version not held")
        expected = self._mac(name, version, hash_input)
        return {"data": {"valid": hmac_lib.compare_digest(expected, hmac or "")}}

    def encrypt_data(
        self, *, name: str, plaintext: str, associated_data: str | None = None, **_: Any
    ) -> dict[str, Any]:
        self._gate()
        aad = base64.b64decode(associated_data) if associated_data is not None else None
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, base64.b64decode(plaintext), aad)
        return {"data": {"ciphertext": "vault:v1:" + base64.b64encode(nonce + ct).decode("ascii")}}

    def decrypt_data(
        self, *, name: str, ciphertext: str, associated_data: str | None = None, **_: Any
    ) -> dict[str, Any]:
        self._gate()
        raw = base64.b64decode(ciphertext.removeprefix("vault:v1:"))
        aad = base64.b64decode(associated_data) if associated_data is not None else None
        pt = self._aes.decrypt(raw[:12], raw[12:], aad)
        return {"data": {"plaintext": base64.b64encode(pt).decode("ascii")}}


class FakeClient:
    """An hvac-shaped client: ``client.secrets.transit`` is the fake."""

    def __init__(self, transit: FakeTransit) -> None:
        self.secrets = type("Secrets", (), {"transit": transit})()


def transit_cipher(transit: FakeTransit) -> TransitCipher:
    """A Transit cipher on ``transit``, with a dedicated audit key as a deployment would set."""
    return TransitCipher(FakeClient(transit), DATA_KEY, audit_key=AUDIT_KEY)


async def assert_a_forged_session_needs_the_transit_check(
    store: Any, raw: Any, monkeypatch: Any
) -> None:
    """The control a server suite runs beside the contracts: one session row written outside the
    store resolves to nothing, and a second, identical but for its token, resolves once Transit's
    check is switched off. So a green contract on that backend is evidence the check ran there.
    ``raw`` is the contracts' ``?``-placeholder statement runner."""
    import time

    from messagefoundry.auth.service import AuthService
    from messagefoundry.auth.tokens import hash_token, mint_token
    from messagefoundry.config.settings import AuthSettings
    from messagefoundry.store.row_seal import TransitRowSealer

    service = AuthService(store, AuthSettings())
    await store.create_user(
        user_id="transit-ctl",
        username="transit-ctl",
        auth_provider="local",
        display_name=None,
        email=None,
        password_hash="h",
        now=time.time(),
        password_generated=False,
    )

    async def forge() -> str:
        token = mint_token()
        now = time.time()
        await raw(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_used_at,"
            " auth_mechanism) VALUES (?,?,?,?,?,?)",
            (hash_token(token), "transit-ctl", now, now + 3600, now, "password"),
        )
        return token

    assert await service.identity_for_token(await forge()) is None

    async def accepts_everything(*_: Any) -> bool:
        return True

    monkeypatch.setattr(TransitRowSealer, "verify_async", accepts_everything)
    switched_off = await service.identity_for_token(await forge())
    assert switched_off is not None and switched_off.user_id == "transit-ctl"
