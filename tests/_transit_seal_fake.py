# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An in-memory stand-in for the three Transit calls the row sealer makes (ADR 0217), shared by the
sealer's own tests and the store tests that run a store under it. Synthetic keys only."""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_lib
import threading

from messagefoundry.store.crypto import CipherError, TransitSealRefused

ACTIVE = "mefor-audit-2"
RETIRED = "mefor-audit-1"


class FakeBackend:
    """The three calls of :class:`~messagefoundry.store.row_seal.TransitSealBackend`, faithful
    enough to fail where Transit fails: versions 1 to ``latest`` per key, ``min_decryption``, a
    verify that refuses an unheld version with a 400, and switches for each failure class."""

    def __init__(self, active: str = ACTIVE) -> None:
        self.active = active
        self.latest: dict[str, int] = {ACTIVE: 1, RETIRED: 1}
        self.min_decryption = 1
        self.down = False
        self.probe_down = False
        self.probe_reply: str | None = None
        self.forbid: set[str] = set()
        self.other_failure = False
        self.hmac_refused = False
        self.hold_mac: str | None = None
        self.entered = threading.Event()
        self.release = threading.Event()
        self.verify_calls = 0
        self.probe_calls = 0
        self.inputs: list[bytes] = []
        self.threads: set[int] = set()
        self.thread_names: set[str] = set()

    @property
    def seal_key_name(self) -> str:
        return self.active

    @property
    def seal_mount(self) -> str:
        return "transit"

    def _mac(self, name: str, version: int, digest: bytes) -> str:
        secret = hashlib.sha256(f"synthetic/{name}/{version}".encode()).digest()
        raw = hmac_lib.new(secret, digest, hashlib.sha256).digest()
        return f"vault:v{version}:" + base64.b64encode(raw).decode("ascii")

    def seal_hmac(self, digest: bytes) -> str:
        self.threads.add(threading.get_ident())
        self.thread_names.add(threading.current_thread().name)
        self.inputs.append(digest)
        if self.down:
            raise CipherError("synthetic outage")
        if self.other_failure:
            raise RuntimeError("synthetic library failure")
        if self.hmac_refused:
            raise TransitSealRefused(403)
        return self._mac(self.active, self.latest[self.active], digest)

    def verify_seal_hmac(self, key_name: str, digest: bytes, mac: str) -> bool:
        self.threads.add(threading.get_ident())
        self.thread_names.add(threading.current_thread().name)
        self.inputs.append(digest)
        self.verify_calls += 1
        if mac == self.hold_mac:
            self.entered.set()
            assert self.release.wait(5)
        if self.down:
            raise CipherError("synthetic outage")
        if self.other_failure:
            raise RuntimeError("synthetic library failure")
        if key_name in self.forbid:
            raise TransitSealRefused(403)
        version = int(mac.removeprefix("vault:v").partition(":")[0])
        if not self.min_decryption <= version <= self.latest[key_name]:
            raise TransitSealRefused(400)
        return hmac_lib.compare_digest(self._mac(key_name, version, digest), mac)

    def seal_probe(self) -> str:
        self.probe_calls += 1
        self.thread_names.add(threading.current_thread().name)
        if self.probe_down:
            raise CipherError("synthetic probe outage")
        if self.hmac_refused:
            raise TransitSealRefused(403)
        if self.other_failure:
            raise RuntimeError("synthetic library failure")
        if self.probe_reply is not None:
            return self.probe_reply
        return self._mac(self.active, self.latest[self.active], b"probe")


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now
