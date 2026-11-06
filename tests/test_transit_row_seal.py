# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Transit row sealer's four answers (ADR 0217, "The four answers, defined once").

Runs against an in-memory stand-in for the three Transit calls the sealer makes, so every answer
is reached without Vault. Synthetic data only.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import hmac as hmac_lib
import pickle
import threading
from typing import Any

import pytest

from messagefoundry.store import row_seal
from messagefoundry.store.crypto import CipherError
from messagefoundry.store.row_seal import (
    SEAL_PREFIX,
    SESSION_KIND,
    USER_KIND,
    RowSealer,
    RowSealError,
    RowSealUnverifiableError,
    TransitRowSealer,
    TransitSealRefused,
    TransitSealUnavailableError,
    TransitSealUnverifiableError,
    transit_mac_version,
    transit_seal_key_id,
)

ACTIVE = "mefor-audit-2"
RETIRED = "mefor-audit-1"
# A synthetic token hash, so a test can show it never reaches Transit or an exception.
TOKEN_HASH = "ab" * 32
FIELDS: list[tuple[str, object]] = [("token_hash", TOKEN_HASH), ("user_id", "u-1"), ("n", 3)]


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
        self.hold_mac: str | None = None
        self.entered = threading.Event()
        self.release = threading.Event()
        self.verify_calls = 0
        self.probe_calls = 0
        self.inputs: list[bytes] = []
        self.threads: set[int] = set()

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
        self.inputs.append(digest)
        if self.down:
            raise CipherError("synthetic outage")
        if self.other_failure:
            raise RuntimeError("synthetic library failure")
        return self._mac(self.active, self.latest[self.active], digest)

    def verify_seal_hmac(self, key_name: str, digest: bytes, mac: str) -> bool:
        self.threads.add(threading.get_ident())
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
        if self.probe_down:
            raise CipherError("synthetic probe outage")
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


def _sealer(backend: FakeBackend, clock: Clock | None = None, **kw: Any) -> TransitRowSealer:
    return TransitRowSealer(backend, clock=clock or Clock(), **kw)


def _with_version(stored: str, version: str) -> str:
    """``stored`` naming another version with the same well-formed MAC body."""
    head, mac = stored[len(SEAL_PREFIX) :].split(":", 1)
    body = mac.split(":", 2)[2]
    return f"{SEAL_PREFIX}{head}:vault:v{version}:{body}"


async def test_holds_and_forged() -> None:
    backend = FakeBackend()
    sealer = _sealer(backend)
    stored = await sealer.seal_async(USER_KIND, FIELDS)
    assert stored.startswith(f"{SEAL_PREFIX}{sealer.key_id}:vault:v1:")
    assert await sealer.verify_async(USER_KIND, FIELDS, stored) is True
    assert await sealer.verify_held_async(USER_KIND, FIELDS, stored) is True
    changed = [*FIELDS[:2], ("n", 4)]
    assert await sealer.verify_async(USER_KIND, changed, stored) is False
    # Another kind over the same fields is another input.
    assert await sealer.verify_async(SESSION_KIND, FIELDS, stored) is False


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: _with_version(s, "01"),  # leading zero
        lambda s: _with_version(s, "12345678901"),  # eleven digits
        lambda s: _with_version(s, "1x"),
        lambda s: s[:-4] + "!!!!",  # not strict base64
        lambda s: s[:-8] + "====",  # decodes short
        lambda s: s + "AAAA",  # decodes long
        lambda s: s.replace("vault:v1:", "vault:v١:"),  # a non-ASCII digit
        lambda s: s.removeprefix(SEAL_PREFIX),
        lambda s: "",
    ],
)
async def test_a_malformed_seal_is_forged_with_no_transit_call(mutate: Any) -> None:
    backend = FakeBackend()
    sealer = _sealer(backend)
    stored = await sealer.seal_async(USER_KIND, FIELDS)
    assert await sealer.verify_held_async(USER_KIND, FIELDS, mutate(stored)) is False
    assert backend.verify_calls == 0


async def test_a_seal_naming_an_unheld_key_id_is_forged_with_no_transit_call() -> None:
    backend = FakeBackend()
    sealer = _sealer(backend)
    stored = await sealer.seal_async(USER_KIND, FIELDS)
    foreign = stored.replace(sealer.key_id, transit_seal_key_id("transit", "someone-else"), 1)
    assert await sealer.verify_held_async(USER_KIND, FIELDS, foreign) is False
    assert backend.verify_calls == 0


@pytest.mark.parametrize("planted", ["9999999999", "2"])
async def test_a_version_transit_will_not_check_is_unverifiable(planted: str) -> None:
    backend = FakeBackend()
    sealer = _sealer(backend)
    stored = _with_version(await sealer.seal_async(USER_KIND, FIELDS), planted)
    with pytest.raises(TransitSealUnverifiableError) as caught:
        await sealer.verify_held_async(USER_KIND, FIELDS, stored)
    assert caught.value.args == (USER_KIND, int(planted), 1)
    # Cached: the second check makes no Transit call and skips the probe, and still denies.
    calls = (backend.verify_calls, backend.probe_calls)
    with pytest.raises(TransitSealUnverifiableError):
        await sealer.verify_held_async(USER_KIND, FIELDS, stored)
    assert (backend.verify_calls, backend.probe_calls) == calls


async def test_a_version_below_the_minimum_is_unverifiable() -> None:
    backend = FakeBackend()
    sealer = _sealer(backend)
    stored = await sealer.seal_async(USER_KIND, FIELDS)
    backend.latest[ACTIVE] = 3
    backend.min_decryption = 2
    with pytest.raises(TransitSealUnverifiableError) as caught:
        await sealer.verify_held_async(USER_KIND, FIELDS, stored)
    assert (caught.value.stored_version, caught.value.probe_version) == (1, 3)


async def test_an_outage_is_never_cached_and_never_a_seal_failure() -> None:
    backend = FakeBackend()
    sealer = _sealer(backend)
    stored = await sealer.seal_async(USER_KIND, FIELDS)
    backend.down = True
    for _ in range(2):
        with pytest.raises(TransitSealUnavailableError):
            await sealer.verify_held_async(USER_KIND, FIELDS, stored)
    assert backend.verify_calls == 2
    with pytest.raises(TransitSealUnavailableError):
        await sealer.seal_async(USER_KIND, FIELDS)
    backend.down = False
    assert await sealer.verify_held_async(USER_KIND, FIELDS, stored) is True


@pytest.mark.parametrize("probe", ["down", "malformed"])
async def test_a_400_the_probe_cannot_clear_is_an_outage(probe: str) -> None:
    backend = FakeBackend()
    sealer = _sealer(backend)
    stored = _with_version(await sealer.seal_async(USER_KIND, FIELDS), "7")
    if probe == "down":
        backend.probe_down = True
    else:
        backend.probe_reply = "vault:v1:not-a-mac"
    with pytest.raises(TransitSealUnavailableError):
        await sealer.verify_held_async(USER_KIND, FIELDS, stored)


async def test_a_403_is_an_outage_on_the_active_key_and_unverifiable_on_a_retired_one() -> None:
    old = FakeBackend(active=RETIRED)
    under_retired = await _sealer(old).seal_async(USER_KIND, FIELDS)
    backend = FakeBackend()
    sealer = _sealer(backend, retired_key_names=[RETIRED])
    under_active = await sealer.seal_async(USER_KIND, FIELDS)
    backend.forbid = {ACTIVE, RETIRED}
    with pytest.raises(TransitSealUnavailableError):
        await sealer.verify_held_async(USER_KIND, FIELDS, under_active)
    with pytest.raises(TransitSealUnverifiableError):
        await sealer.verify_held_async(USER_KIND, FIELDS, under_retired)
    # A 403 on the retired key with the active key's probe failing too is an Outage.
    fresh = _sealer(backend, retired_key_names=[RETIRED])
    backend.probe_down = True
    with pytest.raises(TransitSealUnavailableError):
        await fresh.verify_held_async(USER_KIND, FIELDS, under_retired)


async def test_a_retired_key_holds_a_record_and_never_a_session() -> None:
    under_retired = await _sealer(FakeBackend(active=RETIRED)).seal_async(SESSION_KIND, FIELDS)
    backend = FakeBackend()
    sealer = _sealer(backend, retired_key_names=[RETIRED])
    assert await sealer.verify_held_async(SESSION_KIND, FIELDS, under_retired) is True
    calls = backend.verify_calls
    assert await sealer.verify_async(SESSION_KIND, FIELDS, under_retired) is False
    assert backend.verify_calls == calls  # the session check makes no Transit call for it
    assert await sealer.sealed_by_retired_key_async(SESSION_KIND, FIELDS, under_retired) is True
    under_active = await sealer.seal_async(SESSION_KIND, FIELDS)
    assert await sealer.sealed_by_retired_key_async(SESSION_KIND, FIELDS, under_active) is False
    assert not sealer.is_active(under_retired) and sealer.is_active(under_active)
    # Not listed as retired: a seal under that key is Forged.
    unlisted = _sealer(FakeBackend())
    assert await unlisted.verify_held_async(SESSION_KIND, FIELDS, under_retired) is False


async def test_the_success_cache_expires_and_empties_when_the_probe_moves() -> None:
    backend = FakeBackend()
    clock = Clock()
    sealer = _sealer(backend, clock)
    stored = await sealer.seal_async(USER_KIND, FIELDS)
    assert await sealer.verify_held_async(USER_KIND, FIELDS, stored)
    assert await sealer.verify_held_async(USER_KIND, FIELDS, stored)
    assert backend.verify_calls == 1
    clock.now += 61
    assert await sealer.verify_held_async(USER_KIND, FIELDS, stored)
    assert backend.verify_calls == 2
    # A refused check whose probe names a new latest version empties the cache.
    backend.latest[ACTIVE] = 2
    planted = _with_version(stored, "5")
    with pytest.raises(TransitSealUnverifiableError):
        await sealer.verify_held_async(USER_KIND, FIELDS, planted)
    calls = backend.verify_calls
    assert await sealer.verify_held_async(USER_KIND, FIELDS, stored)
    assert backend.verify_calls == calls + 1
    # A Forged answer is cached too.
    forged = [*FIELDS[:2], ("n", 9)]
    assert not await sealer.verify_held_async(USER_KIND, forged, stored)
    calls = backend.verify_calls
    assert not await sealer.verify_held_async(USER_KIND, forged, stored)
    assert backend.verify_calls == calls


async def test_a_probe_naming_the_same_version_keeps_the_cache() -> None:
    backend = FakeBackend()
    sealer = _sealer(backend)
    stored = await sealer.seal_async(USER_KIND, FIELDS)
    with pytest.raises(TransitSealUnverifiableError):  # the first probe records version 1
        await sealer.verify_held_async(USER_KIND, FIELDS, _with_version(stored, "5"))
    assert await sealer.verify_held_async(USER_KIND, FIELDS, stored)
    with pytest.raises(TransitSealUnverifiableError):  # this probe names version 1 again
        await sealer.verify_held_async(USER_KIND, FIELDS, _with_version(stored, "4"))
    calls = backend.verify_calls
    assert await sealer.verify_held_async(USER_KIND, FIELDS, stored)
    assert backend.verify_calls == calls  # still cached: the version did not move again
    # Control: a probe that names a new version empties it.
    backend.latest[ACTIVE] = 2
    with pytest.raises(TransitSealUnverifiableError):
        await sealer.verify_held_async(USER_KIND, FIELDS, _with_version(stored, "6"))
    assert await sealer.verify_held_async(USER_KIND, FIELDS, stored)
    assert backend.verify_calls == calls + 2


async def test_a_check_that_began_before_the_cache_emptied_is_not_cached() -> None:
    backend = FakeBackend()
    sealer = _sealer(backend)
    stored = await sealer.seal_async(USER_KIND, FIELDS)
    with pytest.raises(TransitSealUnverifiableError):  # records version 1 as the probed version
        await sealer.verify_held_async(USER_KIND, FIELDS, _with_version(stored, "5"))
    backend.hold_mac = stored.split(":", 3)[3]
    slow = asyncio.create_task(sealer.verify_held_async(USER_KIND, FIELDS, stored))
    assert await asyncio.to_thread(backend.entered.wait, 5)
    backend.latest[ACTIVE] = 2  # a rotation lands while the slow check is in Transit
    with pytest.raises(TransitSealUnverifiableError):
        await sealer.verify_held_async(USER_KIND, FIELDS, _with_version(stored, "6"))
    backend.release.set()
    assert await slow is True  # its own caller still gets its answer
    backend.hold_mac = None
    calls = backend.verify_calls
    assert await sealer.verify_held_async(USER_KIND, FIELDS, stored)
    assert backend.verify_calls == calls + 1  # but it was not stored under the new state


async def test_fresh_skips_the_cache_read() -> None:
    backend = FakeBackend()
    sealer = _sealer(backend)
    stored = await sealer.seal_async(USER_KIND, FIELDS)
    assert await sealer.verify_async(USER_KIND, FIELDS, stored)
    assert await sealer.verify_async(USER_KIND, FIELDS, stored)
    assert backend.verify_calls == 1
    assert await sealer.verify_async(USER_KIND, FIELDS, stored, fresh=True)
    assert await sealer.verify_held_async(USER_KIND, FIELDS, stored, fresh=True)
    assert backend.verify_calls == 3


async def test_any_other_failure_of_a_call_is_an_outage() -> None:
    backend = FakeBackend()
    sealer = _sealer(backend)
    stored = await sealer.seal_async(USER_KIND, FIELDS)
    backend.other_failure = True
    with pytest.raises(TransitSealUnavailableError):
        await sealer.seal_async(USER_KIND, FIELDS)
    with pytest.raises(TransitSealUnavailableError):
        await sealer.verify_held_async(USER_KIND, FIELDS, stored)
    backend.other_failure = False
    planted = _with_version(stored, "5")
    original = backend.seal_probe

    def failing_probe() -> str:
        raise RuntimeError("synthetic library failure")

    backend.seal_probe = failing_probe  # type: ignore[method-assign]
    with pytest.raises(TransitSealUnavailableError):
        await sealer.verify_held_async(USER_KIND, FIELDS, planted)
    backend.seal_probe = original  # type: ignore[method-assign]
    with pytest.raises(TransitSealUnverifiableError):
        await sealer.verify_held_async(USER_KIND, FIELDS, planted)


async def test_re_storing_an_answer_does_not_evict_another(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(row_seal, "TRANSIT_SEAL_CACHE_MAX", 2)
    backend = FakeBackend()
    sealer = _sealer(backend)
    first = await sealer.seal_async(USER_KIND, FIELDS)
    second = await sealer.seal_async(SESSION_KIND, FIELDS)
    assert await sealer.verify_held_async(USER_KIND, FIELDS, first)
    assert await sealer.verify_held_async(SESSION_KIND, FIELDS, second)
    assert await sealer.verify_held_async(SESSION_KIND, FIELDS, second, fresh=True)
    calls = backend.verify_calls
    assert await sealer.verify_held_async(USER_KIND, FIELDS, first)
    assert backend.verify_calls == calls  # the first answer survived
    # Control: a third distinct answer does evict the oldest.
    third = await sealer.seal_async(USER_KIND, [*FIELDS, ("x", 1)])
    assert await sealer.verify_held_async(USER_KIND, [*FIELDS, ("x", 1)], third)
    assert await sealer.verify_held_async(USER_KIND, FIELDS, first)
    assert backend.verify_calls == calls + 2


async def test_transit_receives_a_fixed_length_digest_and_runs_off_the_event_loop() -> None:
    backend = FakeBackend()
    sealer = _sealer(backend)
    big = [("blob", "x" * 100_000), *FIELDS]
    stored = await sealer.seal_async(USER_KIND, big)
    assert await sealer.verify_held_async(USER_KIND, big, stored)
    assert {len(i) for i in backend.inputs} == {32}
    assert all(TOKEN_HASH.encode() not in i for i in backend.inputs)
    assert threading.get_ident() not in backend.threads


async def test_the_store_id_is_inside_the_input() -> None:
    backend = FakeBackend()
    one = _sealer(backend, store_id=b"store-one")
    other = _sealer(backend, store_id=b"store-two")
    stored = await one.seal_async(USER_KIND, FIELDS)
    assert await other.verify_held_async(USER_KIND, FIELDS, stored) is False


def test_the_strict_parse() -> None:
    body = base64.b64encode(b"\x01" * 32).decode()
    assert transit_mac_version(f"vault:v1:{body}") == 1
    assert transit_mac_version(f"vault:v9999999999:{body}") == 9999999999
    for bad in (f"vault:v0:{body}", f"vault:v:{body}", f"vault:v1{body}", "vault:v1:"):
        assert transit_mac_version(bad) is None


async def test_the_local_sealer_awaitable_forms_agree() -> None:
    sealer = RowSealer(b"k" * 32, retired_keys=[b"r" * 32])
    old = RowSealer(b"r" * 32)
    stored = await sealer.seal_async(USER_KIND, FIELDS)
    assert stored == sealer.seal(USER_KIND, FIELDS)
    assert await sealer.verify_async(USER_KIND, FIELDS, stored)
    assert await sealer.verify_held_async(USER_KIND, FIELDS, old.seal(USER_KIND, FIELDS))
    assert await sealer.sealed_by_retired_key_async(USER_KIND, FIELDS, old.seal(USER_KIND, FIELDS))


def test_the_refusal_types_are_siblings_and_carry_no_token_hash() -> None:
    """ADR 0217 (c) steps 1 and 2, #4739 item 12."""
    subject = f"{SESSION_KIND}:{TOKEN_HASH[:12]}:0123456789abcdef"
    for cls in (RowSealError, RowSealUnverifiableError):
        err = cls(SESSION_KIND, subject)
        assert err.args == (SESSION_KIND, subject)
        for text in (
            repr(err),
            str(err),
            repr(copy.copy(err)),
            repr(pickle.loads(pickle.dumps(err))),
        ):
            assert TOKEN_HASH not in text
        assert pickle.loads(pickle.dumps(err)).subject == subject
    assert not issubclass(RowSealUnverifiableError, RowSealError)
    assert not issubclass(RowSealError, RowSealUnverifiableError)
    for cls2 in (TransitSealUnavailableError, TransitSealUnverifiableError):
        assert not issubclass(cls2, CipherError | RowSealError | RowSealUnverifiableError)
    assert RowSealError(USER_KIND).args == (USER_KIND, "")
    outage = TransitSealUnavailableError()
    assert outage.args == ()
    assert str(pickle.loads(pickle.dumps(outage))) == str(outage) == str(copy.copy(outage))
    verdict = TransitSealUnverifiableError(USER_KIND, 9, 1)
    assert pickle.loads(pickle.dumps(verdict)).args == (USER_KIND, 9, 1)


def test_the_transit_cipher_maps_vault_refusals() -> None:
    exceptions = pytest.importorskip("hvac.exceptions")
    from messagefoundry.store.crypto_transit import TransitCipher

    class Transit:
        raise_: Exception | None = None

        def verify_signed_data(self, **_: Any) -> dict[str, Any]:
            if self.raise_ is not None:
                raise self.raise_
            return {"data": {"valid": False}}

    transit = Transit()
    client = type("C", (), {"secrets": type("S", (), {"transit": transit})()})()
    cipher = TransitCipher(client, "mefor-data", audit_key=ACTIVE)
    assert (cipher.seal_key_name, cipher.seal_mount) == (ACTIVE, "transit")
    assert cipher.verify_seal_hmac(ACTIVE, b"\x00" * 32, "vault:v1:x") is False
    for exc, status in ((exceptions.InvalidRequest(), 400), (exceptions.Forbidden(), 403)):
        transit.raise_ = exc
        with pytest.raises(TransitSealRefused) as caught:
            cipher.verify_seal_hmac(ACTIVE, b"\x00" * 32, "vault:v1:x")
        assert caught.value.status == status
    transit.raise_ = exceptions.InternalServerError()
    with pytest.raises(CipherError):
        cipher.verify_seal_hmac(ACTIVE, b"\x00" * 32, "vault:v1:x")
