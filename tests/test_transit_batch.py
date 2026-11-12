# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Transit cipher opens and seals many cells per request (vault BACKLOG #6706).

A full restore-verify and ``cipher-audit`` read every cell of a store back through the cipher, and
the first keyed open of a store holding plaintext seals every cell. Under ``vault_transit`` each
cell was one Transit request. These tests count requests against a fake Transit that answers
``batch_input`` as Vault does: a result per item carrying its ``reference``, and HTTP 400 for the
whole batch when one item fails. Synthetic data only."""

from __future__ import annotations

import base64
import json
import os
import traceback
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("requests", reason="Transit batch tests need the [vault] extra")
pytest.importorskip("hvac", reason="Transit batch tests need the [vault] extra")

import requests
from cryptography.exceptions import InvalidTag
from hvac.exceptions import (  # type: ignore[import-untyped]
    Forbidden,
    InternalServerError,
    InvalidRequest,
    UnexpectedError,
)

from messagefoundry.store import crypto, crypto_transit
from messagefoundry.store.cipher_cells import (
    _decrypt_values,
    audit_cipher_cells,
    connect_readonly,
)
from messagefoundry.store.crypto import (
    AesGcmCipher,
    CipherError,
    CipherUnavailableError,
    cell_aad,
    decrypt_or_error,
    encrypt_many,
)
from messagefoundry.store.crypto_transit import TransitCipher
from messagefoundry.store.store import MessageStatus, MessageStore
from tests.test_crypto_transit import _FakeClient, _FakeTransit

_KEY = "mefor-store"


class _BatchTransit(_FakeTransit):
    """The AEAD fake, answering ``batch_input`` as Vault does, and counting requests."""

    def __init__(self) -> None:
        super().__init__()
        self.encrypt_requests = 0
        self.decrypt_requests = 0
        #: When set, replaces a batch reply's ``batch_results`` list.
        self.tamper: Any = None

    def encrypt_data(self, **kw: Any) -> dict[str, Any]:
        self.encrypt_requests += 1
        items = kw.get("batch_input")
        if items is None:
            return super().encrypt_data(**kw)
        results = [
            {
                **super(_BatchTransit, self).encrypt_data(
                    name=kw["name"],
                    plaintext=item["plaintext"],
                    associated_data=item.get("associated_data"),
                )["data"],
                "reference": item.get("reference", ""),
            }
            for item in items
        ]
        return {"data": {"batch_results": self._tampered(results)}}

    def decrypt_data(self, **kw: Any) -> dict[str, Any]:
        self.decrypt_requests += 1
        items = kw.get("batch_input")
        if items is None:
            try:
                return super().decrypt_data(**kw)
            except InvalidTag as exc:  # Vault answers a refused tag 400
                raise InvalidRequest("cipher: message authentication failed") from exc
        results: list[dict[str, Any]] = []
        failed = False
        for item in items:
            result: dict[str, Any] = {"reference": item.get("reference", "")}
            try:
                result.update(
                    super().decrypt_data(
                        name=kw["name"],
                        ciphertext=item["ciphertext"],
                        associated_data=item.get("associated_data"),
                    )["data"]
                )
            except InvalidTag:
                result["error"] = "cipher: message authentication failed"
                failed = True
            results.append(result)
        if failed:
            # Vault answers the whole batch 400 when any item fails, and its body, which hvac makes
            # the message, is every item's result: the others' plaintext included.
            raise InvalidRequest(json.dumps({"data": {"batch_results": results}}))
        return {"data": {"batch_results": self._tampered(results)}}

    def _tampered(self, results: list[dict[str, Any]]) -> Any:
        return results if self.tamper is None else self.tamper(results)


def _cipher(transit: _BatchTransit) -> TransitCipher:
    return TransitCipher(_FakeClient(transit), _KEY)


async def _write_messages(db: Path, n: int, cipher: Any = None) -> None:
    store = await MessageStore.open(db, cipher=cipher)
    try:
        for i in range(n):
            await store.record_received(
                channel_id="IB_TEST",
                raw=f"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M{i}|P|2.5.1\r",
                status=MessageStatus.FILTERED,
                summary="synthetic",
                metadata="{}",
            )
    finally:
        await store.close()


async def test_a_cipher_audit_opens_many_cells_per_transit_request(tmp_path: Path) -> None:
    transit = _BatchTransit()
    db = tmp_path / "store.db"
    await _write_messages(db, 200, _cipher(transit))
    transit.decrypt_requests = 0
    conn = connect_readonly(db, busy_timeout=5.0)
    try:
        audit = audit_cipher_cells(conn, _cipher(transit))
    finally:
        conn.close()
    assert audit.failed == 0
    assert audit.opened == 600  # raw, summary and metadata of each message
    # One request per cell before the batch path: 600. Each column is 200 values, two batches.
    assert transit.decrypt_requests == 6


async def test_the_first_keyed_open_seals_many_cells_per_transit_request(tmp_path: Path) -> None:
    db = tmp_path / "store.db"
    await _write_messages(db, 200)  # keyless: legacy plaintext the keyed open seals
    transit = _BatchTransit()
    store = await MessageStore.open(db, cipher=_cipher(transit))
    await store.close()
    # One request per cell before the batch path: 600. Each surface is 200 values, two batches.
    assert transit.encrypt_requests == 6
    conn = connect_readonly(db, busy_timeout=5.0)
    try:
        audit = audit_cipher_cells(conn, _cipher(transit))
    finally:
        conn.close()
    assert (audit.opened, audit.failed, audit.legacy, audit.unmarked) == (600, 0, 0, 0)


def _sealed(cipher: TransitCipher, n: int) -> list[tuple[str, bytes]]:
    return [
        (cipher.encrypt(f"value {i}", aad=cell_aad("t", "c", i)), cell_aad("t", "c", i))
        for i in range(n)
    ]


def test_one_failed_value_is_reported_as_its_own_and_no_other() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 5)
    items[2] = (items[2][0], cell_aad("t", "c", 999))  # a value moved to another cell
    transit.decrypt_requests = 0
    results = cipher.decrypt_many(items)
    assert [r for i, r in enumerate(results) if i != 2] == [
        "value 0",
        "value 1",
        "value 3",
        "value 4",
    ]
    assert isinstance(results[2], CipherError)
    assert not isinstance(results[2], CipherUnavailableError)
    # The batch's 400, then each value alone to learn which one failed.
    assert transit.decrypt_requests == 1 + 5
    # The 400's body held the other values' plaintext; no result carries it on its chain.
    leaked = base64.b64encode(b"value 0").decode("ascii")
    assert leaked not in "".join(traceback.format_exception(results[2]))


def test_an_item_error_in_a_batch_that_answered_is_that_items_alone() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 3)

    def refuse_middle(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        middle = {"reference": results[1]["reference"], "error": "synthetic-vault-text"}
        return [results[0], middle, results[2]]

    transit.tamper = refuse_middle
    results = cipher.decrypt_many(items)
    assert results[0] == "value 0" and results[2] == "value 2"
    assert isinstance(results[1], CipherError)
    assert "synthetic-vault-text" not in str(results[1])  # Vault's text is not quoted


@pytest.mark.parametrize(
    "tamper",
    [
        pytest.param(lambda r: r[:-1], id="short"),
        pytest.param(lambda r: [*r, r[0]], id="long"),
        pytest.param(lambda r: list(reversed(r)), id="reordered"),
        pytest.param(
            lambda r: [{k: v for k, v in x.items() if k != "reference"} for x in r],
            id="no-reference",
        ),
        pytest.param(lambda r: {"0": r[0]}, id="not-a-list"),
    ],
)
def test_a_batch_reply_that_does_not_match_the_request_is_refused(tamper: Any) -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 4)
    transit.tamper = tamper
    results = cipher.decrypt_many(items)
    assert len(results) == 4
    assert all(isinstance(r, CipherError) for r in results)  # never zipped onto the request
    with pytest.raises(CipherError, match="does not match the request"):
        cipher.encrypt_many([("a", None), ("b", cell_aad("t", "c", 1))])


def test_a_batch_transit_could_not_serve_fails_every_value_as_an_outage() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 3)

    def down(**_: Any) -> dict[str, Any]:
        transit.decrypt_requests += 1
        raise requests.exceptions.ConnectionError("synthetic: connection refused")

    transit.decrypt_data = down  # type: ignore[method-assign]
    transit.decrypt_requests = 0
    results = cipher.decrypt_many(items)
    assert transit.decrypt_requests == 1  # no value-by-value retry against a service that is down
    assert all(isinstance(r, CipherUnavailableError) for r in results)
    assert all(isinstance(r, CipherError) and r.__cause__ is None for r in results)


async def test_an_outage_ends_the_audit_walk_after_one_request(tmp_path: Path) -> None:
    transit = _BatchTransit()
    db = tmp_path / "store.db"
    await _write_messages(db, 50, _cipher(transit))

    def down(**_: Any) -> dict[str, Any]:
        transit.decrypt_requests += 1
        raise requests.exceptions.ConnectionError("synthetic: connection refused")

    transit.decrypt_data = down  # type: ignore[method-assign]
    transit.decrypt_requests = 0
    conn = connect_readonly(db, busy_timeout=5.0)
    try:
        with pytest.raises(CipherUnavailableError):
            audit_cipher_cells(conn, _cipher(transit))
    finally:
        conn.close()
    assert transit.decrypt_requests == 1


def test_batches_keep_the_item_and_size_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, crypto.BATCH_MAX_ITEMS + 1)
    transit.decrypt_requests = 0
    assert cipher.decrypt_many(items) == [f"value {i}" for i in range(len(items))]
    assert transit.decrypt_requests == 2
    # A value over the character bound goes alone, in a single request as before batching.
    monkeypatch.setattr(crypto_transit, "BATCH_MAX_CHARS", len(items[0][0]) + 1)
    transit.decrypt_requests = 0
    assert cipher.decrypt_many(items[:3]) == ["value 0", "value 1", "value 2"]
    assert transit.decrypt_requests == 3


def test_values_transit_never_reads_are_answered_as_decrypt_answers_them() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    sealed = _sealed(cipher, 2)
    transit.decrypt_requests = 0
    results = cipher.decrypt_many([sealed[0], ("", None), ("mfenc:v1:abc:def", None), sealed[1]])
    assert results[0] == "value 0" and results[1] == "" and results[3] == "value 1"
    assert isinstance(results[2], CipherError)  # in-process ciphertext Transit cannot read
    assert transit.decrypt_requests == 1


def test_encrypt_many_round_trips_under_each_cells_aad() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = [(f"plain {i}", cell_aad("t", "c", i)) for i in range(5)]
    sealed = encrypt_many(cipher, items)
    assert transit.encrypt_requests == 1
    assert [cipher.decrypt(s, aad=aad) for s, (_, aad) in zip(sealed, items, strict=True)] == [
        p for p, _ in items
    ]
    with pytest.raises(CipherError):  # a value is bound to its own cell
        cipher.decrypt(sealed[0], aad=items[1][1])


def test_a_cipher_with_no_batch_path_loops_with_the_same_verdicts() -> None:
    cipher = AesGcmCipher(bytearray(os.urandom(32)), write_v2=True)
    good = cipher.encrypt("x", aad=cell_aad("t", "c", 1))
    results = _decrypt_values(
        cipher, [(good, cell_aad("t", "c", 1)), (good, cell_aad("t", "c", 2))]
    )
    assert results[0] == "x"
    assert isinstance(results[1], CipherError)
    assert isinstance(decrypt_or_error(cipher, "mfenc:v9:x", None), CipherError)
    assert [
        cipher.decrypt(s, aad=cell_aad("t", "c", 3))
        for s in encrypt_many(cipher, [("y", cell_aad("t", "c", 3))])
    ] == ["y"]


def test_a_batch_cipher_answering_short_is_refused() -> None:
    class Short(TransitCipher):
        def decrypt_many(self, items: Any) -> list[str | CipherError]:
            return []

    results = _decrypt_values(
        Short(_FakeClient(_BatchTransit()), _KEY), [("mfenc:v3:vault:v1:x", None)]
    )
    assert len(results) == 1 and isinstance(results[0], CipherUnavailableError)


def test_asking_value_by_value_stops_once_transit_cannot_serve() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 5)
    items[0] = (items[0][0], cell_aad("t", "c", 999))  # the batch then answers 400
    real = transit.decrypt_data

    def flaky(**kw: Any) -> dict[str, Any]:
        if kw.get("batch_input") is None and transit.decrypt_requests >= 2:
            transit.decrypt_requests += 1
            raise requests.exceptions.ConnectionError("synthetic: connection refused")
        return real(**kw)

    transit.decrypt_data = flaky  # type: ignore[method-assign]
    transit.decrypt_requests = 0
    results = cipher.decrypt_many(items)
    # The batch's 400, the first value alone (refused), the second alone (Transit down), and no more.
    assert transit.decrypt_requests == 3
    assert isinstance(results[0], CipherError)
    assert not isinstance(results[0], CipherUnavailableError)
    assert all(isinstance(r, CipherUnavailableError) for r in results[1:])
    assert all(isinstance(r, CipherError) and isinstance(r.__cause__, OSError) for r in results[1:])


def test_later_batches_are_not_sent_once_transit_cannot_serve() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, crypto.BATCH_MAX_ITEMS * 2 + 1)

    def down(**_: Any) -> dict[str, Any]:
        transit.decrypt_requests += 1
        raise requests.exceptions.ConnectionError("synthetic: connection refused")

    transit.decrypt_data = down  # type: ignore[method-assign]
    transit.decrypt_requests = 0
    results = cipher.decrypt_many(items)
    assert transit.decrypt_requests == 1  # three runs, one request
    assert len(results) == len(items)
    assert all(isinstance(r, CipherUnavailableError) for r in results)


def test_a_batch_refusal_other_than_a_400_fails_every_value_and_sends_no_more() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, crypto.BATCH_MAX_ITEMS * 2 + 5)

    def forbidden(**_: Any) -> dict[str, Any]:
        transit.decrypt_requests += 1
        raise Forbidden("permission denied")

    transit.decrypt_data = forbidden  # type: ignore[method-assign]
    transit.decrypt_requests = 0
    results = cipher.decrypt_many(items)
    # The batch, then the first value alone, which is refused too: no verdict, so no more.
    assert transit.decrypt_requests == 2
    assert all(isinstance(r, CipherError) and isinstance(r.__cause__, Forbidden) for r in results)


def test_a_mismatched_reply_is_no_verdict() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 3)
    transit.tamper = lambda r: r[:-1]
    assert all(isinstance(r, CipherUnavailableError) for r in cipher.decrypt_many(items))


async def test_an_unanswered_batch_ends_the_audit_walk(tmp_path: Path) -> None:
    transit = _BatchTransit()
    db = tmp_path / "store.db"
    await _write_messages(db, 50, _cipher(transit))
    transit.tamper = lambda r: list(reversed(r))
    transit.decrypt_requests = 0
    conn = connect_readonly(db, busy_timeout=5.0)
    try:
        with pytest.raises(CipherUnavailableError):
            audit_cipher_cells(conn, _cipher(transit))
    finally:
        conn.close()
    assert transit.decrypt_requests == 1  # no cell was counted damaged on a reply that judged none


def test_a_refused_encrypt_batch_seals_each_value_alone() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    real = transit.encrypt_data

    def too_large(**kw: Any) -> dict[str, Any]:
        if kw.get("batch_input") is not None:
            transit.encrypt_requests += 1
            raise UnexpectedError("413 Request Entity Too Large")
        return real(**kw)

    transit.encrypt_data = too_large  # type: ignore[method-assign]
    items = [(f"plain {i}", cell_aad("t", "c", i)) for i in range(4)]
    sealed = encrypt_many(cipher, items)
    assert transit.encrypt_requests == 1 + 4
    assert [cipher.decrypt(v, aad=aad) for v, (_, aad) in zip(sealed, items, strict=True)] == [
        p for p, _ in items
    ]


def test_an_encrypt_batch_transit_could_not_serve_raises() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)

    def down(**_: Any) -> dict[str, Any]:
        transit.encrypt_requests += 1
        raise requests.exceptions.ConnectionError("synthetic: connection refused")

    transit.encrypt_data = down  # type: ignore[method-assign]
    transit.encrypt_requests = 0
    with pytest.raises(CipherUnavailableError):
        encrypt_many(cipher, [("a", None), ("b", None)])
    assert transit.encrypt_requests == 1


def test_a_batch_500_body_never_rides_an_error() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 4)
    body = json.dumps({"data": {"batch_results": [{"plaintext": "dmFsdWUgMA=="}]}})

    def internal(**_: Any) -> dict[str, Any]:
        raise InternalServerError(body)

    transit.decrypt_data = internal  # type: ignore[method-assign]
    results = cipher.decrypt_many(items)
    assert all(isinstance(r, CipherUnavailableError) for r in results)
    for r in results:
        assert isinstance(r, BaseException)
        assert "dmFsdWUgMA==" not in "".join(traceback.format_exception(r))


def test_a_refused_decrypt_batch_asks_alone_and_stops_batching() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, crypto.BATCH_MAX_ITEMS + 2)
    real = transit.decrypt_data
    batches = 0

    def too_large(**kw: Any) -> dict[str, Any]:
        nonlocal batches
        if kw.get("batch_input") is not None:
            batches += 1
            raise UnexpectedError("413 Request Entity Too Large")
        return real(**kw)

    transit.decrypt_data = too_large  # type: ignore[method-assign]
    assert cipher.decrypt_many(items) == [f"value {i}" for i in range(len(items))]
    assert batches == 1  # the second run went value by value without a batch first
