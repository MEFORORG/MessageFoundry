# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Transit cipher opens and seals many cells per request (vault BACKLOG #6706).

A full restore-verify and ``cipher-audit`` read every cell of a store back through the cipher, and
the first keyed open of a store holding plaintext seals every cell. Under ``vault_transit`` each
cell was one Transit request. These tests count requests against a fake Transit that answers
``batch_input`` as Vault does: a result per item carrying its ``reference``, and HTTP 400 for the
whole batch when one item fails. Synthetic data only."""

from __future__ import annotations

import argparse
import base64
import collections
import json
import logging
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
    AADComponentError,
    AesGcmCipher,
    CipherError,
    CipherUnavailableError,
    cell_aad,
    decrypt_or_error,
    detached,
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
            # One result without its reference beside others that carry one: not an unechoing
            # Transit (which falls back to single requests), so the order cannot be trusted.
            lambda r: [{k: v for k, v in r[0].items() if k != "reference"}, *r[1:]],
            id="one-reference-missing",
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
    # The value asked for keeps its own refusal; every value never asked for is no verdict.
    assert not isinstance(results[0], CipherUnavailableError)
    assert all(isinstance(r, CipherUnavailableError) for r in results[1:])
    assert cipher._batch_alone is False  # Transit served no single value, so batching stays on


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


class _RaisingFilter(logging.Filter):
    """A log filter that fails on every record, as a broken redaction filter would."""

    def filter(self, record: logging.LogRecord) -> bool:
        raise ValueError("filter fault")


def test_a_raising_log_filter_does_not_stop_the_switch_to_sending_alone_except_out_of_memory(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """BACKLOG #6707: the warning that batching is off goes through :func:`_warn_quietly`, so a
    log filter that raises leaves every value opened and batching off, and is reported on
    stderr, except out of memory or stack."""
    monkeypatch.setattr(crypto_transit, "_logged_at", {})
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 3)
    real = transit.decrypt_data

    def too_large(**kw: Any) -> dict[str, Any]:
        if kw.get("batch_input") is not None:
            raise UnexpectedError("413 Request Entity Too Large")
        return real(**kw)

    transit.decrypt_data = too_large  # type: ignore[method-assign]
    raising = _RaisingFilter()
    crypto_transit.log.addFilter(raising)
    try:
        assert cipher.decrypt_many(items) == [f"value {i}" for i in range(3)]
    finally:
        crypto_transit.log.removeFilter(raising)
    assert cipher._batch_alone is True
    assert "could not be logged ('ValueError')" in capsys.readouterr().err


def _without_reference(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: v for k, v in r.items() if k != "reference"} for r in results]


def test_a_reply_with_no_reference_echo_is_asked_for_alone() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 5)
    transit.tamper = _without_reference
    transit.decrypt_requests = 0
    assert cipher.decrypt_many(items) == [f"value {i}" for i in range(5)]
    assert transit.decrypt_requests == 1 + 5  # the unused batch, then each value alone
    transit.decrypt_requests = 0
    assert cipher.decrypt_many(items) == [f"value {i}" for i in range(5)]
    assert transit.decrypt_requests == 5  # the cipher now sends each value alone


async def test_the_first_keyed_open_succeeds_when_transit_does_not_echo_reference(
    tmp_path: Path,
) -> None:
    db = tmp_path / "store.db"
    await _write_messages(db, 200)  # keyless: legacy plaintext the keyed open seals
    transit = _BatchTransit()
    transit.tamper = _without_reference
    store = await MessageStore.open(db, cipher=_cipher(transit))
    await store.close()
    # One batch, unused, then every value alone.
    assert transit.encrypt_requests == 1 + 600
    conn = connect_readonly(db, busy_timeout=5.0)
    try:
        audit = audit_cipher_cells(conn, _cipher(transit))
    finally:
        conn.close()
    assert (audit.opened, audit.failed, audit.legacy, audit.unmarked) == (600, 0, 0, 0)


def test_a_classifier_that_raises_on_a_batch_400_carries_no_body_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 4)
    items[1] = (items[1][0], cell_aad("t", "c", 999))  # the batch then answers 400 with a body

    def broken(exc: BaseException) -> bool:
        raise RuntimeError("synthetic classifier fault")

    monkeypatch.setattr(crypto_transit, "is_vault_bad_request", broken)
    results = cipher.decrypt_many(items)  # nothing escapes
    assert results[0] == "value 0" and results[2] == "value 2" and results[3] == "value 3"
    assert isinstance(results[1], CipherError)
    leaked = base64.b64encode(b"value 0").decode("ascii")
    assert leaked not in "".join(traceback.format_exception(results[1]))
    assert cipher._batch_alone is False  # an unclassified failure never turns batching off


def test_an_empty_reference_on_every_result_is_asked_for_alone() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 3)
    transit.tamper = lambda r: [{**x, "reference": ""} for x in r]
    assert cipher.decrypt_many(items) == ["value 0", "value 1", "value 2"]
    assert cipher.encrypt_many([("a", None), ("b", None)])[0].startswith("mfenc:v3:")


def test_the_send_alone_state_outlives_one_call() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 3)
    real = transit.decrypt_data
    batches = 0

    def too_large(**kw: Any) -> dict[str, Any]:
        nonlocal batches
        if kw.get("batch_input") is not None:
            batches += 1
            raise UnexpectedError("413 Request Entity Too Large")
        return real(**kw)

    transit.decrypt_data = too_large  # type: ignore[method-assign]
    for _ in range(3):
        assert cipher.decrypt_many(items) == ["value 0", "value 1", "value 2"]
    assert batches == 1


def test_an_encrypt_batch_400_or_unread_failure_keeps_batching_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    real = transit.encrypt_data

    def bad_request(**kw: Any) -> dict[str, Any]:
        if kw.get("batch_input") is not None:
            raise InvalidRequest("synthetic batch 400")
        return real(**kw)

    transit.encrypt_data = bad_request  # type: ignore[method-assign]
    items = [("a", None), ("b", None)]
    assert all(v.startswith("mfenc:v3:") for v in cipher.encrypt_many(items))
    assert cipher._batch_alone is False  # a 400 never turns batching off

    def broken(exc: BaseException) -> bool:
        raise RuntimeError("synthetic classifier fault")

    monkeypatch.setattr(crypto_transit, "is_vault_bad_request", broken)
    assert all(v.startswith("mfenc:v3:") for v in cipher.encrypt_many(items))
    assert cipher._batch_alone is False  # nor does a failure the classifier could not read


def _frames_reach(error: BaseException, needle: str) -> bool:
    """Whether any frame reachable from any traceback in ``error``'s whole exception graph
    (``__cause__``, ``__context__`` and an exception group's members, breadth first) holds
    ``needle`` in the repr of a local. Written apart from ``crypto.detached`` on purpose."""
    queue: collections.deque[BaseException] = collections.deque([error])
    visited: set[int] = set()
    while queue:
        node = queue.popleft()
        if id(node) in visited:
            continue
        visited.add(id(node))
        tb = node.__traceback__
        while tb is not None:
            frame: Any = tb.tb_frame
            while frame is not None:
                if any(needle in repr(value) for value in frame.f_locals.values()):
                    return True
                frame = frame.f_back
            tb = tb.tb_next
        for linked in (node.__context__, node.__cause__):
            if linked is not None:
                queue.append(linked)
        if isinstance(node, BaseExceptionGroup):
            queue.extend(node.exceptions)
    return False


def test_no_returned_error_reaches_another_values_plaintext() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 4)
    items[3] = (items[3][0], cell_aad("t", "c", 999))  # the batch answers 400, then each alone
    results = cipher.decrypt_many(items)
    assert results[:3] == ["value 0", "value 1", "value 2"]
    error = results[3]
    assert isinstance(error, CipherError)
    assert not _frames_reach(error, "value 0")


def test_a_context_apart_from_the_cause_keeps_no_traceback() -> None:
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 4)
    bad = items[3][0][len("mfenc:v3:") :]
    real = transit.decrypt_data

    def composite(**kw: Any) -> dict[str, Any]:
        if kw.get("batch_input") is not None:
            raise InvalidRequest("synthetic batch 400")
        if kw.get("ciphertext") == bad:
            # A cause and a different context, as urllib3 wraps a TLS failure: the context keeps
            # the traceback whose frames reach the values already opened alone.
            try:
                raise ValueError("synthetic inner failure")
            except ValueError:
                raise InvalidRequest("synthetic refusal") from RuntimeError("synthetic cause")
        return real(**kw)

    transit.decrypt_data = composite  # type: ignore[method-assign]
    results = cipher.decrypt_many(items)
    assert results[:3] == ["value 0", "value 1", "value 2"]
    error = results[3]
    assert isinstance(error, CipherError)
    inner = error.__cause__
    assert inner is not None and isinstance(inner.__context__, ValueError)
    assert inner.__cause__ is not inner.__context__
    assert not _frames_reach(error, "value 0")


def test_detached_clears_every_member_of_an_exception_group() -> None:
    def raised(exc: Exception) -> Exception:
        try:
            raise exc
        except Exception as caught:  # noqa: BLE001 -- builds a traceback for the test
            return caught

    secret = "value 0"  # a local the members' frames reach until they are detached
    member = raised(ValueError("member"))
    group = raised(ExceptionGroup("group", [member]))
    error = CipherError("outer")
    error.__context__ = group
    assert _frames_reach(error, secret)
    detached(error)
    assert not _frames_reach(error, secret)


def test_a_none_key_is_refused_before_any_transit_request() -> None:
    # BACKLOG #5962: a cell_aad with a None key component never reaches Vault. A seal batch refuses
    # it before any request, and an open batch answers it alone, so the rest still batch and
    # batching stays on.
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = [("v", cell_aad("t", "c", i)) for i in range(4)] + [("v", cell_aad("t", "c", None))]
    with pytest.raises(AADComponentError, match=r"^t\.c: "):
        cipher.encrypt_many(items)
    assert transit.encrypt_requests == 0
    sealed = cipher.encrypt_many([("v", cell_aad("t", "c", i)) for i in range(5)])
    transit.decrypt_requests = 0
    opened = cipher.decrypt_many(
        [(sealed[i], cell_aad("t", "c", i)) for i in range(4)]
        + [(sealed[4], cell_aad("t", "c", None))]
    )
    assert opened[:4] == ["v"] * 4
    assert isinstance(opened[4], AADComponentError)
    assert transit.decrypt_requests == 1  # one batch for the four; the refusal sent nothing
    assert cipher._batch_alone is False


# --- vault BACKLOG #6706 added items 1, 2, 7, 14 and 15 ------------------------------------------


def _chain(error: CipherError, links: int) -> CipherError:
    """``error`` with ``links`` raised exceptions chained under it as contexts, each holding a
    traceback whose frame reaches a synthetic local."""
    secret = "value 0"  # a local the links' frames reach until they are cleared
    tail: BaseException | None = None
    for i in range(links):
        try:
            raise ValueError(f"link {i} {secret[:0]}") from None
        except ValueError as caught:
            caught.__context__ = tail
            tail = caught
    error.__context__ = tail
    return error


def _graph_nodes(error: BaseException) -> int:
    """How many exceptions ``error``'s graph holds, walked apart from ``crypto.detached``."""
    seen: set[int] = set()
    queue: collections.deque[BaseException] = collections.deque([error])
    while queue:
        node = queue.popleft()
        if id(node) in seen:
            continue
        seen.add(id(node))
        queue.extend(e for e in (node.__cause__, node.__context__) if e is not None)
        if isinstance(node, BaseExceptionGroup):
            queue.extend(node.exceptions)
    return len(seen)


def test_detached_past_its_limit_cuts_off_what_it_did_not_clear(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Item 1: past _DETACH_LIMIT the error was returned with the rest of its tracebacks attached.
    monkeypatch.setattr(crypto, "_DETACH_LIMIT", 3)
    caplog.set_level(logging.WARNING)
    error = _chain(CipherError("synthetic"), 5)
    assert _frames_reach(error, "value 0")
    assert detached(error) is error  # in place: a caller that keeps `error` keeps it cleared
    assert not _frames_reach(error, "value 0")
    assert _graph_nodes(error) == 3
    assert any(
        r.name == "messagefoundry.store.crypto" and "the rest are cut off it" in r.getMessage()
        for r in caplog.records
    )


def test_detached_at_its_limit_keeps_every_link(monkeypatch: pytest.MonkeyPatch) -> None:
    # The boundary: a graph of exactly _DETACH_LIMIT exceptions is cleared whole, and one more is
    # cut off.
    monkeypatch.setattr(crypto, "_DETACH_LIMIT", 4)
    whole = _chain(CipherError("synthetic"), 3)
    assert detached(whole) is whole and _graph_nodes(whole) == 4
    assert not _frames_reach(whole, "value 0")
    over = _chain(CipherError("synthetic"), 4)
    assert detached(over) is over and _graph_nodes(over) == 4
    assert not _frames_reach(over, "value 0")


def test_detached_past_its_limit_keeps_the_errors_own_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The nearest links are kept, so an outage stays an outage (gave_no_verdict reads the cause).
    monkeypatch.setattr(crypto, "_DETACH_LIMIT", 3)
    error = _chain(CipherError("synthetic"), 5)
    error.__cause__ = requests.ConnectionError("synthetic unreachable")
    assert crypto.gave_no_verdict(error)
    assert detached(error) is error
    assert crypto.gave_no_verdict(error) and not _frames_reach(error, "value 0")


def test_detached_past_its_limit_clears_an_unvisited_group_member(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raised(exc: Exception) -> Exception:
        try:
            raise exc
        except Exception as caught:  # noqa: BLE001 -- builds a traceback for the test
            return caught

    secret = "value 0"  # a local the members' frames reach until they are cleared
    members = [raised(ValueError(f"member {i} {secret[:0]}")) for i in range(4)]
    for member in members:
        member.__context__ = raised(KeyError("deeper"))
    group = raised(ExceptionGroup("group", members))
    error = CipherError("outer")
    error.__context__ = group
    monkeypatch.setattr(crypto, "_DETACH_LIMIT", 3)
    assert detached(error) is error
    assert not _frames_reach(error, "value 0")


def test_detached_past_its_limit_clears_a_group_nested_in_an_unvisited_member(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raised(exc: Exception) -> Exception:
        try:
            raise exc
        except Exception as caught:  # noqa: BLE001 -- builds a traceback for the test
            return caught

    secret = "value 0"  # a local the members' frames reach until they are cleared
    inner = raised(
        ExceptionGroup("inner", [raised(ValueError(f"x {secret[:0]}")) for _ in range(3)])
    )
    outer = raised(ExceptionGroup("outer", [raised(KeyError("a")), raised(KeyError("b")), inner]))
    error = CipherError("synthetic")
    error.__context__ = outer
    monkeypatch.setattr(crypto, "_DETACH_LIMIT", 3)
    assert _frames_reach(error, "value 0")
    assert detached(error) is error
    assert not _frames_reach(error, "value 0")


def test_detached_past_its_limit_cuts_when_its_warning_cannot_be_logged(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Repair item 1: the WARNING was logged before the cut and unguarded, so a raising log filter
    # skipped the cut and returned the rest of the graph with its tracebacks attached.
    monkeypatch.setattr(crypto, "_DETACH_LIMIT", 3)
    error = _chain(CipherError("synthetic"), 5)
    raising = _RaisingFilter()
    crypto._log.addFilter(raising)
    try:
        assert detached(error) is error
    finally:
        crypto._log.removeFilter(raising)
    assert not _frames_reach(error, "value 0")
    assert _graph_nodes(error) == 3
    assert "could not be logged ('ValueError')" in capsys.readouterr().err


class _Interrupt(BaseException):
    """A synthetic non-``Exception`` error, which the WARNING's guard does not catch."""


class _InterruptingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        raise _Interrupt


def test_an_error_escaping_detacheds_warning_holds_nothing_the_cut_unlinked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Round 1: detached's own locals still held the unlinked links, tracebacks attached, while it
    # logged, so an error escaping the log step carried them through detached's frame.
    monkeypatch.setattr(crypto, "_DETACH_LIMIT", 3)
    error = _chain(CipherError("synthetic"), 5)
    interrupting = _InterruptingFilter()
    crypto._log.addFilter(interrupting)
    try:
        with pytest.raises(_Interrupt) as caught:
            detached(error)
    finally:
        crypto._log.removeFilter(interrupting)
    tb = caught.value.__traceback__
    frames = []
    while tb is not None:
        frames.append(tb.tb_frame)
        tb = tb.tb_next
    (frame,) = [f for f in frames if f.f_code.co_name == "detached"]
    held = [v for v in frame.f_locals.values() if isinstance(v, BaseException)]
    held += [e for v in frame.f_locals.values() if isinstance(v, collections.deque) for e in v]
    assert all(e.__traceback__ is None for e in held)
    assert not _frames_reach(error, "value 0")


class _CountedGroup(ExceptionGroup[Exception]):
    """An exception group that counts reads of its ``exceptions``."""

    reads = 0

    @property
    def exceptions(self) -> tuple[Exception, ...]:
        _CountedGroup.reads += 1
        return super().exceptions


def test_detached_past_its_limit_descends_a_shared_member_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Repair item 2: the cut's descent into unvisited groups kept no record of what it cleared, so
    # a member shared down a stack of groups was descended into 2**depth times.
    depth = 12
    try:
        raise ValueError("leaf")
    except ValueError as caught:
        leaf = caught
    shared: Exception = leaf
    for _ in range(depth):
        shared = _CountedGroup("level", [shared, shared])
    error = CipherError("synthetic")
    error.__context__ = ExceptionGroup("top", [KeyError("a"), KeyError("b"), shared])
    monkeypatch.setattr(crypto, "_DETACH_LIMIT", 3)
    _CountedGroup.reads = 0
    assert detached(error) is error
    assert 1 <= _CountedGroup.reads <= depth  # each level read once, by the cut's descent
    assert leaf.__traceback__ is None


def test_detached_past_its_limit_keeps_a_visited_members_links(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Repair item 2: a visited member reached again through an unvisited group had its links,
    # which the cut keeps, set to None.
    kept = ValueError("kept")
    member = ValueError("member")
    member.__context__ = kept
    outer = ExceptionGroup("outer", [member, KeyError("q"), ExceptionGroup("again", [member])])
    error = CipherError("synthetic")
    error.__cause__ = kept
    error.__context__ = outer
    monkeypatch.setattr(crypto, "_DETACH_LIMIT", 4)
    assert detached(error) is error
    assert member.__context__ is kept


def test_detached_past_its_limit_keeps_a_kept_context_visible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Repair item 3: setting __cause__ to None also sets __suppress_context__, so a context the
    # cut kept was hidden from a rendered traceback.
    kept = ValueError("the kept context")
    link = ValueError("link")
    link.__cause__ = KeyError("cut")
    link.__context__ = kept
    link.__suppress_context__ = False
    error = CipherError("synthetic")
    error.__cause__ = kept
    error.__context__ = link
    monkeypatch.setattr(crypto, "_DETACH_LIMIT", 3)
    assert detached(error) is error
    assert link.__cause__ is None and link.__context__ is kept
    assert link.__suppress_context__ is False
    assert "the kept context" in "".join(traceback.format_exception(link))


def test_detached_under_its_limit_returns_the_same_error() -> None:
    error = _chain(CipherError("synthetic"), 3)
    assert detached(error) is error and not _frames_reach(error, "value 0")
    assert _graph_nodes(error) == 4


def _switch_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "messagefoundry.store.crypto_transit"
        and "sending each value alone" in r.getMessage()
    ]


def test_the_decrypt_switch_to_sending_alone_warns_once_naming_the_failure_type(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Items 2 and 15: the WARNING named no failure type, and no test asserted it.
    caplog.set_level(logging.WARNING)
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 3)
    real = transit.decrypt_data

    def too_large(**kw: Any) -> dict[str, Any]:
        if kw.get("batch_input") is not None:
            raise UnexpectedError("413 Request Entity Too Large")
        return real(**kw)

    transit.decrypt_data = too_large  # type: ignore[method-assign]
    assert cipher.decrypt_many(items) == ["value 0", "value 1", "value 2"]
    assert cipher.decrypt_many(items) == ["value 0", "value 1", "value 2"]
    (message,) = _switch_warnings(caplog)
    assert "refused a batch decrypt (UnexpectedError)" in message
    assert "413" not in message


def test_the_encrypt_switch_to_sending_alone_warns_naming_the_failure_type(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING)
    transit = _BatchTransit()
    cipher = _cipher(transit)
    real = transit.encrypt_data

    def too_large(**kw: Any) -> dict[str, Any]:
        if kw.get("batch_input") is not None:
            raise UnexpectedError("413 Request Entity Too Large")
        return real(**kw)

    transit.encrypt_data = too_large  # type: ignore[method-assign]
    encrypt_many(cipher, [(f"plain {i}", cell_aad("t", "c", i)) for i in range(3)])
    (message,) = _switch_warnings(caplog)
    assert "refused a batch encrypt (UnexpectedError)" in message


def test_an_unechoed_reply_switch_warns_with_no_failure_type(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING)
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 3)
    transit.tamper = _without_reference
    cipher.decrypt_many(items)
    (message,) = _switch_warnings(caplog)
    assert "did not echo the reference of a batch decrypt (key=" in message


def test_a_faulting_400_check_does_not_discard_an_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    # Item 7: a fault in is_vault_bad_request discarded True from is_vault_unavailable, so an
    # outage was handled as a 400 and every value asked for alone.
    transit = _BatchTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 4)
    real = transit.decrypt_data
    singles = 0

    def down(**kw: Any) -> dict[str, Any]:
        nonlocal singles
        if kw.get("batch_input") is not None:
            raise requests.ConnectionError("synthetic unreachable")
        singles += 1
        return real(**kw)

    def broken(exc: BaseException) -> bool:
        raise RuntimeError("synthetic classifier fault")

    transit.decrypt_data = down  # type: ignore[method-assign]
    monkeypatch.setattr(crypto_transit, "is_vault_bad_request", broken)
    results = cipher.decrypt_many(items)
    assert all(isinstance(r, CipherUnavailableError) for r in results)
    assert singles == 0
    assert cipher._batch_alone is False


def test_the_cipher_audit_help_states_the_batch_bound_as_a_number() -> None:
    # Item 14: the help named BATCH_MAX_ITEMS and a file path rather than the number.
    from messagefoundry.__main__ import _build_parser

    parser, _ = _build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    help_text = next(c.help for c in sub._choices_actions if c.dest == "cipher-audit")
    assert help_text is not None
    assert f"batches of up to {crypto.BATCH_MAX_ITEMS} values" in help_text
    assert f"{crypto.BATCH_MAX_CHARS:,} characters" in help_text
    assert "BATCH_MAX_ITEMS" not in help_text and "store/crypto.py" not in help_text
