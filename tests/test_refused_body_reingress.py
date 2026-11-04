# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #4796 item 1: a refused loopback re-ingress is charged to the refused-body allowance.

The contract in ``tests/_reingress_refused_body_contract.py`` runs here on SQLite, keyless and keyed,
and from the gated SQL Server and Postgres suites. The unit tests below pin how
:meth:`RefusedBodyAllowance.bound_held` reads a body the engine already holds.

Synthetic bodies only; no real PHI.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ContentType
from messagefoundry.parsing import RawMessage
from messagefoundry.parsing.binary import decode as decode_carriage
from messagefoundry.parsing.binary import is_marked
from messagefoundry.pipeline.refused_body import (
    METADATA_KEY,
    RefusedBodyAllowance,
    RefusedBodyPolicy,
)
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher, verify_refused_body_digest
from tests._reingress_refused_body_contract import CASES

_KEYLESS = make_cipher(None)


@pytest.fixture(params=[False, True], ids=["keyless", "keyed"])
async def store(tmp_path: Path, request: pytest.FixtureRequest) -> AsyncIterator[MessageStore]:
    cipher = make_cipher(generate_key()) if request.param else None
    s = await MessageStore.open(tmp_path / "reingress_refused.db", cipher=cipher)
    yield s
    await s.close()


@pytest.mark.parametrize("case", CASES)
async def test_reingress_refused_body_contract(store: MessageStore, case: Any) -> None:
    await case(store)


def _allowance(allowance_bytes: int, head_bytes: int = 256) -> RefusedBodyAllowance:
    return RefusedBodyAllowance(
        RefusedBodyPolicy(
            allowance_bytes=allowance_bytes, window_seconds=60.0, head_bytes=head_bytes
        )
    )


def _record(metadata: str) -> dict[str, Any]:
    return dict(json.loads(metadata)[METADATA_KEY])


def test_a_canonical_carriage_on_a_binary_loopback_is_described_by_the_bytes_it_carries() -> None:
    payload = bytes(range(256)) * 20  # 5120 bytes, NULs included
    body = RawMessage.from_bytes(payload, ContentType.BINARY.value).raw
    key = generate_key()
    bounded = _allowance(0).bound_held(
        "IB_LOOP", body, ContentType.BINARY.value, "e", cipher=make_cipher(key)
    )
    record = _record(bounded.metadata)
    assert record["bytes"] == len(payload) and record["stored"] == "head"
    assert verify_refused_body_digest(make_cipher(key), payload, record["body_hmac"]) is True
    # The head is the carried bytes' head, in carriage because it holds a NUL: never a cut of the
    # base64 text, and never the carriage string wrapped a second time.
    assert is_marked(bounded.raw) and decode_carriage(bounded.raw) == payload[:256]


def test_a_carriage_inside_the_allowance_is_stored_exactly_as_held() -> None:
    body = RawMessage.from_bytes(b"\x00\x01" * 2000, ContentType.BINARY.value).raw
    allowance = _allowance(len(body))
    bounded = allowance.bound_held("IB_LOOP", body, ContentType.BINARY.value, "e", cipher=_KEYLESS)
    assert bounded.raw == body and bounded.error == "e"
    assert _record(bounded.metadata)["stored"] == "whole"
    # It was charged the carriage it stores, so nothing of the allowance is left.
    assert not allowance.try_charge("IB_LOOP", 1)


def test_a_padded_carriage_is_charged_as_the_text_it_is() -> None:
    # A decoder strips whitespace, so this decodes to 3 bytes. Read as those bytes it would fit any
    # head and be stored whole for free; it is held as text, so it is charged and cut as text.
    body = "mfb64:v1:" + " " * 10_000 + "AAAA"
    bounded = _allowance(0).bound_held(
        "IB_LOOP", body, ContentType.BINARY.value, "e", cipher=_KEYLESS
    )
    record = _record(bounded.metadata)
    assert record["bytes"] == len(body) and record["stored"] == "head"
    # Its head is re-made as carriage of the held text's first bytes, as a listener's would be.
    assert decode_carriage(bounded.raw) == body.encode()[:256]


def test_a_text_loopback_body_that_opens_with_the_marker_is_text() -> None:
    # Only a binary loopback carries bytes in carriage; on a text loopback the marker is just text.
    body = RawMessage.from_bytes(b"A" * 3000, ContentType.BINARY.value).raw
    bounded = _allowance(0).bound_held(
        "IB_LOOP", body, ContentType.JSON.value, "e", cipher=_KEYLESS
    )
    record = _record(bounded.metadata)
    assert record["bytes"] == len(body.encode())
    assert decode_carriage(bounded.raw) == body.encode()[:256]


def test_a_multibyte_reply_is_charged_its_utf8() -> None:
    body = "é" * 1500  # 3000 UTF-8 bytes
    allowance = _allowance(2999)
    bounded = allowance.bound_held("IB_LOOP", body, ContentType.JSON.value, "e", cipher=_KEYLESS)
    assert _record(bounded.metadata) == {
        "bytes": 3000,
        "body_hmac": None,
        "stored": "head",
        "head_bytes": 256,
    }
    assert len(bounded.raw.encode()) <= 256 and body.startswith(bounded.raw)
    # Nothing was charged for the head, so a 2998-byte reply still fits the 2999.
    fits = allowance.bound_held("IB_LOOP", "é" * 1499, ContentType.JSON.value, "e", cipher=_KEYLESS)
    assert _record(fits.metadata)["stored"] == "whole"


def test_a_reply_no_longer_than_its_head_is_stored_whole_and_charges_nothing() -> None:
    allowance = _allowance(0)
    for _ in range(20):
        bounded = allowance.bound_held(
            "IB_LOOP", "x" * 256, ContentType.TEXT.value, "e", cipher=_KEYLESS
        )
        assert bounded.raw == "x" * 256 and _record(bounded.metadata)["stored"] == "whole"


def test_the_loopback_spends_its_own_allowance_not_a_listeners() -> None:
    allowance = _allowance(1000)
    spent = allowance.bound_held(
        "IB_LOOP", "y" * 1000, ContentType.TEXT.value, "e", cipher=_KEYLESS
    )
    assert _record(spent.metadata)["stored"] == "whole"
    assert allowance.try_charge("IB_LISTENER", 1000)
    assert not allowance.try_charge("IB_LOOP", 1)
