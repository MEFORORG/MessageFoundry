# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Row-seal follow-ups to BACKLOG #6717 and #6718: the non-finite refusal on both sealers, its own
error type, a non-text stored seal on the Transit sealer, and pins that a seal written before these
changes still verifies. Synthetic data only.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import asdict
from typing import Any

import pytest

from messagefoundry.store import row_seal
from messagefoundry.store.row_seal import SESSION_KIND, RowSealer, TransitRowSealer, seal_bytes
from messagefoundry.store.store import SessionRecord, session_seal_ok
from tests._transit_seal_fake import Clock, FakeBackend

# Every type the encoder writes, and both zeros, so a change to any encoding moves a pin below.
_PINNED_FIELDS: tuple[tuple[str, object], ...] = (
    ("n", None),
    ("b", True),
    ("i", -7),
    ("x", 1.5),
    ("z", -0.0),
    ("t", 5e-324),
    ("s", "u1"),
    ("y", b"\x00\xff"),
)
_PINNED_KEY = bytes(range(32))
# Read on engine origin/main d2ed8a8bd8, before this branch: what main writes for the fields above.
_MAIN_SEAL = (
    "mfseal:v1:5bb5e8d61e093c73:9f6d72b1305e9a30042794e7ec47c723b83dc51111924ada8fe9c521738021ea"
)
_MAIN_SEAL_BYTES_SHA256 = "e7cc6743199bcdf9bb93bc39dda7971bc774de98df44307f01ef9fd4af6e2373"
_MAIN_TRANSIT_DIGEST = "27668a19875106906f750480d3be8b301fd25fad699aa7256c933e6b4e4c68a1"

_NOT_FINITE = (float("nan"), float("inf"), float("-inf"))


def _transit() -> tuple[TransitRowSealer, FakeBackend]:
    backend = FakeBackend()
    return TransitRowSealer(backend, clock=Clock()), backend


def test_a_seal_main_wrote_still_verifies_and_is_written_again() -> None:
    sealer = RowSealer(_PINNED_KEY)
    assert sealer.verify(SESSION_KIND, _PINNED_FIELDS, _MAIN_SEAL)
    assert sealer.seal(SESSION_KIND, _PINNED_FIELDS) == _MAIN_SEAL
    digest = hashlib.sha256(seal_bytes(SESSION_KIND, _PINNED_FIELDS)).hexdigest()
    assert digest == _MAIN_SEAL_BYTES_SHA256
    # Control: one changed field fails, so the pin is not a sealer that accepts everything.
    assert not sealer.verify(SESSION_KIND, (*_PINNED_FIELDS[:-1], ("y", b"\x00")), _MAIN_SEAL)


def test_the_transit_digest_main_computed_is_unchanged() -> None:
    sealer, _ = _transit()
    assert sealer._digest(SESSION_KIND, _PINNED_FIELDS).hex() == _MAIN_TRANSIT_DIGEST
    assert sealer._digest(SESSION_KIND, _PINNED_FIELDS[:-1]).hex() != _MAIN_TRANSIT_DIGEST


@pytest.mark.parametrize("value", _NOT_FINITE)
def test_the_non_finite_refusal_has_its_own_value_error(value: float) -> None:
    # BACKLOG #6717 item 4: a malformed field tuple raises ValueError too; the refusal is told apart
    # from it by type.
    refused = row_seal.NonFiniteSealValueError
    assert issubclass(refused, ValueError)
    sealer = RowSealer(_PINNED_KEY)
    with pytest.raises(refused):
        sealer.seal(SESSION_KIND, (("expires_at", value),))
    malformed: Any = [("only-a-name",)]
    with pytest.raises(ValueError) as unpack:
        sealer.seal(SESSION_KIND, malformed)
    assert not isinstance(unpack.value, refused)


@pytest.mark.parametrize("value", _NOT_FINITE)
async def test_the_transit_sealer_refuses_a_float_that_is_not_finite(value: float) -> None:
    # BACKLOG #6717: the local sealer refused a NaN or an infinity, and the Transit sealer sealed it.
    sealer, backend = _transit()
    with pytest.raises(row_seal.NonFiniteSealValueError):
        await sealer.seal_async(SESSION_KIND, (("expires_at", value),))
    assert backend.inputs == []  # nothing reached Transit
    stored = await sealer.seal_async(SESSION_KIND, (("expires_at", 1.5),))  # control
    assert await sealer.verify_async(SESSION_KIND, (("expires_at", 1.5),), stored)
    # A row changed to such a value still fails rather than raises.
    assert not await sealer.verify_async(SESSION_KIND, (("expires_at", value),), stored)


@pytest.mark.parametrize(
    "as_type",
    [lambda s: s.encode("ascii"), lambda s: bytearray(s, "ascii"), lambda s: 7, lambda s: 7.5],
    ids=["bytes", "bytearray", "int", "float"],
)
async def test_a_transit_seal_that_is_not_text_fails_every_check_without_raising(
    as_type: Callable[[str], Any],
) -> None:
    # BACKLOG #6718 item 3: TransitRowSealer._parse called startswith on whatever the column held.
    sealer, backend = _transit()
    fields = (("token_hash", "ab" * 32), ("n", 3))
    stored = await sealer.seal_async(SESSION_KIND, fields)
    assert sealer.is_active(stored)  # controls: the text form holds
    assert await sealer.verify_async(SESSION_KIND, fields, stored)
    calls = backend.verify_calls
    other = as_type(stored)
    assert not sealer.is_active(other)
    assert not await sealer.verify_async(SESSION_KIND, fields, other)
    assert not await sealer.verify_held_async(SESSION_KIND, fields, other)
    assert not await sealer.sealed_by_retired_key_async(SESSION_KIND, fields, other)
    assert backend.verify_calls == calls  # read as malformed, with no Transit call


def test_a_session_row_whose_seal_cell_is_not_text_fails_its_check() -> None:
    # BACKLOG #6718 item 2: from_mapping hands a non-text seal cell through as it was read, and the
    # check reads it as a malformed seal rather than raising.
    sealer = RowSealer(_PINNED_KEY)
    record = SessionRecord(
        token_hash="ab" * 32,
        user_id="u1",
        created_at=1.0,
        expires_at=2.0,
        last_used_at=1.0,
        revoked_at=None,
        client=None,
    )
    row = {**asdict(record), "seal": sealer.seal(SESSION_KIND, record.seal_fields())}
    assert session_seal_ok(sealer, SessionRecord.from_mapping(row))  # control
    for cell in (row["seal"].encode("ascii"), 7, 7.5):
        assert not session_seal_ok(sealer, SessionRecord.from_mapping({**row, "seal": cell}))
