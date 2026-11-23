# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Row-seal follow-ups to BACKLOG #6717 and #6718: the non-finite refusal on the Transit sealer and
its own error type, a non-text stored seal on the Transit sealer, and pins on the encoded bytes.
Synthetic data only.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import asdict
from typing import Any

import pytest

from messagefoundry.store.row_seal import (
    SESSION_KIND,
    NonFiniteSealValueError,
    RowSealer,
    TransitRowSealer,
    seal_bytes,
)
from messagefoundry.store.store import SessionRecord, session_seal_ok_async
from tests._transit_seal_fake import RETIRED, Clock, FakeBackend

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
# Read on engine origin/main d2ed8a8bd8, before this branch's refactor of the encoder, to show the
# refactor kept the bytes. A deliberate change to the v1 encoding updates these pins.
_MAIN_SEAL = (
    "mfseal:v1:5bb5e8d61e093c73:9f6d72b1305e9a30042794e7ec47c723b83dc51111924ada8fe9c521738021ea"
)
_MAIN_SEAL_BYTES_SHA256 = "e7cc6743199bcdf9bb93bc39dda7971bc774de98df44307f01ef9fd4af6e2373"
_MAIN_TRANSIT_DIGEST = "27668a19875106906f750480d3be8b301fd25fad699aa7256c933e6b4e4c68a1"

_NOT_FINITE = (float("nan"), float("inf"), float("-inf"))


def _transit(**kw: Any) -> tuple[TransitRowSealer, FakeBackend]:
    backend = FakeBackend()
    return TransitRowSealer(backend, clock=Clock(), **kw), backend


def test_the_encoded_bytes_are_the_ones_main_wrote() -> None:
    sealer = RowSealer(_PINNED_KEY)
    assert sealer.verify(SESSION_KIND, _PINNED_FIELDS, _MAIN_SEAL)
    assert sealer.seal(SESSION_KIND, _PINNED_FIELDS) == _MAIN_SEAL
    digest = hashlib.sha256(seal_bytes(SESSION_KIND, _PINNED_FIELDS)).hexdigest()
    assert digest == _MAIN_SEAL_BYTES_SHA256
    # Control: one changed field fails, so the pin is not a sealer that accepts everything.
    assert not sealer.verify(SESSION_KIND, (*_PINNED_FIELDS[:-1], ("y", b"\x00")), _MAIN_SEAL)
    transit, _ = _transit()
    for finite in (False, True):
        assert transit._digest(SESSION_KIND, _PINNED_FIELDS, finite=finite).hex() == (
            _MAIN_TRANSIT_DIGEST
        )
    assert transit._digest(SESSION_KIND, _PINNED_FIELDS[:-1], finite=False).hex() != (
        _MAIN_TRANSIT_DIGEST
    )


def test_the_non_finite_refusal_is_told_apart_from_a_malformed_field_pair() -> None:
    # BACKLOG #6717 item 4: a malformed field pair raises ValueError too.
    assert issubclass(NonFiniteSealValueError, ValueError)
    malformed: Any = [("only-a-name",)]
    with pytest.raises(ValueError) as unpack:
        RowSealer(_PINNED_KEY).seal(SESSION_KIND, malformed)
    assert not isinstance(unpack.value, NonFiniteSealValueError)


@pytest.mark.parametrize("value", _NOT_FINITE)
async def test_the_transit_sealer_refuses_a_float_that_is_not_finite(value: float) -> None:
    # BACKLOG #6717: the local sealer refused a NaN or an infinity, and the Transit sealer sealed it.
    sealer, backend = _transit()
    with pytest.raises(NonFiniteSealValueError):
        await sealer.seal_async(SESSION_KIND, (("expires_at", value),))
    assert backend.inputs == []  # nothing reached Transit
    stored = await sealer.seal_async(SESSION_KIND, (("expires_at", 1.5),))  # control
    assert await sealer.verify_async(SESSION_KIND, (("expires_at", 1.5),), stored)
    # A row changed to such a value still fails rather than raises.
    assert not await sealer.verify_async(SESSION_KIND, (("expires_at", value),), stored)


@pytest.mark.parametrize(
    "as_type",
    [lambda s: s.encode("ascii"), lambda s: bytearray(s, "ascii")],
    ids=["bytes", "bytearray"],
)
async def test_a_transit_seal_that_is_not_text_fails_every_check_without_raising(
    as_type: Callable[[str], Any],
) -> None:
    # BACKLOG #6718 item 3: TransitRowSealer._parse called startswith on whatever the column held.
    # Each check has a positive control on the text form, so a False below is the parse refusing.
    sealer, backend = _transit(retired_key_names=[RETIRED])
    fields = (("token_hash", "ab" * 32), ("n", 3))
    stored = await sealer.seal_async(SESSION_KIND, fields)
    old = TransitRowSealer(FakeBackend(active=RETIRED), clock=Clock())
    old_stored = await old.seal_async(SESSION_KIND, fields)
    assert sealer.is_active(stored)
    assert await sealer.verify_async(SESSION_KIND, fields, stored)
    assert await sealer.verify_held_async(SESSION_KIND, fields, stored)
    assert await sealer.sealed_by_retired_key_async(SESSION_KIND, fields, old_stored)
    calls = backend.verify_calls
    assert not sealer.is_active(as_type(stored))
    assert not await sealer.verify_async(SESSION_KIND, fields, as_type(stored))
    assert not await sealer.verify_held_async(SESSION_KIND, fields, as_type(stored))
    assert not await sealer.sealed_by_retired_key_async(SESSION_KIND, fields, as_type(old_stored))
    assert backend.verify_calls == calls  # read as malformed, with no Transit call


async def test_a_session_row_whose_seal_cell_is_a_blob_fails_its_check_on_transit() -> None:
    # BACKLOG #6718 items 2 and 3: from_mapping hands a BLOB seal cell through as it was read, and
    # the session read check under the Transit sealer reads it as malformed rather than raising.
    sealer, _ = _transit()
    record = SessionRecord(
        token_hash="ab" * 32,
        user_id="u1",
        created_at=1.0,
        expires_at=2.0,
        last_used_at=1.0,
        revoked_at=None,
        client=None,
    )
    row = {**asdict(record), "seal": await sealer.seal_async(SESSION_KIND, record.seal_fields())}
    assert await session_seal_ok_async(sealer, SessionRecord.from_mapping(row))  # control
    blob = {**row, "seal": row["seal"].encode("ascii")}
    assert not await session_seal_ok_async(sealer, SessionRecord.from_mapping(blob))
