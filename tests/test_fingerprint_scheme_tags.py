# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Stored key fingerprints carry a scheme tag (BACKLOG #3421).

``cipher_meta.key_id``, the DEK row of ``secret_rotation_meta`` and its non-DEK rows used to store a
fingerprint with no marker naming the function that made it. A release that changed that function
would then restart an unchanged key's AES-GCM invocation count at zero (ADR 0196) and reset the DEK's
age clock. Each stored value is now tagged. A value written before tags reads as today's scheme, so
nothing resets on upgrade, and a tag this release does not compile in is refused.

Since BACKLOG #3472 (ADR 0213) a non-DEK row is a sealed store-cipher cell behind its own tag, and a
row an earlier release wrote, tagged or not, keeps its dates and is replaced by a sealed cell.

Synthetic values only: every "secret" here is a test string.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import sqlite3
from pathlib import Path

import pytest

from messagefoundry.config.ai_policy import SecurityEnforcement
from messagefoundry.config.settings import SecretRotationSettings
from messagefoundry.pipeline import secret_rotation as sr
from messagefoundry.store.crypto import (
    KEY_ID_SCHEME,
    ROTATION_FP_SEALED_SCHEME,
    UnknownSchemeError,
    _fingerprint,
    cipher_meta_key,
    generate_key,
    make_cipher,
    read_scheme_tag,
)
from messagefoundry.store.store import MessageStore

_DEK = "MEFOR_STORE_ENCRYPTION_KEY"
_AD = "MEFOR_AUTH_AD_BIND_PASSWORD"
_OLD = "2020-01-01"
_VALUE = "test-only-bind-password"  # nosec B105 - a test value, never a real credential
_NOW = datetime.datetime(2026, 6, 15, 12, 0, tzinfo=datetime.UTC)


# --- the tag reader --------------------------------------------------------------------------


def test_an_untagged_value_reads_as_todays_scheme() -> None:
    dek_id = "3fa1b2c3d4e5f607"
    assert read_scheme_tag(dek_id, KEY_ID_SCHEME) == dek_id
    keyed = "0123456789abcdef:" + "a" * 32  # the pre-tag `<key id>:<mac>` shape
    assert read_scheme_tag(keyed, sr._FP_SCHEME) == keyed
    assert read_scheme_tag(f"{KEY_ID_SCHEME}:{dek_id}", KEY_ID_SCHEME) == dek_id


@pytest.mark.parametrize(
    ("stored", "scheme"),
    [
        ("sha3-16:3fa1b2c3d4e5f607", KEY_ID_SCHEME),
        (f"{sr._FP_SCHEME}:0123456789abcdef:{'a' * 32}", KEY_ID_SCHEME),  # another row's scheme
        (f"{KEY_ID_SCHEME}:3fa1b2c3d4e5f607", sr._FP_SCHEME),
        (":3fa1b2c3d4e5f607", KEY_ID_SCHEME),
    ],
)
def test_a_tag_this_release_does_not_compile_in_is_refused(stored: str, scheme: str) -> None:
    with pytest.raises(UnknownSchemeError):
        read_scheme_tag(stored, scheme)


def test_every_compiled_tag_reads_as_a_tag() -> None:
    # An all-hex tag would read as a pre-tag key id, so the reader would never see it.
    for scheme in (KEY_ID_SCHEME, sr._FP_SCHEME, ROTATION_FP_SEALED_SCHEME):
        assert set(scheme) - set("0123456789abcdef"), scheme
        assert ":" not in scheme


def test_each_tag_still_names_the_function_it_tags() -> None:
    # Known answers. A change to `_fingerprint` or `_bare_mac` fails here, and the fix is a new
    # scheme tag read beside the old one, not new constants (BACKLOG #3421). `_bare_mac` is the MAC
    # inside a sealed cell, so ROTATION_FP_SEALED_SCHEME names it (BACKLOG #3472).
    key = bytes(range(32))
    assert cipher_meta_key(_fingerprint(key)) == "sha256-16:630dcd2966c43366"
    assert sr._bare_mac(key, "synthetic-value") == "150c9b3dc722074a34b2cf276a40e750"


# --- cipher_meta: the invocation count carries over ------------------------------------------


def _rows(db: Path) -> list[tuple[str, int]]:
    with sqlite3.connect(db) as conn:
        return [
            (str(k), int(n))
            for k, n in conn.execute("SELECT key_id, invocations FROM cipher_meta ORDER BY key_id")
        ]


async def test_a_pre_tag_cipher_meta_row_keeps_its_count(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    key = generate_key()
    store = await MessageStore.open(db, cipher=make_cipher(key))
    cipher = store.cipher()
    key_id = cipher.invocation_key_id  # type: ignore[attr-defined]
    for _ in range(5):
        cipher.encrypt("synthetic")
    await store.close()
    [(row_id, spent)] = _rows(db)
    assert row_id == cipher_meta_key(key_id)
    assert spent >= 5, "premise: the close settles what was spent"

    # The store as a release before tags left it: the same row, keyed on the bare id.
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE cipher_meta SET key_id = ? WHERE key_id = ?", (key_id, row_id))
        conn.execute(
            "INSERT INTO cipher_meta (key_id, invocations, updated_at) VALUES (?, ?, 0)",
            ("feedfacefeedface", 7),
        )

    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        assert await store.cipher_invocations(key_id) >= spent  # folded at open, never reset
        assert await store.cipher_invocations("feedfacefeedface") == 7  # read before any fold
        assert await store.add_cipher_invocations("feedfacefeedface", 3) == 10
    finally:
        await store.close()
    rows = dict(_rows(db))
    assert set(rows) == {cipher_meta_key(key_id), cipher_meta_key("feedfacefeedface")}
    assert rows[cipher_meta_key(key_id)] >= spent
    assert rows[cipher_meta_key("feedfacefeedface")] == 10


async def test_two_writers_fold_a_pre_tag_row_once(tmp_path: Path) -> None:
    # Two handles on one file, as `serve` and a CLI command that checkpoints at open would be. A fold
    # that read the bare row outside the write transaction added its count twice.
    db = tmp_path / "s.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    await store.close()
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO cipher_meta (key_id, invocations, updated_at) VALUES (?, ?, 0)",
            ("feedfacefeedface", 100),
        )
    a = await MessageStore.open(db)
    try:
        b = await MessageStore.open(db)
        try:
            totals = await asyncio.gather(
                a.add_cipher_invocations("feedfacefeedface", 1),
                b.add_cipher_invocations("feedfacefeedface", 1),
            )
        finally:
            await b.close()
    finally:
        await a.close()
    assert sorted(totals) == [101, 102]
    assert dict(_rows(db))[cipher_meta_key("feedfacefeedface")] == 102
    assert "feedfacefeedface" not in dict(_rows(db))


# --- secret_rotation_meta: the age clocks carry over ------------------------------------------


_Out = tuple[dict[str, str], dict[str, str], dict[str, str], dict[str, str]]


async def _reconcile(db: Path, key: str, rows: dict[str, str] | None = None) -> _Out:
    """Reconcile a keyed store as the engine does at start, after seeding ``rows`` (class id to
    stored fingerprint, ``""`` for the class's pre-tag form) dated 2020. Returns the stamps'
    last-rotated dates, the stored fingerprints, and each class's pre-tag and tagged forms. The AD
    row's "tagged" form is the sealed tag's prefix only: a sealed cell holds a random key, so two
    seals of one value differ (BACKLOG #3472)."""
    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        dek_id = store.cipher_info().active_key_id
        assert dek_id
        assert store.secret_rotation_cipher() is not None
        tagged = {_DEK: sr.dek_fingerprint(dek_id), _AD: f"{ROTATION_FP_SEALED_SCHEME}:"}
        pre_tag = {
            _DEK: read_scheme_tag(tagged[_DEK], KEY_ID_SCHEME),
            _AD: "0123456789abcdef:" + "a" * 32,  # the pre-tag `<key id>:<mac>` shape
        }
        for class_id, fingerprint in (rows or {}).items():
            await store.upsert_secret_rotation_meta(
                class_id,
                fingerprint=fingerprint or pre_tag[class_id],
                tracked_since=_OLD,
                last_rotated=_OLD,
            )
        stamps = await sr.reconcile_rotation_meta(
            store,
            SecretRotationSettings(),
            dek_key_id=dek_id,
            enforcement=SecurityEnforcement.WARN,
            now=_NOW.timestamp(),
            env_values={_AD: _VALUE},
        )
        stored = await store.get_secret_rotation_meta()
        dates = {c: s.last_rotated.isoformat() for c, s in stamps.items()}
        return dates, {c: r.fingerprint for c, r in stored.items()}, pre_tag, tagged
    finally:
        await store.close()


async def test_fingerprints_are_stored_tagged(tmp_path: Path) -> None:
    _, stored, _, tagged = await _reconcile(tmp_path / "s.db", generate_key())
    assert stored[_DEK] == tagged[_DEK]
    assert stored[_DEK].startswith(f"{KEY_ID_SCHEME}:")
    assert stored[_AD].startswith(tagged[_AD])


async def test_pre_tag_fingerprints_compare_equal_and_keep_their_clocks(tmp_path: Path) -> None:
    db = tmp_path / "s.db"
    dates, stored, pre_tag, tagged = await _reconcile(db, generate_key(), {_DEK: "", _AD: ""})
    assert pre_tag != tagged  # premise: the seeded rows are untagged
    assert dates == {_DEK: _OLD, _AD: _OLD}  # neither clock reset on upgrade
    # Read as today's scheme, then re-stamped tagged, so no untagged row outlives this release. The
    # AD row is not compared at all (BACKLOG #3472): its dates are kept and a sealed cell replaces it.
    assert stored[_DEK] == tagged[_DEK]
    assert stored[_AD].startswith(tagged[_AD])


async def test_an_unknown_scheme_is_refused_and_resets_nothing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    unknown = {_DEK: "sha3-32:" + "b" * 32, _AD: "hmac-sha3-64:0123456789abcdef:" + "c" * 64}
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.secret_rotation"):
        dates, stored, _, tagged = await _reconcile(
            tmp_path / "s.db", generate_key(), dict(unknown)
        )
    # Read as a change, the DEK's clock would restart today and lift its ENFORCE escalation.
    assert dates == {_DEK: _OLD, _AD: _OLD}
    # Re-stamped under today's scheme with the dates kept, so the next rotation is detected.
    assert stored[_DEK] == tagged[_DEK]
    assert stored[_AD].startswith(tagged[_AD])
    assert "1 stored fingerprint(s) name a scheme this release does not know" in caplog.text
    # The non-DEK row is one the engine cannot read, which keeps its dates the same way (#3472).
    assert "1 secret fingerprint(s) could not be read" in caplog.text


def test_fingerprints_equal_refuses_an_unknown_stored_scheme() -> None:
    current = sr.dek_fingerprint("3fa1b2c3d4e5f607")
    assert sr.fingerprints_equal("3fa1b2c3d4e5f607", current)
    assert sr.fingerprints_equal(current, current)
    assert not sr.fingerprints_equal("0000000000000000", current)
    with pytest.raises(UnknownSchemeError):
        sr.fingerprints_equal("sha3-16:3fa1b2c3d4e5f607", current)
    # The pre-tag calling convention, an untagged `current`, is a caller's error, never a silent
    # "changed": rotate-key once passed the bare key id, and every same-key run would read as rotated.
    with pytest.raises(ValueError, match="scheme tag"):
        sr.fingerprints_equal("3fa1b2c3d4e5f607", "3fa1b2c3d4e5f607")
