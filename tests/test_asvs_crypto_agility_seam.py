# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 11.2.2 — the cryptographic-agility seam contract (docs/PHI.md section 3.x).

The owner ruled 2026-08-11 that this project commits to RELEASE-swappability (a release can change an
at-rest algorithm without a data migration) and explicitly refuses RUNTIME reconfiguration (an
operator selecting an algorithm on a running instance).

A published seam contract that nothing checks is a claim, not a control. These pin the three
properties the contract rests on, plus the one limit it states — so the document cannot quietly
become false.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store.crypto import (
    _V2_PREFIX,
    PREFIX,
    Cipher,
    CipherError,
    cell_aad,
    generate_key,
    make_cipher,
)

_ROOT = Path(__file__).resolve().parent.parent


def test_the_stored_value_is_self_describing() -> None:
    """Property 1: a reader learns the algorithm from the value, not out of band."""
    assert _V2_PREFIX == "mfenc:v2:"
    cipher = make_cipher(generate_key(), write_v2=True)
    stored = cipher.encrypt("PHI body", aad=cell_aad("messages", "raw", 1))
    assert stored.startswith(_V2_PREFIX)
    # mfenc:v2:<alg>:<key_id>:<b64> -- the alg segment is present and non-empty.
    alg = stored[len(_V2_PREFIX) :].split(":", 1)[0]
    assert alg, "the v2 marker must carry an algorithm segment or it is not self-describing"


def test_v2_is_the_shipped_default_writer_not_an_opt_in() -> None:
    """The seam only describes reality if v2 is what a new deployment actually WRITES.

    This is the claim the crypto module's own constant comment got wrong until 2026-08-11 (it said
    "not written by default" while the module docstring 60 lines above said the opposite).
    """
    assert StoreSettings().aad_bind is True
    assert "write_v2" in inspect.signature(make_cipher).parameters


@pytest.mark.parametrize(
    "stored",
    [
        "mfenc:v9:deadbeef:AAAA",  # unknown VERSION
        "mfenc:v2:rot13:deadbeef:AAAA",  # unknown ALGORITHM
    ],
)
def test_an_unrecognised_algorithm_fails_closed(stored: str) -> None:
    """Property 2, and the one that makes a swap safe rather than merely possible.

    A downgrade must be REFUSED, never silently mis-decrypted or skipped. Both the version and the
    algorithm are checked, because a swap changes the second while leaving the first intact.
    """
    cipher = make_cipher(generate_key(), write_v2=True)
    with pytest.raises(CipherError):
        cipher.decrypt(stored, aad=cell_aad("messages", "raw", 1))


def test_v1_stays_decodable_so_a_swap_leaves_nothing_unreadable() -> None:
    """A release-level swap must not strand existing ciphertext. v1 is frozen but still READ."""
    key = generate_key()
    v1 = make_cipher(key, write_v2=False).encrypt("older body", aad=cell_aad("messages", "raw", 1))
    assert v1.startswith(PREFIX)
    # The v2-writing cipher still reads it -- old and new coexist in one column during a rollover.
    assert (
        make_cipher(key, write_v2=True).decrypt(v1, aad=cell_aad("messages", "raw", 1))
        == "older body"
    )


def test_the_audit_mac_carries_no_version_discriminator() -> None:
    """THE STATED LIMIT, pinned so the contract cannot silently overclaim.

    The seam covers the at-rest value core and NOT the audit MAC. If someone later gives the audit
    chain an mfenc-style marker, this test fails and the contract's limit paragraph must be revisited
    -- which is the point: the document says "undesigned", and that must stop being true loudly.
    """
    hits = [
        p
        for p in (_ROOT / "messagefoundry" / "store").glob("*.py")
        if "audit" in p.read_text(encoding="utf-8").lower()
        and "mfenc:vaudit" in p.read_text(encoding="utf-8")
    ]
    assert hits == [], f"the audit chain gained a version marker; revisit PHI.md 3.x: {hits}"


def test_the_seam_contract_is_actually_published() -> None:
    """A contract nobody can read is not a contract. Pins the section AND its limit paragraph."""
    phi = (_ROOT / "docs" / "PHI.md").read_text(encoding="utf-8")
    assert "cryptographic-agility seam" in phi
    assert "RELEASE-swappability" in phi
    assert "RUNTIME reconfiguration" in phi
    # The limit is the half a reader is most likely to lose; pin it explicitly.
    assert "audit MAC" in phi and "no version" in phi.replace("*", "")


def test_cipher_exposes_no_operator_facing_algorithm_selector() -> None:
    """The refusal half: runtime selection is not merely absent, it must STAY absent.

    `write_v2` is a FORMAT flag (v1 vs v2 framing), not an algorithm choice -- there is exactly one
    AEAD. A future `algorithm=`/`cipher=` parameter here would be the runtime-selection surface the
    contract refuses, keyed on config rather than on a release.
    """
    params = set(inspect.signature(Cipher.__init__).parameters) | set(
        inspect.signature(make_cipher).parameters
    )
    assert not (params & {"algorithm", "alg", "cipher_alg", "aead"}), (
        f"an algorithm selector appeared on the cipher constructor: {sorted(params)}"
    )
