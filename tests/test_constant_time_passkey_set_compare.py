# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 11.2.4 (BACKLOG #1167): the store side compares passkey digests in constant time.

A timing difference is not measurable in a unit test, so these pin the mechanism instead: the
store's passkey checks reach ``hmac.compare_digest``, and no ``==`` or ``!=`` on a passkey digest or a
credential-id hash is left in the three store backends' source.

Synthetic data only.
"""

from __future__ import annotations

import ast
import hmac
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from messagefoundry.store import store as store_mod
from messagefoundry.store.store import (
    WebAuthnCredential,
    discoverable_way_past,
    passkey_digest,
    passkey_set_matches,
    removal_keeps_way_past,
)

_STORE_DIR = Path(store_mod.__file__).parent
_BACKENDS = ("store.py", "postgres.py", "sqlserver.py")
#: Id hashes under the current ``wc1:`` scheme, so each passkey can count as a way past.
_A = "wc1:" + "a" * 64
_B = "wc1:" + "b" * 64


def _cred(id_hash: str) -> WebAuthnCredential:
    return WebAuthnCredential(
        credential_id_hash=id_hash,
        credential_id="Y3JlZA",
        user_id="u-1",
        rp_id="localhost",
        public_key="cose-public-key-b64url",
        sign_count=0,
        transports=None,
        device_type="multi_device",
        backed_up=True,
        label=f"key {id_hash}",
        aaguid=None,
        created_at=1000.0,
        discoverable=True,
    )


@pytest.fixture
def compares(monkeypatch: pytest.MonkeyPatch) -> list[tuple[bytes, bytes]]:
    seen: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        seen.append((a, b))
        return real(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    return seen


def test_the_set_check_goes_through_compare_digest(compares: list[tuple[bytes, bytes]]) -> None:
    """RED when: ``discoverable_way_past`` compares the passkey digest with ``!=``."""
    creds = [_cred(_A), _cred(_B)]
    digest = passkey_digest(creds)
    assert discoverable_way_past(creds, digest, sealed=True)
    assert (digest.encode(), digest.encode()) in compares


def test_a_set_that_fails_its_digest_still_counts_for_nothing(
    compares: list[tuple[bytes, bytes]],
) -> None:
    creds = [_cred(_A)]
    assert not discoverable_way_past(creds, "0" * 64, sealed=True)
    assert not passkey_set_matches(creds, "0" * 64)
    assert compares


def test_the_removal_check_compares_the_id_hash_and_the_digest_in_constant_time(
    compares: list[tuple[bytes, bytes]],
) -> None:
    """RED when: ``removal_keeps_way_past`` filters by ``!=`` on the id hash, or checks the set's
    digest with ``==``."""
    creds = [_cred(_A), _cred(_B)]
    record = _record(passkey_digest(creds))
    assert removal_keeps_way_past(record, creds, sealed=True, drop_passkey=_A)
    assert (_A.encode(), _A.encode()) in compares
    assert (_B.encode(), _A.encode()) in compares
    digest = passkey_digest(creds).encode()
    assert (digest, digest) in compares
    # Dropping the only passkey leaves none, whatever the compare.
    assert not removal_keeps_way_past(
        _record(passkey_digest(creds[:1])), creds[:1], sealed=True, drop_passkey=_A
    )


def _record(cred_digest: str) -> store_mod.UserAuthzRecord:
    """A stand-in carrying only what ``removal_keeps_way_past`` reads with no TOTP rule given."""
    return cast(
        store_mod.UserAuthzRecord, SimpleNamespace(row=SimpleNamespace(cred_digest=cred_digest))
    )


def _bare_digest_compares(path: Path) -> list[int]:
    """Lines where ``==`` or ``!=`` has a ``passkey_digest(...)`` call or a ``credential_id_hash``
    attribute as an operand."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    hits: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
            continue
        for operand in (node.left, *node.comparators):
            is_digest_call = (
                isinstance(operand, ast.Call)
                and isinstance(operand.func, ast.Name)
                and operand.func.id == "passkey_digest"
            )
            is_id_hash = isinstance(operand, ast.Attribute) and operand.attr == "credential_id_hash"
            if is_digest_call or is_id_hash:
                hits.append(node.lineno)
                break
    return hits


@pytest.mark.parametrize("name", _BACKENDS)
def test_no_backend_compares_a_passkey_digest_with_eq(name: str) -> None:
    """RED when: a store backend compares a passkey digest or a credential-id hash with ``==`` or
    ``!=`` rather than through :func:`passkey_set_matches` or ``constant_time_equal``."""
    assert _bare_digest_compares(_STORE_DIR / name) == []


def test_the_scan_finds_a_bare_compare(tmp_path: Path) -> None:
    """Positive control: the scan above flags both shapes it looks for."""
    sample = tmp_path / "sample.py"
    sample.write_text(
        "if passkey_digest(a) != b:\n    pass\nx = [c for c in d if c.credential_id_hash == e]\n",
        encoding="utf-8",
    )
    assert _bare_digest_compares(sample) == [1, 3]
