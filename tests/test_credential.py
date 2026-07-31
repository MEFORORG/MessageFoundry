# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The neutral credential leaf (ADR 0154 D6): constant-time comparison, the dual-key accumulator, and
the certificate-subject mapping hoisted out of ``api/security.py``.

The empty-credential cases below are the load-bearing ones. ``sha256(b"") == sha256(b"")``, so a
comparison that digests before checking for an absent value authenticates a request that presented no
credential at all — against a key slot the operator never configured, which is the default.
"""

from __future__ import annotations

import pytest

from messagefoundry import credential
from messagefoundry.credential import (
    cert_name_candidates,
    client_cert_principal,
    constant_time_match,
    constant_time_match_any,
)


def test_matching_credentials_compare_equal() -> None:
    assert constant_time_match("s3cr3t", "s3cr3t") is True
    assert constant_time_match(b"s3cr3t", b"s3cr3t") is True
    assert constant_time_match("s3cr3t", b"s3cr3t") is True  # str/bytes are interchangeable


def test_differing_credentials_do_not_match() -> None:
    assert constant_time_match("s3cr3t", "s3cr3u") is False  # same length
    assert constant_time_match("s3cr3t", "s3cr3t-longer") is False  # different length


@pytest.mark.parametrize(
    ("presented", "configured"),
    [
        ("", "s3cr3t"),  # presented empty
        (None, "s3cr3t"),  # presented absent
        (b"", "s3cr3t"),
        ("s3cr3t", ""),  # configured empty
        ("s3cr3t", None),  # configured unset — the DEFAULT for intake_api_key_next
        ("", ""),  # BOTH empty: sha256(b"") == sha256(b"") would say True
        (None, None),
        (b"", b""),
    ],
)
def test_empty_or_absent_never_matches(presented: object, configured: object) -> None:
    assert constant_time_match(presented, configured) is False  # type: ignore[arg-type]


def test_non_ascii_credential_returns_false_instead_of_raising() -> None:
    # AC-11: compare "without raising on a non-ASCII credential". A raise here lands on the
    # UNAUTHENTICATED path, where it becomes a 500 that skips the caller's audited-refusal branch.
    lone_surrogate = "\ud800"
    assert constant_time_match(lone_surrogate, "s3cr3t") is False
    assert constant_time_match("s3cr3t", lone_surrogate) is False

    # ... while a legitimately non-ASCII credential still compares correctly.
    assert constant_time_match("pässwörd", "pässwörd") is True
    assert constant_time_match("pässwörd", "password") is False


def test_dual_key_rotation_accepts_current_and_next() -> None:
    # The rotation contract: both keys are live at once, so a partner cuts over without an outage.
    assert constant_time_match_any("current", ["current", "next"]) is True
    assert constant_time_match_any("next", ["current", "next"]) is True
    assert constant_time_match_any("stale", ["current", "next"]) is False


def test_absent_credential_never_matches_an_unconfigured_slot() -> None:
    # The defect this whole module exists to prevent: no rotation key configured (the default) and a
    # peer presenting nothing must NOT authenticate.
    assert constant_time_match_any("", ["current", None]) is False
    assert constant_time_match_any(None, ["current", None]) is False
    assert constant_time_match_any("", [None, None]) is False
    assert constant_time_match_any("current", ["current", None]) is True


def test_match_any_compares_every_slot_with_no_early_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Mirrors the ASVS 11.2.4 drift guard: neither how many keys are configured nor which one matched
    # may be observable in the number of comparisons performed.
    calls: list[object] = []
    real = credential.constant_time_match

    def counting(presented: object, configured: object) -> bool:
        calls.append(configured)
        return real(presented, configured)  # type: ignore[arg-type]

    monkeypatch.setattr(credential, "constant_time_match", counting)

    assert credential.constant_time_match_any("current", ["current", "next"]) is True
    assert len(calls) == 2, "stopped at the first match — the match position is timing-observable"

    calls.clear()
    assert credential.constant_time_match_any("current", ["current", None]) is True
    assert len(calls) == 2, "an unconfigured slot skipped its comparison — slot count leaks"


def test_unconfigured_slot_sentinel_cannot_authenticate() -> None:
    # The dummy compared for an empty slot is never treated as a credential, even if a peer somehow
    # presented it verbatim — its result is discarded rather than accumulated.
    assert constant_time_match_any(credential._UNCONFIGURED_SLOT, [None, None]) is False


def _peercert(cn: str, san: tuple[str, str] | None = None) -> dict[str, object]:
    cert: dict[str, object] = {"subject": ((("commonName", cn),),)}
    if san is not None:
        cert["subjectAltName"] = (san,)
    return cert


def test_cert_name_candidates_qualifies_the_namespace() -> None:
    # A spoofed commonName must not be able to collide with a pinned DNS SAN (#200).
    assert cert_name_candidates(_peercert("svc.internal", ("DNS", "api.internal"))) == [
        "CN:svc.internal",
        "SAN:DNS:api.internal",
    ]


def test_client_cert_principal_is_deny_by_default() -> None:
    assert client_cert_principal(_peercert("svc.internal"), {"CN:svc.internal": "svc-user"}) == (
        "svc-user"
    )
    assert (
        client_cert_principal(_peercert("attacker.evil"), {"CN:svc.internal": "svc-user"}) is None
    )
    assert client_cert_principal(None, {"CN:svc.internal": "svc-user"}) is None
    assert client_cert_principal(_peercert("svc.internal"), {}) is None


def test_api_security_shares_this_definition_rather_than_copying_it() -> None:
    # The hoist is only worth anything if the two identity planes cannot drift. api/security.py
    # re-imports rather than redefining, so this is an identity check, not an equality one.
    from messagefoundry.api import security

    assert security.client_cert_principal is client_cert_principal
