# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""XML-DSig verify() must require an explicit trust anchor (DELTA-03).

Without an anchor, signxml would trust any signature whose embedded certificate chains to the host's
system CA store (origin-blind verification). The codec is opt-in (called by a code-first Handler), so
the fix is a secure-by-default guard: refuse the no-anchor call rather than verify origin-blind.

These assertions do not need the ``[xml]`` extra installed — the anchor guard fires before signxml is
loaded.
"""

from __future__ import annotations

import pytest

from messagefoundry.parsing.xml.signature import verify

# Any non-None value clears the anchor guard (it is never parsed as a certificate on this code path),
# so a plain sentinel is used instead of a certificate-shaped blob — the latter compiles into the
# .pyc and trips antivirus "embedded certificate" heuristics (Gen:Heur.PHS.1), a false positive.
_DUMMY_ANCHOR = b"unit-test-anchor-sentinel"


@pytest.mark.parametrize("kwargs", [{}, {"x509_cert": None, "ca_pem_file": None}])
def test_verify_without_anchor_is_refused(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="anchor"):
        verify(b"<root/>", **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [{"x509_cert": _DUMMY_ANCHOR}, {"ca_pem_file": _DUMMY_ANCHOR}],
)
def test_verify_with_an_anchor_gets_past_the_guard(kwargs: dict[str, object]) -> None:
    # Supplying either anchor must clear the no-anchor guard. The call then fails downstream (extra
    # absent -> RuntimeError, or extra present -> XmlError / crypto error on the dummy doc/cert) — but
    # never with the anchor-required ValueError.
    try:
        verify(b"<root/>", **kwargs)  # type: ignore[arg-type]
    except ValueError as exc:  # pragma: no cover - only asserts the guard did not misfire
        assert "anchor" not in str(exc).lower(), "anchor supplied but no-anchor guard still fired"
    except Exception:  # noqa: BLE001 - any non-anchor failure means the guard let the call through
        pass
