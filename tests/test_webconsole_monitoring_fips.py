# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The web console's report-only FIPS attestation row (#73, ADR 0120).

Unit-level tests for the ``_fips`` render helper on the monitoring status page. The load-bearing
guarantee is the *wording*: the boolean attests the interpreter's ssl/_hashlib OpenSSL provider state
and must render as **reported**, never as a FIPS-140 **certification** (the scope trap ADR 0120 names).
"""

from __future__ import annotations

import pytest

from messagefoundry_webconsole.pages.monitoring import _fips


@pytest.mark.parametrize(
    "value,expected",
    [
        (True, "reported active"),
        (False, "reported inactive"),
        (None, "undeterminable"),  # non-OpenSSL build with no get_fips_mode
    ],
)
def test_fips_render_tristate(value: bool | None, expected: str) -> None:
    assert _fips(value) == expected


@pytest.mark.parametrize("value", [True, False, None])
def test_fips_render_never_claims_certified(value: bool | None) -> None:
    # AC-5: the wording is deliberately "reported" — it must NEVER imply a FIPS-140 certification.
    rendered = _fips(value).lower()
    assert "certif" not in rendered
    if value is not None:
        assert "reported" in rendered
