# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The DICOM factory's CA checks that the shared factory table in ``tests/test_outbound_ca_anchors.py``
does not cover (BACKLOG #5331): a CA beside ``tls=False`` is never read, and the SCP shape (no
``host``) takes the same checks as the SCU."""

from __future__ import annotations

import pytest

from messagefoundry.config.wiring import DICOM, WiringError


@pytest.mark.parametrize("host", [None, "pacs.internal.example.org"], ids=["scp", "scu"])
def test_a_dicom_ca_beside_tls_off_is_refused_as_unread(host: str | None) -> None:
    """Neither the SCP nor the SCU builds a TLS context with tls off, so the CA is never read."""
    with pytest.raises(ValueError, match="would never be read"):
        DICOM(ae_title="MEFOR", host=host, port=11112, tls=False, tls_ca_file="/org/ca.pem")
    # The control: the same hop with no CA still builds.
    assert DICOM(ae_title="MEFOR", host=host, port=11112).settings["tls_ca_file"] is None


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_ca_on_the_scp_is_refused(blank: str) -> None:
    with pytest.raises(ValueError, match="tls_ca_file is blank"):
        DICOM(ae_title="MEFOR", port=11112, tls=True, tls_ca_file=blank)


def test_a_dicom_ca_beside_a_non_bool_tls_is_refused_as_such() -> None:
    with pytest.raises(WiringError, match="tls"):
        DICOM(ae_title="MEFOR", port=11112, tls=0, tls_ca_file="/org/ca.pem")  # type: ignore[arg-type]
