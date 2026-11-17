# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``tls_ca_file`` and ``tls_ca_pin`` checks the HTTP-family factories make, on the MLLP and
Http factories too (BACKLOG #5329).

A blank ``tls_ca_file`` reads as unset to every connector, so it would turn a listener's
client-certificate check, or a destination's private CA, off while the config reads as pinned. A
malformed pin, or one with no CA, would pass ``messagefoundry check``."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.config.wiring import DICOM, MLLP, Http, WiringError, env

_PIN = "sha256:" + "ab" * 32

_FACTORIES: dict[str, Callable[..., Any]] = {
    "MLLP-inbound": lambda **kw: MLLP(port=2575, tls=True, **kw),
    "MLLP-outbound": lambda **kw: MLLP(host="lis.internal.example.org", port=2575, tls=True, **kw),
    "Http": lambda **kw: Http(port=8080, tls=True, **kw),
    # BACKLOG #5331: the DICOM factory, SCP and SCU.
    "DICOM-scp": lambda **kw: DICOM(ae_title="MEFOR", port=11112, tls=True, **kw),
    "DICOM-scu": lambda **kw: DICOM(
        ae_title="MEFOR", host="pacs.internal.example.org", port=11112, tls=True, **kw
    ),
}


@pytest.mark.parametrize("blank", ["", "   "])
@pytest.mark.parametrize("factory", sorted(_FACTORIES))
def test_a_blank_ca_is_refused(factory: str, blank: str) -> None:
    with pytest.raises(ValueError, match="tls_ca_file is blank"):
        _FACTORIES[factory](tls_ca_file=blank)


@pytest.mark.parametrize("pin", ["not-a-pin", "sha256:abcd", "md5:" + "ab" * 16])
@pytest.mark.parametrize("factory", sorted(_FACTORIES))
def test_a_malformed_pin_is_refused(factory: str, pin: str) -> None:
    with pytest.raises(ValueError, match="tls_ca_pin"):
        _FACTORIES[factory](tls_ca_file="/org/ca.pem", tls_ca_pin=pin)


@pytest.mark.parametrize("factory", sorted(_FACTORIES))
def test_a_pin_with_no_ca_is_refused(factory: str) -> None:
    with pytest.raises(ValueError, match="without a tls_ca_file"):
        _FACTORIES[factory](tls_ca_pin=_PIN)


@pytest.mark.parametrize("factory", sorted(_FACTORIES))
def test_a_well_formed_pin_beside_a_ca_still_builds(factory: str) -> None:
    spec = _FACTORIES[factory](tls_ca_file="/org/ca.pem", tls_ca_pin=_PIN)
    assert spec.settings["tls_ca_pin"] == _PIN
    assert spec.settings["tls_ca_file"] == "/org/ca.pem"


@pytest.mark.parametrize("factory", sorted(_FACTORIES))
def test_env_values_are_left_to_resolve_time(factory: str) -> None:
    spec = _FACTORIES[factory](tls_ca_file=env("partner_ca"), tls_ca_pin=env("partner_pin"))
    assert spec.settings["tls_ca_pin"] is not None


@pytest.mark.parametrize("host", [None, "pacs.internal.example.org"], ids=["scp", "scu"])
def test_a_dicom_ca_beside_tls_off_is_refused_as_unread(host: str | None) -> None:
    """Neither the SCP nor the SCU builds a TLS context with tls off, so the CA is never read."""
    with pytest.raises(ValueError, match="would never be read"):
        DICOM(ae_title="MEFOR", host=host, port=11112, tls=False, tls_ca_file="/org/ca.pem")
    # The control: the same hop with no CA still builds.
    assert DICOM(ae_title="MEFOR", host=host, port=11112).settings["tls_ca_file"] is None


def test_a_dicom_ca_beside_a_non_bool_tls_is_refused_as_such() -> None:
    with pytest.raises(WiringError, match="tls"):
        DICOM(ae_title="MEFOR", port=11112, tls=0, tls_ca_file="/org/ca.pem")  # type: ignore[arg-type]
