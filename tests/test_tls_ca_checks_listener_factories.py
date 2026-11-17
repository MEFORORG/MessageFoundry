# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The MLLP, Http and DICOM CA checks that the shared factory table in
``tests/test_outbound_ca_anchors.py`` does not cover (BACKLOG #5329, #5331): a CA beside ``tls``
off is never read, refused at the factory for a literal and once resolved for an ``env()``, and
the DICOM SCP shape (no ``host``) takes the same checks as the SCU."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import (
    DICOM,
    MLLP,
    Http,
    WiringError,
    env,
    refuse_resolved_verify_off,
    resolve_env_settings,
)

_BUILDERS: dict[str, tuple[ConnectorType, Callable[..., Any]]] = {
    "MLLP": (ConnectorType.MLLP, lambda **kw: MLLP(port=2575, **kw)),
    "Http": (ConnectorType.HTTP, lambda **kw: Http(port=8443, **kw)),
    "DICOM": (ConnectorType.DIMSE, lambda **kw: DICOM(ae_title="MEFOR", port=11112, **kw)),
}


@pytest.mark.parametrize("tls", [False, None])
@pytest.mark.parametrize("factory", sorted(_BUILDERS))
def test_a_ca_beside_tls_off_is_refused_as_unread(factory: str, tls: object) -> None:
    """With tls off no TLS context is built in either direction, so the CA is never read."""
    _, build = _BUILDERS[factory]
    with pytest.raises(ValueError, match=f"{factory} tls_ca_file would never be read: tls is off"):
        build(tls=tls, tls_ca_file="/org/ca.pem")
    # The controls: no CA, or tls on, still builds.
    assert build(tls=tls).settings["tls_ca_file"] is None
    assert build(tls=True, tls_ca_file="/org/ca.pem").settings["tls_ca_file"] == "/org/ca.pem"


@pytest.mark.parametrize("factory", sorted(_BUILDERS))
def test_a_ca_beside_an_env_tls_that_resolves_off_is_refused(factory: str) -> None:
    kind, build = _BUILDERS[factory]
    spec = build(tls=env("tls_on", cast=bool), tls_ca_file="/org/ca.pem")
    off = resolve_env_settings(spec.settings, {"tls_on": "false"})
    with pytest.raises(WiringError, match=f"{factory} tls_ca_file would never be read"):
        refuse_resolved_verify_off(kind, off, "inbound connection 'IB'")
    # The control: resolved on, it passes.
    refuse_resolved_verify_off(
        kind, resolve_env_settings(spec.settings, {"tls_on": "true"}), "inbound connection 'IB'"
    )


@pytest.mark.parametrize("factory", sorted(_BUILDERS))
def test_a_ca_beside_a_non_bool_tls_is_refused_as_such(factory: str) -> None:
    _, build = _BUILDERS[factory]
    with pytest.raises(WiringError, match="tls"):
        build(tls=0, tls_ca_file="/org/ca.pem")


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_ca_on_the_dicom_scp_is_refused(blank: str) -> None:
    with pytest.raises(ValueError, match="tls_ca_file is blank"):
        DICOM(ae_title="MEFOR", port=11112, tls=True, tls_ca_file=blank)
