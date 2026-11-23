# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The DICOM, FHIR, SOAP and remote-file connectors read ``tls`` and ``tls_allow_expired`` strictly
(vault BACKLOG #3234 added step 8).

The load and the build refuse a non-bool literal on a boolean setting, but a connector built from a
``Destination`` or ``Source`` that never passed through them, a Registry built in code or settings
changed after validation, reached these reads, and ``bool("false")`` is True. Each read now goes
through ``flag_from_settings``, which refuses anything that is not a real ``bool`` with the
``require_flag`` message. A real ``bool`` reads as before: the controls."""

from __future__ import annotations

import ssl
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.transports import dicom as dicom_module
from messagefoundry.transports import remotefile as remotefile_module
from messagefoundry.transports.fhir import FhirDestination
from messagefoundry.transports.soap import SoapDestination

_REFUSED = "tls_allow_expired must be true or false, not str"
_NON_BOOLS: list[Any] = ["false", "true", "", 0, 1]


def _fhir(**settings: Any) -> FhirDestination:
    return FhirDestination(
        Destination(
            name="OB_FHIR",
            type=ConnectorType.FHIR,
            settings={"url": "https://127.0.0.1/fhir", **settings},
        )
    )


def _soap(**settings: Any) -> SoapDestination:
    return SoapDestination(
        Destination(
            name="OB_SOAP",
            type=ConnectorType.SOAP,
            settings={"url": "https://127.0.0.1/ws", "soap_action": "urn:x", **settings},
        )
    )


def _refusal(value: Any, key: str = "tls_allow_expired") -> str:
    return f"{key} must be true or false, not {type(value).__name__}"


@pytest.mark.parametrize("value", _NON_BOOLS)
def test_fhir_refuses_a_non_bool_tls_allow_expired(value: Any) -> None:
    with pytest.raises(ValueError, match=_refusal(value)):
        _fhir(tls_allow_expired=value)


def test_fhir_refuses_a_non_bool_tls_allow_expired_with_verify_off() -> None:
    # The verify-off branch never read the setting, so it passed unseen there.
    with pytest.raises(ValueError, match=_REFUSED):
        _fhir(tls_allow_expired="false", verify_tls=False)


@pytest.mark.parametrize("value", [True, False, None])
def test_fhir_builds_on_a_real_bool_tls_allow_expired(value: bool | None) -> None:
    _fhir(tls_allow_expired=value)


@pytest.mark.parametrize("value", _NON_BOOLS)
def test_soap_refuses_a_non_bool_tls_allow_expired(value: Any) -> None:
    with pytest.raises(ValueError, match=_refusal(value)):
        _soap(tls_allow_expired=value)


def test_soap_refuses_a_non_bool_tls_allow_expired_with_verify_off() -> None:
    with pytest.raises(ValueError, match=_REFUSED):
        _soap(tls_allow_expired="false", verify_tls=False)


@pytest.mark.parametrize("value", [True, False, None])
def test_soap_builds_on_a_real_bool_tls_allow_expired(value: bool | None) -> None:
    _soap(tls_allow_expired=value)


@pytest.mark.parametrize("value", _NON_BOOLS)
def test_dicom_listener_refuses_a_non_bool_tls(value: Any) -> None:
    # A truthy value used to switch TLS on, here refused for want of a certificate.
    with pytest.raises(ValueError, match=_refusal(value, "tls")):
        dicom_module._server_ssl_context({"tls": value})


def test_dicom_listener_reads_a_real_bool_tls() -> None:
    assert dicom_module._server_ssl_context({"tls": False}) is None
    with pytest.raises(ValueError, match="requires tls_cert_file"):
        dicom_module._server_ssl_context({"tls": True})


def _scp(tls: Any) -> dicom_module.DicomScpSource:
    return dicom_module.DicomScpSource(
        Source(
            type=ConnectorType.DIMSE,
            settings={"ae_title": "MF_SCP", "port": 0, "host": "10.0.0.5", "tls": tls},
        )
    )


def test_dicom_listener_peer_gate_refuses_a_non_bool_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    # ``mtls_on`` read ``tls`` with bool(). The listener's context build refuses the same value
    # first, so it is stood in for here, and the gate's own read is what refuses.
    monkeypatch.setattr(dicom_module, "_server_ssl_context", lambda s, **_: None)
    with pytest.raises(ValueError, match=_refusal("false", "tls")):
        _scp("false")


def test_dicom_listener_peer_gate_reads_a_real_bool_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    # The control: tls=False off loopback with no other control is the gate's own fail-closed.
    monkeypatch.setattr(dicom_module, "_server_ssl_context", lambda s, **_: None)
    with pytest.raises(ValueError, match="no verifiable peer control"):
        _scp(False)


@pytest.mark.parametrize("value", _NON_BOOLS)
def test_dicom_destination_refuses_a_non_bool_tls(value: Any) -> None:
    with pytest.raises(ValueError, match=_refusal(value, "tls")):
        dicom_module._client_ssl_context({"host": "127.0.0.1", "tls": value})


@pytest.mark.parametrize("value", _NON_BOOLS)
def test_dicom_destination_refuses_a_non_bool_tls_allow_expired(value: Any) -> None:
    with pytest.raises(ValueError, match=_refusal(value)):
        dicom_module._client_ssl_context(
            {"host": "127.0.0.1", "tls": True, "tls_allow_expired": value}
        )


def test_dicom_destination_reads_a_real_bool_tls_and_tls_allow_expired() -> None:
    assert dicom_module._client_ssl_context({"host": "127.0.0.1", "tls": False}) is None
    strict = dicom_module._client_ssl_context({"host": "127.0.0.1", "tls": True})
    relaxed = dicom_module._client_ssl_context(
        {"host": "127.0.0.1", "tls": True, "tls_allow_expired": True}
    )
    assert strict is not None and relaxed is not None
    assert strict.verify_mode is ssl.CERT_REQUIRED and relaxed.verify_mode is ssl.CERT_REQUIRED


@pytest.mark.parametrize("value", _NON_BOOLS)
def test_ftps_context_refuses_a_non_bool_tls_allow_expired(value: Any) -> None:
    with pytest.raises(ValueError, match=_refusal(value)):
        remotefile_module._ftps_ssl_context({"host": "127.0.0.1", "tls_allow_expired": value})


def test_ftps_context_refuses_a_non_bool_tls_allow_expired_with_verify_off() -> None:
    # Read before the verify-off escape, so the refusal names the setting, not the escape.
    with pytest.raises(ValueError, match=_REFUSED):
        remotefile_module._ftps_ssl_context(
            {"host": "127.0.0.1", "tls_verify": False, "tls_allow_expired": "false"}
        )


@pytest.mark.parametrize("value", [True, False, None])
def test_ftps_context_builds_on_a_real_bool_tls_allow_expired(value: bool | None) -> None:
    ctx = remotefile_module._ftps_ssl_context({"host": "127.0.0.1", "tls_allow_expired": value})
    assert ctx.verify_mode is ssl.CERT_REQUIRED


def test_ftps_revocation_guard_refuses_a_non_bool_tls_allow_expired() -> None:
    context = ssl.create_default_context()
    with pytest.raises(ValueError, match=_REFUSED):
        remotefile_module._guard_ftps_revocation(
            context,
            {"host": "127.0.0.1", "tls_allow_expired": "false"},
            direction="destination",
            attested=False,
            attested_reason=None,
            connection="OB_FTPS",
        )


@pytest.mark.parametrize("value", [True, False])
def test_ftps_revocation_guard_reads_a_real_bool_tls_allow_expired(value: bool) -> None:
    remotefile_module._guard_ftps_revocation(
        ssl.create_default_context(),
        {"host": "127.0.0.1", "tls_allow_expired": value},
        direction="destination",
        attested=False,
        attested_reason=None,
        connection="OB_FTPS",
    )
