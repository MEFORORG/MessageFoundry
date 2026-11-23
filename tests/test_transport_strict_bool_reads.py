# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The DICOM connectors read ``tls`` strictly, and the DICOM, FHIR, SOAP and FTPS reads of
``tls_allow_expired`` are strict too (vault BACKLOG #3234 added step 8).

The load and the runner's builds (``_source_config``, ``_dest_config``) refuse a non-bool literal
on a boolean setting. A connector constructed directly from a ``Source`` or ``Destination``, as
tests and embedders do, passes neither, and reached these reads, where ``bool("false")`` is True.
Each read now goes through ``flag_from_settings``, which refuses anything that is not a real
``bool`` with the ``require_flag`` message. A real ``bool`` reads as before: the controls."""

from __future__ import annotations

import ssl
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.tls_policy import skips_validity_period
from messagefoundry.transports import dicom as dicom_module
from messagefoundry.transports import fhir as fhir_module
from messagefoundry.transports import remotefile as remotefile_module
from messagefoundry.transports import soap as soap_module
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


def _spy_expiry_relaxed(monkeypatch: pytest.MonkeyPatch, module: Any) -> list[bool]:
    """Record the ``expiry_relaxed`` a connector hands its revocation guard, which is how it read
    ``tls_allow_expired``."""
    seen: list[bool] = []

    def spy(*args: Any, **kwargs: Any) -> None:
        seen.append(kwargs["expiry_relaxed"])

    monkeypatch.setattr(module, "refuse_unrevoked_verified_hop", spy)
    return seen


@pytest.mark.parametrize("value", _NON_BOOLS)
def test_fhir_refuses_a_non_bool_tls_allow_expired(value: Any) -> None:
    with pytest.raises(ValueError, match=_refusal(value)):
        _fhir(tls_allow_expired=value)


def test_fhir_refuses_a_non_bool_tls_allow_expired_with_verify_off() -> None:
    # The verify-off branch never read the setting, so it passed unseen there.
    with pytest.raises(ValueError, match=_REFUSED):
        _fhir(tls_allow_expired="false", verify_tls=False)


def test_fhir_refuses_a_non_bool_tls_allow_expired_before_its_url_check() -> None:
    # Read first, so a build it refuses reaches no hop guard that could log a crossing.
    with pytest.raises(ValueError, match=_REFUSED):
        FhirDestination(
            Destination(
                name="OB_FHIR", type=ConnectorType.FHIR, settings={"tls_allow_expired": "false"}
            )
        )


@pytest.mark.parametrize(("value", "relaxed"), [(True, True), (False, False), (None, False)])
def test_fhir_reads_a_real_bool_tls_allow_expired(
    monkeypatch: pytest.MonkeyPatch, value: bool | None, relaxed: bool
) -> None:
    seen = _spy_expiry_relaxed(monkeypatch, fhir_module)
    _fhir(tls_allow_expired=value)
    assert seen == [relaxed]


@pytest.mark.parametrize("value", _NON_BOOLS)
def test_soap_refuses_a_non_bool_tls_allow_expired(value: Any) -> None:
    with pytest.raises(ValueError, match=_refusal(value)):
        _soap(tls_allow_expired=value)


def test_soap_refuses_a_non_bool_tls_allow_expired_with_verify_off() -> None:
    with pytest.raises(ValueError, match=_REFUSED):
        _soap(tls_allow_expired="false", verify_tls=False)


def test_soap_refuses_a_non_bool_tls_allow_expired_before_its_url_check() -> None:
    with pytest.raises(ValueError, match=_REFUSED):
        SoapDestination(
            Destination(
                name="OB_SOAP", type=ConnectorType.SOAP, settings={"tls_allow_expired": "false"}
            )
        )


@pytest.mark.parametrize(("value", "relaxed"), [(True, True), (False, False), (None, False)])
def test_soap_reads_a_real_bool_tls_allow_expired(
    monkeypatch: pytest.MonkeyPatch, value: bool | None, relaxed: bool
) -> None:
    seen = _spy_expiry_relaxed(monkeypatch, soap_module)
    _soap(tls_allow_expired=value)
    assert seen == [relaxed]


@pytest.mark.parametrize("value", _NON_BOOLS)
def test_dicom_listener_refuses_a_non_bool_tls(value: Any) -> None:
    # A truthy value used to switch TLS on, here refused for want of a certificate.
    with pytest.raises(ValueError, match=_refusal(value, "tls")):
        dicom_module._server_ssl_context({"tls": value})


@pytest.mark.parametrize("value", [0, ""])
def test_dicom_contexts_refuse_a_falsy_non_bool_tls_before_the_pin_check(value: Any) -> None:
    # The pin check reads tls by truthiness, and would name an unread pin instead.
    pinned = {"host": "127.0.0.1", "tls": value, "tls_ca_file": "x.pem", "tls_ca_pin": "a" * 64}
    with pytest.raises(ValueError, match=_refusal(value, "tls")):
        dicom_module._server_ssl_context(dict(pinned))
    with pytest.raises(ValueError, match=_refusal(value, "tls")):
        dicom_module._client_ssl_context(dict(pinned))


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


def test_dicom_destination_refuses_a_non_bool_tls_allow_expired_with_tls_off() -> None:
    with pytest.raises(ValueError, match=_REFUSED):
        dicom_module._client_ssl_context(
            {"host": "127.0.0.1", "tls": False, "tls_allow_expired": "false"}
        )


def test_dicom_destination_reads_a_real_bool_tls_and_tls_allow_expired() -> None:
    assert dicom_module._client_ssl_context({"host": "127.0.0.1", "tls": False}) is None
    strict = dicom_module._client_ssl_context({"host": "127.0.0.1", "tls": True})
    relaxed = dicom_module._client_ssl_context(
        {"host": "127.0.0.1", "tls": True, "tls_allow_expired": True}
    )
    assert strict is not None and relaxed is not None
    assert not skips_validity_period(strict) and skips_validity_period(relaxed)


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


@pytest.mark.parametrize(("value", "relaxed"), [(True, True), (False, False), (None, False)])
def test_ftps_context_reads_a_real_bool_tls_allow_expired(
    value: bool | None, relaxed: bool
) -> None:
    ctx = remotefile_module._ftps_ssl_context({"host": "127.0.0.1", "tls_allow_expired": value})
    assert skips_validity_period(ctx) is relaxed


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
def test_ftps_revocation_guard_reads_a_real_bool_tls_allow_expired(
    monkeypatch: pytest.MonkeyPatch, value: bool
) -> None:
    seen: list[bool] = []

    class _Guard:
        @staticmethod
        def capture(**kwargs: Any) -> _Guard:
            seen.append(kwargs["expiry_relaxed"])
            return _Guard()

        def enforce_construction(self) -> None:
            return None

    monkeypatch.setattr(remotefile_module, "RevocationHopGuard", _Guard)
    remotefile_module._guard_ftps_revocation(
        ssl.create_default_context(),
        {"host": "127.0.0.1", "tls_allow_expired": value},
        direction="destination",
        attested=False,
        attested_reason=None,
        connection="OB_FTPS",
    )
    assert seen == [value]
