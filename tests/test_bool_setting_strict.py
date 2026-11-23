# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``bool_setting`` refuses a value that is not a real ``bool`` (vault BACKLOG #3234 finding).

It read anything but ``None`` or an empty string with ``bool()``, so on a connector constructed
directly from a ``Source`` or ``Destination``, which passes neither the load's nor the runner's
literal refusal, a ``0`` turned a default-on check off and a ``"false"`` read as on. The read now
refuses both with the ``require_flag`` message. ``None`` and an empty string still take the
default, and a real ``bool`` reads as before: the controls."""

from __future__ import annotations

import ssl
from typing import Any

import pytest

from messagefoundry.auth.trust_anchors import unread_ca_reason
from messagefoundry.config.models import ConnectorType, Destination, Source, bool_setting
from messagefoundry.config.wiring import EnvRef, _declares_hostname_check_off
from messagefoundry.transports import remotefile as remotefile_module
from messagefoundry.transports.dicom import DicomScpSource
from messagefoundry.transports.fhir import FhirDestination
from messagefoundry.transports.soap import SoapDestination

_NON_BOOLS: list[Any] = [0, "false"]


def _refusal(key: str, value: Any) -> str:
    return f"{key} must be true or false, not {type(value).__name__}"


@pytest.mark.parametrize("value", [0, 1, "false", "true", "no", 0.0, []])
def test_bool_setting_refuses_a_non_bool(value: Any) -> None:
    with pytest.raises(ValueError, match=_refusal("tls_verify", value)):
        bool_setting({"tls_verify": value}, "tls_verify", default=True)


@pytest.mark.parametrize("default", [True, False])
@pytest.mark.parametrize("settings", [{}, {"k": None}, {"k": ""}])
def test_bool_setting_unset_takes_the_default(settings: dict[str, Any], default: bool) -> None:
    assert bool_setting(settings, "k", default=default) is default


@pytest.mark.parametrize("value", [True, False])
@pytest.mark.parametrize("default", [True, False])
def test_bool_setting_reads_a_real_bool(value: bool, default: bool) -> None:
    assert bool_setting({"k": value}, "k", default=default) is value


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


def _scp(**settings: Any) -> DicomScpSource:
    return DicomScpSource(
        Source(
            type=ConnectorType.DIMSE,
            settings={"ae_title": "MF_SCP", "port": 0, "host": "127.0.0.1", **settings},
        )
    )


@pytest.mark.parametrize("value", _NON_BOOLS)
def test_fhir_refuses_a_non_bool_verify_tls(value: Any) -> None:
    with pytest.raises(ValueError, match=_refusal("verify_tls", value)):
        _fhir(verify_tls=value)


@pytest.mark.parametrize("value", _NON_BOOLS)
def test_soap_refuses_a_non_bool_verify_tls(value: Any) -> None:
    with pytest.raises(ValueError, match=_refusal("verify_tls", value)):
        _soap(verify_tls=value)


@pytest.mark.parametrize("key", ["tls_verify", "tls_check_hostname"])
@pytest.mark.parametrize("value", _NON_BOOLS)
def test_ftps_context_refuses_a_non_bool_check(key: str, value: Any) -> None:
    with pytest.raises(ValueError, match=_refusal(key, value)):
        remotefile_module._ftps_ssl_context({"host": "127.0.0.1", key: value})


@pytest.mark.parametrize("value", _NON_BOOLS)
def test_dicom_scp_refuses_a_non_bool_require_called_ae_title(value: Any) -> None:
    with pytest.raises(ValueError, match=_refusal("require_called_ae_title", value)):
        _scp(require_called_ae_title=value)


@pytest.mark.parametrize("value", [True, False])
def test_fhir_and_soap_read_a_real_bool_verify_tls(value: bool) -> None:
    _fhir(verify_tls=value)
    _soap(verify_tls=value)


@pytest.mark.parametrize("value", [True, False])
def test_ftps_context_reads_a_real_bool_tls_check_hostname(value: bool) -> None:
    ctx = remotefile_module._ftps_ssl_context({"host": "127.0.0.1", "tls_check_hostname": value})
    assert ctx.check_hostname is value


def test_ftps_context_reads_a_real_bool_tls_verify() -> None:
    ctx = remotefile_module._ftps_ssl_context({"host": "127.0.0.1", "tls_verify": True})
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    # False reaches the verify-off refusal, as before.
    with pytest.raises(ValueError, match="disables server-certificate verification"):
        remotefile_module._ftps_ssl_context({"host": "127.0.0.1", "tls_verify": False})


@pytest.mark.parametrize("value", [True, False])
def test_dicom_scp_reads_a_real_bool_require_called_ae_title(value: bool) -> None:
    assert _scp(require_called_ae_title=value)._require_called_ae_title is value


@pytest.mark.parametrize("key", ["tls", "use_tls", "tls_verify", "verify_tls"])
def test_unread_ca_reason_reads_an_env_ref_as_unknown(key: str) -> None:
    # Before resolution the value is unknown. It reads as on, so the load passes it and the check
    # after resolution decides, as before the read was strict.
    assert unread_ca_reason({key: EnvRef("MEFOR_X")}) is None


def test_hostname_check_report_counts_a_non_bool_as_possibly_off() -> None:
    # A register of loosenings over-reports rather than raise or miss: "false" used to read as on.
    assert _declares_hostname_check_off({"tls_check_hostname": "false"})
    assert _declares_hostname_check_off({"tls_check_hostname": False})
    assert not _declares_hostname_check_off({"tls_check_hostname": True})
    assert not _declares_hostname_check_off({})


def test_dialling_pin_problems_leaves_a_non_bool_flag_to_the_literal_pass() -> None:
    # validate_config collects every problem, so a strict read here must not raise past the pass
    # that names the literal.
    from messagefoundry.config.wiring import ConnectionSpec, Registry, build_outbound_connection

    registry = Registry()
    spec = ConnectionSpec(
        ConnectorType.FHIR,
        {"url": "https://127.0.0.1/fhir", "tls_ca_file": "ca.pem", "tls_ca_pin": "a" * 64},
    )
    registry.add_outbound(build_outbound_connection("OB_FHIR", spec))
    registry.outbound["OB_FHIR"].spec.settings["verify_tls"] = "false"
    assert registry.dialling_pin_problems() == []
    assert any("verify_tls" in p for p in registry.bool_literal_problems())
