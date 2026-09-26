# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Refusals offer ``tls_hop_attested`` only as the supported, audited lever (SDS-3.7).

PR 1510 took the field out of these texts because no supported surface set it then, and
docs/DEPLOYMENT.md forbids offering a field with no factory parameter and no ``connections.toml`` key.
The owner ruled on 2026-09-24 to give it that surface: an ``inbound()`` / ``outbound()`` /
``FhirLookup()`` / ``DatabaseLookup()`` / ``DatabaseRef()`` keyword or a top-level ``connections.toml``
key, always with a mandatory ``tls_hop_attested_reason``, and never a transport setting. So the
refusals whose connection takes it name it again.

Each text test asserts three things: the lever is named with its reason, a refusal does not steer the
operator into the transport settings, and the other real lever is still present. The premise tests at
the bottom pin the surface the texts rely on. If it ever shrinks, they go red first.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV
from messagefoundry.config.tls_policy import HOP_ATTESTATION_LEVER, HopPosture, active_hop_posture
from messagefoundry.config.wiring import HOP_ATTESTATION_KEYS, WiringError
from messagefoundry.pipeline.wiring_runner import (
    check_dimse_tls_exposure,
    check_http_tls_exposure,
    check_mllp_tls_exposure,
    check_tcp_tls_exposure,
)
from messagefoundry.transports.database import _build_dsn
from messagefoundry.transports.email import EmailDestination
from messagefoundry.transports.http_auth import (
    HttpAuthError,
    OAuth2ClientCredentialsProvider,
    digest_handler_from_settings,
)
from messagefoundry.transports.smart import SmartAuthError, SmartBackendTokenProvider

LEVER, REASON_KEY = HOP_ATTESTATION_KEYS
SIDECAR_REASON = "TLS terminates at the site's stunnel sidecar"
ENFORCING = HopPosture(enforcing=True)
NOT_ENFORCING = HopPosture(enforcing=False)

_Gate = Callable[..., None]
_BIND_GATES: list[tuple[_Gate, ConnectorType]] = [
    (check_mllp_tls_exposure, ConnectorType.MLLP),
    (check_http_tls_exposure, ConnectorType.HTTP),
    (check_dimse_tls_exposure, ConnectorType.DIMSE),
    (check_tcp_tls_exposure, ConnectorType.TCP),
    (check_tcp_tls_exposure, ConnectorType.X12),
]
_IDS = [conn_type.value for _, conn_type in _BIND_GATES]


@pytest.fixture(autouse=True)
def _no_blanket_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)


def _assert_offers_the_supported_lever(message: str) -> None:
    """The lever with its reason, and no route into the transport settings, which the loader refuses.

    It asserts the whole spelling: the flag name alone is a substring of the reason key, so checking
    the two names separately could not tell a refusal that names the flag from one that does not."""
    assert HOP_ATTESTATION_LEVER in message
    for settings_route in ("[settings]", "spec.settings", "settings["):
        assert settings_route not in message


def _listener(conn_type: ConnectorType, *, attested: bool = False) -> Source:
    return Source(
        type=conn_type,
        settings={"host": "0.0.0.0", "port": 9000},
        tls_hop_attested=attested,
        tls_hop_attested_reason=SIDECAR_REASON if attested else None,
    )


# --- the four inbound bind gates ---------------------------------------------------------------------


@pytest.mark.parametrize(("gate", "conn_type"), _BIND_GATES, ids=_IDS)
def test_bind_refusal_names_every_real_way_across(gate: _Gate, conn_type: ConnectorType) -> None:
    with pytest.raises(WiringError) as exc:
        gate(_listener(conn_type), "IB", allow_insecure_bind=True, posture=ENFORCING)
    message = str(exc.value)
    _assert_offers_the_supported_lever(message)
    # It names where the lever is authored, so an operator is not left to guess the surface.
    assert "inbound()" in message
    assert "connections.toml" in message
    # The flag is still offered, with the enforcement caveat PR 1510 added.
    assert "--allow-insecure-bind" in message
    assert "[security].enforcement = warn" in message
    # A firewall never clears this gate (it reads only the bind host), so it is not offered as one.
    assert "firewall/segment the port" not in message


@pytest.mark.parametrize(("gate", "conn_type"), _BIND_GATES, ids=_IDS)
def test_bind_warning_names_the_flag_that_let_it_cross(
    gate: _Gate, conn_type: ConnectorType, caplog: pytest.LogCaptureFixture
) -> None:
    """With no attestation set, the WARNING blames the flag and does not claim an attestation."""
    with caplog.at_level(logging.WARNING):
        gate(_listener(conn_type), "IB", allow_insecure_bind=True, posture=NOT_ENFORCING)
    warned = " ".join(r.getMessage() for r in caplog.records)
    # The warning fired, so the absence below means something.
    assert "--allow-insecure-bind" in warned
    assert LEVER not in warned


@pytest.mark.parametrize(("gate", "conn_type"), _BIND_GATES, ids=_IDS)
def test_bind_warning_names_the_attestation_and_its_reason(
    gate: _Gate, conn_type: ConnectorType, caplog: pytest.LogCaptureFixture
) -> None:
    """The other direction: an attested bind crosses an enforcing instance with no flag, and its
    WARNING records the attestation WITH the operator's reason (owner ruling 2026-09-24)."""
    with caplog.at_level(logging.WARNING):
        gate(
            _listener(conn_type, attested=True), "IB", allow_insecure_bind=False, posture=ENFORCING
        )
    warned = " ".join(r.getMessage() for r in caplog.records)
    assert LEVER in warned
    assert SIDECAR_REASON in warned
    assert "--allow-insecure-bind" not in warned


# --- outbound transports ------------------------------------------------------------------------------


def test_database_weakened_tls_refusal() -> None:
    with pytest.raises(ValueError) as exc:
        _build_dsn(
            {
                "server": "sql.example.invalid",
                "database": "MFDB",
                "username": "u",
                "password": "p",
                "trust_server_certificate": True,
            }
        )
    message = str(exc.value)
    _assert_offers_the_supported_lever(message)
    assert "trusted server certificate" in message
    # The escape variable does nothing while enforcing, so the text must say where it does apply.
    assert "[security].enforcement = warn" in message


def test_email_cleartext_refusal() -> None:
    destination = Destination(
        name="OB_EMAIL",
        type=ConnectorType.EMAIL,
        settings={
            "host": "smtp.partner.invalid",
            "sender": "engine@hospital.invalid",
            "recipients": ["clinician@partner.invalid"],
            "use_tls": False,
        },
    )
    with pytest.raises(ValueError) as exc:
        EmailDestination(destination)
    message = str(exc.value)
    _assert_offers_the_supported_lever(message)
    assert "cleartext_accepted" in message
    assert "[security].enforcement = warn" in message


def test_oauth2_cleartext_token_endpoint_refusal() -> None:
    with active_hop_posture(ENFORCING), pytest.raises(HttpAuthError) as exc:
        OAuth2ClientCredentialsProvider(
            token_url="http://auth.example.invalid/token", client_id="cid", client_secret="s3cr3t"
        )
    message = str(exc.value)
    _assert_offers_the_supported_lever(message)
    assert "cleartext_accepted" in message


def test_digest_cleartext_refusal() -> None:
    with active_hop_posture(ENFORCING), pytest.raises(HttpAuthError) as exc:
        digest_handler_from_settings(
            {"http_auth": "digest", "http_auth_user": "u", "http_auth_password": "p"},
            url="http://api.example.invalid/x",
        )
    message = str(exc.value)
    _assert_offers_the_supported_lever(message)
    assert "cleartext_accepted" in message


def test_smart_cleartext_token_endpoint_refusal() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    with active_hop_posture(ENFORCING), pytest.raises(SmartAuthError) as exc:
        SmartBackendTokenProvider(
            token_url="http://auth.example.invalid/token", client_id="c", private_key=pem
        )
    message = str(exc.value)
    _assert_offers_the_supported_lever(message)
    assert "cleartext_accepted" in message


# --- `messagefoundry check` ------------------------------------------------------------------------


def test_generic_db_tls_check_detail(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from messagefoundry import checks
    from messagefoundry.config import wiring

    monkeypatch.setattr(wiring, "load_config", lambda _config_dir: object())
    monkeypatch.setattr(
        wiring, "unverified_generic_db_hops", lambda _registry: [("OB_PG", "no TLS keyword")]
    )
    result = checks._check_generic_db_tls(tmp_path)
    assert "OB_PG" in result.detail  # the reporting arm ran, not the "none" or skip arm
    _assert_offers_the_supported_lever(result.detail)
    assert "cleartext_accepted" in result.detail


# --- the premise: the supported surface the texts above rely on ------------------------------------
#
# docs/DEPLOYMENT.md forbids offering a field with no factory parameter and no connections.toml key.
# These pin that this field has both, and that the transport settings are not a way in.


#: Every public function in config/wiring.py that takes the flag. Pinned exactly: a new taker is a new
#: authoring surface for a silent-ALLOW loosening, so it must be added here on purpose, together with
#: the report that names it (``attested_secure_hops``).
_EXPECTED_TAKERS = {
    "inbound",
    "outbound",
    "build_inbound_connection",
    "build_outbound_connection",
    "FhirLookup",
    "DatabaseLookup",
    "DatabaseRef",
}


def test_the_declaration_surfaces_take_the_field_and_its_reason() -> None:
    from messagefoundry.config import wiring

    takers = {
        name
        for name, obj in vars(wiring).items()
        if inspect.isfunction(obj)
        and not name.startswith("_")
        and LEVER in inspect.signature(obj).parameters
    }
    assert takers == _EXPECTED_TAKERS
    for name in takers:
        assert REASON_KEY in inspect.signature(getattr(wiring, name)).parameters, name
    # No transport factory takes it: it is a declaration on the connection, not a transport setting.
    for factory in (wiring.MLLP, wiring.Http, wiring.Rest, wiring.Database, wiring.DatabasePoll):
        assert LEVER not in inspect.signature(factory).parameters, factory.__name__


_TOML_TABLES = {
    # Both directions: the four bind gates read an INBOUND, whose key set is separate from outbound's.
    "outbound": (
        '[[outbound]]\nname = "OB"\ntransport = "mllp"\n',
        'host = "h.invalid"\nport = 1\n',
    ),
    "inbound": ('[[inbound]]\nname = "IB"\ntransport = "mllp"\nrouter = "r"\n', "port = 1\n"),
}
_TOP_LEVEL_PAIR = f'{LEVER} = true\n{REASON_KEY} = "{SIDECAR_REASON}"\n'


@pytest.mark.parametrize("direction", sorted(_TOML_TABLES))
def test_connections_toml_takes_the_field_as_a_top_level_key(
    direction: str, tmp_path: Path
) -> None:
    from messagefoundry.config.connections_file import load_connections_file
    from messagefoundry.config.wiring import Registry

    head, settings = _TOML_TABLES[direction]
    table = f"[{direction}.settings]\n"
    path = tmp_path / "connections.toml"
    path.write_text(head + _TOP_LEVEL_PAIR + table + settings, encoding="utf-8")
    registry = Registry()
    load_connections_file(path, registry)
    loaded = registry.inbound["IB"] if direction == "inbound" else registry.outbound["OB"]
    assert loaded.tls_hop_attested is True
    # The flag alone is refused: the reason is mandatory on this surface too.
    path.write_text(head + f"{LEVER} = true\n" + table + settings, encoding="utf-8")
    with pytest.raises(WiringError, match=REASON_KEY):
        load_connections_file(path, Registry())


@pytest.mark.parametrize("direction", sorted(_TOML_TABLES))
def test_connections_toml_refuses_the_field_as_a_transport_setting(
    direction: str, tmp_path: Path
) -> None:
    from messagefoundry.config.connections_file import load_connections_file
    from messagefoundry.config.wiring import Registry

    head, settings = _TOML_TABLES[direction]
    table = f"[{direction}.settings]\n"
    path = tmp_path / "connections.toml"
    path.write_text(head + table + settings + f"{LEVER} = true\n", encoding="utf-8")
    with pytest.raises(WiringError, match=LEVER):
        load_connections_file(path, Registry())
    # Control: the same file without the field loads, so the refusal is about the field.
    path.write_text(head + table + settings, encoding="utf-8")
    load_connections_file(path, Registry())
