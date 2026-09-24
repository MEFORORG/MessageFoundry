# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Refusal and warning text must not offer ``tls_hop_attested`` as a remedy (SDS-3.7).

The gates read a per-connection ``tls_hop_attested``, but no supported surface sets it: no connector
factory, ``inbound()`` or ``outbound()`` takes the keyword, and ``connections.toml`` refuses it both as a
top-level key and inside ``[settings]`` (the factory is the schema). The premise tests at the bottom pin
that. Only the unsupported raw-settings escape hatch, a config module writing ``spec.settings``
directly, reaches it. docs/DEPLOYMENT.md forbids naming such a field as an operator lever. These
refusals did anyway, telling an operator to "set tls_hop_attested=true".

Each text test asserts two things: the retired lever is absent, and a lever that DOES exist is present.
The second half is the control -- without it, a refusal that went quiet or changed shape would pass.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import WiringError
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

RETIRED = "tls_hop_attested"
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


def _listener(conn_type: ConnectorType, *, attested: bool = False) -> Source:
    return Source(
        type=conn_type,
        settings={"host": "0.0.0.0", "port": 9000},
        tls_hop_attested=attested,
        tls_hop_attested_reason="set by direct model construction" if attested else None,
    )


# --- the four inbound bind gates ---------------------------------------------------------------------


@pytest.mark.parametrize(("gate", "conn_type"), _BIND_GATES, ids=_IDS)
def test_bind_refusal_names_the_real_way_across(gate: _Gate, conn_type: ConnectorType) -> None:
    with pytest.raises(WiringError) as exc:
        gate(_listener(conn_type), "IB", allow_insecure_bind=True, posture=ENFORCING)
    message = str(exc.value)
    assert RETIRED not in message
    assert "--allow-insecure-bind" in message
    assert "[security].enforcement = warn" in message
    # A firewall never clears this gate (it reads only the bind host), so it is not offered as one.
    assert "firewall/segment the port" not in message


@pytest.mark.parametrize(("gate", "conn_type"), _BIND_GATES, ids=_IDS)
def test_bind_warning_names_the_flag_that_let_it_cross(
    gate: _Gate, conn_type: ConnectorType, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        gate(_listener(conn_type), "IB", allow_insecure_bind=True, posture=NOT_ENFORCING)
    warned = " ".join(r.getMessage() for r in caplog.records)
    # The warning fired, so the absence below means something.
    assert "--allow-insecure-bind" in warned
    assert RETIRED not in warned


@pytest.mark.parametrize(("gate", "conn_type"), _BIND_GATES, ids=_IDS)
def test_bind_warning_still_names_an_attestation_that_was_actually_set(
    gate: _Gate, conn_type: ConnectorType, caplog: pytest.LogCaptureFixture
) -> None:
    """The other direction. When the model does carry the field (a direct embedding), the warning
    must say so rather than blame a flag nobody passed. Reporting it is a fact, not an offer."""
    with caplog.at_level(logging.WARNING):
        gate(
            _listener(conn_type, attested=True), "IB", allow_insecure_bind=False, posture=ENFORCING
        )
    warned = " ".join(r.getMessage() for r in caplog.records)
    assert RETIRED in warned
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
    assert RETIRED not in message
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
    assert RETIRED not in message
    assert "cleartext_accepted" in message
    assert "[security].enforcement = warn" in message


def test_oauth2_cleartext_token_endpoint_refusal() -> None:
    with active_hop_posture(ENFORCING), pytest.raises(HttpAuthError) as exc:
        OAuth2ClientCredentialsProvider(
            token_url="http://auth.example.invalid/token", client_id="cid", client_secret="s3cr3t"
        )
    message = str(exc.value)
    assert RETIRED not in message
    assert "cleartext_accepted" in message


def test_digest_cleartext_refusal() -> None:
    with active_hop_posture(ENFORCING), pytest.raises(HttpAuthError) as exc:
        digest_handler_from_settings(
            {"http_auth": "digest", "http_auth_user": "u", "http_auth_password": "p"},
            url="http://api.example.invalid/x",
        )
    message = str(exc.value)
    assert RETIRED not in message
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
    assert RETIRED not in message
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
    assert RETIRED not in result.detail
    assert "cleartext_accepted" in result.detail


# --- the premise: no supported surface sets the field ---------------------------------------------
#
# The text tests above are only right while this holds. If a factory, inbound()/outbound() or
# connections.toml ever gains the field, these go red, and the refusals should name it again.


def test_no_public_wiring_function_takes_the_field() -> None:
    import inspect

    from messagefoundry.config import wiring

    takers = [
        name
        for name, obj in vars(wiring).items()
        if inspect.isfunction(obj)
        and not name.startswith("_")
        and RETIRED in inspect.signature(obj).parameters
    ]
    assert takers == []
    # Control: the same scan does find a keyword that IS offered, so an empty list is not a dead probe.
    assert "cleartext_accepted" in inspect.signature(wiring.outbound).parameters


@pytest.mark.parametrize("where", ["top-level", "settings"])
def test_connections_toml_refuses_the_field(where: str, tmp_path: Path) -> None:
    from messagefoundry.config.connections_file import load_connections_file
    from messagefoundry.config.wiring import Registry

    top = f"{RETIRED} = true\n" if where == "top-level" else ""
    inner = f"{RETIRED} = true\n" if where == "settings" else ""
    path = tmp_path / "connections.toml"
    path.write_text(
        '[[outbound]]\nname = "OB"\ntransport = "mllp"\n'
        + top
        + '[outbound.settings]\nhost = "h.invalid"\nport = 1\n'
        + inner,
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match=RETIRED):
        load_connections_file(path, Registry())
    # Control: the same file without the field loads, so the refusal is about the field.
    path.write_text(
        '[[outbound]]\nname = "OB"\ntransport = "mllp"\n'
        '[outbound.settings]\nhost = "h.invalid"\nport = 1\n',
        encoding="utf-8",
    )
    load_connections_file(path, Registry())
