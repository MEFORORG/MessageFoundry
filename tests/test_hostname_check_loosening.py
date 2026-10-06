# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``tls_check_hostname=false`` is a RECORDED loosening, never a silent one (ASVS 12.3.2).

The owner's answer to vault #2006 (2026-09-27) holds that a weakening with no refusal, no warning, no
audit line and no ``security_loosenings()`` entry is SILENT. A vault re-read on 2026-10-01 found this
one silent on MLLP, on Email and Direct without credentials, and on a hand-built FTPS spec. It also
found the expiry relaxation's WARNING claiming "hostname ... still verified" on a hop where it was not.

Each warning test has a control arm with defaults that must stay silent, so a test that passes is not
passing because every build warns.
"""

from __future__ import annotations

import logging
import re
import ssl
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.tls_policy import build_smtp_tls_context, relax_verify_expiry
from messagefoundry.config.wiring import (
    ConnectionSpec,
    EnvRef,
    Registry,
    build_inbound_connection,
    build_outbound_connection,
    hostname_unchecked_hops,
)

_MARK = "TLS hostname checking is OFF"


def _hostname_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if _MARK in r.getMessage()]


# --- the construction WARNING, per transport ---------------------------------------------------


def test_smtp_context_warns_naming_the_connection_and_host(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        ctx = build_smtp_tls_context(
            host="relay.example.invalid",
            cell="Email destination",
            check_hostname=False,
            name="OB_M",
        )
    assert ctx.check_hostname is False and ctx.verify_mode == ssl.CERT_REQUIRED
    [line] = _hostname_warnings(caplog)
    assert "Email destination 'OB_M'" in line and "relay.example.invalid" in line


def test_smtp_context_with_defaults_is_silent(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        build_smtp_tls_context(host="relay.example.invalid", cell="Email destination", name="OB_M")
    assert _hostname_warnings(caplog) == []


def _email(**settings: Any) -> Destination:
    base: dict[str, Any] = {
        "host": "smtp.partner.example.invalid",
        "sender": "engine@hospital.example.invalid",
        "recipients": ["clinician@partner.example.invalid"],
    }
    base.update(settings)
    return Destination(name="OB_EMAIL", type=ConnectorType.EMAIL, settings=base)


def test_email_without_credentials_warns_and_names_itself(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from messagefoundry.transports.email import EmailDestination

    with caplog.at_level(logging.WARNING):
        EmailDestination(_email(tls_check_hostname=False))
    [line] = _hostname_warnings(caplog)
    assert "'OB_EMAIL'" in line and "smtp.partner.example.invalid" in line


def test_email_with_defaults_is_silent(caplog: pytest.LogCaptureFixture) -> None:
    from messagefoundry.transports.email import EmailDestination

    with caplog.at_level(logging.WARNING):
        EmailDestination(_email())
    assert _hostname_warnings(caplog) == []


def _mllp(**settings: Any) -> Destination:
    base: dict[str, Any] = {"host": "127.0.0.1", "port": 6661, "tls": True}
    base.update(settings)
    return Destination(name="OB_MLLP", type=ConnectorType.MLLP, settings=base)


def test_mllp_destination_warns_and_names_itself(caplog: pytest.LogCaptureFixture) -> None:
    from messagefoundry.transports.mllp import MLLPDestination

    with caplog.at_level(logging.WARNING):
        dest = MLLPDestination(_mllp(tls_check_hostname=False))
    assert dest._ssl is not None and dest._ssl.check_hostname is False
    [line] = _hostname_warnings(caplog)
    assert "MLLP destination 'OB_MLLP'" in line and "127.0.0.1" in line


def test_mllp_destination_with_defaults_is_silent(caplog: pytest.LogCaptureFixture) -> None:
    from messagefoundry.transports.mllp import MLLPDestination

    with caplog.at_level(logging.WARNING):
        dest = MLLPDestination(_mllp())
    assert dest._ssl is not None and dest._ssl.check_hostname is True
    assert _hostname_warnings(caplog) == []


def test_mllp_verify_off_does_not_add_a_hostname_line(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On the verify-off path the name check goes with the chain, and that hop has its own refusal
    and its own line. A second line here would describe the wrong loosening."""
    from messagefoundry.transports import mllp

    monkeypatch.setattr(mllp, "weakened_tls_escape_permitted_here", lambda: True)
    with caplog.at_level(logging.WARNING):
        mllp._mllp_ssl_context(
            {"tls": True, "tls_verify": False, "tls_check_hostname": False},
            server=False,
            name="OB_X",
        )
    assert _hostname_warnings(caplog) == []


def test_ftps_context_warns_from_a_hand_built_spec(caplog: pytest.LogCaptureFixture) -> None:
    """``Ftp()`` does not take the key, but the context honours it, so the warning lives there."""
    from messagefoundry.transports.remotefile import _ftps_ssl_context

    with caplog.at_level(logging.WARNING):
        ctx = _ftps_ssl_context(
            {"host": "ftps.partner.example.invalid", "tls_check_hostname": False}, name="OB_FTPS"
        )
    assert ctx.check_hostname is False
    [line] = _hostname_warnings(caplog)
    assert "'OB_FTPS'" in line and "ftps.partner.example.invalid" in line


def test_ftps_context_with_defaults_is_silent(caplog: pytest.LogCaptureFixture) -> None:
    from messagefoundry.transports.remotefile import _ftps_ssl_context

    with caplog.at_level(logging.WARNING):
        _ftps_ssl_context({"host": "ftps.partner.example.invalid"}, name="OB_FTPS")
    assert _hostname_warnings(caplog) == []


def test_ftps_destination_and_source_pass_their_names(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The name reaches the line through ``_make_client`` from both directions. Credential-less, as
    a credentialed hop with the name check off is refused (vault BACKLOG #2636)."""
    from messagefoundry.transports.remotefile import RemoteFileDestination, RemoteFileSource

    settings: dict[str, Any] = {
        "protocol": "ftps",
        "host": "ftps.partner.example.invalid",
        "remote_dir": "/in",
        "tls_check_hostname": False,
    }
    with caplog.at_level(logging.WARNING):
        RemoteFileDestination(
            Destination(name="OB_RF", type=ConnectorType.REMOTEFILE, settings=dict(settings))
        )
        RemoteFileSource(
            Source(name="IB_RF", type=ConnectorType.REMOTEFILE, settings=dict(settings))
        )
    lines = _hostname_warnings(caplog)
    assert any("'OB_RF'" in ln for ln in lines), lines
    # The inbound namespace is spelt out, as every inbound refusal does (vault BACKLOG #2370).
    assert any("'inbound:IB_RF'" in ln for ln in lines), lines


# --- credentialed FTPS with the name check off is REFUSED (vault BACKLOG #2636) ---------------
#
# The FTPS twin of the SMTP refusal of #1314: absolute, keyed on no escape, on either half of the
# credential. The credential-less hop keeps the warning above.

_REFUSAL = re.escape("peer NAME is unverified (tls_check_hostname=false); refused")


@pytest.mark.parametrize(
    "credential", [{"username": "svc"}, {"password": "synthetic"}], ids=["username", "password"]
)
def test_ftps_context_refuses_a_credential_with_the_name_check_off(
    credential: dict[str, str], caplog: pytest.LogCaptureFixture
) -> None:
    from messagefoundry.transports.remotefile import _ftps_ssl_context

    settings: dict[str, Any] = {
        "host": "ftps.partner.example.invalid",
        "tls_check_hostname": False,
        **credential,
    }
    with caplog.at_level(logging.WARNING), pytest.raises(ValueError, match=_REFUSAL) as info:
        _ftps_ssl_context(settings, name="OB_FTPS")
    message = str(info.value)
    assert "connection 'OB_FTPS'" in message
    assert "tls_check_hostname on" in message and "sftp" in message  # names the remedy
    assert "synthetic" not in message  # never echoes the credential
    assert _hostname_warnings(caplog) == []  # refused, not warned and then refused


def test_ftps_refusal_has_no_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neither the insecure-TLS escape nor a permissive posture unlocks it. A guard against a later
    edit that makes this arm consult the escape, which the verify-off arm above it does."""
    from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV
    from messagefoundry.transports import remotefile

    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    monkeypatch.setattr(remotefile, "weakened_tls_escape_permitted_here", lambda: True)
    with pytest.raises(ValueError, match=_REFUSAL):
        remotefile._ftps_ssl_context(
            {"host": "h.example.invalid", "tls_check_hostname": False, "username": "svc"}
        )


def test_ftps_refusal_fires_from_both_directions() -> None:
    """The destination upload and the inbound poller both log in, so both are refused at build."""
    from messagefoundry.transports.remotefile import RemoteFileDestination, RemoteFileSource

    settings: dict[str, Any] = {
        "protocol": "ftps",
        "host": "ftps.partner.example.invalid",
        "username": "svc",
        "password": "synthetic",
        "remote_dir": "/in",
        "tls_check_hostname": False,
    }
    with pytest.raises(ValueError, match=_REFUSAL) as out:
        RemoteFileDestination(
            Destination(name="OB_RF", type=ConnectorType.REMOTEFILE, settings=dict(settings))
        )
    assert "'OB_RF'" in str(out.value)
    with pytest.raises(ValueError, match=_REFUSAL) as inb:
        RemoteFileSource(
            Source(name="IB_RF", type=ConnectorType.REMOTEFILE, settings=dict(settings))
        )
    assert "'inbound:IB_RF'" in str(inb.value)


@pytest.mark.parametrize("explicit", [True, False], ids=["explicit-true", "absent"])
def test_ftps_credentials_with_the_name_check_on_are_unaffected(
    explicit: bool, caplog: pytest.LogCaptureFixture
) -> None:
    """Control arm: the same credentials on the shipped posture build silently."""
    from messagefoundry.transports.remotefile import _ftps_ssl_context

    settings: dict[str, Any] = {
        "host": "ftps.partner.example.invalid",
        "username": "svc",
        "password": "synthetic",
    }
    if explicit:
        settings["tls_check_hostname"] = True
    with caplog.at_level(logging.WARNING):
        ctx = _ftps_ssl_context(settings, name="OB_FTPS")
    assert ctx.check_hostname is True and ctx.verify_mode == ssl.CERT_REQUIRED
    assert _hostname_warnings(caplog) == []


# --- credentialed FTPS with tls_verify=false is REFUSED too (vault BACKLOG #2636) -------------
#
# The weaker posture, closed in the same change so the hostname refusal above does not leave an
# inversion behind it. The SMTP twin is #323's credential arm. Every refusal case below permits the
# escape, so the refusal it reaches is the credential one and not the escape-off one.

_VERIFY_OFF_REFUSAL = re.escape(
    "over an unverified TLS session (tls_verify=false); refused -- credentials require a verified"
)


@pytest.fixture
def _escape_permitted(monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV
    from messagefoundry.transports import remotefile

    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    monkeypatch.setattr(remotefile, "weakened_tls_escape_permitted_here", lambda: True)


@pytest.mark.usefixtures("_escape_permitted")
@pytest.mark.parametrize(
    "credential", [{"username": "svc"}, {"password": "synthetic"}], ids=["username", "password"]
)
def test_ftps_verify_off_refuses_a_credential_under_the_escape(
    credential: dict[str, str],
) -> None:
    from messagefoundry.transports.remotefile import _ftps_ssl_context

    settings: dict[str, Any] = {
        "host": "ftps.partner.example.invalid",
        "tls_verify": False,
        **credential,
    }
    with pytest.raises(ValueError, match=_VERIFY_OFF_REFUSAL) as info:
        _ftps_ssl_context(settings, name="OB_FTPS")
    message = str(info.value)
    assert "connection 'OB_FTPS'" in message
    assert "tls_verify on" in message and "sftp" in message  # names the remedy
    assert "synthetic" not in message  # never echoes the credential


@pytest.mark.usefixtures("_escape_permitted")
def test_ftps_verify_off_refusal_fires_from_both_directions() -> None:
    from messagefoundry.transports.remotefile import RemoteFileDestination, RemoteFileSource

    settings: dict[str, Any] = {
        "protocol": "ftps",
        "host": "ftps.partner.example.invalid",
        "username": "svc",
        "password": "synthetic",
        "remote_dir": "/in",
        "tls_verify": False,
    }
    with pytest.raises(ValueError, match=_VERIFY_OFF_REFUSAL) as out:
        RemoteFileDestination(
            Destination(name="OB_RF", type=ConnectorType.REMOTEFILE, settings=dict(settings))
        )
    assert "'OB_RF'" in str(out.value) and "synthetic" not in str(out.value)
    with pytest.raises(ValueError, match=_VERIFY_OFF_REFUSAL) as inb:
        RemoteFileSource(
            Source(name="IB_RF", type=ConnectorType.REMOTEFILE, settings=dict(settings))
        )
    assert "'inbound:IB_RF'" in str(inb.value) and "synthetic" not in str(inb.value)


@pytest.mark.usefixtures("_escape_permitted")
def test_ftps_verify_off_without_a_credential_is_unchanged_under_the_escape(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Control arm: the anonymous hop still builds under the escape, CERT_NONE and loudly logged."""
    from messagefoundry.transports.remotefile import _ftps_ssl_context

    with caplog.at_level(logging.WARNING):
        ctx = _ftps_ssl_context(
            {"host": "ftps.partner.example.invalid", "tls_verify": False}, name="OB_FTPS"
        )
    assert ctx.verify_mode == ssl.CERT_NONE and ctx.check_hostname is False
    assert any("verification is DISABLED" in r.getMessage() for r in caplog.records)


def test_ftps_anonymous_verify_off_stays_behind_the_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without the escape the anonymous verify-off hop is still refused, by the escape arm."""
    from messagefoundry.transports import remotefile

    monkeypatch.setattr(remotefile, "weakened_tls_escape_permitted_here", lambda: False)
    with pytest.raises(ValueError, match="disables server-certificate verification"):
        remotefile._ftps_ssl_context({"host": "h.example.invalid", "tls_verify": False})


# --- the expiry relaxation states what is actually verified ------------------------------------


def test_relax_text_says_the_hostname_is_not_verified_when_it_is_not(
    caplog: pytest.LogCaptureFixture,
) -> None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    with caplog.at_level(logging.WARNING):
        relax_verify_expiry(ctx, host="partner.example.invalid")
    [line] = [r.getMessage() for r in caplog.records if "RELAXED" in r.getMessage()]
    assert "the hostname is NOT" in line
    assert "chain, hostname, and key-usage are still verified" not in line


def test_relax_text_keeps_the_hostname_claim_when_it_holds(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Control arm: the claim is right on a hop that checks the name, so it must survive."""
    ctx = ssl.create_default_context()
    with caplog.at_level(logging.WARNING):
        relax_verify_expiry(ctx, host="partner.example.invalid")
    [line] = [r.getMessage() for r in caplog.records if "RELAXED" in r.getMessage()]
    assert "chain, hostname, and key-usage are still verified" in line


def test_mllp_relax_runs_after_the_hostname_is_set(caplog: pytest.LogCaptureFixture) -> None:
    """The text reads ``ctx.check_hostname``, so it is only true if the caller set it first."""
    from messagefoundry.transports.mllp import _mllp_ssl_context

    with caplog.at_level(logging.WARNING):
        _mllp_ssl_context(
            {"tls": True, "tls_allow_expired": True, "tls_check_hostname": False}, server=False
        )
    [line] = [r.getMessage() for r in caplog.records if "RELAXED" in r.getMessage()]
    assert "the hostname is NOT" in line


# --- the single reader -------------------------------------------------------------------------


def _registry() -> Registry:
    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_OFF",
            ConnectionSpec(
                type=ConnectorType.MLLP,
                settings={
                    "host": "a.example.invalid",
                    "port": 1,
                    "tls": True,
                    "tls_check_hostname": False,
                },
            ),
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_ENV",
            ConnectionSpec(
                type=ConnectorType.MLLP,
                settings={
                    "host": "b.example.invalid",
                    "port": 2,
                    "tls": True,
                    "tls_check_hostname": EnvRef("MEFOR_B_CHECK_HOST"),
                },
            ),
        )
    )
    # Control: an explicit True and an absent key are both the shipped posture.
    reg.add_outbound(
        build_outbound_connection(
            "OB_ON",
            ConnectionSpec(
                type=ConnectorType.MLLP,
                settings={
                    "host": "c.example.invalid",
                    "port": 3,
                    "tls": True,
                    "tls_check_hostname": True,
                },
            ),
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_DEFAULT",
            ConnectionSpec(
                type=ConnectorType.MLLP, settings={"host": "d.example.invalid", "port": 4}
            ),
        )
    )
    reg.add_inbound(
        build_inbound_connection(
            "IB_FTPS",
            ConnectionSpec(
                type=ConnectorType.REMOTEFILE,
                settings={
                    "protocol": "ftps",
                    "host": "e.example.invalid",
                    "remote_dir": "/out",
                    "tls_check_hostname": False,
                },
            ),
            router="r",
        )
    )
    return reg


def test_reader_lists_declarations_in_both_directions_and_an_env_reference() -> None:
    names = [name for name, _ in hostname_unchecked_hops(_registry())]
    assert names == ["OB_ENV", "OB_OFF", "inbound:IB_FTPS"]


def test_expiry_reader_lists_an_inbound_ftps_poller() -> None:
    """CORRECTED by the review: ``Ftp()`` is a source factory and the poller honours
    ``tls_allow_expired``, yet the reader was outbound-only, so the poller was listed nowhere."""
    from messagefoundry.config.wiring import expiry_relaxed_hops

    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            "IB_FTPS",
            ConnectionSpec(
                type=ConnectorType.REMOTEFILE,
                settings={
                    "protocol": "ftps",
                    "host": "e.example.invalid",
                    "tls_allow_expired": True,
                },
            ),
            router="r",
        )
    )
    reg.add_inbound(  # control: the same poller without the flag
        build_inbound_connection(
            "IB_STRICT",
            ConnectionSpec(
                type=ConnectorType.REMOTEFILE,
                settings={"protocol": "ftps", "host": "f.example.invalid"},
            ),
            router="r",
        )
    )
    reg.add_inbound(  # control: a listener whose context never reads the flag
        build_inbound_connection(
            "IB_MLLP",
            ConnectionSpec(
                type=ConnectorType.MLLP, settings={"port": 6661, "tls_allow_expired": True}
            ),
            router="r",
        )
    )
    assert [name for name, _ in expiry_relaxed_hops(reg)] == ["inbound:IB_FTPS"]


def test_ftps_relax_runs_after_the_hostname_is_set(caplog: pytest.LogCaptureFixture) -> None:
    """The FTPS twin of the MLLP ordering test: the expiry line reads ``ctx.check_hostname``."""
    from messagefoundry.transports.remotefile import _ftps_ssl_context

    with caplog.at_level(logging.WARNING):
        _ftps_ssl_context(
            {"host": "h.example.invalid", "tls_allow_expired": True, "tls_check_hostname": False}
        )
    [line] = [r.getMessage() for r in caplog.records if "RELAXED" in r.getMessage()]
    assert "the hostname is NOT" in line


def test_reader_labels_the_peer_by_host_and_port() -> None:
    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_M",
            ConnectionSpec(
                type=ConnectorType.MLLP,
                settings={"host": "a.example.invalid", "port": 7, "tls_check_hostname": False},
            ),
        )
    )
    assert hostname_unchecked_hops(reg) == [("OB_M", "a.example.invalid:7")]
