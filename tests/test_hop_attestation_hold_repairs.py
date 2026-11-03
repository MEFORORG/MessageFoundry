# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The hop-attestation and input-hiding repairs to engine PR 2683 (vault BACKLOG #3007, #3139).

Each test fails on the PR's head before the repair: a typed attestation reason with a CR or LF, the
anonymous-FTP guard's inbound read of the settings pair, a settings secret in a ``Source``,
``OutboundSigning`` or ``WindowsCredential`` validation error, and the ``check`` report marking an
outbound hop the build refuses for its reason as one the engine crosses. Every value is synthetic.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from messagefoundry.config.models import (
    ConnectorType,
    Destination,
    OutboundSigning,
    Source,
    WindowsCredential,
)
from messagefoundry.config.wiring import (
    AttestedHop,
    File,
    InboundConnection,
    OutboundConnection,
    Registry,
    attested_secure_hop_records,
)
from messagefoundry.transports.remotefile import _anon_ftp_guard

REASON = "TLS terminates at the site's stunnel sidecar"
#: A made-up secret, standing in for a resolved env() value.
MARKER = "synthetic-marker-value"


# --- item 1: the typed reason is held to the control-character rule ------------------------------


@pytest.mark.parametrize("forged", ["ok\nWARNING forged line", "ok\rWARNING", "ok\x00"])
@pytest.mark.parametrize("model", [Destination, Source])
def test_a_typed_reason_with_a_control_character_is_refused(model: type, forged: str) -> None:
    kwargs: dict[str, Any] = {"type": ConnectorType.FILE, "tls_hop_attested": True}
    if model is Destination:
        kwargs["name"] = "OB"
    with pytest.raises(ValidationError, match="must not contain control characters"):
        model(tls_hop_attested_reason=forged, **kwargs)
    # Control: the same declaration with a clean reason builds.
    model(tls_hop_attested_reason=REASON, **kwargs)


# --- item 2: the anonymous-FTP guard reads the whole pair, on both sides -------------------------


def _ftp(**extra: Any) -> dict[str, Any]:
    return {"host": "ftp.example.com", "remote_dir": "/in", "protocol": "ftp", **extra}


@pytest.mark.parametrize(
    ("extra", "match"),
    [
        ({"tls_hop_attested": True}, "requires tls_hop_attested_reason"),
        ({"tls_hop_attested": True, "tls_hop_attested_reason": "  "}, "must be non-empty"),
        (
            {"tls_hop_attested": True, "tls_hop_attested_reason": "ok\nWARNING forged"},
            "must not contain control characters",
        ),
        ({"tls_hop_attested_reason": REASON}, "is set without tls_hop_attested=true"),
        ({"tls_hop_attested": True, "tls_hop_attested_reason": 7}, "must be a string"),
    ],
)
def test_the_anonymous_ftp_guard_refuses_a_bad_settings_pair(
    extra: dict[str, Any], match: str
) -> None:
    """The inbound ``RemoteFileSource`` has no ``Destination`` validator in front of the guard, so
    the guard itself must run the reason rules."""
    with pytest.raises(ValueError, match=rf"^connection 'IB_FTP'; .*{match}"):
        _anon_ftp_guard(_ftp(**extra), connection="IB_FTP")


def test_control_the_anonymous_ftp_guard_accepts_a_good_pair() -> None:
    guard = _anon_ftp_guard(
        _ftp(tls_hop_attested=True, tls_hop_attested_reason=REASON), connection="IB_FTP"
    )
    assert guard is not None
    assert _anon_ftp_guard(_ftp(), connection="IB_FTP") is not None


# --- item 3: no settings secret in a validation error, however it is rendered --------------------


def _renderings(exc: ValidationError) -> list[str]:
    return [str(exc), repr(exc), str(exc.errors()), exc.json()]


@pytest.mark.parametrize(
    ("model", "data"),
    [
        # Refused by the model validator: the missing reason. Its error carries the whole input.
        (
            Source,
            {"type": "file", "settings": {"password": MARKER}, "tls_hop_attested": True},
        ),
        # A missing field's error carries the whole input mapping too.
        (OutboundSigning, {"private_key_password": MARKER}),
        (WindowsCredential, {"password": MARKER}),
    ],
    ids=["Source", "OutboundSigning", "WindowsCredential"],
)
def test_a_refusal_never_carries_a_settings_secret(
    model: type[BaseModel], data: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError) as refused:
        model.model_validate(data)
    for text in _renderings(refused.value):
        assert MARKER not in text, text


def test_a_source_nested_in_another_model_still_hides_its_input() -> None:
    class Holder(BaseModel):
        source: Source

    with pytest.raises(ValidationError) as refused:
        Holder.model_validate(
            {"source": {"type": "file", "settings": {"p": MARKER}, "tls_hop_attested": True}}
        )
    for text in _renderings(refused.value):
        assert MARKER not in text, text


# --- item 4: the report marks every typed pair the build refuses --------------------------------


@pytest.mark.parametrize(
    "reason",
    [None, "", "   ", "ok\nWARNING forged line"],
    ids=["missing", "empty", "blank", "newline"],
)
def test_an_outbound_whose_reason_the_build_refuses_is_marked_refused(reason: str | None) -> None:
    reg = Registry()
    spec = File(directory=".")
    reg.add_outbound(
        OutboundConnection("OB_BAD", spec, tls_hop_attested=True, tls_hop_attested_reason=reason)
    )
    reg.add_outbound(
        OutboundConnection("OB_GOOD", spec, tls_hop_attested=True, tls_hop_attested_reason=REASON)
    )
    records = {hop.name: hop.refused for hop in attested_secure_hop_records(reg)}
    assert records == {"OB_BAD": True, "OB_GOOD": False}


def test_an_inbound_whose_reason_the_build_refuses_is_marked_refused() -> None:
    reg = Registry()
    spec = File(directory=".")
    reg.add_inbound(
        InboundConnection(
            "IB_BAD", spec, "R", tls_hop_attested=True, tls_hop_attested_reason="a\nb"
        )
    )
    reg.add_inbound(
        InboundConnection(
            "IB_GOOD", spec, "R", tls_hop_attested=True, tls_hop_attested_reason=REASON
        )
    )
    records = attested_secure_hop_records(reg)
    assert [hop.refused for hop in records] == [True, False]
    assert all(isinstance(hop, AttestedHop) for hop in records)


# --- item 5: a credential in a proxy URL is not a static-credential hop to accept --------------


@pytest.mark.parametrize(
    "url",
    [
        "http://u:p@proxy.example.org:3128",
        "http://u@proxy.example.org:3128",  # a user alone, which urllib sends nothing for
        "http://:p@proxy.example.org:3128",  # a password alone
        "http://u:p@proxy.example.org:3128/x",  # refused for its credential before its shape
    ],
)
@pytest.mark.parametrize("login", [{}, {"proxy_user": "pu", "proxy_password": "pp"}])
def test_a_credential_in_a_proxy_url_is_no_hop_to_accept(url: str, login: dict[str, str]) -> None:
    """The connector's build refuses the URL, so advising ``static_credential_accepted`` for it,
    or auditing it, would describe a hop that never runs. The report asks the build's own test."""
    from messagefoundry.config.static_credentials import _proxy_hop
    from messagefoundry.config.tls_policy import InsecureHopRefused
    from messagefoundry.transports.rest import proxy_config_from_settings

    with pytest.raises(InsecureHopRefused):
        proxy_config_from_settings(
            {"proxy_url": url, **login}, dest_scheme="https", connection="OB"
        )
    assert _proxy_hop("OB", {"proxy_url": url, **login}, None) is None
    assert _proxy_hop("OB", login, url) is None  # inherited from [egress]
    # Control: a proxy_user pair on a URL with no userinfo is still a hop.
    hop = _proxy_hop("OB", {"proxy_url": "http://proxy.example.org:3128", "proxy_user": "pu"}, None)
    assert hop is not None and hop.name == "proxy:OB"


# --- review round 1 ------------------------------------------------------------------------------


def test_an_outbound_with_a_raw_attestation_key_in_its_settings_is_marked_refused() -> None:
    """``_dest_config`` refuses a raw ``tls_hop_attested*`` key in the transport settings, so the
    report marks that connection refused too. The control is the same connection without it."""
    reg = Registry()
    raw = File(directory=".")
    raw.settings["tls_hop_attested_reason"] = REASON
    reg.add_outbound(
        OutboundConnection("OB_RAW", raw, tls_hop_attested=True, tls_hop_attested_reason=REASON)
    )
    reg.add_outbound(
        OutboundConnection(
            "OB_TYPED", File(directory="."), tls_hop_attested=True, tls_hop_attested_reason=REASON
        )
    )
    records = {hop.name: hop.refused for hop in attested_secure_hop_records(reg)}
    assert records == {"OB_RAW": True, "OB_TYPED": False}


def test_a_site_proxy_credential_is_refused_for_it_before_its_shape() -> None:
    """The connector asks the credential first, so the load does too, and names the setting."""
    from messagefoundry.config.settings import EgressSettings

    for url in (
        "http://u:p@proxy.example.org:3128/x",
        "http://svc@proxy.example.org:3128/x",  # a user alone beside the shape fault
        "http://:pw@proxy.example.org:3128/x",  # a password alone
    ):
        with pytest.raises(
            ValidationError, match=r"\[egress\]\.proxy_url holds a user or a password"
        ):
            EgressSettings(proxy_url=url, allowed_proxy=["proxy.example.org"])
    # Control: the same shape fault with no credential keeps the parse's own refusal.
    with pytest.raises(ValidationError, match="2965"):
        EgressSettings(
            proxy_url="http://proxy.example.org:3128/x", allowed_proxy=["proxy.example.org"]
        )


# --- review round 3: the report reads only what the build reads ---------------------------------

_ATTEST: dict[str, Any] = {"tls_hop_attested": True, "tls_hop_attested_reason": REASON}


def test_a_hop_the_build_builds_with_an_int_flag_is_not_marked_refused() -> None:
    """The Source and Destination models coerce the revocation and cleartext flags as lax bool, so
    the build builds a hop that sets one to an int. The report must not call that hop refused."""
    from messagefoundry.config.settings import EgressSettings
    from messagefoundry.pipeline.wiring_runner import _dest_config, _source_config

    spec = File(directory=".")
    revoke: dict[str, Any] = {"tls_revocation_attested": 1, "tls_revocation_attested_reason": "pki"}
    clear: dict[str, Any] = {"cleartext_accepted": 0}
    outbounds = [
        OutboundConnection("OB_REVOKE_INT", spec, **revoke, **_ATTEST),
        OutboundConnection("OB_CLEAR_INT", spec, **clear, **_ATTEST),
    ]
    inbound = InboundConnection("IB_REVOKE_INT", spec, "R", **revoke, **_ATTEST)
    # The premise: the build builds each of them.
    for oc in outbounds:
        _dest_config(oc, {}, None, EgressSettings())
    _source_config(inbound, "127.0.0.1", {})

    reg = Registry()
    for oc in outbounds:
        reg.add_outbound(oc)
    reg.add_inbound(inbound)
    records = {hop.name: hop.refused for hop in attested_secure_hop_records(reg)}
    assert len(records) == 3
    assert not any(records.values()), records


@pytest.mark.parametrize(
    "extra",
    [
        {"cleartext_accepted": True, "cleartext_reason": 5},
        {"tls_revocation_attested": True, "tls_revocation_attested_reason": 5},
        {"tls_revocation_attested": True, "tls_revocation_attested_reason": ["x"]},
    ],
    ids=["cleartext-int", "revocation-int", "revocation-list"],
)
def test_a_non_str_declaration_reason_does_not_crash_the_report(extra: dict[str, Any]) -> None:
    """A reason of a wrong type, set past the factory, must not raise out of the report that
    ``messagefoundry check`` and ``/security/posture`` both render."""
    spec = File(directory=".")
    reg = Registry()
    reg.add_outbound(OutboundConnection("OB_ODD", spec, **extra, **_ATTEST))
    if "cleartext_accepted" not in extra:
        reg.add_inbound(InboundConnection("IB_ODD", spec, "R", **extra, **_ATTEST))
    names = [hop.name for hop in attested_secure_hop_records(reg)]
    assert "OB_ODD" in names
