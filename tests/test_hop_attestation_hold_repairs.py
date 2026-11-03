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


@pytest.mark.parametrize("login", [{}, {"proxy_user": "pu", "proxy_password": "pp"}])
def test_a_credential_in_a_proxy_url_is_no_hop_to_accept(login: dict[str, str]) -> None:
    """The connector's build refuses the URL, so advising ``static_credential_accepted`` for it,
    or auditing it, would describe a hop that never runs."""
    from messagefoundry.config.static_credentials import _proxy_hop

    url = "http://u:p@proxy.example.org:3128"
    assert _proxy_hop("OB", {"proxy_url": url, **login}, None) is None
    assert _proxy_hop("OB", {}, url) is None  # inherited from [egress]
    # Control: a proxy_user pair on a URL with no userinfo is still a hop.
    hop = _proxy_hop("OB", {"proxy_url": "http://proxy.example.org:3128", "proxy_user": "pu"}, None)
    assert hop is not None and hop.name == "proxy:OB"
