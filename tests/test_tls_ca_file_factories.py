# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Per-connection ``tls_ca_file`` on the HTTP-family factories and ``Ftp`` (BACKLOG #1180).

Owner ruling R7 (2026-09-24) funded this key as a supported parameter. The runtime already read
``settings["tls_ca_file"]`` on every hop concerned, but no factory could write it, so the key worked
only on a hand-built spec. These tests go through the PUBLIC factory each time, then through the same
builder the runner uses, so they prove the authoring surface reaches the opener.

Two halves, pulling in opposite directions:

* named, the CA is the hop's ONLY trust anchor, and it beats a pinned instance ``[tls]`` anchor;
* unnamed, the hop is built exactly as before -- the shared ``_NO_REDIRECT_OPENER``, by identity.

This does not move ASVS 12.3.4. Every default is still permissive; the key is opt-in.
"""

from __future__ import annotations

import ssl
import textwrap
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config import wiring
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import TrustAnchorPolicy
from messagefoundry.config.wiring import (
    FHIR,
    ConnectionSpec,
    DICOMweb,
    EnvRef,
    FhirLookup,
    Ftp,
    Registry,
    Rest,
    Soap,
    WiringError,
    build_outbound_connection,
    env,
    load_config,
)
from messagefoundry.pipeline.wiring_runner import _dest_config, _fhir_lookup_settings
from messagefoundry.transports import rest
from messagefoundry.transports.base import build_destination
from messagefoundry.transports.fhir import FhirLookupExecutor
from messagefoundry.transports.http_auth import bearer_provider_from_settings
from messagefoundry.transports.remotefile import _ftps_ssl_context
from tests.test_tls_trust_anchor import _ca_pem, _ca_subjects, _smart_settings, _token_opener

# The four destination factories, each with the least a real config would pass. The CA is the only
# thing a test adds, so the default and the anchored build differ in that one key.
_DESTINATION_FACTORIES: dict[str, Callable[..., ConnectionSpec]] = {
    "Rest": lambda **kw: Rest(url="https://partner.example.org/api", **kw),
    "FHIR": lambda **kw: FHIR(url="https://fhir.internal.example.org/fhir", **kw),
    "Soap": lambda **kw: Soap(url="https://partner.example.org/svc", soap_action="Send", **kw),
    "DICOMweb": lambda **kw: DICOMweb(url="https://pacs.internal.example.org/dicom-web", **kw),
}

_ALL_FACTORIES: dict[str, Callable[..., Any]] = {
    **_DESTINATION_FACTORIES,
    "Ftp": lambda **kw: Ftp(host="ftp.internal.example.org", tls=True, remote_dir="/in", **kw),
    "FhirLookup": lambda **kw: FhirLookup("L", url="https://fhir.internal.example.org/fhir", **kw),
}


@pytest.fixture(autouse=True)
def _isolated_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    # FhirLookup self-registers into the active registry; give every test its own.
    monkeypatch.setattr(wiring, "_active", Registry())


def _pinned(tmp_path: Path) -> TrustAnchorPolicy:
    """An instance ``[tls]`` policy pinned to a DIFFERENT CA, so a test can see which one won."""
    return TrustAnchorPolicy(internal_ca_file=_ca_pem(tmp_path, "mefor-instance-ca"), mode="pinned")


def _destination_opener(
    spec: ConnectionSpec, policy: TrustAnchorPolicy | None = None
) -> urllib.request.OpenerDirector:
    """Build ``spec`` the way the runner does -- ``_dest_config`` then the connector registry."""
    config = _dest_config(build_outbound_connection("OB", spec), {}, trust_anchor_policy=policy)
    opener: urllib.request.OpenerDirector = build_destination(
        config, egress=EgressSettings(deny_by_default=False)
    )._opener  # type: ignore[attr-defined]
    return opener


def _opener_subjects(opener: urllib.request.OpenerDirector) -> set[str]:
    ctx = rest.opener_tls_context(opener, connector="test")
    assert ctx is not None, "the opener carries no https handler"
    return _ca_subjects(ctx)


# --- the factory writes the key --------------------------------------------------------------------


@pytest.mark.parametrize("factory", sorted(_ALL_FACTORIES))
def test_the_factory_passes_the_key_through(factory: str) -> None:
    spec = _ALL_FACTORIES[factory](tls_ca_file="/org/partner-ca.pem")
    assert spec.settings["tls_ca_file"] == "/org/partner-ca.pem"


@pytest.mark.parametrize("factory", sorted(_ALL_FACTORIES))
def test_the_factory_accepts_an_env_ref(factory: str) -> None:
    """A CA path differs per environment, so it must be expressible as ``env()`` like its neighbours."""
    spec = _ALL_FACTORIES[factory](tls_ca_file=env("partner_ca"))
    assert isinstance(spec.settings["tls_ca_file"], EnvRef)


@pytest.mark.parametrize("factory", sorted(_ALL_FACTORIES))
def test_the_factory_default_is_unset(factory: str) -> None:
    assert _ALL_FACTORIES[factory]().settings["tls_ca_file"] is None


@pytest.mark.parametrize("blank", ["", "   "])
@pytest.mark.parametrize("factory", sorted(_ALL_FACTORIES))
def test_a_blank_ca_is_refused(factory: str, blank: str) -> None:
    """Every connector treats a blank value as unset and falls back to the OS store, so a blank
    literal would read as pinned while trusting every public CA."""
    with pytest.raises(ValueError, match="tls_ca_file is blank"):
        _ALL_FACTORIES[factory](tls_ca_file=blank)


def test_a_blank_ca_in_connections_toml_names_the_connection(tmp_path: Path) -> None:
    """The refusal is a ValueError so the loader prefixes the connection and file to it."""
    (tmp_path / "logic.py").write_text("", encoding="utf-8")
    (tmp_path / "connections.toml").write_text(
        textwrap.dedent(
            """
            [[outbound]]
            name = "OB_REST"
            transport = "rest"
              [outbound.settings]
              url = "https://partner.example.org/api"
              tls_ca_file = ""
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match=r"OB_REST.*tls_ca_file is blank"):
        load_config(tmp_path)


@pytest.mark.parametrize(
    "build",
    [
        lambda ca: Ftp(host="ftp.example.org", tls=False, remote_dir="/in", tls_ca_file=ca),
        lambda ca: DICOMweb(url="https://pacs.example.org/dw", verify_tls=False, tls_ca_file=ca),
    ],
    ids=["plain-ftp", "dicomweb-verify-off"],
)
def test_a_ca_the_connection_would_never_read_is_refused(build: Callable[[str], Any]) -> None:
    """A CA that looks configured but is never read is the false pin the check exists to refuse."""
    with pytest.raises(ValueError, match="would never be read"):
        build("/org/ca.pem")


def test_the_unread_refusals_are_about_the_ca_only() -> None:
    # Plain FTP and a verify-off DICOMweb hop are still authorable without a CA, and a verify-off
    # REST hop may still carry one, because a token hop there reads it.
    assert Ftp(host="ftp.example.org", remote_dir="/in").settings["protocol"] == "ftp"
    assert (
        DICOMweb(url="https://pacs.example.org/dw", verify_tls=False).settings["tls_ca_file"]
        is None
    )
    assert Rest(url="https://h.example.org/x", verify_tls=False, tls_ca_file="/org/ca.pem")


# --- named: the CA is the hop's only anchor --------------------------------------------------------


@pytest.mark.parametrize("with_policy", [False, True], ids=["no-policy", "pinned-instance-ca"])
@pytest.mark.parametrize("factory", sorted(_DESTINATION_FACTORIES))
def test_a_named_ca_is_the_destination_hops_only_anchor(
    factory: str, with_policy: bool, tmp_path: Path
) -> None:
    ca = _ca_pem(tmp_path, f"mefor-{factory.lower()}-ca")
    policy = _pinned(tmp_path) if with_policy else None
    opener = _destination_opener(_DESTINATION_FACTORIES[factory](tls_ca_file=ca), policy)
    assert opener is not rest._NO_REDIRECT_OPENER
    # The connection's own CA, and not the instance one, even when the instance is pinned.
    assert _opener_subjects(opener) == {f"mefor-{factory.lower()}-ca"}
    ctx = rest.opener_tls_context(opener, connector="test")
    assert ctx is not None
    # Anchoring chooses the roots. It never turns verification off.
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_a_named_ca_is_the_lookup_hops_only_anchor(tmp_path: Path) -> None:
    ca = _ca_pem(tmp_path, "mefor-lookup-ca")
    spec = FhirLookup("L", url="https://fhir.internal.example.org/fhir", tls_ca_file=ca)
    ex = FhirLookupExecutor(
        {"L": _fhir_lookup_settings(spec, {}, None)},
        trust_anchor_policy=_pinned(tmp_path),
        egress=EgressSettings(deny_by_default=False),
    )
    assert ex._opener["L"] is not rest._NO_REDIRECT_OPENER
    assert _opener_subjects(ex._opener["L"]) == {"mefor-lookup-ca"}


def test_a_named_ca_is_the_ftps_hops_only_anchor(tmp_path: Path) -> None:
    """Through the policy branch the runner takes: ``_dest_config`` always supplies a policy."""
    ca = _ca_pem(tmp_path, "mefor-ftps-ca")
    spec = Ftp(host="ftp.internal.example.org", tls=True, remote_dir="/in", tls_ca_file=ca)
    ctx = _ftps_ssl_context(dict(spec.settings), trust_anchor_policy=_pinned(tmp_path))
    assert _ca_subjects(ctx) == {"mefor-ftps-ca"}
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_an_inbound_ftps_poller_reads_the_ca_without_a_policy(tmp_path: Path) -> None:
    """The inbound FTPS source builds its client with no ``[tls]`` policy, so the CA reaches it
    through the ``create_default_context(cafile=...)`` branch. That branch must still pin."""
    ca = _ca_pem(tmp_path, "mefor-ftps-inbound-ca")
    spec = Ftp(host="ftp.internal.example.org", tls=True, remote_dir="/in", tls_ca_file=ca)
    assert _ca_subjects(_ftps_ssl_context(dict(spec.settings))) == {"mefor-ftps-inbound-ca"}


def test_the_token_hop_reads_the_factory_ca_even_with_verify_tls_off(tmp_path: Path) -> None:
    """The doc says a token hop reads the CA regardless of ``verify_tls``. Pin that, through a
    factory-built spec, because it is why a verify-off REST/FHIR/SOAP CA is not refused as unread."""
    ca = _ca_pem(tmp_path, "mefor-token-ca")
    spec = FHIR(url="https://fhir.internal.example.org/fhir", verify_tls=False, tls_ca_file=ca)
    provider = bearer_provider_from_settings({**spec.settings, **_smart_settings()})
    assert provider is not None
    ctx = rest.opener_tls_context(_token_opener(provider), connector="test")
    assert ctx is not None
    assert _ca_subjects(ctx) == {"mefor-token-ca"}


def test_the_key_loads_from_connections_toml(tmp_path: Path) -> None:
    """``connections.toml`` inherits the key, because the factory is its schema."""
    (tmp_path / "logic.py").write_text("", encoding="utf-8")
    (tmp_path / "connections.toml").write_text(
        textwrap.dedent(
            """
            [[outbound]]
            name = "OB_REST"
            transport = "rest"
              [outbound.settings]
              url = "https://partner.example.org/api"
              tls_ca_file = "/org/partner-ca.pem"

            [[outbound]]
            name = "OB_FTPS"
            transport = "ftp"
              [outbound.settings]
              host = "ftp.internal.example.org"
              tls = true
              remote_dir = "/in"
              tls_ca_file = "/org/partner-ca.pem"
            """
        ),
        encoding="utf-8",
    )
    reg = load_config(tmp_path)
    assert reg.outbound["OB_REST"].spec.settings["tls_ca_file"] == "/org/partner-ca.pem"
    assert reg.outbound["OB_FTPS"].spec.settings["tls_ca_file"] == "/org/partner-ca.pem"


# --- unnamed: nothing changed ----------------------------------------------------------------------


@pytest.mark.parametrize("factory", sorted(_DESTINATION_FACTORIES))
def test_without_a_ca_the_destination_keeps_the_shared_opener(factory: str) -> None:
    """THE negative control. A factory-built spec that names no CA, and now carries an explicit
    ``tls_ca_file: None``, must still be handed the shared opener object -- not an equivalent one."""
    opener = _destination_opener(_DESTINATION_FACTORIES[factory](), TrustAnchorPolicy())
    assert opener is rest._NO_REDIRECT_OPENER


def test_without_a_ca_the_lookup_keeps_the_shared_opener() -> None:
    spec = FhirLookup("L", url="https://fhir.internal.example.org/fhir")
    ex = FhirLookupExecutor(
        {"L": _fhir_lookup_settings(spec, {}, None)},
        trust_anchor_policy=TrustAnchorPolicy(),
        egress=EgressSettings(deny_by_default=False),
    )
    assert ex._opener["L"] is rest._NO_REDIRECT_OPENER


def test_without_a_ca_ftps_builds_what_an_absent_key_builds(tmp_path: Path) -> None:
    """The FTPS negative control. FTPS has no shared opener, so compare the explicit ``None`` the
    factory now writes against a settings dict with no key at all. A pinned instance CA makes the
    expected trust store non-empty and the same on every OS, so an empty store cannot pass."""
    policy = _pinned(tmp_path)
    settings = dict(Ftp(host="ftp.internal.example.org", tls=True, remote_dir="/in").settings)
    absent = {k: v for k, v in settings.items() if k != "tls_ca_file"}
    with_none = _ftps_ssl_context(settings, trust_anchor_policy=policy)
    without = _ftps_ssl_context(absent, trust_anchor_policy=policy)
    assert _ca_subjects(with_none) == _ca_subjects(without) == {"mefor-instance-ca"}
