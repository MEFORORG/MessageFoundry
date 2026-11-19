# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""With an ECH sidecar, a CRL on the engine's opener does not relax the token hop's revocation guard.

Vault BACKLOG #2169. The SMART and OAuth2 token hops share one guard call, in
``_TokenEndpointProvider._open_token_hop``. It read the TLS context of the provider's opener, so a
``[tls].crl_file`` covering the token host relaxed the refusal. That is right when the engine dials
the token host. With ``ech_sidecar`` set it is not: the token POST is re-addressed to the loopback
sidecar, and the sidecar makes its own TLS connection to the token host. The engine's context only
ever meets the sidecar, so a production hop would have crossed with no revocation check behind it.

The guard is now handed no opener on that arm. Only the per-connection attestation crosses it.

Each provider gets the refusal and two controls. Without ECH the same CRL still relaxes the hop, so
the refusal is the ECH arm and not a CRL that failed to load. With ECH and the attestation the hop
builds, so the refusal is the guard and not a rejected sidecar setting.
"""

from __future__ import annotations

import urllib.request
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import (
    TLS_REVOCATION_ATTESTED_ENV,
    HopPosture,
    InsecureHopRefused,
    TrustAnchorPolicy,
    active_hop_posture,
    context_checks_revocation,
)
from messagefoundry.config.wiring import Rest
from messagefoundry.transports import build_destination, rest, smart
from messagefoundry.transports.http_auth import oauth2_cc_provider_from_settings
from messagefoundry.transports.rest import (
    ECH_HOP_WAYS_ACROSS,
    ProxyConfig,
    opener_tls_context,
    proxy_config_from_settings,
    refuse_unrevoked_verified_hop,
)
from messagefoundry.transports.smart import token_provider_from_settings
from tests._crl_pki import empty_crl, throwaway_ca

PROD_PHI = HopPosture(enforcing=True)

REMOTE = "10.0.0.5"  # a non-loopback host; nothing here dials it
TOKEN_URL = f"https://{REMOTE}/token"
SIDECAR = "http://127.0.0.1:8123"

_PROVIDERS = ["SMART", "OAuth2"]


@pytest.fixture(autouse=True)
def _no_blanket_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The blanket attestation and the insecure-TLS escape start unset, so neither masks a result."""
    monkeypatch.delenv(TLS_REVOCATION_ATTESTED_ENV, raising=False)
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)


@pytest.fixture(scope="module")
def bare_crl(tmp_path_factory: pytest.TempPathFactory) -> str:
    """A bare CRL from a throwaway CA: the shape a hop on the system trust store accepts. Synthetic."""
    crl = empty_crl(*throwaway_ca("mefor-2169-ca"))
    path = tmp_path_factory.mktemp("crl2169") / "crl_only.pem"
    path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    return str(path)


@pytest.fixture(scope="module")
def settings_for() -> dict[str, dict[str, object]]:
    """Each provider's settings for the one remote token host. The SMART key is synthetic, and is EC
    because nothing here verifies a signature and EC keygen is cheap."""
    smart_key = (
        ec.generate_private_key(ec.SECP384R1())
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )
    return {
        "SMART": {
            "smart_token_url": TOKEN_URL,
            "smart_client_id": "cid",
            "smart_private_key": smart_key,
            "smart_algorithm": "ES384",
        },
        "OAuth2": {
            "oauth2_token_url": TOKEN_URL,
            "oauth2_client_id": "cid",
            "oauth2_client_secret": "synthetic-secret",
        },
    }


_FACTORY: dict[str, Callable[..., Any]] = {
    "SMART": token_provider_from_settings,
    "OAuth2": oauth2_cc_provider_from_settings,
}


def _provider(
    name: str,
    settings: dict[str, object],
    *,
    crl: str | None,
    ech: bool,
    attested: bool = False,
) -> Any:
    """Build one token provider the way a destination does: resolved settings, the instance
    ``[tls]`` policy, and the connection's ECH sidecar when it has one."""
    if attested:
        settings = {
            **settings,
            "tls_revocation_attested": True,
            "tls_revocation_attested_reason": "revocation-checking PKI at the partner edge",
        }
    provider = _FACTORY[name](
        settings,
        ech_sidecar=SIDECAR if ech else None,
        trust_anchor_policy=TrustAnchorPolicy(crl_file=crl),
    )
    assert provider is not None
    return provider


def _checks_a_crl(provider: Any) -> bool:
    """Whether the opener this provider posts through carries ``VERIFY_CRL_CHECK_LEAF``."""
    return context_checks_revocation(opener_tls_context(provider._opener, connector="probe"))


@pytest.mark.parametrize("name", _PROVIDERS)
def test_an_ech_sidecar_and_a_crl_still_refuse_the_token_hop(
    name: str, settings_for: dict[str, dict[str, object]], bare_crl: str
) -> None:
    settings = settings_for[name]
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation") as exc:
        _provider(name, settings, crl=bare_crl, ech=True)
    assert f"{name} token endpoint" in str(exc.value)
    assert "synthetic-secret" not in str(exc.value)
    # CONTROL 1: without the sidecar the engine dials the token host itself, so the same CRL on the
    # same host still relaxes the hop.
    with active_hop_posture(PROD_PHI):
        direct = _provider(name, settings, crl=bare_crl, ech=False)
    assert _checks_a_crl(direct) is True
    # CONTROL 2: the sidecar setting is valid, and the per-connection attestation still crosses.
    with active_hop_posture(PROD_PHI):
        _provider(name, settings, crl=bare_crl, ech=True, attested=True)


@pytest.mark.parametrize("name", _PROVIDERS)
def test_the_ech_token_hop_refusal_offers_only_a_lever_that_can_cross_it(
    name: str, settings_for: dict[str, dict[str, object]], bare_crl: str
) -> None:
    """The default refusal offers ``[tls].crl_file``, which cannot cross an ECH hop, so its refusal
    names the attestation alone, in fixed text."""
    settings = settings_for[name]
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation") as exc:
        _provider(name, settings, crl=bare_crl, ech=True)
    text = str(exc.value)
    assert ECH_HOP_WAYS_ACROSS in text
    assert "tls_revocation_attested=true" in text and "tls_revocation_attested_reason" in text
    assert "[tls].crl_file" not in text
    assert "egress proxy" not in text
    # CONTROL: without the sidecar, and with no CRL, the refusal is the default text, unchanged.
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation") as exc:
        _provider(name, settings, crl=None, ech=False)
    default = str(exc.value)
    assert ECH_HOP_WAYS_ACROSS not in default
    assert "Configure [tls].crl_file so the engine checks a CRL on this hop" in default
    # BACKLOG #2987: the default no longer offers an egress proxy, a lever no call site can set.
    assert "egress proxy" not in default
    assert "tls_revocation_attested=true" in default


@pytest.mark.parametrize("name", _PROVIDERS)
def test_the_ech_arm_also_refuses_with_no_crl(
    name: str, settings_for: dict[str, dict[str, object]]
) -> None:
    """The CRL changes nothing on the ECH arm: the hop was refused with none, and it still is."""
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation"):
        _provider(name, settings_for[name], crl=None, ech=True)


@pytest.mark.parametrize("name", _PROVIDERS)
@pytest.mark.parametrize("ech", [True, False])
def test_which_opener_the_token_hop_guard_is_handed(
    name: str,
    ech: bool,
    settings_for: dict[str, dict[str, object]],
    bare_crl: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ARGUMENT, beside the outcome above. No opener with a sidecar. Without one, the opener the
    provider keeps and posts through, by identity."""
    seen: list[object] = []

    def spy(*args: Any, **kwargs: Any) -> None:
        seen.append(kwargs.get("opener"))
        refuse_unrevoked_verified_hop(*args, **kwargs)

    monkeypatch.setattr(smart, "refuse_unrevoked_verified_hop", spy)
    provider = _provider(name, settings_for[name], crl=bare_crl, ech=ech)  # unstamped: builds
    assert len(seen) == 1
    if ech:
        assert seen[0] is None
        # Vault BACKLOG #2977 item 5: the CRL no longer reaches this opener either. It is the plain
        # one the REST destination's ECH hop uses, anchored for no host, since it only ever meets
        # the sidecar. Before, it carried the token host's anchor and CRL.
        assert _checks_a_crl(provider) is False
    else:
        assert seen[0] is provider._opener
        # CONTROL: without the sidecar the same CRL does reach the opener the provider keeps.
        assert _checks_a_crl(provider) is True


@pytest.mark.parametrize("name", _PROVIDERS)
def test_the_ech_token_hop_opener_carries_no_proxy_and_no_token_host_anchor(
    name: str, settings_for: dict[str, dict[str, object]], ca_pem: str
) -> None:
    """Vault BACKLOG #2977 item 5. With an ECH sidecar the token POST goes to the loopback sidecar.
    The opener kept the token host's anchor, so with an https sidecar it would have handshaken with
    the sidecar under the token host's CA. A per-connection ``tls_ca_file``, and a web proxy handed
    to a provider built directly, now reach neither the opener nor the request. CONTROL: without
    the sidecar both do."""
    settings = {**settings_for[name], "tls_ca_file": ca_pem}
    # A Basic-credentialed proxy, so an empty _proxy_auth on the ECH arm is a credential that did
    # not reach the request, not one there never was (review round 3, F3).
    with_ech = _FACTORY[name](settings, ech_sidecar=SIDECAR, proxy=_proxy(credentialed=True))
    direct = _FACTORY[name](settings, proxy=_proxy(credentialed=True))
    assert _CA_NAME not in _anchor_names(with_ech._opener)
    assert _proxy_map(with_ech._opener) == {}
    assert with_ech._proxy_auth == {}
    assert _anchor_names(direct._opener) == {_CA_NAME}
    assert _proxy_map(direct._opener) == {"http": _PROXY_URL, "https": _PROXY_URL}
    assert direct._proxy_auth["Proxy-Authorization"].startswith("Basic ")


# --- vault BACKLOG #2977 item 12: the token hop's opener shapes ----------------------------------
#
# The destination arms build a forward proxy and a per-connection CA file
# (tests/test_http_destination_revocation_guard_reads_its_opener.py). These are the token hop's:
# its guard is handed the opener the provider keeps and posts through, whatever its shape, and a
# CRL that reaches that opener relaxes the refusal.

_PROXY_URL = "http://10.0.0.9:3128"
_CA_NAME = "mefor-2977-token-ca"


@pytest.fixture(scope="module")
def ca_pem(tmp_path_factory: pytest.TempPathFactory) -> str:
    """A throwaway CA certificate for a per-connection ``tls_ca_file``. Synthetic."""
    _, ca = throwaway_ca(_CA_NAME)
    path = tmp_path_factory.mktemp("ca2977") / "ca.pem"
    path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    return str(path)


def _proxy(*, credentialed: bool = False) -> ProxyConfig:
    settings: dict[str, object] = {"proxy_url": _PROXY_URL}
    if credentialed:
        settings |= {"proxy_user": "pu", "proxy_password": "pw"}
    proxy = proxy_config_from_settings(
        settings,
        dest_scheme="https",
        cleartext_accepted=credentialed,
        cleartext_reason="synthetic test proxy" if credentialed else None,
        connection=None,
    )
    assert proxy is not None
    return proxy


def _anchor_names(opener: Any) -> set[str]:
    """The common names of the CA certificates loaded into the opener's TLS context. A context on
    the system store may list that store's roots, so a test reads one name, never an empty set."""
    context = opener_tls_context(opener, connector="probe")
    assert context is not None
    names: set[str] = set()
    for cert in context.get_ca_certs():
        subject: Any = cert.get("subject", ())
        for rdn in subject:
            names.update(value for key, value in rdn if key == "commonName")
    return names


def _proxy_map(opener: Any) -> dict[str, str]:
    for handler in opener.handlers:
        if isinstance(handler, urllib.request.ProxyHandler):
            return dict(getattr(handler, "proxies"))  # noqa: B009 -- untyped in typeshed
    return {}


_SHAPES = ["proxy", "ca_file"]


def _shaped(
    name: str,
    shape: str,
    settings_for: dict[str, dict[str, object]],
    ca_pem: str,
    *,
    crl: str | None,
) -> Any:
    settings = dict(settings_for[name])
    if shape == "ca_file":
        settings["tls_ca_file"] = ca_pem
    return _FACTORY[name](
        settings,
        proxy=_proxy() if shape == "proxy" else None,
        trust_anchor_policy=TrustAnchorPolicy(crl_file=crl),
    )


@pytest.mark.parametrize("name", _PROVIDERS)
@pytest.mark.parametrize("shape", _SHAPES)
@pytest.mark.parametrize("with_crl", [True, False])
def test_the_token_hop_guard_is_handed_the_opener_of_each_shape(
    name: str,
    shape: str,
    with_crl: bool,
    settings_for: dict[str, dict[str, object]],
    ca_pem: str,
    bare_crl: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[object] = []

    def spy(*args: Any, **kwargs: Any) -> None:
        seen.append(kwargs.get("opener"))
        refuse_unrevoked_verified_hop(*args, **kwargs)

    monkeypatch.setattr(smart, "refuse_unrevoked_verified_hop", spy)
    # Unstamped, so it builds.
    provider = _shaped(name, shape, settings_for, ca_pem, crl=bare_crl if with_crl else None)
    assert seen == [provider._opener]
    # CONTROL: the shape built the provider its own opener, so the identity is not the shared one.
    assert provider._opener is not rest._shared_no_redirect_opener()
    if shape == "proxy":
        assert _proxy_map(provider._opener) == {"http": _PROXY_URL, "https": _PROXY_URL}
    else:
        assert _anchor_names(provider._opener) == {_CA_NAME}


@pytest.mark.parametrize("name", _PROVIDERS)
@pytest.mark.parametrize("shape", _SHAPES)
def test_a_crl_on_a_shaped_token_hop_relaxes_the_refusal(
    name: str,
    shape: str,
    settings_for: dict[str, dict[str, object]],
    ca_pem: str,
    bare_crl: str,
) -> None:
    with active_hop_posture(PROD_PHI):
        provider = _shaped(name, shape, settings_for, ca_pem, crl=bare_crl)
    assert _checks_a_crl(provider) is True
    # CONTROL: the same shape with no CRL is still refused, and names the token hop.
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation") as exc:
        _shaped(name, shape, settings_for, ca_pem, crl=None)
    assert f"{name} token endpoint" in str(exc.value)


def test_a_rest_destination_passes_its_sidecar_to_the_token_hop_guard(
    settings_for: dict[str, dict[str, object]], bare_crl: str
) -> None:
    """The WIRING, end to end. A REST destination with an ECH sidecar hands that sidecar to its
    bearer provider, so the token hop is refused, and it is refused first because the provider is
    built above the destination's own guard. Before #2169 the CRL let the token hop through and the
    refusal named the REST destination instead."""
    cfg = Destination(
        name="OB",
        type=ConnectorType.REST,
        settings={
            **Rest(url=f"https://{REMOTE}/x").settings,
            **settings_for["OAuth2"],
            "ech_egress": True,
            "ech_sidecar": SIDECAR,
        },
        trust_anchor_policy=TrustAnchorPolicy(crl_file=bare_crl),
    )
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation") as exc:
        build_destination(
            cfg,
            egress=EgressSettings(deny_by_default=False, allowed_ech_sidecar=["127.0.0.1:8123"]),
        )
    assert "OAuth2 token endpoint" in str(exc.value)
    assert "REST destination" not in str(exc.value)
