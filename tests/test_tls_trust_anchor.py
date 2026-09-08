# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pinned internal-CA trust anchor (#190, ADR 0093).

Covers the pure resolver precedence (connection-ca wins; system/augment/pinned; pinned excludes the
OS default roots; the loopback exemption), the byte-identical default (no ``[tls]`` block), and the
composition with the connectors' existing fail-closed no-CA / ``tls_verify=false`` refusals — the
internal CA SUPPLIES a trust anchor to a still-verifying context, it never disables verification.
"""

from __future__ import annotations

import datetime
import importlib
import ssl
import sys
import types
import urllib.request
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import ServiceSettings, TlsSettings, load_settings
from messagefoundry.config.tls_policy import (
    TrustAnchor,
    TrustAnchorPolicy,
    build_anchored_https_handler,
    build_verifying_client_context,
    requests_verify_from_anchor,
    resolve_trust_anchor,
)
from messagefoundry.transports import rest, soap
from messagefoundry.transports.fhir import FhirLookupExecutor
from messagefoundry.transports.mllp import _mllp_ssl_context


def _ca_pem(tmp_path: Path, cn: str = "mefor-internal-ca") -> str:
    """A self-signed CA cert PEM (CA:TRUE) usable as a trust anchor."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    p = tmp_path / f"{cn}.pem"
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(p)


# --- pure resolver precedence -------------------------------------------------


def test_connection_ca_wins_verbatim_over_every_mode() -> None:
    # A connection that names its own tls_ca_file is authoritative regardless of the instance policy.
    for mode in ("system", "augment", "pinned"):
        policy = TrustAnchorPolicy(internal_ca_file="/org/internal-ca.pem", mode=mode)  # type: ignore[arg-type]
        anchor = resolve_trust_anchor(
            connection_ca_file="/conn/own-ca.pem", host="pacs.internal", policy=policy
        )
        assert anchor == TrustAnchor(cafile="/conn/own-ca.pem", load_system_roots=False)


def test_system_mode_is_os_trust_store_only() -> None:
    anchor = resolve_trust_anchor(
        connection_ca_file=None,
        host="pacs.internal",
        policy=TrustAnchorPolicy(internal_ca_file="/org/internal-ca.pem", mode="system"),
    )
    assert anchor == TrustAnchor(cafile=None, load_system_roots=True)


def test_augment_mode_is_os_roots_plus_internal_ca() -> None:
    anchor = resolve_trust_anchor(
        connection_ca_file=None,
        host="pacs.internal",
        policy=TrustAnchorPolicy(internal_ca_file="/org/internal-ca.pem", mode="augment"),
    )
    assert anchor == TrustAnchor(cafile="/org/internal-ca.pem", load_system_roots=True)


def test_pinned_mode_is_internal_ca_only_no_default_roots() -> None:
    anchor = resolve_trust_anchor(
        connection_ca_file=None,
        host="pacs.internal",
        policy=TrustAnchorPolicy(internal_ca_file="/org/internal-ca.pem", mode="pinned"),
    )
    assert anchor == TrustAnchor(cafile="/org/internal-ca.pem", load_system_roots=False)


def test_unset_internal_ca_falls_back_to_system_even_in_pinned() -> None:
    # No internal CA configured → nothing to pin → the OS trust store (byte-identical).
    anchor = resolve_trust_anchor(
        connection_ca_file=None,
        host="pacs.internal",
        policy=TrustAnchorPolicy(internal_ca_file=None, mode="pinned"),
    )
    assert anchor == TrustAnchor(cafile=None, load_system_roots=True)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "", "::1", "127.5.6.7"])
def test_loopback_hop_is_exempt(host: str) -> None:
    # An on-box hop needs no org-PKI anchor — the internal CA is for verifying internal NETWORK peers.
    anchor = resolve_trust_anchor(
        connection_ca_file=None,
        host=host,
        policy=TrustAnchorPolicy(internal_ca_file="/org/internal-ca.pem", mode="pinned"),
    )
    assert anchor == TrustAnchor(cafile=None, load_system_roots=True)


# --- build_verifying_client_context: which roots are trusted ------------------


def test_pinned_context_excludes_default_roots(tmp_path: Path) -> None:
    ca = _ca_pem(tmp_path)
    pinned = build_verifying_client_context(TrustAnchor(cafile=ca, load_system_roots=False))
    system = build_verifying_client_context(TrustAnchor(cafile=None, load_system_roots=True))
    # Pinned trusts exactly the one internal CA; the OS store carries many roots.
    assert len(pinned.get_ca_certs()) == 1
    assert len(system.get_ca_certs()) > 1
    # Verification stays ON in every mode (never CERT_NONE) — the anchor only picks roots.
    assert pinned.verify_mode == ssl.CERT_REQUIRED
    assert pinned.check_hostname is True


def test_augment_context_is_system_plus_internal(tmp_path: Path) -> None:
    ca = _ca_pem(tmp_path)
    system = build_verifying_client_context(TrustAnchor(cafile=None, load_system_roots=True))
    augment = build_verifying_client_context(TrustAnchor(cafile=ca, load_system_roots=True))
    # Augment = the OS roots plus exactly the one extra internal CA (self-signed → not already present).
    assert len(augment.get_ca_certs()) == len(system.get_ca_certs()) + 1


# --- byte-identical default (no [tls] block) ----------------------------------


def test_service_settings_default_tls_is_system_noop(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text("[api]\nport = 9000\n", encoding="utf-8")  # no [tls] section at all
    settings = load_settings(config_path=cfg, environ={})
    assert settings.tls.policy() == TrustAnchorPolicy(internal_ca_file=None, mode="system")


def test_default_destination_policy_is_system_noop() -> None:
    dest = Destination(name="OB_X", type=ConnectorType.MLLP)
    assert dest.trust_anchor_policy == TrustAnchorPolicy(internal_ca_file=None, mode="system")


def test_default_policy_context_is_byte_identical_to_no_policy(tmp_path: Path) -> None:
    # A default (system) policy resolves to exactly the historical create_default_context(cafile=ca).
    ca = _ca_pem(tmp_path)
    s = {"tls": True, "host": "db.example", "tls_verify": True, "tls_ca_file": ca}
    none_ctx = _mllp_ssl_context(s, server=False, trust_anchor_policy=None)
    sys_ctx = _mllp_ssl_context(s, server=False, trust_anchor_policy=TrustAnchorPolicy())
    assert none_ctx is not None and sys_ctx is not None
    # Connection's own CA wins under both → exactly that one anchor, no OS roots.
    assert len(none_ctx.get_ca_certs()) == 1 == len(sys_ctx.get_ca_certs())


# --- compose with the existing no-CA / verify-off refusals --------------------


def test_internal_ca_supplied_makes_the_internal_hop_verify(tmp_path: Path) -> None:
    # With no per-connection CA, a pinned internal CA supplies the trust anchor the internal hop needs.
    ca = _ca_pem(tmp_path)
    s = {"tls": True, "host": "pacs.internal", "tls_verify": True}
    ctx = _mllp_ssl_context(
        s,
        server=False,
        trust_anchor_policy=TrustAnchorPolicy(internal_ca_file=ca, mode="pinned"),
    )
    assert ctx is not None
    # Exactly the internal CA is trusted (pinned excludes the OS default roots) and verification is ON.
    assert len(ctx.get_ca_certs()) == 1
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_internal_ca_never_bypasses_the_verify_off_refusal() -> None:
    # tls_verify=false is MITM-able and refused (no escape here); supplying an internal CA must NOT
    # silence that refusal — the anchor only picks roots for a still-verifying context.
    s = {"tls": True, "host": "pacs.internal", "tls_verify": False}
    with pytest.raises(ValueError, match="tls_verify=false"):
        _mllp_ssl_context(
            s,
            server=False,
            trust_anchor_policy=TrustAnchorPolicy(internal_ca_file="/org/ca.pem", mode="pinned"),
        )


def test_verify_off_path_is_cert_none_regardless_of_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    # With the dev escape set, verify-off is permitted — and stays CERT_NONE; the internal CA is inert
    # on that path (it never turns an unverified hop into a verified one, and vice-versa).
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    s = {"tls": True, "host": "pacs.internal", "tls_verify": False}
    ctx = _mllp_ssl_context(
        s,
        server=False,
        trust_anchor_policy=TrustAnchorPolicy(internal_ca_file="/org/ca.pem", mode="pinned"),
    )
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


# --- the [tls] section loads from TOML + threads onto the outbound ------------


def test_tls_section_loads_from_toml(tmp_path: Path) -> None:
    ca = _ca_pem(tmp_path)
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(
        f'[tls]\ninternal_ca_file = "{Path(ca).as_posix()}"\ntrust_anchor_mode = "augment"\n',
        encoding="utf-8",
    )
    settings = load_settings(config_path=cfg, environ={})
    assert settings.tls.internal_ca_file == Path(ca).as_posix()
    assert settings.tls.trust_anchor_mode == "augment"
    assert settings.tls.policy() == TrustAnchorPolicy(
        internal_ca_file=Path(ca).as_posix(), mode="augment"
    )


def test_invalid_trust_anchor_mode_rejected(tmp_path: Path) -> None:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text('[tls]\ntrust_anchor_mode = "nonsense"\n', encoding="utf-8")
    with pytest.raises(ValueError):
        load_settings(config_path=cfg, environ={})


def test_settings_tls_defaults_when_omitted() -> None:
    assert ServiceSettings().tls == TlsSettings()


def test_pinned_mode_without_internal_ca_is_rejected_at_load(tmp_path: Path) -> None:
    # "pinned" excludes public CAs — with no internal_ca_file it would silently fall back to the full
    # OS trust store (fail-open). Refuse it at load rather than let the exclusion collapse.
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text('[tls]\ntrust_anchor_mode = "pinned"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="pinned.*requires.*internal_ca_file"):
        load_settings(config_path=cfg, environ={})


def test_pinned_mode_without_internal_ca_is_rejected_direct() -> None:
    with pytest.raises(ValueError, match="pinned.*requires.*internal_ca_file"):
        TlsSettings(trust_anchor_mode="pinned")


def test_pinned_mode_with_internal_ca_loads(tmp_path: Path) -> None:
    ca = _ca_pem(tmp_path)
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(
        f'[tls]\ninternal_ca_file = "{Path(ca).as_posix()}"\ntrust_anchor_mode = "pinned"\n',
        encoding="utf-8",
    )
    settings = load_settings(config_path=cfg, environ={})
    assert settings.tls.policy() == TrustAnchorPolicy(
        internal_ca_file=Path(ca).as_posix(), mode="pinned"
    )


def test_augment_mode_without_internal_ca_is_allowed() -> None:
    # augment-without-CA equals system (harmless), so it loads — only pinned needs the anchor.
    s = TlsSettings(trust_anchor_mode="augment")
    assert s.policy() == TrustAnchorPolicy(internal_ca_file=None, mode="augment")


# --- the HTTP egress family: the anchor was INEXPRESSIBLE there (#1180, ASVS 12.3.4) ---------------
#
# Measured at a2eef0f37: `resolve_trust_anchor` reached mllp / dicom / remotefile and NOTHING in
# rest.py, soap.py, fhir.py or dicomweb.py, which exposed a `verify_tls` boolean and no CA parameter
# of any kind. So an operator who set `[tls].internal_ca_file` had it honoured on some hops and
# silently ignored on every https one — REST, SOAP, FHIR, DICOMweb and the fhir_lookup read.
#
# Two halves are under test below and they pull in opposite directions, which is why both are here:
# a hop that names NO anchor must be constructed exactly as it was (identity with the shared opener,
# and a context matching urllib's own), and a hop that DOES name one must actually get it.


def _opener_context(opener: urllib.request.OpenerDirector) -> ssl.SSLContext | None:
    """The ``SSLContext`` ``opener``'s https handler will hand every connection it opens."""
    for handler in opener.handlers:
        if hasattr(handler, "https_open"):
            ctx = getattr(handler, "_context", None)
            if isinstance(ctx, ssl.SSLContext):
                return ctx
    return None


def _ca_subjects(ctx: ssl.SSLContext) -> set[str]:
    """Every CA common name loaded into ``ctx``'s trust store."""
    names: set[str] = set()
    for cert in ctx.get_ca_certs():
        for rdn in cert.get("subject", ()):
            for attr, value in rdn:
                if attr == "commonName":
                    names.add(value)
    return names


def _internal_policy(ca: str, mode: str = "pinned") -> TrustAnchorPolicy:
    return TrustAnchorPolicy(internal_ca_file=ca, mode=mode)  # type: ignore[arg-type]


def _client_cert_pair(tmp_path: Path) -> tuple[str, str]:
    """A self-signed client cert + its key, as PEM paths — a loadable mTLS identity."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-client")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "client.crt"
    key_path = tmp_path / "client.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


def _http_dest(ctype: ConnectorType, settings: dict[str, object], **over: object) -> object:
    from messagefoundry.transports.base import build_destination

    return build_destination(
        Destination(name="OB", type=ctype, settings=settings, **over)  # type: ignore[arg-type]
    )


# --- the negative: nothing configured, nothing changed ---------------------------------------------


def test_default_http_hop_still_gets_the_shared_opener_object() -> None:
    """No ``[tls]`` block, no per-connection CA → the SHARED module-level opener, by IDENTITY.

    The strongest available statement that the default did not move: not "an equivalent opener" but
    the very object every stock https destination has always been handed."""
    dest = _http_dest(
        ConnectorType.REST,
        {"url": "https://partner.example.org/api", "method": "POST"},
    )
    assert dest._opener is rest._NO_REDIRECT_OPENER  # type: ignore[attr-defined]


def test_default_http_hop_with_a_system_policy_still_gets_the_shared_opener() -> None:
    """A ``[tls]`` block in ``system`` mode (or with no internal CA) is a no-op here too.

    This is the shipped default the item describes as "the mechanism ships off" — the resolver runs,
    resolves to the OS trust store, and the hop is handed the same shared opener as before."""
    for policy in (
        TrustAnchorPolicy(),
        TrustAnchorPolicy(internal_ca_file="/org/internal-ca.pem", mode="system"),
        TrustAnchorPolicy(internal_ca_file=None, mode="augment"),
    ):
        dest = _http_dest(
            ConnectorType.REST,
            {"url": "https://partner.example.org/api", "method": "POST"},
            trust_anchor_policy=policy,
        )
        assert dest._opener is rest._NO_REDIRECT_OPENER, policy  # type: ignore[attr-defined]


def test_loopback_hop_is_exempt_on_the_http_family_too(tmp_path: Path) -> None:
    """The resolver's loopback exemption reaches these hops: an on-box hop needs no org-PKI anchor."""
    dest = _http_dest(
        ConnectorType.REST,
        {"url": "https://127.0.0.1:8443/api", "method": "POST"},
        trust_anchor_policy=_internal_policy(_ca_pem(tmp_path)),
    )
    assert dest._opener is rest._NO_REDIRECT_OPENER  # type: ignore[attr-defined]


def test_unanchored_opener_context_still_matches_urllibs_own() -> None:
    """An unanchored opener still carries urllib's OWN context, not a look-alike.

    ``build_asserted_https_handler`` documents the measurement that forced this: urllib's context adds
    ALPN and post-handshake auth that ``ssl.create_default_context()`` does not, so substituting one
    would silently change the handshake. Threading a trust anchor through these builders must not
    start doing that on the hops that named no anchor."""
    engine = _opener_context(rest._no_redirect_opener())
    unanchored = _opener_context(
        rest._no_redirect_opener(trust_anchor=TrustAnchor(cafile=None, load_system_roots=True))
    )
    stock = _opener_context(urllib.request.build_opener(rest._NoRedirectHandler))
    assert engine is not None and unanchored is not None and stock is not None
    for ctx in (engine, unanchored):
        assert ctx.post_handshake_auth == stock.post_handshake_auth
        assert ctx.verify_mode == stock.verify_mode
        assert ctx.check_hostname == stock.check_hostname
        assert ctx.minimum_version == stock.minimum_version
        assert len(ctx.get_ca_certs()) == len(stock.get_ca_certs())


# --- the positive: an anchor named is an anchor honoured -------------------------------------------


def test_anchored_https_handler_trusts_only_the_internal_ca(tmp_path: Path) -> None:
    """A pinned anchor yields a context holding EXACTLY the internal CA — no public bundle."""
    ca = _ca_pem(tmp_path, "mefor-only-anchor")
    handler = build_anchored_https_handler(
        anchor=TrustAnchor(cafile=ca, load_system_roots=False), connector="test"
    )
    ctx = handler._context
    assert _ca_subjects(ctx) == {"mefor-only-anchor"}
    # Verification is NEVER turned off by anchoring — it only chooses which roots do the verifying.
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    # and the handshake deltas urllib applies are replayed, not silently dropped.
    stock = urllib.request.HTTPSHandler()._context
    assert ctx.post_handshake_auth == stock.post_handshake_auth


def test_anchored_https_handler_augment_keeps_the_public_roots(tmp_path: Path) -> None:
    """``augment`` loads the internal CA INTO urllib's own context rather than replacing it.

    Adding a root needs no new context, so this arm rebuilds nothing and replays nothing — the only
    difference from a stock hop is one more trusted issuer."""
    ca = _ca_pem(tmp_path, "mefor-augmenting-ca")
    ctx = build_anchored_https_handler(
        anchor=TrustAnchor(cafile=ca, load_system_roots=True), connector="test"
    )._context
    stock = urllib.request.HTTPSHandler()._context
    assert "mefor-augmenting-ca" in _ca_subjects(ctx)
    assert len(ctx.get_ca_certs()) == len(stock.get_ca_certs()) + 1
    assert ctx.post_handshake_auth == stock.post_handshake_auth
    assert ctx.verify_mode == stock.verify_mode


@pytest.mark.parametrize(
    ("ctype", "settings"),
    [
        (ConnectorType.REST, {"url": "https://partner.example.org/api", "method": "POST"}),
        (ConnectorType.SOAP, {"url": "https://partner.example.org/svc", "soap_action": "Send"}),
        (ConnectorType.FHIR, {"url": "https://fhir.internal.example.org/fhir"}),
        (ConnectorType.DICOMWEB, {"url": "https://pacs.internal.example.org/dicom-web"}),
    ],
)
def test_every_http_family_destination_honours_the_internal_ca(
    ctype: ConnectorType, settings: dict[str, object], tmp_path: Path
) -> None:
    """THE expressibility assertion, over the four destinations the item names.

    Before #1180 each of these built the shared OS-trust-store opener and there was no configuration
    an operator could write to change that."""
    ca = _ca_pem(tmp_path, "mefor-org-ca")
    dest = _http_dest(ctype, settings, trust_anchor_policy=_internal_policy(ca))
    opener = dest._opener  # type: ignore[attr-defined]
    assert opener is not rest._NO_REDIRECT_OPENER
    ctx = _opener_context(opener)
    assert ctx is not None
    assert _ca_subjects(ctx) == {"mefor-org-ca"}


def test_the_fhir_lookup_executor_honours_the_internal_ca(tmp_path: Path) -> None:
    """The sanctioned live read-only lookup (ADR 0043) is the most on-point instance of the verb's
    condition in the product, and it has no ``Destination`` to carry the policy — the runner threads
    it in explicitly."""
    ca = _ca_pem(tmp_path, "mefor-lookup-ca")
    ex = FhirLookupExecutor(
        {"L": {"url": "https://fhir.internal.example.org/fhir"}},
        trust_anchor_policy=_internal_policy(ca),
    )
    ctx = _opener_context(ex._opener["L"])
    assert ctx is not None
    assert _ca_subjects(ctx) == {"mefor-lookup-ca"}


def test_the_fhir_lookup_executor_default_is_the_shared_opener() -> None:
    ex = FhirLookupExecutor({"L": {"url": "https://fhir.example.org/fhir"}})
    assert ex._opener["L"] is rest._NO_REDIRECT_OPENER


def test_soap_mutual_tls_opener_honours_the_internal_ca(tmp_path: Path) -> None:
    """mTLS is the deployment likeliest to sit behind an internal CA, and its opener builds its own
    context — so it needs the anchor threaded separately from the shared verifying path."""
    ca = _ca_pem(tmp_path, "mefor-mtls-server-ca")
    cert, key = _client_cert_pair(tmp_path)
    ctx = _opener_context(
        soap._client_cert_opener(
            cert,
            key,
            None,
            trust_anchor=TrustAnchor(cafile=ca, load_system_roots=False),
        )
    )
    assert ctx is not None
    assert _ca_subjects(ctx) == {"mefor-mtls-server-ca"}


def test_expiry_relaxed_opener_honours_the_internal_ca(tmp_path: Path) -> None:
    """Expiry tolerance and anchor narrowing are independent: relaxing the validity window must not
    quietly widen the trust store back to the OS roots."""
    ca = _ca_pem(tmp_path, "mefor-expiry-ca")
    ctx = _opener_context(
        rest._expiry_relaxed_opener(
            "partner.example.org", trust_anchor=TrustAnchor(cafile=ca, load_system_roots=False)
        )
    )
    assert ctx is not None
    assert _ca_subjects(ctx) == {"mefor-expiry-ca"}
    assert ctx.verify_mode == ssl.CERT_REQUIRED


# --- the two hvac clients: no CA argument reached them at all --------------------------------------


def test_requests_verify_maps_the_three_anchor_shapes() -> None:
    """``requests`` takes ONE bundle path, so two shapes map exactly and the third must be refused."""
    assert requests_verify_from_anchor(TrustAnchor(None, True), cell="c") is None
    assert requests_verify_from_anchor(TrustAnchor("/org/ca.pem", False), cell="c") == "/org/ca.pem"
    with pytest.raises(ValueError, match="augment"):
        # Silently passing the path would NARROW a hop the operator asked to widen; silently dropping
        # it would ignore the anchor. Refusing is the only reading that is not a lie.
        requests_verify_from_anchor(TrustAnchor("/org/ca.pem", True), cell="c")


@pytest.mark.parametrize(
    ("module", "env_var"),
    [
        ("messagefoundry.config.secretprovider_vault", "MEFOR_SECRETS_VAULT_CA_FILE"),
        ("messagefoundry.store.keyprovider_vault", "MEFOR_STORE_VAULT_CA_FILE"),
    ],
)
def test_hvac_clients_take_a_ca_only_when_one_is_configured(
    module: str, env_var: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both hvac sites — including the one that hands out the store's data-encryption key.

    Measured before this change: each passed exactly ``url``/``token``/``allow_redirects`` and no CA
    argument of any kind, so an internal-CA Vault could not be reached at all (``requests`` defaults
    to the PUBLIC certifi bundle, so that hop fails closed rather than trusting broadly)."""
    calls: list[dict[str, object]] = []

    class _Client:
        def __init__(self, **kwargs: object) -> None:
            calls.append(dict(kwargs))

    fake = types.ModuleType("hvac")
    fake.Client = _Client  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "hvac", fake)
    mod = importlib.import_module(module)

    monkeypatch.delenv(env_var, raising=False)
    mod._build_client("https://vault.internal:8200", "s.token")
    assert "verify" not in calls[-1], "an unconfigured hop must be constructed exactly as before"
    assert set(calls[-1]) == {"url", "token", "allow_redirects"}

    ca = _ca_pem(tmp_path, "mefor-vault-ca")
    monkeypatch.setenv(env_var, ca)
    mod._build_client("https://vault.internal:8200", "s.token")
    assert calls[-1]["verify"] == ca


@pytest.mark.parametrize(
    ("module", "env_var"),
    [
        ("messagefoundry.config.secretprovider_vault", "MEFOR_SECRETS_VAULT_CA_FILE"),
        ("messagefoundry.store.keyprovider_vault", "MEFOR_STORE_VAULT_CA_FILE"),
    ],
)
def test_hvac_ca_path_that_is_not_a_file_fails_closed(
    module: str, env_var: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A typo'd anchor must name itself, not surface as an opaque failure on the first Vault call."""
    mod = importlib.import_module(module)
    monkeypatch.setenv(env_var, str(tmp_path / "absent.pem"))
    with pytest.raises(Exception, match=env_var):
        mod._vault_ca_kwargs("https://vault.internal:8200")
