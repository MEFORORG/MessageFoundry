# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``[egress]`` destination allowlist matcher (WP-11c; ASVS 13.2.4/13.2.5/14.2.3).

Every check that decides whether the engine may dial a host lives here, beside the connector build
seam that runs it: :func:`~messagefoundry.transports.base.build_destination` and
:func:`~messagefoundry.transports.base.build_source` take a required ``egress`` policy and refuse a
destination this module refuses, and so do both live-lookup executors (vault BACKLOG #2605). It sits
in ``transports/`` rather than ``pipeline/`` so the build seam can call it: ``transports/`` must not
import ``pipeline/``.

This is a load-time check on the configured host string. It does not see the address a connection
finally reaches, and it does not see a native driver that dials on its own.
"""

from __future__ import annotations

import logging
import urllib.parse
from collections.abc import Mapping
from pathlib import Path
from typing import Any, NoReturn

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import BLOCK_UNLISTED_OUTBOUND_IN_FORCE, EgressSettings
from messagefoundry.config.wiring import WiringError
from messagefoundry.secretscrub import credential_query_params
from messagefoundry.transports.email import envelope_address_problem, envelope_recipients
from messagefoundry.transports.rest import PROXY_DEFAULT, refuse_url_credentials

log = logging.getLogger(__name__)


#: The connector types delivered through the stdlib HTTP opener family. They share the
#: ``[egress].allowed_http`` destination arm AND read the ADR 0126 forward-proxy settings, so both the
#: destination gate and :func:`_check_forward_proxy_egress` key off this one tuple.
_HTTP_FAMILY_DEST_TYPES: tuple[ConnectorType, ...] = (
    ConnectorType.REST,
    ConnectorType.SOAP,
    ConnectorType.FHIR,
    ConnectorType.DICOMWEB,
)


def _allowlist_for(conn_type: ConnectorType, egress: EgressSettings) -> list[str]:
    """The ``[egress]`` allowlist that governs a connector type (X12 shares TCP's; REST/SOAP/FHIR share
    the HTTP list). Returns ``[]`` for a type with no egress list — which under ``deny_by_default`` means
    'nothing is configured to permit it', so the destination is refused."""
    if conn_type is ConnectorType.MLLP:
        return egress.allowed_mllp
    if conn_type in (ConnectorType.TCP, ConnectorType.X12, ConnectorType.DIMSE):
        return egress.allowed_tcp  # DIMSE is a raw socket (the Phase-2 C-STORE SCU dials it out)
    if conn_type is ConnectorType.FILE:
        return egress.allowed_file_dirs
    if conn_type in _HTTP_FAMILY_DEST_TYPES:
        return egress.allowed_http  # DICOMWEB is STOW-RS over HTTP (gated like REST/SOAP/FHIR)
    if conn_type is ConnectorType.DATABASE:
        return egress.allowed_db
    if conn_type is ConnectorType.REMOTEFILE:
        return egress.allowed_remote
    if conn_type is ConnectorType.EMAIL:
        return egress.allowed_smtp  # SMTP destination (ADR 0029)
    if conn_type is ConnectorType.DIRECT:
        return egress.allowed_direct  # Direct S/MIME-over-SMTP HISP relay (ADR 0085)
    return []


def check_source_allowed(source: Source, name: str, egress: EgressSettings) -> None:
    """Fail-closed connect-allowlist for an inbound connector that **dials out** to a server to receive
    (today: the DATABASE source, which polls a SQL host). Reuses ``[egress].allowed_db``: although the
    DB source pulls data *in* rather than exfiltrating it, it still opens an outbound connection to an
    operator-named host, so the same allowlist guards against pointing the engine at an arbitrary
    server. Opt-in (an empty list = unrestricted), matching destinations; checked at load/reload/start.

    A TCP/MLLP/File *source* is a local **listener** (it binds ``[inbound].bind_host`` and waits for
    peers, never dialing out), so there is nothing to connect-gate here — ``[egress].allowed_tcp``
    governs only the TCP *destination* (see :func:`check_egress_allowed`).

    Under ``[egress].deny_by_default`` a DATABASE/REMOTEFILE source whose allowlist is empty is refused
    outright; a listener source (TCP/MLLP/File) never dials out, so it is unaffected."""
    if egress.deny_by_default:
        if source.type is ConnectorType.DATABASE and not egress.allowed_db:
            raise WiringError(
                f"inbound {name!r}: {BLOCK_UNLISTED_OUTBOUND_IN_FORCE} and "
                "[egress].allowed_db is empty — list the DATABASE server to permit it"
            )
        if source.type is ConnectorType.REMOTEFILE and not egress.allowed_remote:
            raise WiringError(
                f"inbound {name!r}: {BLOCK_UNLISTED_OUTBOUND_IN_FORCE} and "
                "[egress].allowed_remote is empty — list the REMOTEFILE host to permit it"
            )
    if source.type is ConnectorType.DATABASE and egress.allowed_db:
        host = str(source.settings.get("server", ""))
        port = source.settings.get("port", 1433)
        if not host_port_allowed(host, port, egress.allowed_db):  # same host[:port] matching
            log.warning(
                "connect denied: inbound %r DATABASE server %r not in [egress].allowed_db",
                name,
                host,
            )
            raise WiringError(
                f"inbound {name!r}: DATABASE server {host!r} is not in the "
                "[egress].allowed_db allowlist"
            )
    elif source.type is ConnectorType.REMOTEFILE and egress.allowed_remote:
        host = str(source.settings.get("host", ""))
        port = source.settings.get("port")
        if not host_port_allowed(host, port, egress.allowed_remote):  # same host[:port] matching
            log.warning(
                "connect denied: inbound %r REMOTEFILE host %r not in [egress].allowed_remote",
                name,
                host,
            )
            raise WiringError(
                f"inbound {name!r}: REMOTEFILE host {host!r} is not in the "
                "[egress].allowed_remote allowlist"
            )


def check_lookup_allowed(
    name: str,
    settings: Mapping[str, Any],
    egress: EgressSettings,
    *,
    label: str = "DatabaseLookup",
) -> None:
    """Fail-closed connect-allowlist for a ``DatabaseLookup`` (it dials out to a SQL host for a live,
    read-only ``db_lookup``). Reuses ``[egress].allowed_db`` (opt-in; an empty list = unrestricted), like
    the DATABASE source — checked at load/reload/start so the engine is never pointed at a non-allowlisted
    server. ``settings`` are the already-``env()``-resolved connection settings. Under
    ``[egress].deny_by_default`` an empty ``allowed_db`` refuses the lookup outright. ``label`` names
    the kind of dial-out in a refusal: a DATABASE reference source shares this rule."""
    if egress.deny_by_default and not egress.allowed_db:
        raise WiringError(
            f"{label} {name!r}: {BLOCK_UNLISTED_OUTBOUND_IN_FORCE} and "
            "[egress].allowed_db is empty — list the server to permit it"
        )
    if egress.allowed_db:
        host = str(settings.get("server", ""))
        port = settings.get("port", 1433)
        if not host_port_allowed(host, port, egress.allowed_db):  # same host[:port] matching
            log.warning(
                "connect denied: %s %r server %r not in [egress].allowed_db", label, name, host
            )
            raise WiringError(
                f"{label} {name!r}: server {host!r} is not in the [egress].allowed_db allowlist"
            )


# Every settings key naming a SECOND egress host that the HTTP family POSTs **credentials** to — a
# host distinct from the data ``url`` the caller's own gate already checks — AND that is itself a PHI
# DESTINATION-class host. Each one rides the same ``[egress].allowed_http`` allowlist; an ungated one
# would be a fail-open credential-exfiltration hole, the allowlist gating the data host while the
# credential leaves for anywhere.
#
# ADD A KEY HERE when a new credential-bearing endpoint setting is introduced. That is the whole
# maintenance contract — both call sites iterate this table, so a new key is gated on both arms at
# once and cannot repeat the DELTA-04 drift (one arm gated, the other not).
#
# ``proxy_url`` IS credential-bearing and is DELIBERATELY NOT IN THIS TABLE (BACKLOG #1659). ADR 0126
# rules the proxy host out of this gate's scope in terms: "The forward proxy is an operator-chosen
# transport intermediary, not a PHI destination; gating it against ``allowed_http`` would be wrong
# (one corporate proxy fronts many hosts, and it would have to be co-listed with every destination)."
# It is gated instead by its own ``[egress].allowed_proxy`` list — see
# :func:`_check_forward_proxy_egress`, called from BOTH arms beside this table's helper. Adding
# ``proxy_url`` here would re-create the co-listing the ADR rejected; do not.
_CREDENTIAL_EGRESS_URL_KEYS: tuple[tuple[str, str], ...] = (
    # ADR 0024 — the connector POSTs a signed ``client_assertion`` here.
    ("smart_token_url", "SMART token endpoint"),
    # ADR 0126 — the client-credentials grant POSTs ``client_id`` + ``client_secret`` here, either as
    # form fields or as a Basic header (``transports/http_auth.py`` ``_fetch_token``). Ungated until
    # 2026-07-31: the scheme was constrained to http(s) and nothing else, so a crafted
    # ``oauth2_token_url`` exfiltrated the client credentials to any host while ``[egress]
    # .allowed_http`` gated only the data URL. Found re-scoring ASVS 14.2.3.
    ("oauth2_token_url", "OAuth2 token endpoint"),
)


def _check_credential_token_url_egress(
    label: str, settings: Mapping[str, Any], allowed_http: list[str]
) -> None:
    """Gate every credential-bearing token endpoint on an HTTP-family connection against
    ``[egress].allowed_http`` — see :data:`_CREDENTIAL_EGRESS_URL_KEYS` for the keys and why each one
    carries a secret. A crafted token URL pointing at an un-allowlisted host would exfiltrate the
    credential (a fail-open hole), so this is checked at config load/reload/start alongside the data
    host. Shared by the FHIR/REST **outbound** and the **FhirLookup** read arm so the two never drift
    out of lockstep — DELTA-04 was exactly that drift (the read arm gated only ``url``). An unset key
    is a no-op. Call only when ``allowed_http`` is non-empty (matching the host gate's own guard)."""
    for key, what in _CREDENTIAL_EGRESS_URL_KEYS:
        token_url = str(settings.get(key, "") or "")
        if not token_url:
            continue
        refuse_url_credentials(
            token_url,
            f"{label} {key}",
            use="the connection's client credential settings",
            error=WiringError,
        )
        if not _http_egress_allowed(token_url, allowed_http):
            host = _egress_host_label(token_url)
            log.warning(
                "egress denied: %s %s host %r not in [egress].allowed_http",
                label,
                what,
                host,
            )
            raise WiringError(
                f"{label}: {what} host {host!r} is not in the [egress].allowed_http allowlist"
            )


def _check_forward_proxy_egress(
    label: str, settings: Mapping[str, Any], allowed_proxy: list[str]
) -> None:
    """Gate the resolved forward/egress web proxy host (ADR 0126) against ``[egress].allowed_proxy``.

    The proxy is a THIRD egress host on an http-family connection — distinct from the data ``url`` and
    from the token endpoints :data:`_CREDENTIAL_EGRESS_URL_KEYS` covers — and it is credential-bearing:
    under the default ``proxy_auth_type = basic`` the connector mints a pre-emptive
    ``Proxy-Authorization: Basic …`` that urllib carries to the proxy on an ``http`` destination as a
    request header and on an ``https`` one inside the ``CONNECT`` tunnel, so it reaches the proxy on
    BOTH schemes. An un-listed proxy would therefore receive that credential on first delivery.

    **Its own list, not ``allowed_http``.** ADR 0126 puts the proxy host out of ``allowed_http``'s
    scope — that list gates the PHI destination, and one corporate proxy fronts many destinations, so
    folding it in would force the proxy to be co-listed with every host. A dedicated list answers the
    objection instead of evading it, and leaves the ADR's scope sentence literally true.

    **Deny-by-default**, following ``[ai].allowed_endpoints`` (ADR 0135) rather than the permissive-
    when-empty destination lists: a configured proxy with an EMPTY ``allowed_proxy`` is refused. The
    asymmetry is deliberate — an empty list refuses nothing until a proxy is actually configured, and
    permissive-when-empty would leave this credential-bearing host ungated on the default posture,
    which is the hole the key exists to close.

    The ``"default"`` sentinel is exempt: it names no address at config time (urllib resolves the OS
    proxy at request time), and ``proxy_config_from_settings`` refuses to combine it with proxy
    credentials, so that path mints no ``Proxy-Authorization``. ``settings`` are the already-``env()``-
    resolved settings with the ``[egress]`` site-wide default merged in by
    :func:`_apply_egress_proxy_default`, so this sees the EFFECTIVE proxy either way. An unset
    ``proxy_url`` is a no-op."""
    proxy_url = str(settings.get("proxy_url", "") or "").strip()
    if not proxy_url or proxy_url.lower() == PROXY_DEFAULT:
        return
    if not allowed_proxy:
        log.warning(
            "egress denied: %s forward proxy set with an empty [egress].allowed_proxy", label
        )
        raise WiringError(
            f"{label}: a forward proxy is configured but [egress].allowed_proxy is empty — list the "
            "proxy host to permit it (the proxy receives a Proxy-Authorization credential, so this "
            "list is deny-by-default, unlike the [egress].allowed_* destination lists)"
        )
    if not _http_egress_allowed(proxy_url, allowed_proxy):
        host = _egress_host_label(proxy_url)
        log.warning(
            "egress denied: %s forward proxy host %r not in [egress].allowed_proxy", label, host
        )
        raise WiringError(
            f"{label}: forward proxy host {host!r} is not in the [egress].allowed_proxy allowlist"
        )


def check_fhir_lookup_allowed(
    name: str, settings: Mapping[str, Any], egress: EgressSettings
) -> None:
    """Fail-closed egress allowlist for a ``FhirLookup`` (it dials out to an HTTP(S) FHIR host for a live,
    read-only ``fhir_lookup``, ADR 0043). Reuses ``[egress].allowed_http`` — the **exact arm** the FHIR
    outbound + SMART token endpoint use (a read is an egress host) — checked at load/reload/start so the
    engine is never pointed at a non-allowlisted FHIR server. ``settings`` are the already-``env()``-resolved
    connection settings. Under ``[egress].deny_by_default`` an empty ``allowed_http`` refuses the read
    outright — an un-allowlisted FHIR read can never dial out (the SSRF-shaped fail-open is closed).

    The read arm dials through the same ADR 0126 forward proxy as the FHIR outbound, so it is gated by
    ``[egress].allowed_proxy`` here too — outside the ``allowed_http`` guard below, because that list
    being empty says nothing about whether the proxy is permitted (BACKLOG #1659, DELTA-04 lockstep)."""
    _check_forward_proxy_egress(f"FhirLookup {name!r}", settings, egress.allowed_proxy)
    warn_url_query_credentials(f"FhirLookup {name!r}", settings)  # ASVS 14.2.1
    if egress.deny_by_default and not egress.allowed_http:
        raise WiringError(
            f"FhirLookup {name!r}: {BLOCK_UNLISTED_OUTBOUND_IN_FORCE} and "
            "[egress].allowed_http is empty — list the FHIR host to permit it"
        )
    if egress.allowed_http:
        url = str(settings.get("url", ""))
        refuse_url_credentials(url, f"FhirLookup {name!r} 'url'", error=WiringError)
        if not _http_egress_allowed(
            url, egress.allowed_http
        ):  # same host[:port] matching as the FHIR outbound
            host = _egress_host_label(url)
            log.warning(
                "connect denied: FhirLookup %r host %r not in [egress].allowed_http", name, host
            )
            raise WiringError(
                f"FhirLookup {name!r}: host {host!r} is not in the [egress].allowed_http allowlist"
            )
        # Every credential-bearing token endpoint is a SECOND egress host on this read arm — gate
        # each with the same allowlist as the FHIR outbound, or a crafted smart_token_url (set via
        # with_smart_backend()) exfiltrates the signed client_assertion, and a crafted
        # oauth2_token_url exfiltrates client_id + client_secret, to an unlisted host (DELTA-04).
        _check_credential_token_url_egress(f"FhirLookup {name!r}", settings, egress.allowed_http)


def warn_url_query_credentials(label: str, settings: Mapping[str, Any]) -> None:
    """Log a WARNING when a connection's resolved ``url`` carries a credential-like query parameter
    (ASVS 14.2.1). ``label`` names the connection (``"outbound 'OB_X'"``); the line carries it and
    the parameter NAMES, never a value or the URL.

    WARN, not refuse, and the reason is the difference from the userinfo precedent.
    ``transports.rest.refuse_url_credentials`` REFUSES ``user:password@`` because that shape never
    authenticated anything: urllib reads it as part of the host, and the error text carried the
    password into ``queue.last_error``. A query credential does authenticate, and some partner APIs
    take it nowhere else (a shared-access ``sig``, an API ``key``), so a refusal would remove the
    hop with no header to move it to. The detection is also a heuristic over names, and a false
    refusal has no override. What the warning records is the cost: the request line, query and all,
    lands in the partner's and every proxy's access log. The engine's own log lines already drop the
    query (``_peer_label``, ``rest._redact_url``).

    Called from :func:`check_egress_allowed`, the one function every outbound build path runs
    (check, start, operator start, test), and from :func:`check_fhir_lookup_allowed`, its FhirLookup
    twin. Both run on env-resolved settings, so this sees a URL that ``env()`` supplied.
    ``config.wiring.query_credential_hops`` is the graph-side reader for ``check`` and the posture
    registry, and walks the same two tables."""
    url = settings.get("url")
    if not isinstance(url, str):
        return
    names = credential_query_params(url)
    if names:
        log.warning(
            "%s: the endpoint url carries a credential in its query string (parameter(s) "
            "%s). It rides the request line, so the partner's and any proxy's access log will hold "
            "it. Move it to a header if the partner accepts one (bearer_token, basic auth, or a "
            "headers table supplied whole by env()); see docs/SECURITY-LOOSENING.md (ASVS 14.2.1).",
            label,
            ", ".join(names),
        )


def check_egress_allowed(dest: Destination, egress: EgressSettings) -> None:
    """Fail-closed: refuse (raise :class:`WiringError`) an outbound destination not on the ``[egress]``
    allowlist (WP-11c — ASVS 13.2.4/13.2.5/14.2.3), so a fat-fingered or hostile destination can't
    exfiltrate PHI. ``build_destination`` runs it on every build (vault BACKLOG #2605). Under the
    default ``deny_by_default`` an empty list refuses; only the audited opt-out makes an empty list
    unrestricted, and ``allowed_proxy`` and ``allowed_recipient_domains`` stay deny-by-default on
    their own terms either way. Checked against the resolved
    (``env()``-substituted) destination at config load/reload/start. Webhook/SMTP alert sinks carry no
    PHI bodies and keep their own ``[alerts]`` host allowlists.

    Under ``[egress].deny_by_default`` a destination whose transport has no allowlist is refused
    outright (fail-closed); with the list set, the per-list matching below is unchanged."""
    # ADR 0126 forward proxy: an http-family destination may dial through an operator-chosen proxy that
    # receives a Proxy-Authorization credential. Gated by its OWN [egress].allowed_proxy list, BEFORE
    # and independently of the per-transport destination chain below — an empty allowed_http says
    # nothing about whether the proxy is permitted (BACKLOG #1659).
    if dest.type in _HTTP_FAMILY_DEST_TYPES:
        _check_forward_proxy_egress(f"outbound {dest.name!r}", dest.settings, egress.allowed_proxy)
    # ASVS 14.2.1: a recorded loosening, never a silent one
    warn_url_query_credentials(f"outbound {dest.name!r}", dest.settings)
    if egress.deny_by_default and not _allowlist_for(dest.type, egress):
        # Names the switch the way the raise below does, not the internal field. NSSM captures stderr
        # to files, so this log line is a forensic surface an operator reads -- and "under
        # deny_by_default", sitting beside "[egress] allowlist" in one sentence, reads as a settable
        # [egress] key. It is not: ADR 0118 relocated it, and writing it there is refused at next
        # start with "unrecognized config key(s)" (BACKLOG #1361). The spelling guard in
        # tests/test_relocated_key_messages.py cannot see this line -- it reads print, add_argument
        # and *Error constructors only -- so the fix is here rather than left for a red.
        log.warning(
            "egress denied: outbound %r %s has no [egress] allowlist while %s",
            dest.name,
            dest.type.value,
            BLOCK_UNLISTED_OUTBOUND_IN_FORCE,
        )
        raise WiringError(
            f"outbound {dest.name!r}: {BLOCK_UNLISTED_OUTBOUND_IN_FORCE} and no allowlist permits a "
            f"{dest.type.value} destination — add it to the matching [egress].allowed_* list"
        )
    if dest.type is ConnectorType.MLLP and egress.allowed_mllp:
        host = str(dest.settings.get("host", "127.0.0.1"))
        port = dest.settings.get("port")
        if not host_port_allowed(host, port, egress.allowed_mllp):
            log.warning(
                "egress denied: outbound %r MLLP %s:%s not in [egress].allowed_mllp",
                dest.name,
                host,
                port,
            )
            raise WiringError(
                f"outbound {dest.name!r}: MLLP destination {host}:{port} is not in the "
                "[egress].allowed_mllp allowlist"
            )
    elif dest.type is ConnectorType.TCP and egress.allowed_tcp:
        host = str(dest.settings.get("host", "127.0.0.1"))
        port = dest.settings.get("port")
        if not host_port_allowed(host, port, egress.allowed_tcp):  # same host[:port] matching
            log.warning(
                "egress denied: outbound %r TCP %s:%s not in [egress].allowed_tcp",
                dest.name,
                host,
                port,
            )
            raise WiringError(
                f"outbound {dest.name!r}: TCP destination {host}:{port} is not in the "
                "[egress].allowed_tcp allowlist"
            )
    elif dest.type is ConnectorType.X12 and egress.allowed_tcp:
        # X12 is raw TCP, so it shares the [egress].allowed_tcp allowlist (same host[:port] matching).
        host = str(dest.settings.get("host", "127.0.0.1"))
        port = dest.settings.get("port")
        if not host_port_allowed(host, port, egress.allowed_tcp):
            log.warning(
                "egress denied: outbound %r X12 %s:%s not in [egress].allowed_tcp",
                dest.name,
                host,
                port,
            )
            raise WiringError(
                f"outbound {dest.name!r}: X12 destination {host}:{port} is not in the "
                "[egress].allowed_tcp allowlist"
            )
    elif dest.type is ConnectorType.DIMSE and egress.allowed_tcp:
        # DIMSE (the Phase-2 C-STORE SCU destination) dials a raw socket, so it shares the
        # [egress].allowed_tcp allowlist (same host[:port] matching as X12). Gated now so a future SCU
        # destination is never fail-open (ADR 0025 §6.4).
        host = str(dest.settings.get("host", "127.0.0.1"))
        port = dest.settings.get("port")
        if not host_port_allowed(host, port, egress.allowed_tcp):
            log.warning(
                "egress denied: outbound %r DIMSE %s:%s not in [egress].allowed_tcp",
                dest.name,
                host,
                port,
            )
            raise WiringError(
                f"outbound {dest.name!r}: DIMSE destination {host}:{port} is not in the "
                "[egress].allowed_tcp allowlist"
            )
    elif dest.type is ConnectorType.FILE and egress.allowed_file_dirs:
        directory = dest.settings.get("directory")
        if directory is None or not _dir_egress_allowed(str(directory), egress.allowed_file_dirs):
            log.warning(
                "egress denied: outbound %r File dir %r not under [egress].allowed_file_dirs",
                dest.name,
                directory,
            )
            raise WiringError(
                f"outbound {dest.name!r}: File directory {directory!r} is not under any "
                "[egress].allowed_file_dirs entry"
            )
    elif dest.type in _HTTP_FAMILY_DEST_TYPES and egress.allowed_http:
        # DICOMWEB (STOW-RS) folds into the HTTP host-check branch: it stores its endpoint under "url"
        # (the same key Rest()/FHIR() use), so the host gate reads it unchanged (ADR 0025 §6.4).
        url = str(dest.settings.get("url", ""))
        refuse_url_credentials(url, f"outbound {dest.name!r} 'url'", error=WiringError)
        if not _http_egress_allowed(url, egress.allowed_http):
            host = _egress_host_label(url)
            log.warning(
                "egress denied: outbound %r %s host %r not in [egress].allowed_http",
                dest.name,
                dest.type.value,
                host,
            )
            raise WiringError(
                f"outbound {dest.name!r}: {dest.type.value} host {host!r} is not in the "
                "[egress].allowed_http allowlist"
            )
        # Credential-bearing token endpoints are SECOND egress hosts — the connector POSTs the signed
        # client_assertion (ADR 0024) or client_id + client_secret (ADR 0126) there — so gate each
        # with the same allowlist. Shared helper, so the FhirLookup read arm in
        # check_fhir_lookup_allowed stays in lockstep (DELTA-04).
        _check_credential_token_url_egress(
            f"outbound {dest.name!r}", dest.settings, egress.allowed_http
        )
    elif dest.type is ConnectorType.DATABASE and egress.allowed_db:
        host = str(dest.settings.get("server", ""))
        port = dest.settings.get("port", 1433)
        if not host_port_allowed(host, port, egress.allowed_db):  # same host[:port] matching
            log.warning(
                "egress denied: outbound %r DATABASE server %r not in [egress].allowed_db",
                dest.name,
                host,
            )
            raise WiringError(
                f"outbound {dest.name!r}: DATABASE server {host!r} is not in the "
                "[egress].allowed_db allowlist"
            )
    elif dest.type is ConnectorType.REMOTEFILE and egress.allowed_remote:
        host = str(dest.settings.get("host", ""))
        port = dest.settings.get("port")
        if not host_port_allowed(host, port, egress.allowed_remote):  # same host[:port] matching
            log.warning(
                "egress denied: outbound %r REMOTEFILE host %r not in [egress].allowed_remote",
                dest.name,
                host,
            )
            raise WiringError(
                f"outbound {dest.name!r}: REMOTEFILE host {host!r} is not in the "
                "[egress].allowed_remote allowlist"
            )
    elif dest.type is ConnectorType.EMAIL and egress.allowed_smtp:
        # SMTP destination (ADR 0029): the SMTP host is gated with the same host[:port] matching as
        # MLLP/TCP/DB, so a fat-fingered or hostile mail relay can't exfiltrate PHI.
        host = str(dest.settings.get("host", ""))
        port = dest.settings.get("port", 587)
        if not host_port_allowed(host, port, egress.allowed_smtp):  # same host[:port] matching
            log.warning(
                "egress denied: outbound %r EMAIL host %r not in [egress].allowed_smtp",
                dest.name,
                host,
            )
            raise WiringError(
                f"outbound {dest.name!r}: EMAIL host {host!r} is not in the "
                "[egress].allowed_smtp allowlist"
            )
    elif dest.type is ConnectorType.DIRECT and egress.allowed_direct:
        # Direct S/MIME-over-SMTP (ADR 0085): the HISP relay host is gated with the same host[:port]
        # matching as EMAIL/MLLP, but against its own [egress].allowed_direct list so a Direct relay is
        # permitted independently of generic SMTP egress.
        host = str(dest.settings.get("host", ""))
        port = dest.settings.get("port", 587)
        if not host_port_allowed(host, port, egress.allowed_direct):  # same host[:port] matching
            log.warning(
                "egress denied: outbound %r DIRECT host %r not in [egress].allowed_direct",
                dest.name,
                host,
            )
            raise WiringError(
                f"outbound {dest.name!r}: DIRECT host {host!r} is not in the "
                "[egress].allowed_direct allowlist"
            )
    if dest.type is ConnectorType.EMAIL:
        # The host arm above gates only the relay hop, which forwards to any address. This arm bounds
        # where the mail ends up (vault BACKLOG #2616), and it is deny-by-default on its own terms.
        _check_email_recipient_domains(dest, egress.allowed_recipient_domains)


def _check_email_recipient_domains(dest: Destination, allowed: list[str]) -> None:
    """Refuse an EMAIL destination with any recipient outside ``[egress].allowed_recipient_domains``.
    An empty list refuses every EMAIL destination. Matching is exact and case-insensitive on the
    domain after the last ``@``; a subdomain needs its own entry. The log line and the error name
    the destination and the domain, never the full address. ``EgressSettings`` has already
    normalised the entries."""
    try:
        addresses = envelope_recipients(dest.settings.get("recipients"))
    except ValueError as exc:
        # The transport's own construction message, so the operator fixes the connection rather
        # than the allowlist.
        log.warning("egress denied: outbound %r EMAIL recipients are unreadable", dest.name)
        raise WiringError(f"outbound {dest.name!r}: {exc}") from exc
    if not addresses:
        # Fail closed without leaning on the parser: a gate that checked nothing has not passed.
        log.warning("egress denied: outbound %r EMAIL names no recipient address", dest.name)
        raise WiringError(f"outbound {dest.name!r}: EMAIL destination names no recipient address")
    permitted = set(allowed)
    for address in addresses:
        problem = envelope_address_problem(address)
        if problem is not None:
            _refuse_email_recipient(dest.name, problem)
        domain = address.rpartition("@")[2].lower()
        if domain not in permitted:
            log.warning(
                "egress denied: outbound %r EMAIL recipient domain %r not in "
                "[egress].allowed_recipient_domains",
                dest.name,
                domain,
            )
            raise WiringError(
                f"outbound {dest.name!r}: EMAIL recipient domain {domain!r} is not in the "
                "[egress].allowed_recipient_domains allowlist (an empty list permits no recipient)"
            )


def _refuse_email_recipient(name: str, why: str) -> NoReturn:
    log.warning("egress denied: outbound %r EMAIL recipient %s", name, why)
    raise WiringError(
        f"outbound {name!r}: an EMAIL recipient {why}, so the "
        "[egress].allowed_recipient_domains check cannot pass it"
    )


def host_port_allowed(host: str, port: object, allowed: list[str]) -> bool:
    host = host.lower()
    for entry in allowed:
        allow_host, _, allow_port = entry.partition(":")
        if allow_host.strip().lower() == host and (
            not allow_port or str(port) == allow_port.strip()
        ):
            return True
    return False


def _dir_egress_allowed(directory: str, allowed: list[str]) -> bool:
    try:
        target = Path(directory).resolve()
    except (OSError, ValueError, RuntimeError):
        return False
    for entry in allowed:
        try:
            base = Path(entry).resolve()
        except (OSError, ValueError, RuntimeError):
            continue
        if target == base or base in target.parents:
            return True
    return False


def _egress_host_label(url: str) -> str:
    """The host an egress refusal may print (BACKLOG #1793). urllib unquotes the host, so one that
    holds an ``@`` once unquoted is userinfo written as ``%40``, and printing it prints the password.

    Every egress check runs BEFORE the connector constructor, so the construction refusal in the
    connector never speaks first. The data, token and FhirLookup arms therefore also call
    ``refuse_url_credentials`` up front, for a refusal that names the setting. The proxy arm cannot,
    since a proxy may carry its own userinfo, and this label is what keeps its message clean."""
    host = urllib.parse.urlsplit(url).hostname or ""
    return "(withheld: it holds a credential)" if "@" in urllib.parse.unquote(host) else host


def _http_egress_allowed(url: str, allowed: list[str]) -> bool:
    """True if ``url``'s host (and port, when an allow entry pins one) is on the allowlist — the same
    ``host`` / ``host:port`` matching as MLLP.

    A port ``urlsplit`` cannot read is NOT allowed, and this never raises (BACKLOG #1793). The
    ``ValueError`` from ``.port`` quotes the port text, and a password holding an unencoded ``/``,
    ``?`` or ``#`` ends the authority early, so its head IS that text. ``redact()`` does not match it."""
    parts = urllib.parse.urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    for entry in allowed:
        allow_host, _, allow_port = entry.partition(":")
        if allow_host.strip().lower() == host and (
            not allow_port or str(port) == allow_port.strip()
        ):
            return True
    return False
