# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 13.1.1 / 13.1.2 / 13.1.3 drift guard: the communications inventory in
``docs/ASVS-L2-PHASE0-CHANGES.md`` §5 and the resource-management tables in
``docs/CONNECTIONS.md`` must stay complete and true at HEAD.

For these three requirements the **shipped documentation IS the control** — an assessor scores the
table, not the code — so an incomplete or stale table is the defect. Both failure modes have already
happened here: §5 shipped 12 rows while the engine dialled ~40 distinct hops, and CONNECTIONS.md
carried a "no explicit acquire timeout *yet* (WP-L3-07)" sentence for months after the timeout landed
(``transports/database.py``). This module makes both a build failure, modelled on
``tests/test_secret_rotation_inventory.py`` (curated registry + doc-slice whole-token assertion +
a planted-omission self-test). Five mechanisms:

1. **Registry-driven half (auto-catching).** Importing ``messagefoundry.transports`` runs every
   module's ``register_*`` at import time; the guard reads the resulting registries and asserts each
   :class:`~messagefoundry.config.models.ConnectorType`'s ``.value`` appears **inside backticks in a
   row's FIRST CELL** — of the §5.1 slice *and* of both ``CONNECTIONS.md`` resource tables. A new
   ``transports/`` module therefore fails the build until rows land in all three. First-cell matching
   is load-bearing, not stylistic: a whole-slice search was inert for ``http``, because
   ``` `http` ``` also occurs in the REST row's prose ("a cleartext-``http`` credential hop"), so
   deleting the entire ADR 0023 HTTP-listener row passed. The backticks matter for the same reason —
   half these values (``file``, ``rest``, ``http``, ``email``, ``direct``, ``timer``) are ordinary
   English words.
2. **Curated infra half (manual, disclosed).** :data:`INFRA_HOPS` maps a token to the sub-section it
   must appear in, covering the hops that live in **no** registry — the AI broker and the SMART /
   OAuth2 token endpoints in particular, which are not registered connectors, so mechanism 1 can
   never force their rows. *Disclosed limitation:* a wholly new infrastructure client still needs one
   manual registration here (the same accepted shape as the 13.1.4 rotation guard).
3. **Doc-slice discipline.** Each document is sliced by exact headings and both markers must exist
   and be ordered, so a renamed heading fails loudly instead of silently matching the whole file.
   Every match is whole-token (``\\b``-style identifier boundaries), never a bare substring.
4. **Negative + shape assertions.** Retired false phrases must stay gone; Table A and Table B must
   carry an **identical row set in identical order** (the "documented in one table, missing from the
   other" failure that keeps re-opening 13.1.2/13.1.3); and every default the tables state is
   **imported from the code** — all 30 of them, from ``model_fields[...].default`` or a module
   constant — and asserted to appear on the same line as its anchor token, so changing a constant
   reds the doc rather than letting it rot.
5. **Planted-omission self-test.** The checkers are pure functions exercised against synthetic
   slices, so the guard itself cannot silently stop asserting.

PHI-free — it reads setting/connector *names*, doc prose and code constants only.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType

_ROOT = Path(__file__).resolve().parent.parent
_PHASE0 = _ROOT / "docs" / "ASVS-L2-PHASE0-CHANGES.md"
_CONNECTIONS = _ROOT / "docs" / "CONNECTIONS.md"

# --- doc slice markers (exact headings; a rename fails loudly) ---------------------------------
_S5_START = "## 5. Communications inventory (ASVS 13.1.1)"
_S5_END = "## 6. Dependency-remediation policy (ASVS 15.1.1 / 15.2.1)"
_S51 = "### 5.1 Message-plane connectors"
_S52 = "### 5.2 Control-plane listeners"
_S53 = "### 5.3 Infrastructure hops"

_RES_START = "## Resource management & limits (ASVS 13.1.2 / 13.1.3 / 13.2.6)"
_RES_END = "## Competitive parity — full connector catalog"
_TABLE_A = "### Table A — concurrency limits & behaviour at the limit (ASVS 13.1.2 / 13.2.6)"
_TABLE_B = "### Table B — per-service resource strategy (ASVS 13.1.3)"

# Registered connectors that open NO socket and reach no external system: TIMER is clock-driven
# (ADR 0011), LOOPBACK is inert re-ingress only (ADR 0013), PT is an internal Handler-fed
# pass-through. They still need an inventory row (an assessor reading §5.1 must be able to see that
# they are internal), but they belong on the single "opens no socket" row rather than getting a
# transport/TLS/auth row of their own — asserted as such below.
_NO_SOCKET_CONNECTORS: frozenset[ConnectorType] = frozenset(
    {ConnectorType.TIMER, ConnectorType.LOOPBACK, ConnectorType.PT}
)
_NO_SOCKET_ROW_MARKER = "open no socket"

#: Infrastructure hops that live in no connector registry → token ⇒ the §5 sub-section it must appear
#: in. These are the hops mechanism 1 can never discover: unregistered transports (the AI broker, the
#: SMART and generic-OAuth2 token endpoints), the auth-tier clients, the store backends, and the
#: logging/alerting/proxy egress. Every token here must ALSO appear in both CONNECTIONS.md tables.
INFRA_HOPS: dict[str, str] = {
    # --- control plane (§5.2) ---
    "trusted_proxies": _S52,
    # The primary control-plane listener itself. Without this the §5.2 API/UI/WS row was pinned by
    # NOTHING — deleting it left the whole suite green.
    "[api].port": _S52,
    # --- store backends (§5.3) ---
    "sqlite": _S53,
    "sqlserver": _S53,
    "postgres": _S53,
    # --- directory / federation (§5.3) ---
    "ad_server": _S53,
    "ad_session_recheck_seconds": _S53,
    "kerberos_spn": _S53,
    "oidc_token_endpoint": _S53,
    "oidc_jwks_uri": _S53,
    # --- unregistered outbound HTTP clients (§5.3) ---
    "smart_token_url": _S53,
    "oauth2_token_url": _S53,
    "[ai].endpoint": _S53,
    # --- secrets providers (§5.3) ---
    "MEFOR_STORE_VAULT_ADDR": _S53,
    # ADR 0138: the SAME Vault address in a wholly different volume regime — one Transit round trip
    # per encrypted CELL, not one per DEK unwrap. A single row cannot honestly carry both.
    "MEFOR_STORE_TRANSIT_KEY": _S53,
    "MEFOR_SECRETS_VAULT_ADDR": _S53,
    # --- alerting / logging / time (§5.3) ---
    "email_smtp_host": _S53,
    "webhook_url": _S53,
    "forward_host": _S53,
    "ntp_peer": _S53,
    # --- DR + per-user notification (§5.3) ---
    "[backup].destination": _S53,
    "notify_security_events": _S53,
    # --- egress path shaping (§5.3) ---
    "proxy_url": _S53,
    "ech_sidecar": _S53,
}

#: §5-ONLY hops: interfaces that belong in the communications inventory but have no engine-side
#: concurrency/timeout posture to tabulate in CONNECTIONS.md, because the engine opens no socket on
#: them. Kept separate from :data:`INFRA_HOPS` precisely so the both-resource-tables coupling does not
#: force a meaningless row.
S5_ONLY_HOPS: dict[str, str] = {
    # ADR 0142's browser-mediated leg: the BROWSER is redirected to the operator-pinned authorization
    # endpoint and the IdP returns the code to the engine's own [api] listener, which already has its
    # own §5.2 row and its own resource-table rows. This is the literal instance of 13.1.1's "such as
    # a URL for a callback" clause, so its absence was a straight inventory gap.
    "oidc_authorization_endpoint": _S53,
    "oidc_redirect_path": _S53,
}

#: Row-LABEL markers for every §5.2/§5.3 row, so each row is pinned by its own identity rather than by
#: a token a SIBLING row may also carry. Two rows were provably deletable with the suite green — the
#: Alerts SMTP sink (``email_smtp_host`` survives in the per-user notification row) and the Vault
#: Transit DEK hop (``MEFOR_STORE_VAULT_ADDR`` survives in the bulk-cipher row) — because token
#: presence alone cannot distinguish "this row exists" from "some row mentions this".
S5_ROW_MARKERS: dict[str, str] = {
    # §5.2
    "Engine JSON API": _S52,
    "Reverse proxy → engine segment": _S52,
    # §5.3 — store backends
    "Store — SQLite": _S53,
    "Store — SQL Server": _S53,
    "Store — Postgres": _S53,
    # §5.3 — directory / federation
    "Active Directory — login binds": _S53,
    "Active Directory — directory session reconciler": _S53,
    "Kerberos / SPNEGO browser SSO": _S53,
    "OIDC IdP — authorization endpoint": _S53,
    "OIDC IdP — token endpoint": _S53,
    "OIDC IdP — JWKS fetch": _S53,
    # §5.3 — unregistered outbound HTTP clients
    "SMART Backend Services token endpoint": _S53,
    "Generic OAuth2 client-credentials token endpoint": _S53,
    "Engine-brokered AI assistance": _S53,
    # §5.3 — secrets / key material
    "store DEK envelope-decrypt": _S53,
    "bulk at-rest cipher": _S53,
    "HashiCorp Vault KV v2": _S53,
    # §5.3 — DR, alerting, logging, time
    "DR backup destination": _S53,
    "Security-event notification email, per user": _S53,
    "Alerts — SMTP notification sink": _S53,
    "Alerts — webhook sink": _S53,
    "Off-box syslog log forwarder": _S53,
    "SNTP / NTP startup clock-sync probe": _S53,
    # §5.3 — egress path shaping
    "Forward / egress web proxy": _S53,
    "Loopback ECH sidecar": _S53,
}

#: The same row-identity pin for §5.1. The registry check above asserts each ``ConnectorType`` value
#: appears in SOME first cell, but FIVE types own two rows each (mllp listener/destination, file
#: local/UNC-SMB, remotefile SFTP/FTP, dimse SCP/SCU, database DATABASE/DatabaseRef) — so deleting
#: either half left the value still present and the whole suite green. Verified by planting: 10 of
#: the 20 message-plane rows were individually deletable with zero failures, including the MLLP
#: listener, the engine's primary PHI ingress interface. 13.1.1 asks for the inventory itself, so a
#: silently losable row is the defect.
S51_ROW_MARKERS: dict[str, str] = dict.fromkeys(
    (
        "MLLP listener",
        "MLLP destination",
        "Raw TCP endpoint",
        "X12 EDI endpoint",
        "Web-service listener",
        "File endpoint — local filesystem",
        "File endpoint — UNC / SMB share",
        "SFTP source + destination",
        "FTP / FTPS source + destination",
        "REST destination",
        "SOAP destination",
        "FHIR destination and",
        "DICOMweb STOW-RS destination",
        "DICOM C-STORE SCP",
        "DICOM C-STORE SCU",
        "SMTP email destination",
        "Direct-Project S/MIME destination",
        "DATABASE destination, poll source",
        "Reference-set sync dial-out",
        "Internal sources that",
    ),
    _S51,
)

#: EVERY registered connector -> the Table A / Table B row-label fragment that must carry it. The
#: resource tables name services, not ``ConnectorType`` values, so the §5.1 registry check cannot
#: reach them — and without this, deleting BOTH tables' rows for SFTP/FTP/FTPS, REST, SOAP, DICOMweb,
#: the DICOM SCP/SCU, EMAIL, DIRECT or the UNC/SMB File endpoint left the whole suite green (verified
#: by planting: 18 rows removed, 0 failures). ``test_every_connector_has_a_row_in_both_resource_tables``
#: asserts this map's key set EQUALS the live registry minus the socket-less exemptions, so a new
#: transports/ module fails until it has rows in both tables, and a removed one fails until its stale
#: mapping goes.
CONNECTOR_ROW_TOKENS: dict[str, tuple[str, ...]] = {
    "mllp": ("MLLP",),
    "tcp": ("Raw TCP",),
    # X12 is a SEPARATE row from raw TCP in both tables: their behaviour at the limit differs
    # materially (transports/x12.py emits no connection_event at all), and merging them concealed
    # that. Keyed on the X12-only label so a silent re-merge fails.
    "x12": ("X12 listener",),
    "http": ("HTTP web-service listener",),
    "file": ("File endpoint",),
    # SFTP and FTP/FTPS are separate rows because their 30 s timeout means different things: a TCP
    # connect bound on SFTP (paramiko) vs a genuine whole-socket bound on FTP (ftplib).
    "remotefile": ("SFTP (remote-file)", "FTP / FTPS (remote-file)"),
    "rest": ("REST destination",),
    "soap": ("SOAP destination",),
    "fhir": ("FHIR",),
    "dicomweb": ("DICOMweb",),
    "dimse": ("DICOM C-STORE SCP", "DICOM C-STORE SCU"),
    "email": ("EMAIL",),
    "direct": ("DIRECT",),
    "database": ("DATABASE",),
}

#: Hops that live in the connector registry but whose CONNECTIONS.md rows are not forced by the §5.1
#: backtick check (the tables name them by service, not by ``ConnectorType`` value). Kept small and
#: explicit so the two tables cannot quietly lose a message-plane service.
CONNECTOR_TABLE_TOKENS: tuple[str, ...] = (
    "max_connections",
    "receive_timeout",
    "acquire_timeout",
    "pool_max",
    "DatabaseRef",
    # FileRef reference-set sources are a §5 hop (a local-or-UNC read on the set's refresh cadence)
    # that had rows in neither table while its DatabaseRef sibling had both.
    "FileRef",
    "fhir_lookup",
    "pooled_max_processing_lanes",
    "retry_max_attempts",
)

#: Statements that were FALSE at HEAD and must never come back to the resource-management section.
#: One parametrized test per phrase, so a resurrection names itself.
RETIRED_PHRASES: tuple[str, ...] = (
    "no explicit acquire timeout",
    "WP-L3-07",
    "plus an accept throttle",
    "not accepted until one frees",
    # Sftp()/Ftp() expose NO timeout argument — the 30 s value is a hard-coded module fallback in
    # transports/remotefile.py, and `Sftp(connect_timeout=5)` raises TypeError.
    "exposes `connect_timeout` only",
    # /ai/chat depends on plain require(Permission.AI_ASSIST); no admin-write pacing applies.
    "RBAC gate and the admin-write throttle",
    # Table B's store rows contradict it three paragraphs later (busy_timeout, idempotent re-run).
    "Every infrastructure hop in Table B is single-shot",
    # transports/wincred.py runs alt-credential SMB work on its OWN single-worker executor — its
    # module docstring says it must never use the shared pool (impersonation would leak) — and the
    # same section's UNC/SMB rows say so. The paragraph contradicted them.
    "the SMB impersonation worker — shares the event loop's",
    # The three Vault rows named `hvac`/`requests` defaults without a value, in a column headed
    # "Timeout setting + default"; `requests` has NO default timeout, so the phrasing implied a
    # fallback that does not exist.
    "so `hvac`/`requests` defaults apply",
    # X12 and DICOM emit NO connection event at all, so a blanket per-listener at_capacity claim is
    # false; the merged Raw-TCP/X12 row concealed it.
    "Raw TCP / X12 listener",
    # #1051: the retry DEFAULT is finite (100) since the cap landed. Both forms the section used to
    # disclose it in — "is `None` = retry forever" and "is unset = retry forever" — end in this.
    # Naming `max_attempts=None` as an available CHOICE stays allowed; it is the sentence that makes
    # retry-forever the DEFAULT that must not come back.
    "= retry forever",
)

#: The corrected replacements for :data:`RETIRED_PHRASES` — asserted PRESENT, so deleting the false
#: sentence without stating the truth in its place also fails (a silent narrowing, not a fix).
REQUIRED_TRUTHS: tuple[str, ...] = (
    "no accept-rate throttle",
    "at_capacity",
    "acquire_timeout",
    "no per-statement timeout",
    # 13.1.2: the AI broker's real bound, and the absence of the one the doc used to claim.
    "There is NO per-actor pacing on `POST /ai/chat`",
    # 13.1.3: the resource class the requirement names by example, with no knob of its own.
    "ThreadPoolExecutor",
    # 13.1.3: the store backends are the deliberate exception to "single-shot".
    "are the deliberate exception",
    # 13.1.1/13.1.2: ADR 0138 makes Transit a per-CELL hop, not a startup-only one.
    "per encrypted CELL",
    # 13.1.2/13.1.3: the SMB impersonation worker's real bound — its own single-worker executor.
    "mefor-filecred",
    # 13.1.3: the two off-loop pools with a knob, and the one class of off-loop work with NO bound.
    "pooled_fusing_workers",
    "no timeout at all",
    # 13.1.2: the telemetry asymmetry that the merged listener row concealed.
    "No ADR 0021 connection_event is emitted",
    # 13.1.3: the Handler-side bound that actually releases the transform worker for the two lookups.
    "_LOOKUP_RESULT_TIMEOUT_SECONDS",
    # 13.1.3: the hvac-inherited Vault timeout, named with its value and its provenance.
    "hvac.adapters.Adapter",
    # 13.1.3 (#1051): the finite cap, and the property that makes it safe as a default. Deleting the
    # retired disclosure without stating the cap would leave the section silent on the one number an
    # assessor scores the retry posture on.
    "`retry_max_attempts` is 100",
    "attempts are counted **per row**",
)


def _import_code_defaults() -> list[tuple[str, float | int, str]]:
    """``(anchor token, value, provenance)`` for every default the CONNECTIONS.md tables state.

    The values are **imported from the code**, not copied, so changing a constant reds the doc. Each
    is asserted to appear on the SAME LINE as its anchor token (a markdown table row is one line), so
    a stray "30" elsewhere in the section cannot satisfy the check.
    """
    import inspect

    from messagefoundry import logging_setup
    from messagefoundry.auth import oidc_http
    from messagefoundry.auth.oidc import flow as oidc_flow
    from messagefoundry.config import wiring
    from messagefoundry.config.models import RetryPolicy
    from messagefoundry.config.settings import (
        AlertsSettings,
        AuthSettings,
        PipelineSettings,
        StoreSettings,
    )
    from messagefoundry.pipeline import alert_sinks, wiring_runner
    from messagefoundry.transports import (
        ai_broker,
        database,
        http_auth,
        http_listener,
        mllp,
        smart,
    )

    def _default(model: type, field: str) -> float | int:
        value = model.model_fields[field].default  # type: ignore[attr-defined]
        assert isinstance(value, int | float), f"{model.__name__}.{field} default is not numeric"
        return value

    return [
        ("max_connections", mllp.DEFAULT_MAX_CONNECTIONS, "transports.mllp"),
        ("receive_timeout", mllp.DEFAULT_RECEIVE_TIMEOUT, "transports.mllp"),
        ("acquire_timeout", database._DEFAULT_DB_ACQUIRE_TIMEOUT, "transports.database"),
        (
            "pooled_max_processing_lanes",
            _default(PipelineSettings, "pooled_max_processing_lanes"),
            "config.settings",
        ),
        ("ad_connect_timeout", _default(AuthSettings, "ad_connect_timeout"), "config.settings"),
        ("ad_receive_timeout", _default(AuthSettings, "ad_receive_timeout"), "config.settings"),
        ("forward_host", logging_setup._FORWARD_TCP_TIMEOUT, "logging_setup"),
        ("ntp_peer", logging_setup._SNTP_TIMEOUT, "logging_setup"),
        # The token POST does NOT use the shared IdP constant: AuthService._oidc_exchange passes no
        # timeout=, so it falls to exchange_code's OWN signature default. Pinning this row to
        # oidc_http.DEFAULT_IDP_TIMEOUT_SECONDS made the check decorative for the hop it names.
        (
            "oidc_token_endpoint",
            float(inspect.signature(oidc_flow.exchange_code).parameters["timeout"].default),
            "auth.oidc.flow.exchange_code",
        ),
        ("oidc_jwks_uri", oidc_http.DEFAULT_IDP_TIMEOUT_SECONDS, "auth.oidc_http"),
        ("smart_token_url", smart._DEFAULT_TOKEN_TIMEOUT, "transports.smart"),
        ("oauth2_token_url", http_auth._DEFAULT_TOKEN_TIMEOUT, "transports.http_auth"),
        ("[ai].endpoint", ai_broker._DEFAULT_TIMEOUT, "transports.ai_broker"),
        ("webhook_url", alert_sinks._MAX_QUEUE, "pipeline.alert_sinks"),
        # The rest of what the tables quote. The docstring used to claim "every default the tables
        # state is imported from the code" while only the 14 above were pinned; these close it.
        ("[store].pool_size", _default(StoreSettings, "pool_size"), "config.settings"),
        ("warm_pool_timeout", _default(StoreSettings, "warm_pool_timeout"), "config.settings"),
        ("command_timeout", _default(StoreSettings, "command_timeout"), "config.settings"),
        # SECTION-QUALIFIED. The bare token `connect_timeout` occurs on FOUR rows carrying the value
        # 15, two of which derive from the CONNECTOR default (wiring.Database), so the store pin
        # could be satisfied by a row it does not describe. `[store].connect_timeout` matches only
        # the two store rows (whole_token_present treats `[` and `.` as boundaries).
        ("[store].connect_timeout", _default(StoreSettings, "connect_timeout"), "config.settings"),
        # ...and the connector tier is pinned to its OWN constant, so the two cannot be conflated.
        (
            "`connect_timeout` 15 s (DSN **login** timeout only)",
            int(inspect.signature(wiring.Database).parameters["connect_timeout"].default),
            "config.wiring.Database",
        ),
        # The Handler-side result bridge that releases the transform worker for db_lookup/fhir_lookup
        # — the bound the thread-inventory paragraph says is what does the releasing.
        (
            "_LOOKUP_RESULT_TIMEOUT_SECONDS",
            wiring_runner._LOOKUP_RESULT_TIMEOUT_SECONDS,
            "pipeline.wiring_runner",
        ),
        (
            "pooled_fusing_workers",
            _default(PipelineSettings, "pooled_fusing_workers"),
            "config.settings",
        ),
        (
            "max_body_bytes",
            http_listener.DEFAULT_MAX_BODY_BYTES // (1024 * 1024),
            "transports.http_listener",
        ),
        (
            "max_header_bytes",
            http_listener.DEFAULT_MAX_HEADER_BYTES // 1024,
            "transports.http_listener",
        ),
        # The API row quotes the three throttles as prose ("login 10 per IP and 60 global per
        # 60 s, PHI reads 120 per actor per 60 s, admin writes 12 per actor per second"), so the
        # anchor is the row's own [api].port token.
        (
            "[api].port",
            _default(AuthSettings, "login_rate_limit_per_ip"),
            "config.settings",
        ),
        (
            "[api].port",
            _default(AuthSettings, "phi_read_rate_limit_per_actor"),
            "config.settings",
        ),
        (
            "[api].port",
            _default(AuthSettings, "admin_write_rate_limit_per_actor"),
            "config.settings",
        ),
        (
            "ad_session_recheck_max_users",
            _default(AuthSettings, "ad_session_recheck_max_users"),
            "config.settings",
        ),
        (
            "ad_session_revoke_max",
            _default(AuthSettings, "ad_session_revoke_max"),
            "config.settings",
        ),
        (
            "oidc_jwks_ttl_seconds",
            _default(AuthSettings, "oidc_jwks_ttl_seconds"),
            "config.settings",
        ),
        (
            "oidc_jwks_min_refetch_seconds",
            _default(AuthSettings, "oidc_jwks_min_refetch_seconds"),
            "config.settings",
        ),
        ("email_timeout", _default(AlertsSettings, "email_timeout"), "config.settings"),
        ("webhook_timeout", _default(AlertsSettings, "webhook_timeout"), "config.settings"),
        ("retry_backoff_seconds", _default(RetryPolicy, "backoff_seconds"), "config.models"),
        # max_backoff is stated on the same prose line as the backoff base ("capped at 300 s").
        ("multiplier", _default(RetryPolicy, "max_backoff_seconds"), "config.models"),
        # The retry CAP itself (#1051). Unpinnable while it was None — `_default` requires a number —
        # so the section could and did state a default the code no longer had. Now that it is finite
        # the doc is pinned to it like every other bound in these tables.
        ("retry_max_attempts", _default(RetryPolicy, "max_attempts"), "config.models"),
    ]


# --- pure helpers (exercised by the self-tests below) ------------------------------------------


def slice_between(text: str, start: str, end: str, *, where: str) -> str:
    """The document text between two exact headings. Both must exist and be ordered."""
    s = text.find(start)
    e = text.find(end)
    assert s != -1, f"heading {start!r} missing from {where}"
    assert e != -1 and e > s, f"heading {end!r} missing or misordered in {where}"
    return text[s:e]


def whole_token_present(token: str, section: str) -> bool:
    """Identifier-boundary match, never a bare substring — so deleting a token that is a prefix of a
    surviving one (``ad_server`` vs ``ad_server_x``) still fails."""
    return (
        re.search(r"(?<![A-Za-z0-9_])" + re.escape(token) + r"(?![A-Za-z0-9_])", section)
        is not None
    )


def missing_tokens(tokens: dict[str, str], slices: dict[str, str]) -> list[str]:
    """Tokens whose required slice does not contain them, whole-token."""
    return sorted(t for t, key in tokens.items() if not whole_token_present(t, slices[key]))


def present_retired_phrases(phrases: tuple[str, ...], section: str) -> list[str]:
    """Retired (now-false) phrases that have crept back into ``section``, case-insensitively."""
    lowered = section.lower()
    return [p for p in phrases if p.lower() in lowered]


def table_row_labels(section: str, heading: str) -> list[str]:
    """The first-column label of every data row of the markdown table under ``heading``."""
    start = section.find(heading)
    assert start != -1, f"table heading {heading!r} missing"
    labels: list[str] = []
    for line in section[start + len(heading) :].splitlines():
        stripped = line.strip()
        if stripped.startswith("###") or stripped.startswith("## "):
            break
        if not stripped.startswith("|"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        first = cells[0]
        if not first or set(first) <= set("-: "):  # separator row
            continue
        if first.lower().startswith(("service/hop", "interface")):  # header row
            continue
        labels.append(first)
    return labels


def value_on_anchor_line(anchor: str, value: float | int, section: str) -> bool:
    """True when at least one line carrying ``anchor`` also carries ``value`` as a standalone number
    (``30`` matches "30 s" but not "300" or "30.5")."""
    text_value = f"{value:g}"
    number = re.compile(r"(?<![0-9.])" + re.escape(text_value) + r"(?![0-9.])")
    return any(
        whole_token_present(anchor, line) and number.search(line) for line in section.splitlines()
    )


# --- fixtures ----------------------------------------------------------------------------------


def _phase0_slices() -> dict[str, str]:
    text = _PHASE0.read_text(encoding="utf-8")
    section5 = slice_between(text, _S5_START, _S5_END, where=_PHASE0.name)
    return {
        "§5": section5,
        _S51: slice_between(section5, _S51, _S52, where=f"{_PHASE0.name} §5"),
        _S52: slice_between(section5, _S52, _S53, where=f"{_PHASE0.name} §5"),
        _S53: section5[section5.index(_S53) :],
    }


def _resource_section() -> str:
    text = _CONNECTIONS.read_text(encoding="utf-8")
    return slice_between(text, _RES_START, _RES_END, where=_CONNECTIONS.name)


# --- 13.1.1: the inventory is complete ---------------------------------------------------------


def test_every_registered_connector_has_an_inventory_row() -> None:
    # Importing the package runs every module's register_* at import time, so the registries below are
    # the live truth. A new transports/ module with no §5.1 row fails HERE, not at the next audit.
    import messagefoundry.transports  # noqa: F401  (import = registration)
    from messagefoundry.transports.base import _DESTINATIONS, _SOURCES

    registered = set(_SOURCES) | set(_DESTINATIONS)
    assert registered, "connector registries are empty — the import-time registration broke"
    section = _phase0_slices()[_S51]
    # Matched against each row's FIRST CELL. A whole-slice substring search was inert for
    # ConnectorType.HTTP: `http` (backticked) also occurs in the REST row's prose
    # ("a cleartext-`http` credential hop"), so deleting the entire Web-service listener row — the
    # ADR 0023 HTTP listener — left this check green.
    labels = table_row_labels(section, _S51)
    assert labels, "the §5.1 table has no data rows; the row parser is broken"
    missing = sorted(
        kind.value for kind in registered if not any(f"`{kind.value}`" in label for label in labels)
    )
    assert not missing, (
        "registered connector type(s) with no row in the §5.1 communications inventory of "
        f"docs/ASVS-L2-PHASE0-CHANGES.md (add a row whose FIRST cell names `<type>`): "
        f"{missing}"
    )


def test_no_socket_connectors_are_declared_as_such() -> None:
    # The three socket-less internal sources must be a strict subset of the live registry (so a
    # deleted connector cannot leave a stale exemption) and must sit on the dedicated
    # "open no socket" row rather than being given a transport/TLS/auth row they do not have.
    import messagefoundry.transports  # noqa: F401
    from messagefoundry.transports.base import _SOURCES

    assert set(_SOURCES) > _NO_SOCKET_CONNECTORS, (
        "_NO_SOCKET_CONNECTORS is not a strict subset of the registered sources — a connector was "
        "renamed or removed; update the exemption set"
    )
    section = _phase0_slices()[_S51]
    rows = [ln for ln in section.splitlines() if _NO_SOCKET_ROW_MARKER in ln]
    assert len(rows) == 1, (
        f"expected exactly one §5.1 row containing {_NO_SOCKET_ROW_MARKER!r}, found {len(rows)}"
    )
    absent = sorted(k.value for k in _NO_SOCKET_CONNECTORS if f"`{k.value}`" not in rows[0])
    assert not absent, f"socket-less connector(s) missing from the 'opens no socket' row: {absent}"


def test_curated_infra_hops_appear_in_their_inventory_subsection() -> None:
    # The half no registry can discover. A hop documented in the wrong sub-section also fails, so the
    # control-plane / infrastructure split stays meaningful.
    missing = missing_tokens(INFRA_HOPS, _phase0_slices())
    assert not missing, (
        "infrastructure hop(s) missing from their §5 sub-section in "
        f"docs/ASVS-L2-PHASE0-CHANGES.md: {missing}"
    )


def test_s5_only_hops_appear_in_their_inventory_subsection() -> None:
    """Hops that belong in §5 but have no engine-side resource posture to tabulate.

    RULE (13.1.1): "note where the end user provides an external location **such as a URL for a
    callback**". The OIDC authorization endpoint + its authorization-code callback are the literal
    instance of that clause, and they had no row: §5.3 documented only the token and JWKS legs.
    Kept out of :data:`INFRA_HOPS` because that set additionally requires a row in BOTH
    CONNECTIONS.md resource tables, which this browser-mediated leg has no engine-side bound for.
    """
    missing = missing_tokens(S5_ONLY_HOPS, _phase0_slices())
    assert not missing, (
        "§5-only hop(s) missing from their sub-section in "
        f"docs/ASVS-L2-PHASE0-CHANGES.md: {missing}"
    )
    section = _phase0_slices()["§5"]
    assert "such as a URL for a callback" in section, (
        "the §5 preamble truncates ASVS 13.1.1's clause at 'the end user provides an external "
        "location', dropping the callback half the OIDC row now discharges."
    )


def missing_row_labels(markers: dict[str, str], slices: dict[str, str]) -> list[str]:
    """Row-label markers with no matching FIRST-CELL label in their sub-section's table."""
    gaps: list[str] = []
    for marker, key in markers.items():
        heading = key
        labels = table_row_labels(slices[key], heading)
        if not any(marker in label for label in labels):
            gaps.append(marker)
    return sorted(gaps)


def test_every_message_plane_row_is_pinned_by_its_own_label() -> None:
    """§5.1's half of the same property — the half that was never applied.

    ``test_every_registered_connector_has_an_inventory_row`` pins each ``ConnectorType`` VALUE, not
    each row, so the five types owning two rows each could lose either one silently. This binds all
    twenty message-plane rows by their own first-cell identity.
    """
    missing = missing_row_labels(S51_ROW_MARKERS, _phase0_slices())
    assert not missing, (
        "§5.1 message-plane row(s) missing from docs/ASVS-L2-PHASE0-CHANGES.md (matched on "
        "the row's FIRST cell, so a deleted row is detected even when its ConnectorType value "
        f"survives in a sibling row): {missing}"
    )


def test_every_control_plane_and_infra_row_is_pinned_by_its_own_label() -> None:
    """Row identity, not token presence — the check that makes a whole-row deletion detectable.

    Two rows were provably deletable with the entire suite green, because their only pinning token
    also occurs in a SIBLING row: the Alerts SMTP sink (``email_smtp_host`` survives in the per-user
    security-event row) and the Vault Transit DEK hop (``MEFOR_STORE_VAULT_ADDR`` survives in the
    bulk-cipher row). Keying on the row's own first-cell label closes that for all 25 rows.
    """
    slices = _phase0_slices()
    missing = missing_row_labels(S5_ROW_MARKERS, slices)
    assert not missing, (
        "§5.2/§5.3 row(s) missing from docs/ASVS-L2-PHASE0-CHANGES.md (matched on the "
        f"row's FIRST cell, so a deleted row is detected even when a sibling repeats its tokens): "
        f"{missing}"
    )


def test_row_label_guard_detects_a_planted_row_deletion() -> None:
    """Proves the check above can fail on exactly the two rows token-presence could not see."""
    slices = dict(_phase0_slices())
    for victim in ("Alerts — SMTP notification sink", "store DEK envelope-decrypt"):
        mutated = "\n".join(
            line
            for line in slices[_S53].splitlines()
            if not (line.strip().startswith("|") and victim in line.split("|")[1])
        )
        probe = dict(slices)
        probe[_S53] = mutated
        gaps = missing_row_labels(S5_ROW_MARKERS, probe)
        assert gaps == [victim], (
            f"deleting the {victim!r} row must be reported by the label guard; it reported {gaps}"
        )
        # And confirm the OLD, token-only check really was blind to it — the defect being fixed.
        assert not missing_tokens(INFRA_HOPS, probe), (
            f"fixture drifted: the token-only check now catches the {victim!r} deletion, so the "
            "label guard's rationale needs restating"
        )


def test_message_plane_label_guard_detects_a_planted_row_deletion() -> None:
    """The §5.1 half, on a row the ConnectorType check provably could not see.

    ``mllp`` owns two rows, so deleting the MLLP **listener** leaves the value present in the MLLP
    destination row — the registry check stays green while the engine's primary PHI ingress
    interface has vanished from the inventory.
    """
    slices = dict(_phase0_slices())
    victim = "MLLP listener"
    mutated = "\n".join(
        line
        for line in slices[_S51].splitlines()
        if not (line.strip().startswith("|") and victim in line.split("|")[1])
    )
    assert mutated != slices[_S51], "the planted deletion did not apply; the §5.1 row label moved"
    probe = dict(slices)
    probe[_S51] = mutated
    gaps = missing_row_labels(S51_ROW_MARKERS, probe)
    assert gaps == [victim], (
        f"deleting the {victim!r} row must be reported by the label guard; it reported {gaps}"
    )
    # And confirm the ConnectorType check really is blind to it — the defect being fixed.
    labels = table_row_labels(probe[_S51], _S51)
    assert any("`mllp`" in label for label in labels), (
        "fixture drifted: `mllp` no longer survives the listener row's deletion, so this guard's "
        "rationale needs restating"
    )


def test_egress_note_names_the_current_posture_switch() -> None:
    # [egress].deny_by_default was relocated to [security].block_unlisted_outbound (ADR 0118) and is
    # REJECTED at load in its old section; the note must not send an operator to a rejected key.
    section = _phase0_slices()["§5"]
    assert whole_token_present("block_unlisted_outbound", section), (
        "the §5 egress note must name [security].block_unlisted_outbound (ADR 0118)"
    )
    assert "deny_by_default" not in section or "retired" in section, (
        "the §5 egress note still presents the retired [egress].deny_by_default key as current"
    )


# --- 13.1.2 / 13.1.3: the resource-management tables are true and complete ----------------------


@pytest.mark.parametrize("phrase", RETIRED_PHRASES)
def test_retired_false_phrase_stays_deleted(phrase: str) -> None:
    # One failure per resurrection, named. Each of these was factually wrong at HEAD: the DB pool
    # acquire IS bounded, WP-L3-07 is closed, and there is no accept throttle anywhere in transports/.
    found = present_retired_phrases((phrase,), _resource_section())
    assert not found, (
        f"the retired (false) phrase {phrase!r} is back in the resource-management section of "
        "docs/CONNECTIONS.md"
    )


@pytest.mark.parametrize("truth", REQUIRED_TRUTHS)
def test_corrected_statement_is_present(truth: str) -> None:
    # Deleting a false sentence is only half the fix — the requirement scores what the doc SAYS about
    # behaviour at the limit and per-service timeouts, so the corrected statement must be there.
    assert truth.lower() in _resource_section().lower(), (
        f"the corrected statement {truth!r} is missing from the resource-management section of "
        "docs/CONNECTIONS.md"
    )


def test_resource_tables_cover_every_documented_hop() -> None:
    section = _resource_section()
    slices = {"table": section}
    tokens = dict.fromkeys(INFRA_HOPS, "table") | dict.fromkeys(CONNECTOR_TABLE_TOKENS, "table")
    missing = missing_tokens(tokens, slices)
    assert not missing, (
        "hop/setting token(s) named in the §5 communications inventory but absent from the "
        f"resource-management section of docs/CONNECTIONS.md: {missing}"
    )


def test_table_a_and_table_b_carry_the_same_rows() -> None:
    # 13.1.2 (concurrency + behaviour at the limit) and 13.1.3 (timeout/release/failure/retry) are
    # scored PER SERVICE. A hop present in one table and missing from the other is precisely the
    # omission that keeps re-opening these cells, so the row sets must match exactly and in order.
    section = _resource_section()
    a = table_row_labels(section, _TABLE_A)
    b = table_row_labels(section, _TABLE_B)
    assert a, "Table A has no data rows"
    assert a == b, (
        "Table A (13.1.2) and Table B (13.1.3) row sets differ — every hop must appear in BOTH.\n"
        f"only in A: {[x for x in a if x not in b]}\nonly in B: {[x for x in b if x not in a]}"
    )


def test_every_infra_hop_is_in_both_resource_tables() -> None:
    section = _resource_section()
    a = "\n".join(table_row_labels(section, _TABLE_A))
    b = "\n".join(table_row_labels(section, _TABLE_B))
    missing_a = missing_tokens(INFRA_HOPS, dict.fromkeys(set(INFRA_HOPS.values()), a))
    missing_b = missing_tokens(INFRA_HOPS, dict.fromkeys(set(INFRA_HOPS.values()), b))
    assert not missing_a, f"infra hop(s) with no Table A (13.1.2) row: {missing_a}"
    assert not missing_b, f"infra hop(s) with no Table B (13.1.3) row: {missing_b}"


def _connector_row_gaps(labels_a: list[str], labels_b: list[str]) -> list[str]:
    """Connector tokens with no row label in Table A and/or Table B."""
    gaps: list[str] = []
    for kind, fragments in sorted(CONNECTOR_ROW_TOKENS.items()):
        for fragment in fragments:
            in_a = any(fragment in label for label in labels_a)
            in_b = any(fragment in label for label in labels_b)
            if not (in_a and in_b):
                where = "A" if in_b else "B" if in_a else "A and B"
                gaps.append(f"{kind} ({fragment!r}): missing from Table {where}")
    return gaps


def test_every_connector_has_a_row_in_both_resource_tables() -> None:
    """The message-plane half of the 13.1.2/13.1.3 tables, driven off the LIVE registry.

    RULE: a registered connector needs a row in **both** resource tables. Completeness used to be
    asserted only over 20 curated ``INFRA_HOPS`` tokens plus 8 generic ``CONNECTOR_TABLE_TOKENS``
    settings names, and ``test_table_a_and_table_b_carry_the_same_rows`` compares A to B only — so
    deleting a service from BOTH tables was invisible. Verified by planting: removing the 18 rows for
    SFTP/FTP/FTPS, REST, SOAP, DICOMweb, the DICOM SCP/SCU, EMAIL, DIRECT and the UNC/SMB File
    endpoint produced **zero** failures. It also closes the asymmetry that let a NEW ``transports/``
    module force a §5.1 row and then stop.
    """
    import messagefoundry.transports  # noqa: F401  (import = registration)
    from messagefoundry.transports.base import _DESTINATIONS, _SOURCES

    registered = {kind.value for kind in set(_SOURCES) | set(_DESTINATIONS)}
    exempt = {kind.value for kind in _NO_SOCKET_CONNECTORS}
    assert set(CONNECTOR_ROW_TOKENS) == registered - exempt, (
        "CONNECTOR_ROW_TOKENS is out of step with the live connector registry: "
        f"{sorted(set(CONNECTOR_ROW_TOKENS) ^ (registered - exempt))}. A new connector needs rows in "
        "BOTH resource tables of docs/CONNECTIONS.md and a mapping here; a removed one needs its "
        "stale mapping gone."
    )
    section = _resource_section()
    gaps = _connector_row_gaps(
        table_row_labels(section, _TABLE_A), table_row_labels(section, _TABLE_B)
    )
    assert not gaps, (
        "registered connector(s) with no resource-strategy row — 13.1.2 (concurrency + behaviour at "
        f"the limit) and 13.1.3 (timeout/release/failure/retry) are scored PER SERVICE: {gaps}"
    )


def test_connector_row_checker_flags_a_planted_omission() -> None:
    """Proves the connector completeness check can fail — the earlier token list could not."""
    section = _resource_section()
    labels_a = table_row_labels(section, _TABLE_A)
    labels_b = table_row_labels(section, _TABLE_B)
    assert not _connector_row_gaps(labels_a, labels_b), "baseline is not clean"
    victim = "REST destination"
    mutated_a = [x for x in labels_a if victim not in x]
    mutated_b = [x for x in labels_b if victim not in x]
    assert len(mutated_a) == len(labels_a) - 1 and len(mutated_b) == len(labels_b) - 1
    gaps = _connector_row_gaps(mutated_a, mutated_b)
    assert gaps == [f"rest ({victim!r}): missing from Table A and B"], (
        f"deleting the {victim} rows from BOTH tables must be reported; got {gaps}"
    )


@pytest.mark.parametrize(
    ("anchor", "value", "provenance"),
    _import_code_defaults(),
    ids=lambda v: v if isinstance(v, str) else repr(v),
)
def test_documented_default_matches_the_code(
    anchor: str, value: float | int, provenance: str
) -> None:
    # Pin the DOC to the CODE, not to itself: the value is imported, and it must appear on the same
    # markdown row as its anchor token. Change the constant without the doc and this reds.
    section = _resource_section()
    assert value_on_anchor_line(anchor, value, section), (
        f"the resource-management section of docs/CONNECTIONS.md does not state {value:g} on a line "
        f"naming {anchor!r} — the default in {provenance} changed and the doc did not"
    )


# --- self-tests: the guard must actually catch a regression -------------------------------------


def test_checker_flags_a_planted_omission(tmp_path: Path) -> None:
    # Mirrors test_secret_rotation_inventory.test_scanner_flags_a_planted_secret: a doc slice missing
    # one known token must be reported as exactly that token, and nothing else.
    doc = tmp_path / "fake.md"
    doc.write_text(
        "### S\n| hop | note |\n| `ntp_peer` | probe |\n| `webhook_url` | alerts |\n",
        encoding="utf-8",
    )
    slices = {"s": doc.read_text(encoding="utf-8")}
    tokens = {"ntp_peer": "s", "webhook_url": "s", "smart_token_url": "s"}
    assert missing_tokens(tokens, slices) == ["smart_token_url"]


def test_checker_flags_a_planted_retired_phrase() -> None:
    planted = "…the pool acquire has no explicit acquire timeout yet (WP-L3-07)…"
    assert present_retired_phrases(RETIRED_PHRASES, planted) == [
        "no explicit acquire timeout",
        "WP-L3-07",
    ]
    assert present_retired_phrases(RETIRED_PHRASES, "bounded by `acquire_timeout` (30 s)") == []


def test_checker_flags_a_planted_table_divergence() -> None:
    section = (
        f"{_TABLE_A}\n"
        "| Service/hop | x |\n|---|---|\n| AD login | a |\n| Vault | b |\n\n"
        f"{_TABLE_B}\n"
        "| Service/hop | x |\n|---|---|\n| AD login | a |\n"
    )
    assert table_row_labels(section, _TABLE_A) == ["AD login", "Vault"]
    assert table_row_labels(section, _TABLE_B) == ["AD login"]


def test_value_anchor_check_rejects_a_near_miss() -> None:
    # "300" and "30.5" must NOT satisfy a documented default of 30, and the value must be on the
    # anchor's own line — otherwise the pin is decorative.
    assert value_on_anchor_line("acquire_timeout", 30.0, "| `acquire_timeout` default 30 s |")
    assert not value_on_anchor_line("acquire_timeout", 30.0, "| `acquire_timeout` default 300 s |")
    assert not value_on_anchor_line("acquire_timeout", 30.0, "| `acquire_timeout` |\n| 30 s |")


def test_slice_helper_fails_on_a_renamed_heading() -> None:
    with pytest.raises(AssertionError, match="missing from"):
        slice_between("## A\nbody\n## B\n", "## Renamed", "## B", where="fake")
    with pytest.raises(AssertionError, match="misordered"):
        slice_between("## B\nbody\n## A\n", "## A", "## B", where="fake")
