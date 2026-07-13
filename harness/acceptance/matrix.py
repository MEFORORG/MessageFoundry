# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The WIN2025 test matrix as data — the single source of truth the runner executes.

Each :class:`MatrixRow` mirrors one row of ``docs/testing/WIN2025-TEST-MATRIX.md`` and declares HOW
it is checked (:class:`Coverage`):

* ``PROBE``   — a live host/environment check in :mod:`harness.acceptance.probes` (the new code; the
  rows nothing else covers — ODBC driver present, firewall ports, GUI session, …). ``refs`` holds the
  single probe key.
* ``PYTEST``  — the existing suites that already assert this row. ``refs`` holds pytest node ids
  (file granularity); the server-DB ones self-skip off-server via their ``MEFOR_TEST_*`` gates, so the
  same matrix degrades cleanly from dev PC to the real box.
* ``HARNESS`` — driven by ``python -m harness …`` (load/failover); reported with the command to run
  (only auto-run with ``--run-harness``, since it needs a live engine).
* ``MANUAL``  — a human step the box itself gates (real AD/Kerberos domain login, NSSM install, the
  visual no-console-flash check). Reported MANUAL with instructions, never auto-passed.

Keep this list in lockstep with the markdown matrix; :mod:`tests.test_win2025_acceptance` guards that
every ``PROBE`` key is registered and every ``PYTEST`` node-id file exists on disk.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Status(str, Enum):
    """Outcome of a single matrix row. ``str`` mix-in so it serialises as its value."""

    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"  # not applicable / not reachable here (e.g. server-DB suite on the dev PC)
    MANUAL = "MANUAL"  # requires a human on the box; not auto-checkable
    ERROR = "ERROR"  # the check itself broke (bad node id, probe raised)


class Coverage(str, Enum):
    """How a row is exercised."""

    PROBE = "probe"
    PYTEST = "pytest"
    HARNESS = "harness"
    MANUAL = "manual"


# "Per-DB?" column values — `PER_DB` marks the rows that should be repeated once per reachable backend.
ONCE = "once"
PER_DB = "Per-DB x3"


@dataclass(frozen=True)
class MatrixRow:
    """One matrix row and how to check it."""

    id: str
    section: str
    title: str
    per_db: str
    coverage: Coverage
    #: PROBE → one probe key; PYTEST → pytest node ids; HARNESS → one command; MANUAL → unused.
    refs: tuple[str, ...] = ()
    notes: str = ""


# Section titles (A–H) mirror the markdown matrix headings.
SECTIONS: dict[str, str] = {
    "A": "Environment & prerequisites",
    "B": "Database backend setup & connectivity",
    "C": "Store functional parity (staged pipeline)",
    "D": "Transports / connectors (inbound + outbound)",
    "E": "HL7 / payload handling",
    "F": "Auth, RBAC, API, Console",
    "G": "HA / clustering & deployment",
    "H": "Performance & security validation",
}


def _row(
    id: str,
    title: str,
    per_db: str,
    coverage: Coverage,
    refs: tuple[str, ...] = (),
    notes: str = "",
) -> MatrixRow:
    return MatrixRow(
        id=id,
        section=id[0],
        title=title,
        per_db=per_db,
        coverage=coverage,
        refs=refs,
        notes=notes,
    )


# The store-parity rows share the same three suites: the SQLite suite always runs; the two server-DB
# suites self-skip unless MEFOR_TEST_SQLSERVER / MEFOR_TEST_POSTGRES (+ MEFOR_STORE_*) are set.
_STORE_SUITES = (
    "tests/test_store_backend.py",
    "tests/test_sqlserver_store.py",
    "tests/test_postgres_store.py",
)

MATRIX: tuple[MatrixRow, ...] = (
    # ---- A. Environment & prerequisites -----------------------------------------------------------
    _row(
        "A1",
        "Python 3.14+ + project .venv + requirements.lock present",
        ONCE,
        Coverage.PROBE,
        ("python_runtime",),
    ),
    _row(
        "A2",
        "Optional extras import: [postgres], [sqlserver], [dicom]",
        ONCE,
        Coverage.PROBE,
        ("optional_extras",),
    ),
    _row(
        "A3",
        "SQL Server ODBC Driver 18 installed & discoverable",
        ONCE,
        Coverage.PROBE,
        ("sqlserver_odbc_driver",),
    ),
    _row(
        "A4",
        "PostgreSQL client (asyncpg) imports & reports a version",
        ONCE,
        Coverage.PROBE,
        ("postgres_client",),
    ),
    _row(
        "A5",
        "Firewall rules for listener ports (MLLP/DICOM/TCP/API)",
        ONCE,
        Coverage.PROBE,
        ("firewall_ports",),
        "Bindability is auto-checked; external firewall rules are manual.",
    ),
    _row(
        "A6",
        "Service-account writable store/config/log dirs",
        ONCE,
        Coverage.PROBE,
        ("writable_dirs",),
        "Writability auto-checked; service-account ACLs are manual.",
    ),
    _row(
        "A7",
        "Console runs (Desktop Experience, PySide6)",
        ONCE,
        Coverage.PROBE,
        ("console_gui",),
        "Interactive GUI session confirmation is manual.",
    ),
    # ---- B. Database backend setup & connectivity -------------------------------------------------
    _row(
        "B1",
        "backend = sqlite|sqlserver|postgres opens cleanly",
        PER_DB,
        Coverage.PYTEST,
        _STORE_SUITES,
    ),
    _row("B2", "Schema auto-creates on first start", PER_DB, Coverage.PYTEST, _STORE_SUITES),
    _row(
        "B3",
        "Connection/auth from MEFOR_* env (no secrets in file)",
        PER_DB,
        Coverage.PYTEST,
        ("tests/test_settings.py", "tests/test_sqlserver_store.py", "tests/test_postgres_store.py"),
    ),
    _row(
        "B4",
        "Encryption at rest; key_provider byte-identical",
        PER_DB,
        Coverage.PYTEST,
        ("tests/test_store_encryption.py", "tests/test_keyprovider.py"),
    ),
    _row(
        "B5",
        "Off-box audit tee (single PHI-redaction path)",
        PER_DB,
        Coverage.PYTEST,
        ("tests/test_audit_offbox_tee.py",),
    ),
    _row(
        "B6",
        "Reconnect / transient-error handling under DB restart",
        PER_DB,
        Coverage.PYTEST,
        ("tests/test_task_resilience.py", "tests/test_connection_resilience.py"),
        "Live DB-restart drill on the box is manual.",
    ),
    # ---- C. Store functional parity (staged pipeline) ---------------------------------------------
    _row(
        "C1",
        "ingress->routed->outbound handoffs atomic; no loss/dup",
        PER_DB,
        Coverage.PYTEST,
        _STORE_SUITES,
    ),
    _row(
        "C2",
        "ACK-on-receipt: raw committed before ACK",
        PER_DB,
        Coverage.PYTEST,
        ("tests/test_ingest_time.py", "tests/test_reingress.py"),
    ),
    _row(
        "C3",
        "Disposition finalizer correctness",
        PER_DB,
        Coverage.PYTEST,
        ("tests/test_consistency.py", "tests/test_store_backend.py"),
    ),
    _row(
        "C4",
        "Strict per-lane FIFO ordering preserved",
        PER_DB,
        Coverage.PYTEST,
        ("tests/test_fifo_ordering.py",),
    ),
    _row(
        "C5",
        "reset_stale_inflight recovers every stage on startup",
        PER_DB,
        Coverage.PYTEST,
        ("tests/test_reingress.py", "tests/test_task_resilience.py"),
    ),
    _row(
        "C6",
        "Dead-letter capture + bulk replay",
        PER_DB,
        Coverage.PYTEST,
        ("tests/test_store_backend.py",),
    ),
    _row("C7", "Request/response (reply) capture", PER_DB, Coverage.PYTEST, _STORE_SUITES),
    _row(
        "C8",
        "Retry/back-off, error->dead-letter routing",
        PER_DB,
        Coverage.PYTEST,
        ("tests/test_delivery_settings.py", "tests/test_task_resilience.py"),
    ),
    # ---- D. Transports / connectors ---------------------------------------------------------------
    _row(
        "D1",
        "MLLP in + out, ACK/NAK modes, TLS",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_mllp_tls.py", "tests/test_mllp_encoding_override.py"),
    ),
    _row(
        "D2",
        "File in + out (Windows paths, atomic move)",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_connections_file.py",),
    ),
    _row(
        "D3",
        "RemoteFile SFTP/FTP in + out",
        ONCE,
        Coverage.MANUAL,
        (),
        "Needs a reachable SFTP/FTP endpoint; drive via the harness File panel.",
    ),
    _row(
        "D4", "TCP in + out (raw framing)", ONCE, Coverage.PYTEST, ("tests/test_tcp_transport.py",)
    ),
    _row(
        "D5",
        "X12 in + out (ISA/IEA framing, split)",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_x12_transport.py", "tests/test_x12_parsing.py"),
    ),
    _row(
        "D6",
        "DICOM C-STORE SCP inbound; SR->HL7 handler",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_dicom_scp.py", "tests/test_dicom_codec.py"),
    ),
    _row(
        "D7",
        "Database source + destination; db_lookup enrichment",
        PER_DB,
        Coverage.PYTEST,
        (
            "tests/test_database_connector_integration.py",
            "tests/test_database_transport.py",
            "tests/test_db_lookup.py",
        ),
    ),
    _row(
        "D8",
        "REST / SOAP / FHIR destinations",
        ONCE,
        Coverage.PYTEST,
        (
            "tests/test_rest_transport.py",
            "tests/test_soap_transport.py",
            "tests/test_fhir_transport.py",
        ),
    ),
    _row(
        "D9",
        "Timer + Loopback sources",
        ONCE,
        Coverage.HARNESS,
        ("python -m harness --list-scenarios",),
        "Exercise via the harness scenarios on the box.",
    ),
    _row(
        "D10",
        "Count-and-log: nothing accepted-and-dropped",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_consistency.py",),
    ),
    # ---- E. HL7 / payload handling ----------------------------------------------------------------
    _row(
        "E1",
        "Tolerant peek (python-hl7) routing",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_parsing.py",),
    ),
    _row(
        "E2",
        "Strict validation opt-in (hl7apy); explicit version",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_hl7schema.py",),
    ),
    _row(
        "E3",
        "Non-conformant input -> ERROR, no connection crash",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_parsing.py", "tests/test_message.py"),
    ),
    _row(
        "E4",
        "Payload-agnostic ingress (content_type selects path)",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_message.py", "tests/test_x12_parsing.py"),
    ),
    _row(
        "E5",
        "Binary carriage (mfb64:v1:) NUL-safe",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_binary_carriage.py",),
    ),
    _row(
        "E6",
        "Raw message preserved alongside transformed",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_store_backend.py",),
    ),
    # ---- F. Auth, RBAC, API, Console --------------------------------------------------------------
    _row(
        "F1",
        "Local (+ AD/LDAP/Kerberos) login",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_api_auth.py", "tests/test_auth_service.py", "tests/test_ad_group_scope.py"),
        "AD/Kerberos against a real domain is a manual on-box step.",
    ),
    _row(
        "F2",
        "Native TOTP MFA for local accounts (WP-14)",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_step_up.py", "tests/test_mfa.py"),
    ),
    _row(
        "F3",
        "Deny-by-default per-route RBAC; admin defense",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_channel_rbac.py", "tests/test_field_authz.py"),
    ),
    _row(
        "F4",
        "API binds 127.0.0.1; auth required; TLS",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_api_tls.py", "tests/test_inbound_bind.py"),
    ),
    _row(
        "F5",
        "Config reload confined to allow-listed roots",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_api_reload.py",),
    ),
    _row(
        "F6",
        "Console reaches engine over HTTP API only (web console + apiclient; PySide6 desktop console retired #103)",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_apiclient.py", "tests/test_dependency_boundaries.py"),
    ),
    _row(
        "F7",
        "No console-window flash on service poll (CREATE_NO_WINDOW)",
        ONCE,
        Coverage.PROBE,
        ("console_no_window",),
        "Static flag check is auto; the visual confirmation is manual.",
    ),
    _row(
        "F8",
        "PHI access audited with acting user",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_audit_integrity.py",),
    ),
    # ---- G. HA / clustering & deployment ----------------------------------------------------------
    _row(
        "G1",
        "NSSM service install/uninstall; autostart; crash-restart",
        ONCE,
        Coverage.MANUAL,
        (),
        "Run scripts/service/*.ps1 on the box; CI covers it via windows-service-smoke.",
    ),
    _row(
        "G2",
        "Active-passive leadership lease + leader-gated graph",
        PER_DB,
        Coverage.PYTEST,
        ("tests/test_cluster_lease.py",),
        "Real lease only on the server DBs (SQL Server/Postgres).",
    ),
    _row(
        "G3",
        "Failover under load; per-lane FIFO preserved",
        PER_DB,
        Coverage.PYTEST,
        ("tests/test_cluster_failover_sqlserver.py", "tests/test_cluster_failover_postgres.py"),
        "Also drivable via python -m harness --failover.",
    ),
    _row(
        "G4",
        "/cluster observability + alerts + dead-letters page",
        ONCE,
        Coverage.PYTEST,
        (
            "tests/test_cluster.py",
            "tests/test_alert_rules.py",
        ),
    ),
    _row(
        "G5",
        "SQLite single-node = byte-identical baseline",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_store_backend.py",),
    ),
    # ---- H. Performance & security validation -----------------------------------------------------
    _row(
        "H1",
        "Throughput baseline under load harness",
        PER_DB,
        Coverage.HARNESS,
        (
            "python -m harness --load fanout-baseline --db-backend <backend> --report-json out/load/baseline-<backend>.json",
            "python -m harness --load closed-loop --db-backend <backend> --report-json out/load/ceiling-<backend>.json",
        ),
        "Run once per reachable backend against a live engine: fanout-baseline = realistic-mix baseline, closed-loop = max-throughput ceiling.",
    ),
    _row(
        "H2",
        "No full PHI payloads at INFO+; redaction",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_redaction.py", "tests/test_logging.py"),
    ),
    _row(
        "H3",
        "Secrets only from MEFOR_* env; none in config/logs",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_secrets_dpapi.py", "tests/test_settings.py"),
    ),
    _row(
        "H4",
        "Off-box log shipping reachable from the server",
        ONCE,
        Coverage.PYTEST,
        ("tests/test_audit_offbox_tee.py",),
        "Network reachability to the collector is manual.",
    ),
)


def matrix_by_section() -> dict[str, list[MatrixRow]]:
    """Group :data:`MATRIX` rows by section letter, preserving order."""
    grouped: dict[str, list[MatrixRow]] = {letter: [] for letter in SECTIONS}
    for row in MATRIX:
        grouped.setdefault(row.section, []).append(row)
    return grouped


def pytest_node_ids() -> list[str]:
    """The de-duplicated set of pytest node ids referenced by all ``PYTEST`` rows (run order)."""
    seen: dict[str, None] = {}
    for row in MATRIX:
        if row.coverage is Coverage.PYTEST:
            for ref in row.refs:
                seen.setdefault(ref, None)
    return list(seen)


# Sanity-light: every row id is unique. (The full guard lives in the test module.)
assert len({r.id for r in MATRIX}) == len(MATRIX), "duplicate matrix row id"
