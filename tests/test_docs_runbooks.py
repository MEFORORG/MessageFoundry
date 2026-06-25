# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Docs-contract guards for the DB-TLS CA-import + cert-rotation runbooks (hardening H5/M11).

These pin the *operator-facing* contract so it can't silently regress into the exact footgun the
runbook exists to retire — an operator disabling certificate validation
(``TrustServerCertificate=true``) instead of trusting the DB CA. The standards basis is NIST SP
800-52r2 (validate the full chain to a trusted CA; rotate before expiry), HIPAA §164.312(e)(1)
(transmission security), and CWE-295 (improper certificate validation).

There is no engine code path here — the artifacts are Markdown runbooks plus an elevated-PowerShell
helper — so the guard is a structural assertion over those files, not a behavioral test.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_DEPLOY_DB = _ROOT / "docs" / "DEPLOY-SERVER-DB.md"
_IMPORT_SCRIPT = _ROOT / "scripts" / "service" / "import-db-ca.ps1"

# The supported full-chain-trust anchor for ODBC 18 (no connection-string CA-file keyword).
_MACHINE_STORE = r"LocalMachine\Root"


def _deploy_db_text() -> str:
    return _DEPLOY_DB.read_text(encoding="utf-8")


def test_runbook_has_machine_store_ca_import_section() -> None:
    """The runbook documents importing the DB CA into the Windows machine trust store."""
    text = _deploy_db_text()
    assert "## 5. DB-TLS trust" in text, "DB-TLS trust runbook section is missing"
    assert _MACHINE_STORE in text, (
        "runbook must name the LocalMachine\\Root machine store (ODBC 18 has no CA-file keyword)"
    )
    # Must steer away from the per-user store, which the service principal can't read.
    assert "CurrentUser" in text, (
        "runbook should contrast the machine store with the per-user store"
    )


def test_runbook_names_both_backends() -> None:
    """Both server backends are addressed (Postgres file-pin OR machine store; SQL Server machine only)."""
    text = _deploy_db_text()
    assert "PostgreSQL" in text
    assert "SQL Server" in text
    # Postgres has the file-pin alternative; SQL Server is machine-store only.
    assert "ssl_root_cert" in text


def test_runbook_documents_make_before_break_overlap() -> None:
    """CA/cert rotation is make-before-break with an overlap window (no validation outage)."""
    text = _deploy_db_text().lower()
    assert "make-before-break" in text, "rotation runbook must describe make-before-break rotation"
    assert "overlap" in text, "rotation runbook must describe an overlap window"
    # The concrete mechanics for each backend.
    assert "multi-root pem bundle" in text, "Postgres overlap = multi-root PEM bundle"
    assert "add-new-then-remove-old" in text, "SQL Server overlap = add-new-then-remove-old"


def test_runbook_never_recommends_disabling_validation() -> None:
    """The runbook must NOT offer disabling validation as a remedy.

    Every mention of ``TrustServerCertificate=true`` / ``trust_server_certificate = true`` must sit in
    a prohibiting context (the same line or an adjacent line says "never" / "not the answer" / "no
    `TrustServerCertificate`"), never as a fix. We scan each mention with its neighbours as context.
    """
    lines = _deploy_db_text().splitlines()
    # Markers that, in the *neighbourhood* of a mention, prove it's a prohibition not a fix.
    prohibitions = ("never", "not the answer", "not** the answer", "no `trustservercertificate`")
    for i, line in enumerate(lines):
        low = line.lower()
        if "trustservercertificate=true" in low or "trust_server_certificate = true" in low:
            window = " ".join(lines[max(0, i - 2) : i + 3]).lower()
            assert any(marker in window for marker in prohibitions), (
                f"mention of disabling validation lacks a prohibition nearby: {line!r}"
            )


def test_import_script_targets_machine_store() -> None:
    """The helper imports into LocalMachine\\Root (the machine store), not the per-user store."""
    assert _IMPORT_SCRIPT.exists(), "import-db-ca.ps1 helper is missing"
    script = _IMPORT_SCRIPT.read_text(encoding="utf-8")
    # The store the import actually targets is bound to the machine root store...
    assert '$StoreLocation = "Cert:\\LocalMachine\\Root"' in script, (
        "helper must bind its import target to the machine root store"
    )
    # ...and the import call uses that variable (never a hardcoded per-user store).
    assert "-CertStoreLocation $StoreLocation" in script
    assert "Import-Certificate" in script
    # Requires elevation — part of the operator contract for writing the machine store.
    assert "Administrator" in script


def test_runbook_cites_transit_security_standards() -> None:
    """Cite NIST 800-52r2 / HIPAA 164.312(e)(1) / CWE-295 (not the SDS)."""
    text = _deploy_db_text()
    assert "800-52r2" in text
    assert "164.312(e)(1)" in text
    assert "CWE-295" in text
