# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What a `serve` fixture must PROVIDE to start clean, now that every instance carries patient data.

BACKLOG #1279 retired `[security].handles_real_patient_data = false`. One line used to buy a quiet
`serve --env dev` in a test that was probing something else entirely -- log levels, path anchoring,
console mounting -- and it did so by turning off nineteen start-up gates at once.

There is no such line now, so a fixture names the gates it needs. That is more typing and it is the
point: a test that reads :data:`PHI_GATE_PROVISIONS_TOML` can see exactly which protections its
scenario is standing down, and a reviewer can tell at a glance whether the test under it is still
measuring what its name says.

**This is a TEST-FIXTURE convenience, never a recommended operator configuration.** Every entry but
the egress one is an audited loosening that `security_loosenings()` reports and the serve gate warns about;
`docs/SECURITY-LOOSENING.md` is the operator-facing account of what each costs. A deployment reaches
for at most the one it needs.

Use :data:`PHI_GATE_PROVISIONS_TOML` when the fixture writes a `messagefoundry.toml`, and
:func:`setenv_phi_gate_provisions` when it drives the same settings through the environment.

The bundles below are COMPOSED from the per-gate parts rather than written out one by one. Three
near-identical string literals is the drift this module exists to prevent: an edit lands in one, the
others keep the old line, and the difference between two bundles stops being the difference their
names claim.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pathlib import Path

    import pytest

#: Satisfies the unrestricted-egress refusal by declaring deny-by-default rather than an allowlist,
#: since a fixture's destinations are usually assigned at run time.
_EGRESS = "security.block_unlisted_outbound = true\n"

#: The at-rest gate's audited opt-out, BOTH acks, because under the shipped ``enforcement = enforce``
#: keyless PHI is deliberately never one flag away (ADR 0140). A fixture that can just as easily set a
#: store key should do that instead.
_AT_REST_ACKS = (
    "security.allow_unencrypted_phi = true\n"
    "security.allow_unencrypted_phi_under_strict_enforcement = true\n"
)

#: Accepts the pull-only security-event feed, so a fixture does not have to stand up an SMTP transport
#: it never reads.
_ALERTS_OPT_OUT = "alerts.security_notifications_required = false\n"

#: The per-tier retention acknowledgements (BACKLOG #1967) for the two warn-only tiers that ship with
#: no window: under the shipped `enforce` an instance refuses without a window or these. They are
#: `[security]` keys rather than `retention.*` windows on purpose: a dotted `retention.` key declares
#: the `[retention]` table, which would break every fixture that writes its own `[retention]` header.
#: The app-log and backup tiers need nothing here, because each applies only once a fixture sets a
#: `log_dir` or a backup destination, and such a fixture should set that tier's window beside it.
_RETENTION_ACKS = (
    "security.allow_keeping_transform_state_indefinitely = true\n"
    "security.allow_keeping_search_presets_indefinitely = true\n"
)

#: Dotted keys throughout, so a fixture can concatenate this and still add its own `[section]`
#: headers without TOML redefining a table.
PHI_GATE_PROVISIONS_TOML = _EGRESS + _AT_REST_ACKS + _RETENTION_ACKS + _ALERTS_OPT_OUT

#: The same, minus the `alerts.` line, for a fixture that declares its own `[alerts]` TABLE. TOML
#: refuses to declare a table twice, and a dotted `alerts.x` key counts as declaring it -- so a
#: fixture that configures a real SMTP transport must take this one and satisfy the notification gate
#: the honest way. Splitting the constant rather than dropping the line from both keeps the
#: distinction visible at the call site instead of leaving it to whoever debugs the TOML error.
PHI_GATE_PROVISIONS_NO_ALERTS_TOML = _EGRESS + _AT_REST_ACKS + _RETENTION_ACKS

# NO BUNDLE SUITS A TEST WHOSE SUBJECT IS THE AT-REST GATE, and none should be added. Both bundles
# carry `allow_unencrypted_phi_under_strict_enforcement`, so a test asserting that a MISSING ack
# refuses cannot take either -- it would provision away its own scenario and pass on whatever gate
# fired next. A third "no acks" bundle looks like the fix and is not: such a test still has to spell
# out the exact at-rest flags it is measuring, so the bundle saves nothing and invites the next author
# to reach for a shared constant here when the point is that this file's constants do not apply. See
# the `keyless-prod-phi-single-flag-refuses` row in tests/test_checks_gate_parity.py.

#: The same entries, as the environment variables the loader reads. Kept beside the TOML deliberately:
#: two spellings of one list drift, and a fixture that sets all but one gets a refusal whose message
#: names a gate the author was not thinking about.
PHI_GATE_PROVISIONS_ENV: dict[str, str] = {
    "MEFOR_SECURITY_BLOCK_UNLISTED_OUTBOUND": "true",
    "MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI": "true",
    "MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI_UNDER_STRICT_ENFORCEMENT": "true",
    "MEFOR_SECURITY_ALLOW_KEEPING_TRANSFORM_STATE_INDEFINITELY": "true",
    "MEFOR_SECURITY_ALLOW_KEEPING_SEARCH_PRESETS_INDEFINITELY": "true",
    "MEFOR_ALERTS_SECURITY_NOTIFICATIONS_REQUIRED": "false",
}


def setenv_phi_gate_provisions(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set :data:`PHI_GATE_PROVISIONS_ENV` on the environment for one test."""
    for name, value in PHI_GATE_PROVISIONS_ENV.items():
        monkeypatch.setenv(name, value)


#: BACKLOG #1967, for a fixture that asserts a QUIET start: windows on the two warn-only tiers that
#: ship with none, set through the environment so no `[retention]` table is declared. Windows rather
#: than :data:`_RETENTION_ACKS`, because an acknowledgement is an audited loosening and writes to the
#: very streams such a test reads. Test-only in the sense this module states: for transform state
#: the operator's answer is the acknowledgement, since a state window deletes by write time.
RETENTION_WINDOWS_ENV: dict[str, str] = {
    "MEFOR_RETENTION_STATE_MAX_AGE_DAYS": "30",
    "MEFOR_RETENTION_SEARCH_PRESET_DAYS": "30",
}


def setenv_retention_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set :data:`RETENTION_WINDOWS_ENV` on the environment for one test."""
    for name, value in RETENTION_WINDOWS_ENV.items():
        monkeypatch.setenv(name, value)


#: Only the at-rest opt-out, for a KEYLESS fixture that is not `serve`. Since BACKLOG #1916 every
#: command that opens a fresh store with no key is refused without it -- `backup`, `admin-unlock`,
#: `audit-anchor` and the rest -- because its first audit row would start a keyless chain. Same caveat
#: as the bundles: a fixture that can just as easily set a store key should do that instead. Dotted
#: keys, so it must come BEFORE any `[section]` header in the TOML it is prepended to.
AT_REST_OPT_OUT_TOML = _AT_REST_ACKS
AT_REST_OPT_OUT_ENV: dict[str, str] = {
    name: value
    for name, value in PHI_GATE_PROVISIONS_ENV.items()
    if name.startswith("MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI")
}


def setenv_at_rest_opt_out(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set :data:`AT_REST_OPT_OUT_ENV` on the environment for one test."""
    for name, value in AT_REST_OPT_OUT_ENV.items():
        monkeypatch.setenv(name, value)


#: BACKLOG #1966 (owner ruling R4 (a), ADR 0200): an enforcing PHI start refuses without off-box
#: forwarding configured as verified TLS to a non-loopback collector. The gate reads configuration
#: only, so the collector need not exist: `siem.invalid` is a reserved name that never resolves, and
#: the forwarder reports that at ERROR as a permanent failure and starts without itself. The CRL is
#: there because the forwarder's #1498 revocation guard refuses verified TLS with no revocation
#: check under `enforce`, and nothing attests past it.
VERIFIED_LOG_FORWARDING_HOST = "siem.invalid"


def make_syslog_ca_and_crl(dir_path: Path) -> str:
    """A CA bundled with its own fresh CRL -- it loads only where the same CA is loaded first
    (BACKLOG #1890). Synthetic, no PHI. Returns the PEM path, usable as both CA and CRL file."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.UTC)
    day = datetime.timedelta(days=1)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-syslog-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - day)
        .not_valid_after(now + 365 * day)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.subject)
        .last_update(now - 2 * day)
        .next_update(now + 30 * day)
        .sign(key, hashes.SHA256())
    )
    path = dir_path / "syslog_ca_and_crl.pem"
    path.write_bytes(
        ca.public_bytes(serialization.Encoding.PEM) + crl.public_bytes(serialization.Encoding.PEM)
    )
    return str(path)


def verified_log_forwarding_env(bundle: str) -> dict[str, str]:
    """The environment that satisfies the #1966 gate, given a CA+CRL bundle path."""
    return {
        "MEFOR_LOGGING_FORWARD_HOST": VERIFIED_LOG_FORWARDING_HOST,
        "MEFOR_LOGGING_FORWARD_PROTOCOL": "tls",
        "MEFOR_LOGGING_FORWARD_TLS_CA_FILE": bundle,
        "MEFOR_LOGGING_FORWARD_TLS_CRL_FILE": bundle,
    }


def setenv_verified_log_forwarding(monkeypatch: pytest.MonkeyPatch, bundle: str) -> None:
    """Set :func:`verified_log_forwarding_env` on the environment for one test."""
    for name, value in verified_log_forwarding_env(bundle).items():
        monkeypatch.setenv(name, value)
