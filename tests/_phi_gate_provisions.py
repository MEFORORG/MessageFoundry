# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""What a `serve` fixture must PROVIDE to start clean, now that every instance carries patient data.

BACKLOG #1279 retired `[security].handles_real_patient_data = false`. One line used to buy a quiet
`serve --env dev` in a test that was probing something else entirely -- log levels, path anchoring,
console mounting -- and it did so by turning off nineteen start-up gates at once.

There is no such line now, so a fixture names the gates it needs. That is more typing and it is the
point: a test that reads :data:`PHI_GATE_PROVISIONS_TOML` can see exactly which protections its
scenario is standing down, and a reviewer can tell at a glance whether the test under it is still
measuring what its name says.

**This is a TEST-FIXTURE convenience, never a recommended operator configuration.** Three of the four
entries are audited loosenings that `security_loosenings()` reports and the serve gate warns about;
`docs/SECURITY-LOOSENING.md` is the operator-facing account of what each costs. A deployment reaches
for at most the one it needs.

Use :data:`PHI_GATE_PROVISIONS_TOML` when the fixture writes a `messagefoundry.toml`, and
:func:`setenv_phi_gate_provisions` when it drives the same settings through the environment.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    import pytest

#: Dotted keys throughout, so a fixture can concatenate this and still add its own `[section]`
#: headers without TOML redefining a table.
#:
#: * ``block_unlisted_outbound`` -- satisfies the unrestricted-egress refusal (declaring deny-by-default
#:   rather than an allowlist, since a fixture's destinations are usually assigned at run time).
#: * ``allow_unencrypted_phi`` + ``..._under_strict_enforcement`` -- the at-rest gate's audited opt-out,
#:   BOTH acks, because under the shipped ``enforcement = enforce`` keyless PHI is deliberately never one
#:   flag away (ADR 0140). A fixture that can just as easily set a key should do that instead.
#: * ``alerts.security_notifications_required`` -- accepts the pull-only security-event feed, so the
#:   fixture does not have to stand up an SMTP transport it never reads.
PHI_GATE_PROVISIONS_TOML = (
    "security.block_unlisted_outbound = true\n"
    "security.allow_unencrypted_phi = true\n"
    "security.allow_unencrypted_phi_under_strict_enforcement = true\n"
    "alerts.security_notifications_required = false\n"
)

#: The same, minus the `alerts.` line, for a fixture that declares its own `[alerts]` TABLE. TOML
#: refuses to declare a table twice, and a dotted `alerts.x` key counts as declaring it -- so a
#: fixture that configures a real SMTP transport must take this one and satisfy the notification gate
#: the honest way. Splitting the constant rather than dropping the line from both keeps the
#: distinction visible at the call site instead of leaving it to whoever debugs the TOML error.
PHI_GATE_PROVISIONS_NO_ALERTS_TOML = (
    "security.block_unlisted_outbound = true\n"
    "security.allow_unencrypted_phi = true\n"
    "security.allow_unencrypted_phi_under_strict_enforcement = true\n"
)

#: The same four, as the environment variables the loader reads. Kept beside the TOML deliberately:
#: two spellings of one list drift, and a fixture that sets three of four gets a refusal whose message
#: names a gate the author was not thinking about.
PHI_GATE_PROVISIONS_ENV: dict[str, str] = {
    "MEFOR_SECURITY_BLOCK_UNLISTED_OUTBOUND": "true",
    "MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI": "true",
    "MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI_UNDER_STRICT_ENFORCEMENT": "true",
    "MEFOR_ALERTS_SECURITY_NOTIFICATIONS_REQUIRED": "false",
}


def setenv_phi_gate_provisions(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set :data:`PHI_GATE_PROVISIONS_ENV` on the environment for one test."""
    for name, value in PHI_GATE_PROVISIONS_ENV.items():
        monkeypatch.setenv(name, value)
