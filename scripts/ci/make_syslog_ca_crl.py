#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Write a synthetic syslog CA+CRL PEM for a CI serve leg, and print its path (BACKLOG #1966).

An enforcing PHI start refuses without off-box forwarding configured as verified TLS to a
non-loopback collector (owner ruling R4 (a), ADR 0200). The gate reads configuration only, so a leg
points the forwarder at ``siem.invalid``, a reserved name that never resolves, and the engine starts
without the forwarder after reporting that at ERROR. The CRL is needed because the forwarder's #1498
revocation guard refuses verified TLS with no revocation check under ``enforce``.

The certificate code is the test suite's own (``tests/_phi_gate_provisions.py``), imported rather
than copied so the two cannot drift. Usage: ``python scripts/ci/make_syslog_ca_crl.py <out-dir>``.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests._phi_gate_provisions import make_syslog_ca_and_crl  # noqa: E402


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: make_syslog_ca_crl.py <out-dir>", file=sys.stderr)
        return 2
    out = Path(argv[0])
    out.mkdir(parents=True, exist_ok=True)
    print(make_syslog_ca_and_crl(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
