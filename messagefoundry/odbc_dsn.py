# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Brace quoting and the TLS tail of a SQL Server ODBC Driver 18 connection string (BACKLOG #3714).

The SQL Server store (:func:`messagefoundry.store.sqlserver.connection_string`) and the DATABASE
connector (:func:`messagefoundry.transports.database._build_dsn`) both build their strings here.
``transports/`` may not import ``store/`` (``tests/test_dependency_boundaries.py``), so this is a
leaf module that imports nothing from the engine.

Two rules hold for every string built here:

* :func:`odbc_brace` quotes a free-text value, so a value holding ``;``, ``{``, ``}`` or ``=`` (a
  password, say) cannot add keywords (STORE-5).
* :func:`odbc_connection_string` puts the TLS keywords **last**. ODBC takes the last value of a
  repeated keyword, so nothing earlier in the string can weaken TLS.

What the pin does under ``Encrypt=strict``, and how far that was measured, is stated once, in the
``ssl_root_cert`` row of ``docs/CONFIGURATION.md``.
"""

from __future__ import annotations

from collections.abc import Sequence

__all__ = ["odbc_brace", "odbc_connection_string"]


def odbc_brace(value: str) -> str:
    """ODBC-quote ``value`` in braces, doubling any ``}`` inside it.

    Inside braces the driver reads ``;``, ``{`` and ``=`` as text, and ``}}`` as one ``}``, so an
    attacker-influenced value cannot end the value early and add a keyword."""
    return "{" + value.replace("}", "}}") + "}"


def odbc_connection_string(
    head: Sequence[str],
    *,
    encrypt: bool,
    trust_server_certificate: bool,
    pin: str | None = None,
) -> str:
    """Join ``head`` and the TLS tail into one ``;``-terminated ODBC connection string.

    ``head`` is every ``KEY=value`` part but the TLS ones, already quoted. The tail follows it:
    ``ServerCertificate`` when ``pin`` is set, then ``Encrypt`` and ``TrustServerCertificate``.
    ``Encrypt`` is ``strict`` when a pin is sent, and otherwise ``yes`` or ``no`` from ``encrypt``.

    A pin beside ``encrypt=False`` or ``trust_server_certificate=True`` raises ``ValueError``: the
    driver verifies nothing there, so the pin would look like a control and be none. No current
    caller passes that shape. The pin file's own checks are the caller's job, as
    :func:`messagefoundry.store.sqlserver.check_pinned_certificate` is the store's."""
    if pin and (not encrypt or trust_server_certificate):
        raise ValueError(
            "an ODBC ServerCertificate pin needs encrypt on and trust_server_certificate off; "
            "the driver verifies nothing on a weakened posture, so the engine sends no pin there"
        )
    tail = [f"ServerCertificate={odbc_brace(pin)}"] if pin else []
    tail.append(f"Encrypt={'strict' if pin else ('yes' if encrypt else 'no')}")
    tail.append(f"TrustServerCertificate={'yes' if trust_server_certificate else 'no'}")
    return ";".join([*head, *tail]) + ";"
