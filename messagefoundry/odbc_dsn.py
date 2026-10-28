# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Brace quoting and the TLS tail of a SQL Server ODBC Driver 18 connection string (BACKLOG #3714).

The SQL Server store (:func:`messagefoundry.store.sqlserver.connection_string`) and the DATABASE
connector (:func:`messagefoundry.transports.database._build_dsn`) both build their strings here.
``transports/`` may not import ``store/`` (``tests/test_dependency_boundaries.py``), so this is a
leaf module that imports nothing from the engine.

Two rules hold for every string built here:

* :func:`odbc_brace` quotes a free-text value, so a value holding ``;``, ``{``, ``}`` or ``=`` (a
  password, say) cannot add keywords (STORE-5). It does not refuse a control character.
* :func:`odbc_connection_string` puts the TLS keywords **last**, after every other part.

The two builders used to say the tail wins because ODBC keeps the last value of a repeated keyword.
Microsoft's ODBC reference for ``SQLDriverConnect`` says a driver uses the FIRST occurrence, and
Microsoft's SQL Server driver has not been measured here either way. So the position is not the
guard against a second TLS keyword. The guard is that every head part is either a fixed keyword or
a quoted or validated value, so no head part can carry one.

What the pin does under ``Encrypt=strict``, and how far that was measured, is stated once, in the
``ssl_root_cert`` row of ``docs/CONFIGURATION.md``.
"""

from __future__ import annotations

__all__ = ["odbc_brace", "odbc_connection_string"]


def odbc_brace(value: str) -> str:
    """ODBC-quote ``value`` in braces, doubling any ``}`` inside it.

    Inside braces the driver reads ``;``, ``{`` and ``=`` as text, and ``}}`` as one ``}``, so an
    attacker-influenced value cannot end the value early and add a keyword."""
    return "{" + value.replace("}", "}}") + "}"


def odbc_connection_string(
    head: list[str],
    *,
    encrypt: bool,
    trust_server_certificate: bool,
    pin: str | None = None,
) -> str:
    """Join ``head`` and the TLS tail into one ``;``-terminated ODBC connection string.

    ``head`` is every ``KEY=value`` part but the TLS ones, already quoted. A list, so a joined
    string cannot type-check here. The tail follows it: ``ServerCertificate`` when ``pin`` is set,
    then ``Encrypt`` and ``TrustServerCertificate``. ``Encrypt`` is ``strict`` when a pin is sent,
    and otherwise ``yes`` or ``no`` from ``encrypt``.

    A pin beside ``encrypt=False`` or ``trust_server_certificate=True`` raises ``ValueError``. The
    caller asked for a weakened hop, and a pin sends ``Encrypt=strict``, which Microsoft documents
    as ignoring ``TrustServerCertificate``. So the string would quietly turn on encryption or
    verification the caller turned off, and the two settings would disagree. No current caller
    passes that shape. The pin file's own checks are the caller's job, as
    :func:`messagefoundry.store.sqlserver.check_pinned_certificate` is the store's."""
    if pin and (not encrypt or trust_server_certificate):
        raise ValueError(
            "an ODBC ServerCertificate pin needs encrypt on and trust_server_certificate off: "
            "a pin sends Encrypt=strict, which would override the weakened posture asked for"
        )
    tail = [f"ServerCertificate={odbc_brace(pin)}"] if pin else []
    tail.append(f"Encrypt={'strict' if pin else ('yes' if encrypt else 'no')}")
    tail.append(f"TrustServerCertificate={'yes' if trust_server_certificate else 'no'}")
    return ";".join([*head, *tail]) + ";"
