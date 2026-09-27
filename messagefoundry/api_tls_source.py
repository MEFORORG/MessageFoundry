# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Where the engine's API TLS material comes from, and where it mints its own (ADR 0172).

Stdlib-only, so both :mod:`messagefoundry.api.tls` (which serves with the material) and
:mod:`messagefoundry.tray` (which must verify it, and by ADR 0113 may not import ``api/`` or
``config/``) share ONE copy of the rule. Two copies had drifted before: keying the scheme on
``[api].tls_cert_file`` alone read the shipped default as cleartext (BACKLOG #1126).
"""

from __future__ import annotations

from typing import Literal

#: Where the material the API bind serves with comes from. ``upstream`` is the one source that is not
#: material at all -- a declared reverse proxy terminates TLS in front and the engine serves plaintext.
ApiTlsSource = Literal["operator", "generated", "upstream"]

#: The filename the engine mints its self-signed API certificate to, beside the store database.
GENERATED_CERT_NAME = "api-generated-cert.pem"


def api_tls_source(*, cert_file: str | None, tls_terminated_upstream: bool) -> ApiTlsSource:
    """The ORDER: an operator chain wins, a declared upstream terminator mints nothing, else generated.

    Takes the two settings rather than an ``ApiSettings``, so a caller that cannot afford the
    settings machinery -- the tray reads an untrusted, possibly-malformed service TOML and must
    degrade rather than raise -- shares the ordering without sharing the machinery.
    """
    if cert_file:
        return "operator"
    return "upstream" if tls_terminated_upstream else "generated"
