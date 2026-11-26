# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #8163, the residuals of #3471 that engine PR 2818 left on ``main``.

Item 2: the AD probe named any ``InsecureHopRefused`` whose traceback passed
``_refuse_ad_revocation`` as the LDAPS guard's refusal, so one the TLS context factory raised read
as the guard's, with the guard's remedy. Only the guard's own call counts now.

All material is synthetic. No PHI.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from messagefoundry.config.tls_policy import InsecureHopRefused
from tests.test_b3471_key_and_hop_refusal_text import _HOST, _escaping, _host_echoing

# --- item 2: only the guard's own call is the guard's refusal -------------------------------------


def test_a_hop_refusal_from_the_tls_context_is_not_named_as_the_guards() -> None:
    """Red before the fix: the refusal passed through ``_refuse_ad_revocation``, so the probe gave
    the guard's fixed text and its CRL remedy for an error the guard never raised."""
    from messagefoundry.auth import ldap
    from messagefoundry.config.settings import AuthSettings
    from messagefoundry.privilege_probes import _AD_GUARD_REFUSAL, _ad_why

    def context() -> None:
        raise _host_echoing()

    tls: Any = SimpleNamespace(handshake_context=context)
    settings = AuthSettings(ad_server="ldaps://dc.synthetic.test:636")
    refusal = _escaping(lambda: ldap._refuse_ad_revocation(settings, tls, None))
    assert type(refusal) is InsecureHopRefused, type(refusal)
    text = _ad_why(refusal)
    assert text != _AD_GUARD_REFUSAL
    assert text == "InsecureHopRefused"
    assert _HOST not in text
