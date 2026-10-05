# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The retracted "nobody can sign in before ``provision-admin``" claim, as one pattern (BACKLOG #1133).

A Windows sign-in is not refused for want of an Administrator: on a new store it creates a directory
account with no role. So nobody can MANAGE such an engine, but somebody can sign in. Two suites refuse
the old claim, ``tests/test_docs_security_pathways.py`` over the docs and
``tests/test_start_without_an_administrator.py`` over the engine's log line and CLI help, so the
pattern lives here rather than being written twice.

It reads one clause at a time: nobody, no one or no way, then within 40 characters a sign-in verb in
any of the spellings the tree uses ("sign in", "signs in", "sign into", "sign-in", "log in",
"log on"). The span is bounded so a clause that says "nobody" and, much later, "signed-in" for an
unrelated reason does not read as the claim.
"""

from __future__ import annotations

import re

__all__ = ["SIGN_IN_CLAIM"]

SIGN_IN_CLAIM = re.compile(
    r"\b(?:nobody|no one|no way)\b[^.;]{0,40}?"
    # "signed in" / "logged in" are left out on purpose: "nobody is signed in" describes a state,
    # true where SECURITY.md uses it, and is not a claim about who is able to sign in.
    r"\b(?:sign(?:s|ing)?[ -]?in(?:to)?|log(?:s|ging)?[ -]?(?:in|on)(?:to)?)\b",
    re.IGNORECASE,
)
