# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The retracted "nobody can sign in before ``provision-admin``" claim, as one pattern (BACKLOG #1133).

A Windows sign-in is not refused for want of an Administrator: on a new store it creates a directory
account with no role. So nobody can MANAGE such an engine, but somebody can sign in. Two suites refuse
the old claim, ``tests/test_docs_security_pathways.py`` over the docs and
``tests/test_start_without_an_administrator.py`` over the engine's log line and CLI help, so the
pattern lives here rather than being written twice.

``SIGN_IN_VERB`` is the act of signing in, in the spellings the tree uses: "sign in", "signs in",
"sign into", "sign-in", "signin", "log in", "login", "log on". It leaves out "signed in" and "logged
in", which describe a state ("nobody is signed in") rather than who is able to sign in. It also leaves
out "sign-in lock": ADR 0197's lock is a noun phrase, and "no way past a sign-in lock" is a true
sentence about lockout, not the retracted claim.

``SIGN_IN_CLAIM`` reads one clause: nobody, no one or no way, then within 40 characters a
``SIGN_IN_VERB``. The span is bounded so a clause that says "nobody" and, much later, mentions sign-in
for an unrelated reason does not read as the claim.
"""

from __future__ import annotations

import re

__all__ = ["SIGN_IN_ANY_TENSE", "SIGN_IN_CLAIM", "SIGN_IN_VERB", "rejoin_wrapped_hyphens"]

SIGN_IN_VERB = re.compile(
    r"\b(?:sign(?:s|ing)?[ -]?in(?:to)?|log(?:s|ging)?[ -]?(?:in|on)(?:to)?)\b"
    r"(?![ -]?lock(?:s|out|outs)?\b)",
    re.IGNORECASE,
)

#: The verb in any tense, the states included. For a claim about WHEN a password crosses the wire,
#: "every user who signed in" is the same claim as "every user who signs in".
SIGN_IN_ANY_TENSE = re.compile(
    SIGN_IN_VERB.pattern + r"|\b(?:signed|logged)[ -]?(?:in|on)\b", re.IGNORECASE
)

# "no one" is not "no one-time password": the lookahead keeps the hyphenated compound out.
SIGN_IN_CLAIM = re.compile(
    r"\b(?:nobody|no one(?!-)|no way)\b[^.;]{0,40}?(?:" + SIGN_IN_VERB.pattern + ")",
    re.IGNORECASE,
)


def rejoin_wrapped_hyphens(text: str) -> str:
    """``text`` with a hyphen split by a line wrap joined again, then its whitespace collapsed.

    ``argparse`` wraps help with ``break_on_hyphens``, so "sign-in" can come out as "sign-" at the end
    of one line and "in" at the start of the next. Collapsing whitespace alone leaves "sign- in", which
    no spelling above matches, so the result would depend on the terminal width the test ran at. Only
    a hyphen that ENDS a line is joined, so spaced text such as "pre- and post-" is left alone."""
    return " ".join(re.sub(r"(\w-)[ \t]*\r?\n\s*(?=\w)", r"\1", text).split())
