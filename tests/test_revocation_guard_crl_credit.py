# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One rule decides whether a CRL may relax a revocation guard (vault BACKLOG #4912, #2977 item 11).

``crl_credited`` in ``config/tls_policy.py`` is that rule: the context consults a CRL and does not
skip validity-period checks. ``RevocationHopGuard.capture`` and the Vault and proxy legs in
``transports/strict_requests.py`` read it. Until this change the Vault and proxy legs read
``context_checks_revocation`` alone, so a relaxed context handed to them would have earned the
credit ``capture`` refuses. The scan below fails a call to ``context_checks_revocation`` by its
name anywhere in the package except inside ``crl_credited``. It reads names, not values, so a call
through ``getattr`` or a stored reference passes it; review owns those.
"""

from __future__ import annotations

import ast
import ssl
from pathlib import Path

import pytest

from messagefoundry.config import tls_policy
from messagefoundry.config.tls_policy import (
    RevocationHopGuard,
    context_checks_revocation,
    crl_credited,
    relax_verify_expiry,
    skips_validity_period,
)

_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE = _ROOT / "messagefoundry"
_NAME = "context_checks_revocation"
_POLICY = "messagefoundry/config/tls_policy.py"
_RULE = "crl_credited"


def _context(*, crl: bool, relaxed: bool) -> ssl.SSLContext:
    """A verifying client context with the CRL flag and the time-check relaxation set as asked.

    Setting the flag is enough here: both predicates read ``verify_flags`` and nothing dials."""
    ctx = ssl.create_default_context()
    if crl:
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    if relaxed:
        relax_verify_expiry(ctx, host="partner.example")
    return ctx


@pytest.mark.parametrize(
    ("crl", "relaxed", "credited"),
    [(False, False, False), (True, False, True), (False, True, False), (True, True, False)],
)
def test_a_crl_is_credited_only_on_a_context_that_checks_time(
    crl: bool, relaxed: bool, credited: bool
) -> None:
    ctx = _context(crl=crl, relaxed=relaxed)
    # The inputs are what they claim, so a pass is not a pass over two unset flags.
    assert context_checks_revocation(ctx) is crl
    assert skips_validity_period(ctx) is relaxed
    assert crl_credited(ctx) is credited


def test_no_context_is_no_credit() -> None:
    assert crl_credited(None) is False


def test_capture_reads_the_rule() -> None:
    """A guard handed a relaxed context with a CRL credits none, with no ``expiry_relaxed``."""

    def guard(ctx: ssl.SSLContext) -> RevocationHopGuard:
        return RevocationHopGuard.capture(
            host="partner.example",
            cell="test hop",
            description="test hop",
            attested=False,
            context=ctx,
            connection=None,
        )

    assert guard(_context(crl=True, relaxed=False)).crl_checked is True
    assert guard(_context(crl=True, relaxed=True)).crl_checked is False


def _bare_reads(rel: str, source: str) -> list[str]:
    """Each use of ``context_checks_revocation`` by name in ``source`` outside the rule itself.

    A use is a call, an import of the name, or an attribute read of it. Inside ``tls_policy.py``
    the one allowed place is the body of ``crl_credited``; the def itself is not a use."""
    tree = ast.parse(source)
    allowed: set[int] = set()
    if rel == _POLICY:
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == _RULE:
                allowed.update(id(inner) for inner in ast.walk(node))
    found: list[str] = []
    for node in ast.walk(tree):
        if id(node) in allowed:
            continue
        if (
            (isinstance(node, ast.Name) and node.id == _NAME)
            or (isinstance(node, ast.Attribute) and node.attr == _NAME)
            or (isinstance(node, ast.ImportFrom) and any(a.name == _NAME for a in node.names))
        ):
            found.append(f"{rel}:{node.lineno}")
    return found


def test_only_the_rule_reads_the_crl_flag_alone() -> None:
    reads: list[str] = []
    for path in sorted(_PACKAGE.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if _NAME not in source:
            continue
        reads.extend(_bare_reads(path.relative_to(_ROOT).as_posix(), source))
    assert not reads, (
        f"{_NAME} read outside {_RULE}: {reads}. A guard that credits a CRL reads {_RULE}, which "
        "also refuses the credit on a context that skips validity-period checks (ADR 0173 §13)."
    )


def test_the_scan_sees_the_rule_and_flags_each_shape() -> None:
    """Positive control: the real rule is found and allowed, and each shape the scan names fails."""
    policy = (_ROOT / _POLICY).read_text(encoding="utf-8")
    assert f"def {_RULE}(" in policy and f"{_NAME}(ctx)" in policy
    assert _bare_reads(_POLICY, policy) == []
    assert tls_policy.crl_credited is crl_credited
    shapes = {
        "call": "from x import y\ndef f(c):\n    return context_checks_revocation(c)\n",
        "import": "from messagefoundry.config.tls_policy import context_checks_revocation\n",
        "attribute": "def f(tp, c):\n    return tp.context_checks_revocation(c)\n",
    }
    for shape, source in shapes.items():
        assert _bare_reads("messagefoundry/transports/x.py", source), shape
    # The same call is a read in tls_policy.py too, outside the rule's body.
    outside = "def other(c):\n    return context_checks_revocation(c)\n"
    assert _bare_reads(_POLICY, outside) == [f"{_POLICY}:2"]
