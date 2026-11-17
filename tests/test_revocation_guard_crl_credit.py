# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One rule decides whether a CRL may relax a revocation guard (vault BACKLOG #4912, #2977 item 11).

``crl_credited`` in ``config/tls_policy.py`` is that rule: the context verifies the peer, consults
a CRL, and does not skip validity-period checks. At least ``RevocationHopGuard.capture`` and the
Vault and proxy legs in ``transports/strict_requests.py`` read it; until this change those two legs
read ``context_checks_revocation`` alone. The leg tests below hand each leg a relaxed context.

The scan fails a read of ``context_checks_revocation`` by that name anywhere in the engine package
except inside the module-level ``crl_credited``. It reads names, not values, so a guard that reads
the CRL flag another way (the raw flag bits, a stored reference, ``getattr``) passes it.
"""

from __future__ import annotations

import ast
import ssl
from pathlib import Path

import pytest

from messagefoundry.config.tls_policy import (
    HopPosture,
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
_ENFORCING = HopPosture(enforcing=True)


def _context(*, crl: bool, relaxed: bool, verifies: bool = True) -> ssl.SSLContext:
    """A client context with the CRL flag, the time-check relaxation and verification as asked.

    Setting the flags is enough here: every predicate reads them and nothing dials."""
    ctx = ssl.create_default_context()
    if crl:
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    if relaxed:
        relax_verify_expiry(ctx, host="partner.example")
    if not verifies:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
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


def test_no_context_and_a_non_verifying_context_earn_no_credit() -> None:
    assert crl_credited(None) is False
    ctx = _context(crl=True, relaxed=False, verifies=False)
    assert context_checks_revocation(ctx) is True
    assert crl_credited(ctx) is False


@pytest.mark.parametrize("relaxed", [False, True])
def test_the_vault_leg_reads_the_rule(relaxed: bool) -> None:
    """The adapter's kept CRL read, the Vault leg's input. Red with ``context_checks_revocation``
    in place of ``crl_credited`` at that read, on the relaxed arm."""
    from messagefoundry.transports.strict_requests import StrictReplyAdapter

    ctx = _context(crl=True, relaxed=relaxed)
    adapter = StrictReplyAdapter(
        connector="Vault test hop",
        ssl_context_factory=lambda: ctx,
        revocation_attested=False,
        attestation_section="store",
    )
    assert adapter._checks_revocation() is not relaxed


@pytest.mark.parametrize("relaxed", [False, True])
def test_the_proxy_leg_reads_the_rule(relaxed: bool) -> None:
    """An enforcing proxy leg crosses on a CRL only when the context checks time. Red with
    ``context_checks_revocation`` in place of ``crl_credited`` there, on the relaxed arm."""
    from messagefoundry.transports.strict_requests import (
        VaultHopRefused,
        _refuse_an_unrevoked_proxy_leg,
    )

    def leg() -> None:
        _refuse_an_unrevoked_proxy_leg(
            _context(crl=True, relaxed=relaxed),
            "proxy.example",
            connector="Vault test hop",
            revocation_attested=False,
            attestation_section="store",
            posture=_ENFORCING,
        )

    if relaxed:
        with pytest.raises(VaultHopRefused):
            leg()
    else:
        leg()


def _rule_body(tree: ast.Module) -> set[int]:
    """The node ids inside the one module-level ``crl_credited``; asserts there is exactly one."""
    rules = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == _RULE]
    assert len(rules) == 1, f"expected one module-level def {_RULE}, found {len(rules)}"
    return {id(inner) for inner in ast.walk(rules[0])}


def _bare_reads(rel: str, source: str) -> list[str]:
    """Each read of ``context_checks_revocation`` by name in ``source`` outside the rule itself:
    a name, an attribute, or an import of it. The def itself is not a read."""
    tree = ast.parse(source)
    allowed = _rule_body(tree) if rel == _POLICY else set()
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
    scanned: list[str] = []
    for path in sorted(_PACKAGE.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if _NAME not in source:
            continue
        rel = path.relative_to(_ROOT).as_posix()
        scanned.append(rel)
        reads.extend(_bare_reads(rel, source))
    # A floor, so a moved package or a broken glob cannot pass over nothing.
    assert _POLICY in scanned, scanned
    assert not reads, (
        f"{_NAME} read outside {_RULE}: {reads}. A guard that credits a CRL reads {_RULE}, which "
        "also refuses the credit on a context that skips validity-period checks (ADR 0173 §13)."
    )


def test_the_scan_flags_each_shape() -> None:
    """Negative controls: each shape the scan names fails, in another module and in
    ``tls_policy.py`` outside the rule, and a second def of the rule is refused."""
    shapes = {
        "call": "def f(c):\n    return context_checks_revocation(c)\n",
        "import": "from messagefoundry.config.tls_policy import context_checks_revocation\n",
        "attribute": "def f(tp, c):\n    return tp.context_checks_revocation(c)\n",
    }
    for shape, source in shapes.items():
        assert _bare_reads("messagefoundry/transports/x.py", source), shape
    rule = "def crl_credited(c):\n    return context_checks_revocation(c)\n"
    assert _bare_reads(_POLICY, rule) == []
    outside = rule + "def other(c):\n    return context_checks_revocation(c)\n"
    assert _bare_reads(_POLICY, outside) == [f"{_POLICY}:4"]
    with pytest.raises(AssertionError, match="expected one module-level def"):
        _bare_reads(_POLICY, rule + "class K:\n    def crl_credited(self):\n        pass\n" + rule)
