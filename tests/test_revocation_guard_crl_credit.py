# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One rule decides whether a CRL may relax a revocation guard (vault BACKLOG #4912, #2977 item 11).

``crl_no_credit`` in ``config/tls_policy.py`` is that rule, and ``crl_credited`` its yes-or-no
form: the context sets ``CERT_REQUIRED``, does not skip validity-period checks, and consults a CRL.
At least ``RevocationHopGuard.capture`` and the Vault and proxy legs in
``transports/strict_requests.py`` read it; until this change those two legs read
``context_checks_revocation`` alone. The leg tests below hand each leg a relaxed context. The guard
words its record from the same reason, so a hop whose context does not set ``CERT_REQUIRED`` is
never called verified and is never offered a CRL.

The scan fails a read of ``context_checks_revocation`` by that name anywhere in the engine package
except inside the module-level ``crl_no_credit``. It reads names, not values, so a guard that reads
the CRL flag another way (the raw flag bits, a stored reference, ``getattr``) passes it.
"""

from __future__ import annotations

import ast
import ssl
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config import tls_policy
from messagefoundry.config.tls_policy import (
    EXPIRY_RELAXED_WAYS_ACROSS,
    UNVERIFIED_WAYS_ACROSS,
    CrlNoCredit,
    HopDisposition,
    HopPosture,
    InsecureHopRefused,
    RevocationHopGuard,
    context_checks_revocation,
    crl_credited,
    crl_no_credit,
    relax_verify_expiry,
    skips_validity_period,
)

_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE = _ROOT / "messagefoundry"
_NAME = "context_checks_revocation"
_POLICY = "messagefoundry/config/tls_policy.py"
_RULE = "crl_no_credit"
_ENFORCING = HopPosture(enforcing=True)


def _context(
    *, crl: bool, relaxed: bool, verifies: bool = True, mode: ssl.VerifyMode = ssl.CERT_NONE
) -> ssl.SSLContext:
    """A client context with the CRL flag, the time-check relaxation and verification as asked.
    ``verifies=False`` sets ``mode``, ``CERT_NONE`` unless the caller names another.

    Setting the flags is enough here: every predicate reads them and nothing dials."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if crl:
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    if relaxed:
        relax_verify_expiry(ctx, host="partner.example")
    if not verifies:
        if mode == ssl.CERT_NONE:
            ctx.check_hostname = False
        ctx.verify_mode = mode
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
    assert crl_no_credit(None) is CrlNoCredit.NO_CRL
    ctx = _context(crl=True, relaxed=False, verifies=False)
    assert context_checks_revocation(ctx) is True
    assert crl_credited(ctx) is False
    assert crl_no_credit(ctx) is CrlNoCredit.UNVERIFIED


def test_only_cert_required_earns_credit() -> None:
    """``CERT_OPTIONAL`` earns no credit; only ``CERT_REQUIRED`` does, as ``verifies_peer_fully``
    asks (vault BACKLOG #4912). Red with a rule that refuses only ``CERT_NONE``."""
    optional = _context(crl=True, relaxed=False, verifies=False, mode=ssl.CERT_OPTIONAL)
    assert optional.verify_mode == ssl.CERT_OPTIONAL
    assert context_checks_revocation(optional) is True
    assert crl_credited(optional) is False
    assert crl_no_credit(optional) is CrlNoCredit.UNVERIFIED
    # The control: the same context with CERT_REQUIRED is credited.
    assert crl_credited(_context(crl=True, relaxed=False)) is True


def test_the_reasons_come_in_order() -> None:
    """A context that fails several conditions gets the first: not CERT_REQUIRED, then the
    skipped time check, then no CRL."""
    assert crl_no_credit(_context(crl=False, relaxed=True, verifies=False)) is (
        CrlNoCredit.UNVERIFIED
    )
    assert crl_no_credit(_context(crl=False, relaxed=True)) is CrlNoCredit.EXPIRY_RELAXED
    assert crl_no_credit(_context(crl=False, relaxed=False)) is CrlNoCredit.NO_CRL
    assert crl_no_credit(_context(crl=True, relaxed=False)) is None


@pytest.mark.parametrize(
    ("relaxed", "verifies", "credited"),
    [(False, True, True), (True, True, False), (False, False, False), (True, False, False)],
)
def test_capture_reads_the_rule(relaxed: bool, verifies: bool, credited: bool) -> None:
    """A guard handed a context with a CRL credits it only as the rule does. The non-verifying arm
    is red with the bare ``context_checks_revocation`` read capture used before this change."""
    guard = RevocationHopGuard.capture(
        host="partner.example",
        cell="test hop",
        description="test hop",
        attested=False,
        context=_context(crl=True, relaxed=relaxed, verifies=verifies),
        connection=None,
    )
    assert guard.crl_checked is credited


@pytest.mark.parametrize(
    ("relaxed", "verifies", "remedy"),
    [
        (False, True, None),
        (True, True, EXPIRY_RELAXED_WAYS_ACROSS),
        (False, False, UNVERIFIED_WAYS_ACROSS),
        (True, False, UNVERIFIED_WAYS_ACROSS),
    ],
)
def test_capture_offers_no_crl_where_none_is_credited(
    relaxed: bool, verifies: bool, remedy: str | None
) -> None:
    """A hop whose context verifies no peer is not told a CRL would admit it (vault BACKLOG
    #4912), relaxed or not: ``EXPIRY_RELAXED_WAYS_ACROSS`` offers removing ``tls_allow_expired``
    so a CRL can admit the hop, which cannot work there either. The non-verifying arms are red
    when capture keeps the connection-shaped default or the relaxed one. A remedy the caller
    passes is kept."""
    ctx = _context(crl=False, relaxed=relaxed, verifies=verifies)

    def capture(ways_across: str | None = None) -> RevocationHopGuard:
        return RevocationHopGuard.capture(
            host="partner.example",
            cell="test hop",
            description="test hop",
            attested=False,
            context=ctx,
            ways_across=ways_across,
            connection=None,
        )

    assert capture().ways_across == remedy
    assert capture("own remedy").ways_across == "own remedy"


_UNVERIFIED_ARMS = [
    pytest.param(False, ssl.CERT_NONE, id="none"),
    pytest.param(True, ssl.CERT_NONE, id="none-relaxed"),
    pytest.param(False, ssl.CERT_OPTIONAL, id="optional"),
]


def _unverified_guard(relaxed: bool, mode: ssl.VerifyMode, **over: Any) -> RevocationHopGuard:
    kwargs: dict[str, Any] = {
        "host": "10.0.0.5",
        "cell": "test hop",
        "description": "test hop",
        "attested": False,
        "context": _context(crl=True, relaxed=relaxed, verifies=False, mode=mode),
        "posture": _ENFORCING,
        "connection": "OB_TEST",
    }
    kwargs.update(over)
    return RevocationHopGuard.capture(**kwargs)


@pytest.mark.parametrize(("relaxed", "mode"), _UNVERIFIED_ARMS)
def test_an_unverified_refusal_calls_nothing_verified_and_offers_no_crl(
    relaxed: bool, mode: ssl.VerifyMode
) -> None:
    """The refusal on a hop whose context does not set ``CERT_REQUIRED`` does not say the peer
    certificate is verified, offers no CRL and no removal of ``tls_allow_expired``, and names the
    attestation, which does cross it (vault BACKLOG #4912). Red with the guard keyed on
    ``expiry_relaxed`` alone, as before."""
    guard = _unverified_guard(relaxed, mode)
    assert guard.no_credit is CrlNoCredit.UNVERIFIED
    assert guard.disposition() is HopDisposition.REFUSE
    with pytest.raises(InsecureHopRefused) as exc:
        guard.enforce_construction()
    text = str(exc.value)
    assert "verified" not in text.replace("CERT_REQUIRED", ""), text
    assert "crl_file" not in text, text
    assert "remove tls_allow_expired" not in text, text
    assert UNVERIFIED_WAYS_ACROSS in text
    # The control: the same hop with CERT_REQUIRED and no CRL keeps the plain words.
    plain = RevocationHopGuard.capture(
        host="10.0.0.5",
        cell="test hop",
        description="test hop",
        attested=False,
        context=_context(crl=False, relaxed=False),
        posture=_ENFORCING,
        connection="OB_TEST",
    )
    with pytest.raises(InsecureHopRefused, match="the peer certificate is verified"):
        plain.enforce_construction()


@pytest.mark.parametrize(("relaxed", "mode"), _UNVERIFIED_ARMS)
def test_an_attested_unverified_hop_crosses_and_its_line_does_not_say_verified(
    relaxed: bool, mode: ssl.VerifyMode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The attestation the remedy names does cross such a hop, and the crossing record does not
    call it a verified TLS hop (vault BACKLOG #4912). The disposition is unchanged."""
    lines: list[dict[str, Any]] = []
    monkeypatch.setattr(tls_policy, "log_attested_crossing", lambda _log, **kw: lines.append(kw))
    # The caller's flag does not change the wording on such a context.
    guard = _unverified_guard(
        relaxed, mode, attested=True, attested_reason="partner PKI", expiry_relaxed=relaxed
    )
    assert guard.disposition() is HopDisposition.ALLOW
    guard.enforce_construction()
    assert len(lines) == 1
    assert "verified" not in lines[0]["crossing"].replace("CERT_REQUIRED", "")
    assert "the peer certificate is verified" not in lines[0]["detail"]
    assert "chain's signatures are verified" not in lines[0]["detail"]


def test_a_guard_without_cert_required_cannot_be_built_crediting_a_crl() -> None:
    import dataclasses

    guard = _unverified_guard(False, ssl.CERT_NONE)
    with pytest.raises(ValueError, match="CERT_REQUIRED"):
        dataclasses.replace(guard, crl_checked=True)


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
    assert adapter._checks_revocation() is (not relaxed)


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
    """The node ids inside the one module-level ``crl_no_credit``; asserts there is exactly one."""
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
        "also refuses the credit on a context without CERT_REQUIRED or one that skips "
        "validity-period checks (ADR 0173 §13)."
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
    rule = "def crl_no_credit(c):\n    return context_checks_revocation(c)\n"
    assert _bare_reads(_POLICY, rule) == []
    outside = rule + "def other(c):\n    return context_checks_revocation(c)\n"
    assert _bare_reads(_POLICY, outside) == [f"{_POLICY}:4"]
    with pytest.raises(AssertionError, match="expected one module-level def"):
        _bare_reads(_POLICY, rule + "class K:\n    def crl_no_credit(self):\n        pass\n" + rule)
