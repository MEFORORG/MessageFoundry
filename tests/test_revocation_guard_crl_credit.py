# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The CRL-credit rule the outbound revocation guards read (vault BACKLOG #4912, #2977 item 11).

``crl_no_credit`` in ``config/tls_policy.py`` is that rule, and ``crl_credited`` its yes-or-no
form: the context's ``verify_mode`` is not ``CERT_NONE``, it does not skip validity-period
checks, and it consults a CRL.
At least ``RevocationHopGuard.capture`` and the Vault and proxy legs in
``transports/strict_requests.py`` read it; until this change those two legs read
``context_checks_revocation`` alone. The leg tests below hand each leg a relaxed context. The guard
words its record from the same reason. On a hop whose context's ``verify_mode`` is ``CERT_NONE``,
the records the guard writes do not call the hop verified where the caller's words say "verified"
(the tests below pin the shipped words and the punctuated shapes), and its default remedy offers
no CRL. The AI broker words its own record from the guard's reason; its own test pins that. A remedy the
caller passes is used as given, and can still offer one.

The scan fails a read of ``context_checks_revocation`` by that name anywhere in the engine package
except inside the module-level ``crl_no_credit``. It reads names, not values, so a guard that reads
the CRL flag another way (the raw flag bits, a stored reference, ``getattr``) passes it.
"""

from __future__ import annotations

import ast
import re
import ssl
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config import tls_policy
from messagefoundry.config.tls_policy import (
    EXPIRY_RELAXED_WAYS_ACROSS,
    PEER_NOT_VERIFIED_WAYS_ACROSS,
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
#: A record that calls its hop verified; "unverified" and "verify" do not match.
_VERIFIED = re.compile(r"\bverified\b", re.IGNORECASE)


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
    assert crl_no_credit(ctx) is CrlNoCredit.PEER_NOT_VERIFIED


def test_cert_optional_with_a_crl_is_credited_and_cert_none_is_not() -> None:
    """In client mode ``CERT_OPTIONAL`` enforces the chain and a loaded CRL, so a CRL on it is
    credited, as on main; ``CERT_NONE`` earns none (vault BACKLOG #4912). The optional arm is red
    with a rule that credits only ``CERT_REQUIRED``, as d119f22c36 did."""
    optional = _context(crl=True, relaxed=False, verifies=False, mode=ssl.CERT_OPTIONAL)
    assert optional.verify_mode == ssl.CERT_OPTIONAL
    assert context_checks_revocation(optional) is True
    assert crl_no_credit(optional) is None
    assert crl_credited(optional) is True
    none = _context(crl=True, relaxed=False, verifies=False, mode=ssl.CERT_NONE)
    assert none.verify_mode == ssl.CERT_NONE
    assert context_checks_revocation(none) is True
    assert crl_credited(none) is False
    assert crl_no_credit(none) is CrlNoCredit.PEER_NOT_VERIFIED
    # A guard handed the CERT_OPTIONAL context with a CRL crosses an enforcing posture unattested.
    guard = RevocationHopGuard.capture(
        host="10.0.0.5",
        cell="test hop",
        description="test hop",
        attested=False,
        context=optional,
        posture=_ENFORCING,
        connection="OB_TEST",
    )
    assert guard.crl_checked is True
    assert guard.disposition() is HopDisposition.ALLOW


def test_the_reasons_come_in_order() -> None:
    """A context that fails several conditions gets the first: not verifying the peer, then the
    skipped time check, then no CRL."""
    assert crl_no_credit(_context(crl=False, relaxed=True, verifies=False)) is (
        CrlNoCredit.PEER_NOT_VERIFIED
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
        (False, False, PEER_NOT_VERIFIED_WAYS_ACROSS),
        (True, False, PEER_NOT_VERIFIED_WAYS_ACROSS),
    ],
)
def test_capture_offers_no_crl_where_none_is_credited(
    relaxed: bool, verifies: bool, remedy: str | None
) -> None:
    """A hop whose context does not verify the peer is not told a CRL would admit it (vault
    BACKLOG #4912), relaxed or not: ``EXPIRY_RELAXED_WAYS_ACROSS`` offers removing
    ``tls_allow_expired`` so a CRL can admit the hop, which cannot work there either. The non-verifying arms are red
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


_PEER_NOT_VERIFIED_ARMS = [
    pytest.param(False, ssl.CERT_NONE, id="none"),
    pytest.param(True, ssl.CERT_NONE, id="none-relaxed"),
]


def _peer_not_verified_guard(
    relaxed: bool, mode: ssl.VerifyMode, **over: Any
) -> RevocationHopGuard:
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


@pytest.mark.parametrize(("relaxed", "mode"), _PEER_NOT_VERIFIED_ARMS)
def test_a_peer_not_verified_refusal_calls_nothing_verified_and_offers_no_crl(
    relaxed: bool, mode: ssl.VerifyMode
) -> None:
    """The refusal on a hop whose context does not verify the peer does not say the peer
    certificate is verified, offers no CRL, no removal of ``tls_allow_expired`` and no
    attestation, and names making the context verify the peer (vault BACKLOG #4912). The
    disposition still ALLOWs an attested hop; only the text changed. Red with the guard
    keyed on ``expiry_relaxed`` alone, as before."""
    guard = _peer_not_verified_guard(relaxed, mode)
    assert guard.no_credit is CrlNoCredit.PEER_NOT_VERIFIED
    assert guard.disposition() is HopDisposition.REFUSE
    with pytest.raises(InsecureHopRefused) as exc:
        guard.enforce_construction()
    text = str(exc.value)
    assert not _VERIFIED.search(text), text
    assert "crl_file" not in text, text
    assert "remove tls_allow_expired" not in text, text
    assert "tls_revocation_attested=true" not in text, text
    assert "tls_revocation_attested_reason" not in text, text
    assert "on this connection" not in text, text
    assert PEER_NOT_VERIFIED_WAYS_ACROSS in text
    # The lead says it once; the remedy does not say it again.
    assert text.count("does not verify the peer") == 1, text
    # The control: the same hop verifying the peer with no CRL keeps the plain words.
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


@pytest.mark.parametrize(("relaxed", "mode"), _PEER_NOT_VERIFIED_ARMS)
def test_an_attested_peer_not_verified_hop_crosses_and_its_line_does_not_say_verified(
    relaxed: bool, mode: ssl.VerifyMode, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An attested hop whose context does not verify the peer still crosses, as on main,
    and the crossing record does not call it a verified TLS hop (vault BACKLOG #4912). The
    disposition is unchanged; only the remedy stopped offering the attestation."""
    lines: list[dict[str, Any]] = []
    monkeypatch.setattr(tls_policy, "log_attested_crossing", lambda _log, **kw: lines.append(kw))
    # The caller's flag does not change the wording on such a context.
    guard = _peer_not_verified_guard(
        relaxed, mode, attested=True, attested_reason="partner PKI", expiry_relaxed=relaxed
    )
    assert guard.disposition() is HopDisposition.ALLOW
    guard.enforce_construction()
    assert len(lines) == 1
    assert not _VERIFIED.search(lines[0]["crossing"]), lines[0]
    assert not _VERIFIED.search(lines[0]["detail"]), lines[0]
    assert lines[0]["crossing"] == guard.crossing_lead


def _caller_words() -> list[tuple[str, str]]:
    """The literal words ``RevocationHopGuard.capture`` calls in the engine package pass as their
    ``cell`` or ``description``: each literal piece of the argument, an f-string's included, and a
    module-level string constant it names. A value bound any other way, such as rest.py's local
    ``description``, is not read here; the REST end-to-end test below covers that default.
    ``(where, text)`` pairs."""
    found: list[tuple[str, str]] = []
    for path in sorted(_PACKAGE.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if "RevocationHopGuard.capture(" not in source:
            continue
        rel = path.relative_to(_ROOT).as_posix()
        tree = ast.parse(source)
        constants = {
            target.id: node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        for call in ast.walk(tree):
            if not (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "capture"
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "RevocationHopGuard"
            ):
                continue
            for kw in call.keywords:
                if kw.arg not in ("cell", "description"):
                    continue
                for node in ast.walk(kw.value):
                    if isinstance(node, ast.Constant) and isinstance(node.value, str):
                        found.append((f"{rel}:{node.lineno}", node.value))
                    elif isinstance(node, ast.Name) and node.id in constants:
                        found.append((f"{rel}:{node.lineno}", constants[node.id]))
    return found


def test_no_callers_words_call_a_peer_not_verified_hop_verified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The literal ``cell`` and ``description`` words of the capture callers, through the guard,
    on a hop whose context does not verify the peer: neither the refusal nor the attested
    crossing line the guard writes says "verified" (vault BACKLOG #4912). The shipped words are
    joined by the shapes a caller could write next: "verified" before a comma, a closing
    parenthesis, or the end of the text. The AI broker's own record is not written by the guard;
    ``tests/test_ai_broker_revocation_guard.py`` covers it. Red with the guard writing the caller's
    words unchanged, and the punctuated shapes red with a rule that drops the word only before a
    space."""
    words = _caller_words() + [
        ("shape", "x (TLS verified, no revocation check)"),
        ("shape", "x (TLS verified)"),
        ("shape", "delivers over TLS that is verified"),
        ("shape", "x (Verified, TLS)"),
    ]
    # A floor, so a broken scan cannot pass over nothing: at least these callers say "verified".
    where = {w.split(":", 1)[0] for w, text in words if _VERIFIED.search(text)}
    for rel in (
        "messagefoundry/transports/rest.py",
        "messagefoundry/transports/mllp.py",
        "messagefoundry/auth/ldap.py",
        "messagefoundry/store/postgres.py",
    ):
        assert rel in where, (rel, sorted(where))
    mode = ssl.CERT_NONE
    lines: list[dict[str, Any]] = []
    monkeypatch.setattr(tls_policy, "log_attested_crossing", lambda _log, **kw: lines.append(kw))
    for at, text in words:
        refused = _peer_not_verified_guard(False, mode, cell=text, description=text)
        with pytest.raises(InsecureHopRefused) as exc:
            refused.enforce_construction()
        assert not _VERIFIED.search(str(exc.value)), (at, str(exc.value))
        lines.clear()
        _peer_not_verified_guard(
            False, mode, cell=text, description=text, attested=True, attested_reason="partner PKI"
        ).enforce_construction()
        assert len(lines) == 1, at
        assert not _VERIFIED.search(f"{lines[0]['crossing']} {lines[0]['detail']}"), (at, lines)
    # The control: on a hop that verifies the peer the caller's words are kept as given.
    kept = RevocationHopGuard.capture(
        host="10.0.0.5",
        cell="x (verified TLS, no revocation check)",
        description="delivers over verified https",
        attested=False,
        context=_context(crl=False, relaxed=False),
        connection=None,
    )
    assert kept.stated_cell == kept.cell
    assert kept.stated_description == kept.description


def test_the_rest_refusal_does_not_say_verified_on_a_peer_not_verified_opener() -> None:
    """The REST destination's own guard call, end to end, with an opener whose https context does
    not verify the peer: its "(verified TLS" cell and "over verified https" description reach the
    refusal without the word (vault BACKLOG #4912)."""
    from messagefoundry.config.tls_policy import active_hop_posture
    from messagefoundry.transports.rest import refuse_unrevoked_verified_hop

    ctx = _context(crl=True, relaxed=False, verifies=False, mode=ssl.CERT_NONE)
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    with active_hop_posture(_ENFORCING), pytest.raises(InsecureHopRefused) as exc:
        refuse_unrevoked_verified_hop(
            "https",
            "https://10.0.0.5/fhir",
            connector="REST destination",
            opener=opener,
            connection="OB_TEST",
        )
    text = str(exc.value)
    assert "REST destination (TLS, no revocation check)" in text, text
    assert not _VERIFIED.search(text), text


def test_a_guard_not_verifying_the_peer_cannot_be_built_crediting_a_crl() -> None:
    import dataclasses

    guard = _peer_not_verified_guard(False, ssl.CERT_NONE)
    with pytest.raises(ValueError, match="peer_not_verified cannot credit"):
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
        "also refuses the credit on a context whose verify_mode is CERT_NONE or one that skips "
        "validity-period checks (ADR 0173 §4.3)."
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
