# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the provider-agnostic auth core (permissions, identity, policy, tokens, passwords)."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from messagefoundry.auth import (
    AuthProvider,
    Identity,
    PasswordPolicy,
    Permission,
    Role,
    hash_password,
    hash_token,
    mint_token,
    needs_rehash,
    permissions_for_roles,
    verify_password,
)
from messagefoundry.auth.permissions import BUILTIN_ROLE_PERMISSIONS


def test_administrator_has_every_permission() -> None:
    assert BUILTIN_ROLE_PERMISSIONS[Role.ADMINISTRATOR] == frozenset(Permission)


def test_permissions_union_across_roles() -> None:
    perms = permissions_for_roles([Role.VIEWER, Role.AUDITOR])
    assert Permission.MESSAGES_READ in perms  # from Viewer
    assert Permission.AUDIT_READ in perms  # from Auditor
    assert Permission.MESSAGES_VIEW_RAW not in perms  # neither grants PHI raw


def test_no_roles_grant_nothing() -> None:
    assert permissions_for_roles([]) == frozenset()


def test_deployment_and_coding_roles_are_scoped() -> None:
    deploy = permissions_for_roles([Role.DEPLOYMENT])
    assert Permission.CONFIG_DEPLOY in deploy
    assert Permission.CODE_EDIT not in deploy
    coding = permissions_for_roles([Role.CODING])
    assert Permission.CODE_EDIT in coding
    assert Permission.CONFIG_DEPLOY not in coding


def test_identity_build_resolves_permissions_and_has() -> None:
    ident = Identity.build(
        user_id="u1", username="alice", auth_provider=AuthProvider.LOCAL, roles=[Role.OPERATOR]
    )
    assert ident.has(Permission.CONNECTIONS_CONTROL)
    assert not ident.has(Permission.USERS_MANAGE)
    assert ident.auth_provider is AuthProvider.LOCAL
    assert ident.roles == frozenset({Role.OPERATOR})


def test_password_policy_accepts_strong_and_flags_weak() -> None:
    policy = PasswordPolicy()  # ASVS 5.0 defaults: min 15, classes OFF, breach + context screening
    assert policy.violations("a-long-unguessable-passphrase") == []
    weak = policy.violations("short")
    assert any("15 characters" in v for v in weak)  # length-first
    # character classes are opt-in now, not mandatory by default
    assert policy.violations("alllowercaseandlongenough") == []
    assert PasswordPolicy(require_symbol=True).violations("alllowercaseandlongenough") == [
        "contain a symbol"
    ]


def test_password_policy_screens_breached_and_context() -> None:
    policy = PasswordPolicy()
    # a known-common password (short — set a low min_length to isolate the breach check)
    assert "not be a common or breached password" in PasswordPolicy(min_length=6).violations(
        "letmein"
    )
    # app/vendor terms are rejected even inside an otherwise-long password
    assert "not contain application or vendor terms" in policy.violations(
        "my-messagefoundry-passphrase"
    )
    # both screens are individually switchable off
    assert PasswordPolicy(min_length=6, check_breached=False).violations("letmein") == []
    assert policy.violations("my-corepoint-passphrase-long") and not PasswordPolicy(
        check_context=False
    ).violations("my-corepoint-passphrase-long")


def test_password_policy_rejects_username_in_password() -> None:
    policy = PasswordPolicy()  # check_username on by default
    # The user's own username inside an otherwise-fine password is rejected (6.2.11) — including the
    # common "username + suffix" pattern, which exact-equality would miss.
    assert "not contain your username" in policy.violations(
        "jsmith-favorite-passphrase", username="jsmith"
    )
    assert "not contain your username" in policy.violations(
        "Jsmith2026!longenough", username="jsmith"
    )
    # A password that doesn't embed the username passes.
    assert policy.violations("an-unrelated-passphrase", username="jsmith") == []
    # Short usernames (< 4 chars) are not substring-matched (false-positive guard).
    assert policy.violations("alxander-the-great-pass", username="al") == []
    # No username context (e.g. bootstrap generation) → the check is skipped.
    assert "not contain your username" not in policy.violations("jsmith-passphrase-long")
    # Switchable off.
    assert (
        PasswordPolicy(check_username=False).violations(
            "jsmith-favorite-passphrase", username="jsmith"
        )
        == []
    )


def test_operator_breach_corpus_plaintext(tmp_path: Path) -> None:
    corpus = tmp_path / "extra-plain.txt"
    corpus.write_text("Hunter2-The-Long-One\nanother-leaked-passphrase\n", encoding="utf-8")
    policy = PasswordPolicy(breach_corpus_file=str(corpus))
    # Case-insensitive membership against the operator corpus (augments the bundled corpus).
    assert "not be a common or breached password" in policy.violations("hunter2-the-long-one")
    assert policy.violations("a-totally-novel-passphrase") == []  # in neither corpus


def test_operator_breach_corpus_hibp_sha1(tmp_path: Path) -> None:
    pw = "leaked-but-long-enough-pass"
    digest = hashlib.sha1(pw.encode(), usedforsecurity=False).hexdigest().upper()
    corpus = tmp_path / "hibp-hashes.txt"  # HIBP export format: <40-hex>:<count>
    corpus.write_text(f"{digest}:42\n{'0' * 40}:1\n", encoding="utf-8")
    policy = PasswordPolicy(breach_corpus_file=str(corpus))
    assert "not be a common or breached password" in policy.violations(pw)
    assert policy.violations("a-different-unleaked-pass") == []


def test_operator_breach_corpus_missing_file_is_noop(tmp_path: Path) -> None:
    # A configured-but-unreadable corpus must not break password checks (best-effort degrade).
    policy = PasswordPolicy(breach_corpus_file=str(tmp_path / "does-not-exist.txt"))
    assert policy.violations("a-perfectly-fine-passphrase") == []


def test_password_hash_roundtrip_and_rejections() -> None:
    h = hash_password("Str0ng!Passphrase")
    assert h != "Str0ng!Passphrase"  # never stored in clear
    assert verify_password(h, "Str0ng!Passphrase") is True
    assert verify_password(h, "wrong") is False
    assert verify_password("not-a-valid-hash", "x") is False
    assert needs_rehash(h) is False


def test_tokens_are_unique_and_only_the_hash_is_storable() -> None:
    t1, t2 = mint_token(), mint_token()
    assert t1 != t2  # unguessable + unique
    assert hash_token(t1) == hash_token(t1)  # deterministic lookup
    assert hash_token(t1) != t1  # only the hash is ever persisted
    assert len(hash_token(t1)) == 64  # sha256 hex digest


# --- BACKLOG #1134 (ASVS 6.2.4): the corpus must clear the POLICY, not merely be large -----------


def test_breach_corpus_meets_the_asvs_6_2_4_policy_matching_bar() -> None:
    """ASVS 6.2.4 asks for at least the top 3000 passwords WHICH MATCH THE APPLICATION'S POLICY.

    A big corpus is not the requirement: at the shipped `password_min_length = 15`, only **18** of the
    original 10,000 entries reached that length -- an entry shorter than the minimum can only reject
    what the length clause already rejects, so it added nothing. The bar is on the POLICY-CLEARING
    subset, and this pins it so a future corpus swap cannot quietly drop back under it.

    `check_breached` is off HERE FOR THE SAME REASON IT WAS OFF WHEN THE CORPUS WAS BUILT: with it on,
    every entry rejects itself against the corpus it belongs to, and this would measure nothing.
    """
    from messagefoundry.auth.policy import _common_passwords

    matches_policy = PasswordPolicy(check_breached=False, check_username=False)
    clearing = [e for e in _common_passwords() if not matches_policy.violations(e)]
    assert len(clearing) >= 3000, (
        f"only {len(clearing)} corpus entries clear the shipped policy; ASVS 6.2.4 wants at least "
        "3000. A corpus can grow and still fail this -- the entries must MATCH THE POLICY"
    )


def test_breach_corpus_growth_did_not_over_block_or_regress() -> None:
    """The two directions a corpus change can break, asserted together.

    Growing a screen is only safe if it still rejects what it did before AND has not started
    rejecting things it should accept. A test for either alone would pass a corpus that swallowed
    every password, or one that had quietly emptied.
    """
    policy = PasswordPolicy()
    # REGRESSION arm: a short known-common value is still screened (isolated from the length clause).
    assert "not be a common or breached password" in PasswordPolicy(min_length=6).violations(
        "letmein"
    )
    # COVERAGE arm: a long breached value is now screened, which is what #1134 bought.
    assert "not be a common or breached password" in policy.violations("1234567891234567")
    # OVER-BLOCK arm: a strong passphrase that is not in the corpus is still accepted.
    assert policy.violations("correct-horse-battery-staple-xyz") == []


# --- BACKLOG #1134: the prose the corpus rebuild falsified, and a gate so it cannot rot again -----
#
# The #1134 build grew the bundled list well past the original ten thousand entries. Seven shipped
# sites still described it as a "top-10k" list afterwards -- a module docstring, an OPERATOR-FACING
# startup warning, a settings comment, two rows of the configuration reference and two paragraphs of
# the security narrative. None of them is a control, so none of them broke; they simply asserted a
# number that had stopped being true, in the places an operator reads to decide whether to configure
# a larger corpus. That is the failure mode this file's other #1134 gate cannot see: it measures the
# CORPUS, and prose is not the corpus.
#
# The fix is to keep the counts in exactly one place (``common_passwords.NOTICE``, beside the data)
# and let every other site describe the list without a size. The gate below pins that.

#: Size claims about the BUNDLED list, in the forms the seven falsified sites actually used. The
#: upstream member is legitimately named ``Pwdb_top-10000.txt`` in the NOTICE -- a filename, not a
#: claim about what ships -- so the patterns deliberately require the ``k`` or the thousands comma,
#: and ``test_stale_corpus_size_checker_detects_planted_claims`` proves that allowance is a real
#: exclusion rather than an accident of the current text.
_STALE_CORPUS_SIZE_CLAIMS = (
    re.compile(r"top[-\s]?10\s?k\b", re.IGNORECASE),
    re.compile(r"top[-\s]?10,000", re.IGNORECASE),
    re.compile(r"10,?000[-\s]entry", re.IGNORECASE),
)

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _corpus_prose_sites() -> list[Path]:
    """Where a bundled-corpus size claim can live.

    The engine half is a GLOB, not a list, so the same wording landing in a module written next year
    is caught rather than missed; the doc half is pinned because these two files are the operator-
    facing pair. ``tests/`` is deliberately NOT scanned -- the planted-claim self-test below has to
    contain the banned strings to do its job, and a scanner that reads its own fixtures reports
    itself forever.
    """
    sites = sorted((_REPO_ROOT / "messagefoundry").rglob("*.py"))
    sites.append(_REPO_ROOT / "messagefoundry" / "auth" / "data" / "common_passwords.NOTICE")
    sites.append(_REPO_ROOT / "docs" / "CONFIGURATION.md")
    sites.append(_REPO_ROOT / "docs" / "SECURITY.md")
    return sites


def _stale_size_claims(text: str, label: str) -> list[str]:
    """``"<label>:<lineno>: <line>"`` for every line asserting a stale bundled-corpus size."""
    hits: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if any(pattern.search(line) for pattern in _STALE_CORPUS_SIZE_CLAIMS):
            hits.append(f"{label}:{number}: {line.strip()}")
    return hits


def test_no_shipped_site_asserts_a_stale_bundled_corpus_size() -> None:
    """No engine module or operator document may describe the bundled list by a size.

    The counts belong to ``common_passwords.NOTICE``, which sits beside the data and is regenerated
    with it. Anywhere else they are a copy that goes stale silently -- which is exactly what
    happened, in seven places at once, and what nothing in CI noticed.
    """
    hits: list[str] = []
    for path in _corpus_prose_sites():
        if not path.exists():  # a source tree may legitimately not carry every doc
            continue
        hits += _stale_size_claims(
            path.read_text(encoding="utf-8"), path.relative_to(_REPO_ROOT).as_posix()
        )
    assert not hits, (
        "these sites still size the bundled breach corpus in prose, and the #1134 rebuild made the "
        "number wrong: " + "; ".join(hits) + ". Describe the list without a size and let "
        "messagefoundry/auth/data/common_passwords.NOTICE carry the counts."
    )


def test_stale_corpus_size_checker_detects_planted_claims() -> None:
    """The positive control for the zero above, in the same checker.

    A scan that finds nothing is indistinguishable from a scan that cannot see. Every wording the
    seven real sites used is planted here and must be reported -- and the upstream FILENAME must
    not be, because the NOTICE has to be free to name the member it drew from.
    """
    planted = "\n".join(
        (
            "the bundled offline top-10k common-password list",
            "augments the bundled top 10k list",
            "a bundled offline top-10,000 list",
            "a bundled 10,000-entry offline corpus",
        )
    )
    reported = _stale_size_claims(planted, "planted")
    assert len(reported) == 4, f"the checker missed a real wording: {reported}"

    allowed = "1. Pwdb_top-10000.txt      all 10,000 entries (the original bundle)"
    assert _stale_size_claims(allowed, "notice") == [], (
        "naming the upstream member file must stay legal, or the NOTICE cannot cite its own source"
    )


def test_operator_reference_warns_that_a_short_corpus_entry_buys_nothing() -> None:
    """The caveat an operator needs before pointing ``password_breach_corpus_file`` at a big list.

    ``PasswordPolicy.violations`` records the length clause and the corpus clause independently, so
    a below-minimum entry does not fail the check -- it just cannot reject anything the length rule
    would have let through. A site that reads only the line count of a general-purpose leaked-
    password list will therefore over-estimate what it bought, which is the same mistake #1134
    found in the bundled list. Both setting names come from the live model, so a rename reds this
    rather than leaving a doc row pointing at a field that no longer exists.
    """
    from messagefoundry.config.settings import AuthSettings

    doc = _REPO_ROOT / "docs" / "CONFIGURATION.md"
    if not doc.exists():  # pragma: no cover - present in every checkout that ships docs
        return
    setting = "password_breach_corpus_file"
    floor = "password_min_length"
    assert {setting, floor} <= set(AuthSettings.model_fields), "settings renamed; update this guard"
    # Match the row whose FIRST cell is the setting, not any line that mentions it: neighbouring
    # rows cross-reference this one, and a substring match silently graded the wrong row.
    lead = f"| `{setting}` |"
    row = next(
        (line for line in doc.read_text(encoding="utf-8").splitlines() if line.startswith(lead)),
        None,
    )
    assert row is not None, f"docs/CONFIGURATION.md no longer has a row starting {lead!r}"
    assert floor in row, (
        f"the `{setting}` row must say that an entry shorter than {floor} adds no coverage. "
        "Without it the reference invites sizing a corpus by its line count, which is what left "
        "the bundled list contributing 18 usable entries (BACKLOG #1134)."
    )
