# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the provider-agnostic auth core (permissions, identity, policy, tokens, passwords)."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

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
    # Case-insensitive membership against the operator corpus (augments the bundled top-10k).
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
    bar: int = _corpus_generator().ASVS_6_2_4_BAR  # stated once, in the generator
    clearing = [e for e in _common_passwords() if not matches_policy.violations(e)]
    assert len(clearing) >= bar, (
        f"only {len(clearing)} corpus entries clear the shipped policy; ASVS 6.2.4 wants at least "
        f"{bar}. A corpus can grow and still fail this -- the entries must MATCH THE POLICY"
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


# --- BACKLOG #1433: the notice's numbers are GENERATED, so one gate replaces every hand-copied one --


def _corpus_generator() -> ModuleType:
    """Load the corpus generator by path. ``scripts/`` is not an importable package."""
    script = (
        Path(__file__).resolve().parents[1] / "scripts" / "security" / "build_password_corpus.py"
    )
    spec = importlib.util.spec_from_file_location("_build_password_corpus", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["_build_password_corpus"] = module
    spec.loader.exec_module(module)
    return module


def test_the_corpus_notice_is_a_fixed_point_of_its_generator(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """THE GATE. Every count and the digest in ``common_passwords.NOTICE`` is recomputed from the
    shipped corpus and must match what the notice records.

    This is ONE assertion covering what would otherwise be a pinned number per line -- the headline
    policy-clearing count, each row of the by-floor table, the line and distinct counts, the two-run
    split, and the digest. A per-number gate has to be written before it can catch anything, so it
    can only ever pin the numbers whoever wrote it thought of; this one catches a change to any
    recorded number including ones nobody has added yet.

    The remedy is a command, not arithmetic. Before #1433 there was no tool, so a red here told you
    to re-derive each count by hand -- which is how a wrong number survives a corpus change.
    """
    module = _corpus_generator()
    assert module.check(None) == 0, capsys.readouterr().err


def test_the_gate_sees_a_corpus_that_gained_one_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MADE TO FAIL ON PURPOSE. The gate is evidence only if it can see the change class it exists
    to catch.

    A fixed-point assertion is exactly as good as its ability to move, and a generator that read the
    notice instead of the corpus would pass the test above forever while measuring nothing. Adding
    one policy-clearing entry must change the block."""
    module = _corpus_generator()
    before = module.render_block(module.measure())

    planted = tmp_path / "common_passwords.txt"
    planted.write_bytes(module.CORPUS_PATH.read_bytes() + b"a-planted-passphrase-entry\n")
    monkeypatch.setattr(module, "CORPUS_PATH", planted)
    assert module.render_block(module.measure()) != before

    monkeypatch.undo()
    assert module.render_block(module.measure()) == before  # and it reads the path at call time


def test_the_corpus_keeps_its_sub_minimum_entries() -> None:
    """The entries BELOW the shipped floor are load-bearing and must not be tidied away.

    They are unreachable at ``password_min_length = 15`` -- the length clause rejects them first --
    which makes them look like 90 KB of dead weight to anyone reading the file at the shipped
    default. But the floor is an OPERATOR SETTING. A site that lowers it makes every short entry
    operative again, so deleting them would remove protection from exactly the configuration that
    needs it most. Asserted as a floor rather than a count so it survives a corpus refresh.
    """
    from messagefoundry.auth.policy import _common_passwords

    shipped = PasswordPolicy()
    # Deliberately NOT the ASVS bar, which is also 3000 and counts the opposite population: that one
    # counts entries CLEARING the floor, this one counts entries BELOW it. The collision is a
    # coincidence, and a reader who fuses them draws a wrong conclusion from either.
    sub_minimum_floor = 3000
    short = [e for e in _common_passwords() if len(e) < shipped.min_length]
    assert len(short) > sub_minimum_floor, (
        f"only {len(short)} corpus entries sit below the shipped {shipped.min_length}-character "
        "floor; a swap that dropped the short entries would silently weaken every deployment that "
        "has LOWERED password_min_length"
    )


def test_the_rebuild_reproduces_the_two_run_structure_from_upstream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ``--seclists`` arm, exercised against a FAKE SecLists root.

    That arm was the untested half, and it is where the one real defect in this work lived: the
    generator used to parse the upstream digests back out of the block it had itself rendered, and
    its prefix test also matched the corpus digest line -- so a source-less rebuild erased the
    provenance it existed to preserve. Nothing failed, because nothing ran this path.

    A real SecLists checkout is 8 MB and is deliberately not vendored, so this plants the smallest
    input that can distinguish the behaviours: run 1 must arrive ENTIRE including entries the floor
    rejects, and run 2 must be filtered to what clears the shipped policy and is not already there.
    """
    module = _corpus_generator()
    root = tmp_path / "SecLists"
    (root / "Passwords" / "Common-Credentials").mkdir(parents=True)

    # Run 1 is taken whole: two entries the 15-char floor rejects, one that clears it.
    (root / module.RUN1_MEMBER).write_text(
        "123456\nletmein\na-passphrase-that-clears\n", encoding="utf-8"
    )
    # Run 2 is filtered. Only the first survives: the rest are too short, a duplicate of run 1,
    # context-denied, and IPv4-shaped respectively.
    (root / module.RUN2_MEMBER).write_text(
        "another-clearing-passphrase\n"
        "short\n"
        "a-passphrase-that-clears\n"
        "administrator-passphrase\n"
        "203.0.113.99\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "RUN1_LINES", 3)

    assert module.rebuild_corpus(root) == [
        "123456",
        "letmein",
        "a-passphrase-that-clears",
        "another-clearing-passphrase",
    ]


def test_recorded_upstream_digests_are_verified_not_carried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A RECORDED member digest that disagrees with the checkout is a problem; an unrecorded one is a
    note.

    The distinction is the fix for the defect above. Provenance now lives in module constants, which
    a rebuild VERIFIES, rather than in prose the tool parses back out of its own output -- so writer
    and reader cannot desync, because there is only one of them.
    """
    module = _corpus_generator()
    root = tmp_path / "SecLists"
    (root / "Passwords" / "Common-Credentials").mkdir(parents=True)
    (root / module.RUN1_MEMBER).write_text("one\n", encoding="utf-8")
    (root / module.RUN2_MEMBER).write_text("two\n", encoding="utf-8")

    # Unrecorded: a note naming the value to paste, and NO problem.
    problems, notes = module.check_upstream_digests(root)
    assert problems == []
    assert any("RUN1_MEMBER_SHA256" in note for note in notes)

    # Recorded and wrong: a problem, because that is a different upstream file.
    monkeypatch.setattr(module, "RUN1_MEMBER_SHA256", "0" * 64)
    problems, _ = module.check_upstream_digests(root)
    assert len(problems) == 1
    assert "DIFFERENT upstream file" in problems[0]

    # Recorded and right: silent.
    actual, _ = module.upstream_digests(root)
    monkeypatch.setattr(module, "RUN1_MEMBER_SHA256", actual)
    assert module.check_upstream_digests(root)[0] == []
