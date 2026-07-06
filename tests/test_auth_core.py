# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the provider-agnostic auth core (permissions, identity, policy, tokens, passwords)."""

from __future__ import annotations

import hashlib
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
