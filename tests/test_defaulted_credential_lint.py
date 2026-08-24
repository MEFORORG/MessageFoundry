# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A credential-named key must not ship a hard-coded literal default (BACKLOG #1091).

The shape is `POSTGRES_PASSWORD: "${MEFOR_STORE_PASSWORD:-changeme}"` -- a shell default that makes a
deployment come up with a working password nobody chose. Compose substitution reads the shell
environment or a `.env` beside `compose.yaml`; an `env_file:` does NOT feed it, so the fallback is
what actually runs.

THIS WAS A GITLEAKS RULE AND THE PLACEMENT WAS THE DEFECT. A LEAKED SECRET and a DEFAULTED CREDENTIAL
mean opposite things by history:

    a leaked value is compromised the moment it is pushed  -> scanning ALL history is correct
    a defaulted credential is a property of the SHIPPED TIP -> fixing the tip removes it

`security.yml` runs gitleaks at `fetch-depth: 0`, and the pattern matched 12 of 14 historical
revisions of `docker/compose.yaml`. A clean tip could therefore never turn that gate green -- not a
tuning problem, a category error, with the permanently-red gate reporting it correctly. So the check
moved to where tip-properties are checked and the scanner kept the job it is actually for.

WHY A RULE AND NOT AN ENTROPY THRESHOLD, unchanged from the original finding: gitleaks' generic rule
is entropy-gated, and the credentials that matter here sit below any useful threshold. `changeme` is
the whole problem and it has almost no entropy.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]

#: Byte-identical to the retired gitleaks rule's regex. The key-name group is NON-CAPTURING and the
#: DEFAULT VALUE is group 1: that is the part a reader needs to see and the part an allowlist tests.
#: Capturing the key name instead made every finding report the literal word "password".
_DEFAULTED_CREDENTIAL = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[_-]?key)[^\n:=]*[:=][^\n]*"
    r"\$\{[A-Za-z_][A-Za-z0-9_]*:-([^}\s]+)\}"
)

#: Documented fill-me-in markers. NEVER add a real credential here -- a real one must not exist in
#: the tree at all, which is what this check is for.
_PLACEHOLDERS = (
    re.compile(r"REPLACE_or_omit"),
    re.compile(r"CHANGE_?ME_?BEFORE"),
)

#: This file's own fixtures ARE the detected shape -- that is what they are for. The exemption is
#: scoped to this ONE path, exactly as the retired rule's was, so every other file stays covered.
_EXEMPT_PATHS = {"tests/test_defaulted_credential_lint.py"}


def _tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(_REPO), "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    ).stdout
    return [p for p in out.split("\0") if p]


def _findings() -> list[tuple[str, int, str]]:
    """Every (path, line number, default value) in the TIP that ships a defaulted credential."""
    hits: list[tuple[str, int, str]] = []
    for rel in _tracked_files():
        if rel in _EXEMPT_PATHS:
            continue
        f = _REPO / rel
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            # Binary or unreadable. Not a silent skip: the count is asserted below so a tree that
            # became entirely unreadable cannot pass as clean.
            continue
        for n, line in enumerate(text.splitlines(), 1):
            m = _DEFAULTED_CREDENTIAL.search(line)
            if not m:
                continue
            if any(p.search(line) for p in _PLACEHOLDERS):
                continue
            hits.append((rel, n, m.group(1)))
    return hits


# --- the pattern itself, before it is pointed at the repo ----------------------
#
# A repo scan that returns zero is indistinguishable from a pattern that matches nothing. These run
# first so the zero below is a RESULT rather than a broken instrument.


@pytest.mark.parametrize(
    "line",
    [
        pytest.param('POSTGRES_PASSWORD: "${MEFOR_STORE_PASSWORD:-changeme}"', id="compose-yaml"),
        pytest.param("API_KEY=${SOME_KEY:-dev-key}", id="env-assignment"),
        pytest.param('  secret: "${APP_SECRET:-s3cr3t}"', id="indented-yaml"),
        pytest.param("api-key: ${K:-x}", id="hyphenated-key-name"),
    ],
)
def test_the_pattern_MATCHES_a_defaulted_credential(line: str) -> None:
    """POSITIVE CONTROL. Without these the repo scan proves nothing."""
    assert _DEFAULTED_CREDENTIAL.search(line), (
        "the pattern is inert; the repo scan below is vacuous"
    )


@pytest.mark.parametrize(
    "line",
    [
        pytest.param('POSTGRES_PASSWORD: "${MEFOR_STORE_PASSWORD}"', id="no-default-at-all"),
        pytest.param(
            'POSTGRES_PASSWORD: "${MEFOR_STORE_PASSWORD:?required}"', id="required-not-defaulted"
        ),
        pytest.param("      id-token: write", id="github-permission-not-a-credential"),
        pytest.param("contents: read", id="another-github-permission"),
    ],
)
def test_the_pattern_IGNORES_shapes_that_are_not_defaulted_credentials(line: str) -> None:
    """NEGATIVE CONTROLS, and `id-token: write` is the load-bearing one.

    `.github/workflows/release.yml` carries nine `id-token: write` lines. Those are GitHub
    PERMISSIONS, not credentials, and a naive `token\\s*[:=]` rule reddens a required gate nine times
    on its first run. `:?` is the OPPOSITE of the defect -- it fails closed with a message rather
    than supplying a value -- so it must not be flagged either.
    """
    assert not _DEFAULTED_CREDENTIAL.search(line)


def test_the_group_reported_is_the_DEFAULT_not_the_key_name() -> None:
    """The retired gitleaks rule shipped this backwards once and it silently broke its allowlist:
    with the key name captured, every finding reported `Secret: "password"`, which no placeholder
    regex can match. Pinned here so the relocation does not reintroduce it."""
    m = _DEFAULTED_CREDENTIAL.search('POSTGRES_PASSWORD: "${MEFOR_STORE_PASSWORD:-changeme}"')
    assert m and m.group(1) == "changeme"


# --- the tree ------------------------------------------------------------------


def test_the_scan_actually_reads_a_meaningful_number_of_files() -> None:
    """The scan's own denominator. A `git ls-files` that returned nothing, or a tree of unreadable
    files, would make the assertion below pass over an empty set."""
    files = _tracked_files()
    assert len(files) > 500, f"only {len(files)} tracked files; the scan is not seeing the repo"
    readable = sum(1 for r in files if (_REPO / r).is_file())
    assert readable > 500, f"only {readable} readable; the scan would pass over almost nothing"


def test_no_tracked_file_ships_a_defaulted_credential() -> None:
    hits = _findings()
    rendered = "\n".join(f"  {p}:{n} -> default {v!r}" for p, n, v in hits)
    assert not hits, (
        "a credential-named key ships a hard-coded default, so a deployment comes up with a working "
        "password nobody chose:\n" + rendered + "\n\n"
        "Use `${VAR:?message}` so it fails closed with an explanation. Note an `env_file:` does NOT "
        "feed compose substitution -- that reads the shell environment or a .env beside compose.yaml."
    )
