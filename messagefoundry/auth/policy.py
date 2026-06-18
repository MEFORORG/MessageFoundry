# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Password-strength and account-lockout policy (ASVS 6.2.x).

Modernized per ASVS 5.0 (WP-3): length-first (15+), **no mandatory character-class composition**
(the class rules are kept as *opt-in* knobs, default off), plus **offline breached/common-password
screening**, a small **context-word deny-list** (app/vendor/HL7 terms), and **username-in-password
rejection** (6.2.11). Defaults remain a direct improvement on Mirth, whose password requirements
default to zero. Operators tune these via the ``[auth]`` settings section.

The breach corpus is a bundled offline top-10k common-password list (see ``data/common_passwords.txt``
+ its ``.NOTICE``); the check is a case-insensitive set membership — no network/live-HIBP call.
Operators can widen it with an offline ``breach_corpus_file`` (6.2.12) — a plaintext list **or** an
HIBP-style SHA-1-hash export (``HASH[:count]`` lines, auto-detected), still fully offline. (True HIBP
k-anonymity needs a live range query, which this on-prem engine deliberately doesn't make.)
"""

from __future__ import annotations

import functools
import hashlib
import re
from dataclasses import dataclass
from importlib.resources import files

#: Shortest username we'll substring-match inside a password — below this the false-positive risk on a
#: legitimate long passphrase outweighs the value (a 2-3 char username fragment is too common).
_MIN_USERNAME_MATCH = 4

#: A line in an HIBP-style SHA-1 export: 40 hex chars, optionally ``:<count>``. Used to auto-detect a
#: hashed corpus from its first entry.
_HASH_LINE = re.compile(r"[0-9A-Fa-f]{40}(:\d+)?")

#: App/vendor/protocol terms a local password must not *contain* (case-insensitive) — so an obvious
#: in-context credential like ``messagefoundry2026`` or ``Mefor-Admin!`` is rejected (ASVS 6.2.5).
#: Deliberately app-specific (not a generic dictionary) to keep false-positives rare; the broader
#: "common word" coverage comes from the breach corpus.
CONTEXT_WORDS: frozenset[str] = frozenset(
    {
        "messagefoundry",
        "mefor",
        "mllp",
        "hl7",
        "corepoint",
        "mirth",
        "rhapsody",
        "changeme",
        "bootstrap",
        "admin",
        "administrator",
        "password",
    }
)


@functools.lru_cache(maxsize=1)
def _common_passwords() -> frozenset[str]:
    """The bundled offline common/breached-password set (lower-cased), loaded once and cached."""
    data = (files("messagefoundry.auth") / "data" / "common_passwords.txt").read_bytes()
    text = data.decode("utf-8", "ignore")
    return frozenset(line.strip().lower() for line in text.splitlines() if line.strip())


@functools.lru_cache(maxsize=4)
def _operator_corpus(path: str) -> tuple[frozenset[str], bool]:
    """Load an operator-supplied offline breach corpus, returning ``(entries, hashed)``. Format is
    auto-detected from the first non-empty line: an HIBP-style SHA-1 export (``HASH[:count]``) is
    stored as upper-hex hashes (``hashed=True``); anything else is a plaintext list stored lower-cased.
    Loaded once per path and cached. Raises ``OSError`` if the file can't be read (the caller degrades
    gracefully; a configured-but-unreadable corpus is warned about at startup)."""
    entries: set[str] = set()
    hashed: bool | None = None
    with open(path, encoding="utf-8", errors="ignore") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            if hashed is None:  # detect format from the first real entry
                hashed = _HASH_LINE.fullmatch(line) is not None
            entries.add(line.split(":", 1)[0].upper() if hashed else line.lower())
    return frozenset(entries), bool(hashed)


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    """Rules applied to *local* passwords (AD passwords are governed by the directory).

    ASVS-aligned defaults: a 15-char minimum, **no** mandatory character classes (the ``require_*``
    flags are opt-in, default off), and breach + context screening on. ``violations`` is the single
    enforcement point — used on both create-user and change-password.
    """

    min_length: int = 15
    require_uppercase: bool = False
    require_lowercase: bool = False
    require_digit: bool = False
    require_symbol: bool = False
    check_breached: bool = True  # reject known common/breached passwords (offline corpus)
    check_context: bool = True  # reject passwords containing app/vendor/HL7 terms
    check_username: bool = True  # reject passwords containing the user's own username (6.2.11)
    breach_corpus_file: str | None = None  # optional operator-supplied offline corpus (6.2.12)
    lockout_threshold: int = 5  # consecutive failed logins before the account locks
    lockout_minutes: int = 15  # how long a locked account stays locked

    def violations(self, password: str, *, username: str | None = None) -> list[str]:
        """Return clauses completing *"password must …"*; an empty list means the password is
        acceptable. Order: length → opt-in character classes → breach → username → context.

        ``username`` enables the 6.2.11 own-username check (omit it where there is no user context,
        e.g. generating the bootstrap password)."""
        problems: list[str] = []
        if len(password) < self.min_length:
            problems.append(f"be at least {self.min_length} characters")
        if self.require_uppercase and not any(c.isupper() for c in password):
            problems.append("contain an uppercase letter")
        if self.require_lowercase and not any(c.islower() for c in password):
            problems.append("contain a lowercase letter")
        if self.require_digit and not any(c.isdigit() for c in password):
            problems.append("contain a digit")
        if self.require_symbol and all(c.isalnum() for c in password):
            problems.append("contain a symbol")
        lowered = password.lower()
        if self.check_breached and (
            lowered in _common_passwords() or self._in_operator_corpus(password)
        ):
            problems.append("not be a common or breached password")
        if (
            self.check_username
            and username
            and len(username) >= _MIN_USERNAME_MATCH
            and username.lower() in lowered
        ):
            problems.append("not contain your username")
        if self.check_context and any(word in lowered for word in CONTEXT_WORDS):
            problems.append("not contain application or vendor terms")
        return problems

    def _in_operator_corpus(self, password: str) -> bool:
        """Whether ``password`` is in the operator-supplied corpus (if one is configured). Best-effort:
        a missing/unreadable corpus file returns ``False`` rather than breaking a password change — the
        misconfiguration is warned about once at startup (see ``AuthService``)."""
        if not self.breach_corpus_file:
            return False
        try:
            entries, hashed = _operator_corpus(self.breach_corpus_file)
        except OSError:
            return False
        if hashed:
            digest = (
                hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
            )
            return digest in entries
        return password.lower() in entries
