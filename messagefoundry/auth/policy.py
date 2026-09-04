# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Password-strength and account-lockout policy (ASVS 6.2.x).

Modernized per ASVS 5.0 (WP-3): length-first (15+), **no mandatory character-class composition**
(the class rules are kept as *opt-in* knobs, default off), plus **offline breached/common-password
screening**, a small **context-word deny-list** (app/vendor/HL7 terms), and **username-in-password
rejection** (6.2.11). Defaults remain a direct improvement on Mirth, whose password requirements
default to zero. Operators tune these via the ``[auth]`` settings section.

The breach corpus is a bundled offline common-password list (see ``data/common_passwords.txt`` and
its ``.NOTICE``, which carries the entry counts and the policy filter that built the list — BACKLOG
#1134 grew it, so do not restate a size here); the check is a case-insensitive set membership — no
network/live-HIBP call. Only entries at or above ``min_length`` add coverage: a shorter one can
reject only what the length clause already rejects.
Operators can widen it with an offline ``breach_corpus_file`` (6.2.12) — a plaintext list **or** an
HIBP-style SHA-1-hash export (``HASH[:count]`` lines, auto-detected), still fully offline. (True HIBP
k-anonymity needs a live range query, which this on-prem engine deliberately doesn't make.)
The bundled corpus is **load-bearing, so its loss is loud**: an unreadable, empty or truncated file
raises :class:`BreachCorpusUnavailable` out of :meth:`PasswordPolicy.violations` rather than loading as
an empty set that silently stops screening while ``check_breached`` still reports ``True``
(BACKLOG #1438). ``AuthService`` loads it once at startup and logs the same defect as an error.
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


#: ASVS 6.2.4 asks for at least the top 3000 breached passwords **that clear the application's own
#: policy**, and ``tests/test_auth_core.py::test_breach_corpus_meets_the_asvs_6_2_4_policy_matching_bar``
#: pins that policy-clearing subset at build time (BACKLOG #1134).
#:
#: The runtime guard below re-uses the same number against a DIFFERENT quantity -- the whole corpus,
#: not the clearing subset -- because that is a **necessary condition** for the pinned bar rather than
#: a restatement of it: the clearing subset is a subset of the corpus, so a corpus holding fewer than
#: 3000 entries in total cannot possibly hold 3000 that clear the policy. Deliberately the weaker of
#: the two checks. It costs one ``len()`` on an already-cached frozenset and can never be stricter
#: than the build-time test, so it cannot fail an install the test would have passed.
#:
#: **Keying on the clearing subset instead would be WRONG, not merely more expensive**, and this is
#: the load-bearing reason for the choice. The clearing count tracks ``min_length`` hard -- measured
#: on the shipped corpus: 5,274 entries clear at 15, 3,173 at 16, and 1,735 at 17. So a runtime guard
#: keyed to clearing would start refusing every password on a site that had just raised its minimum
#: to 17, with a sound corpus, punishing the operator for making the policy STRONGER. The total is
#: invariant to ``min_length``; the clearing subset is not.
#:
#: Those three counts are measured against THE CORPUS AS IT SHIPS TODAY and move together if it is
#: ever regenerated -- read them as an illustration of the shape, not as constants. The ARGUMENT does
#: not depend on them: it needs only that the clearing subset shrinks with ``min_length`` while the
#: total does not, which is true of any corpus.
ASVS_6_2_4_MIN_CORPUS_ENTRIES = 3000


class BreachCorpusUnavailable(RuntimeError):
    """The **bundled** common/breached-password corpus is missing, empty, or truncated.

    Raised from :meth:`PasswordPolicy.violations` when ``check_breached`` is on, so a screen that
    cannot run **refuses** the password instead of accepting every password. ``check_breached`` ships
    ``True``; before this, an empty or truncated file loaded as an empty ``frozenset``, the
    "not be a common or breached password" clause stopped being emitted, and nothing logged -- the
    shipped configuration would assert a check that was not happening on a first deployment.

    Blast radius on an ESTABLISHED instance is narrow by construction: only the password *create* and
    *change* paths screen a password, so this never touches login, never invalidates a session, and
    never stops message flow.

    **A FIRST RUN IS THE EXCEPTION, and it is not narrow.** On an empty store ``AuthService.initialize``
    mints the bootstrap admin, whose generator screens its own candidate, so this raises out of an
    unguarded lifespan call and the engine does not start at all. That is fail-closed but arguably
    disproportionate, because the candidate is a 192-bit random token the breach clause can never match.
    Tracked separately; do not read the paragraph above as covering a first run.
    ``AuthService`` also loads the corpus eagerly at startup and logs the same defect as an error, so
    an operator learns about it from the log rather than from a user's failed password change.
    """


@functools.lru_cache(maxsize=1)
def _common_passwords() -> frozenset[str]:
    """The bundled offline common/breached-password set (lower-cased), loaded once and cached.

    Raises :class:`BreachCorpusUnavailable` when the file cannot be read or holds fewer than
    ``ASVS_6_2_4_MIN_CORPUS_ENTRIES`` entries, rather than returning the empty set that silently
    disabled screening. ``lru_cache`` does not cache exceptions, so a broken install re-reads the file
    on each attempt and recovers the moment the file is repaired -- one file read per password attempt
    on an install that is already refusing them, which is the cheaper side of the trade.
    """
    resource = files("messagefoundry.auth") / "data" / "common_passwords.txt"
    try:
        data = resource.read_bytes()
    except OSError as exc:
        raise BreachCorpusUnavailable(
            f"the bundled breach corpus at {resource} could not be read: {exc}"
        ) from exc
    entries = frozenset(
        line.strip().lower() for line in data.decode("utf-8", "ignore").splitlines() if line.strip()
    )
    if len(entries) < ASVS_6_2_4_MIN_CORPUS_ENTRIES:
        raise BreachCorpusUnavailable(
            f"the bundled breach corpus at {resource} holds {len(entries)} entries, below the floor "
            f"of {ASVS_6_2_4_MIN_CORPUS_ENTRIES} (ASVS 6.2.4) -- breach screening cannot run"
        )
    return entries


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
        e.g. generating the bootstrap password).

        Raises :class:`BreachCorpusUnavailable` when ``check_breached`` is on and the bundled corpus is
        unusable (BACKLOG #1438) -- a refusal, not a silent pass. Callers get a list or an exception,
        never a list that quietly stopped screening."""
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
        # `_common_passwords()` RAISES on an unusable bundled corpus (BACKLOG #1438), and Python's `or`
        # evaluates it first, so the bundled floor is checked before any operator corpus is consulted.
        # That is deliberate: an operator corpus is ADDITIVE (6.2.12), it has no floor of its own, and a
        # bundled file that has been truncated or replaced is evidence about the INSTALL, not about the
        # screen. A large operator export therefore does not excuse it -- the repair is to reinstall the
        # wheel, which is cheap, and the alternative is honouring `check_breached=True` with a screen
        # nobody has validated.
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
