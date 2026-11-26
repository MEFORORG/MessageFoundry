# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The rule a new local account's username must pass (BACKLOG #5521).

It imports only the standard library and the engine-free ``controlchars`` leaf, so the request
model ``api.auth_models.UserCreateRequest`` can apply the same rule the service does without
importing the service. ``AuthService.create_local_user`` checks it before anything is generated or
written, and the model mirrors it, so ``POST /users`` refuses a name it refuses. The console's
``POST /ui/users`` applies it to the name after ``str.strip``, which takes the characters
``str.isspace`` counts as white space from the ends (at least the C0 separators U+001C to U+001F
and the line and paragraph separators among them), so a name refused only for such characters at
its ends is created there trimmed, and the trimmed name passes the rule. A control, format or
blank-glyph character at an end that is not white space is still refused there. Paths that write a username without it include
at least
``provision-admin``, the directory create paths (``POST /users/directory`` and an AD sign-in that
creates its account) and the directory rename refresh (``AuthService._refresh_cached_username``),
so an account one of them writes can hold a name this rule refuses.

A name is refused when it is blank or white space alone, when it starts or ends with white space
(refused rather than trimmed, so the duplicate check and the stored value are the same string),
when it holds a character of :data:`~messagefoundry.controlchars.CONTROL_CATEGORIES` (a C0 or C1
control, NUL included, a format or zero-width character, a line or paragraph separator, a lone
surrogate, a private-use or unassigned code point), a default-ignorable code point
(:data:`_DEFAULT_IGNORABLE`) or a blank glyph that renders as nothing (:data:`_BLANK_GLYPHS`,
U+2800 among them), or when it takes one of the forms the audit trail writes for its own
synthetic actors (:data:`RESERVED_ACTOR_FORMS`). An account named
``system`` would otherwise be indistinguishable from the engine in ``GET /audit?actor=system``
and in an audit export. The NUL case is pinned by
``tests/test_username_rule.py::test_the_rule_refuses``.

The bare word ``directory`` is NOT reserved: nothing at HEAD writes it as an audit actor. The
``granted_by`` marker ``<directory>`` (``api.security.DIRECTORY_GRANTED_BY``), which a directory
sign-in and the directory reconciler put on the ``administrator_granted`` alert, is reserved, by
the ``<...>`` form.

What it admits, at least: a space separator inside the name (U+00A0, U+3000), a blank glyph
:data:`_BLANK_GLYPHS` does not list, and a lookalike letter from another script, so a Cyrillic
spelling that reads as ``system`` passes, as does a reserved form spelled with a delimiter
lookalike :data:`_DELIMITER_LOOKALIKES` does not list. At least some lookalikes from the same
script pass too: ``cli:root`` spelled with a dotless i (U+0131), and ``<oidc>`` spelled with the
modifier low arrowheads U+02F1 and U+02F2. It matches the reserved forms against the key
:func:`_reserved_form_key` builds, whose docstring lists its steps. Among them it drops combining
marks (BACKLOG #5519), so ``system`` with an accent on a letter, or ``<oidc>`` followed by a
combining low line (U+0332) or an enclosing circle (U+20DD), is refused. It folds no other
confusable letters, in any script.

This docstring is the one statement of the rule; the request model, the service and
docs/SECURITY.md point here rather than restate it.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Final

from messagefoundry.controlchars import CONTROL_CATEGORIES

#: The audit trail's synthetic actor forms, which no account may take: ``system`` exactly, any
#: ``system:`` form (``system:rotate-key``, ``system:cluster-convergence``), any ``cli:`` form (the
#: host CLI's ``cli:<OS user>``) and any ``<...>`` form (``<oidc>``, ``<kerberos>``,
#: ``<reconciler>``). Matched against :func:`_reserved_form_key`, not the name as typed. The
#: literal actor sites are not rewritten to use this; it names their forms, so a new synthetic
#: actor form must be added here too.
RESERVED_ACTOR_FORMS: Final = re.compile(r"(?s)system(:.*)?|cli:.*|<.*>")

#: Lookalikes of the delimiters :data:`RESERVED_ACTOR_FORMS` reads that NFKC leaves as they are,
#: each taken to the ASCII character it renders as before the reserved-form match (BACKLOG #5520
#: items 3, 14 and 35), so ``cli`` + RATIO + ``root`` or ``<oidc>`` in angle quotation marks is
#: refused as ``cli:root`` and ``<oidc>`` are. Code points taken from Unicode's confusables data
#: for ``:``, ``<`` and ``>``, and not every lookalike of them. At least these are left out: some
#: letters it lists (Canadian syllabics PA and PO, a runic letter and a Lisu tone letter), so a
#: name in those scripts is not refused as a ``<...>`` form, though the modifier letters U+02D0,
#: U+02F8, U+A789, U+02C2 and U+02C3 are kept; and U+FE30, which NFKC turns into two full stops
#: (``..``) rather than a colon. Applied after NFKD, which takes U+2329 and U+232A to U+3008
#: and U+3009.
_DELIMITER_LOOKALIKES: Final = str.maketrans(
    dict.fromkeys(
        (0x02D0, 0x02F8, 0x0589, 0x05C3, 0x0703, 0x0704, 0x0903, 0x0A83, 0x16EC, 0x17D6, 0x1803)
        + (0x1809, 0x205A, 0x2236, 0xA789),
        ":",
    )
    | dict.fromkeys((0x02C2, 0x2039, 0x276C, 0x276E, 0x27E8, 0x3008, 0x1D236), "<")
    | dict.fromkeys((0x02C3, 0x203A, 0x276D, 0x276F, 0x27E9, 0x3009, 0x1D237), ">")
)


def _reserved_form_key(username: str) -> str:
    """What :data:`RESERVED_ACTOR_FORMS` is matched against, in this order: the name's NFKD form,
    its :data:`_DELIMITER_LOOKALIKES` taken to ASCII, its combining marks (categories Mn, Mc and
    Me) dropped, case folded, and stripped of white space at its ends.

    NFKD folds width, as NFKC does, and also splits an accented letter into its base and its
    marks. Dropping the marks is for a store or audit column that compares accent-insensitively,
    which would find ``system`` spelled with a y acute (U+00FD) as ``system`` (BACKLOG #5519). A
    letter with no decomposition, such as o with stroke (U+00F8) or the dotless i (U+0131), is
    left as it is, so a collation that folds one of those still matches a name this rule admits.
    The delimiter table runs before the drop, because some of its entries, such as U+0903, are
    marks, and the drop also leaves U+226E and U+226F, NOT LESS-THAN and NOT GREATER-THAN, as the
    angle brackets they decompose into. The drop runs before folding, because folding turns at
    least one mark into a letter (U+0345 into an iota). The strip is for a spacing accent that
    NFKD takes to a space and a mark, at least the diaeresis U+00A8, the acute U+00B4 and the
    breve U+02D8, so ``system`` followed by one keys as ``system``. A spacing accent with no
    decomposition, such as the caron U+02C7 or the grave accent, is left as it is."""
    decomposed = unicodedata.normalize("NFKD", username).translate(_DELIMITER_LOOKALIKES)
    unmarked = "".join(ch for ch in decomposed if not unicodedata.category(ch).startswith("M"))
    return unmarked.casefold().strip()


#: Unicode's Default_Ignorable_Code_Point ranges (DerivedCoreProperties.txt), inclusive. Most are
#: format characters :data:`CONTROL_CATEGORIES` already refuses; the rest render as nothing from
#: other categories, at least the combining grapheme joiner U+034F, the variation selectors and the
#: Hangul fillers U+115F, U+1160, U+3164 and U+FFA0. Refused too, so ``sys`` + U+034F + ``tem``
#: cannot render as ``system`` and a name of fillers alone cannot render as a blank.
_DEFAULT_IGNORABLE: Final = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)

#: Code points outside both lists above whose glyph renders as nothing, so a name of them alone
#: would read as a blank and one at an edge would hide from the white-space check: the Braille
#: pattern blank U+2800, the musical null notehead U+1D159 and the Khitan small script filler
#: U+16FE4. Not every such glyph; a font may draw others blank too.
_BLANK_GLYPHS: Final = frozenset({0x2800, 0x16FE4, 0x1D159})

#: The refusal of a blank name, shared with ``provision-admin``'s (BACKLOG #3391), so the two
#: answer a blank name alike.
BLANK_USERNAME_REFUSAL: Final = "a username is required and must not be blank"


#: Unicode's Prepended_Concatenation_Mark characters (PropList.txt): format characters (Cf) that
#: draw a visible glyph, such as the Arabic number sign U+0600 and end of ayah U+06DD.
_VISIBLE_FORMAT: Final = frozenset(
    {0x0600, 0x0601, 0x0602, 0x0603, 0x0604, 0x0605, 0x06DD, 0x070F, 0x0890, 0x0891, 0x08E2}
    | {0x110BD, 0x110CD}
)


def renders_as_nothing(ch: str) -> bool:
    """Whether ``ch`` is one of the characters this module treats as drawing no glyph: a format
    character (category Cf) other than :data:`_VISIBLE_FORMAT`, a default-ignorable code point
    (:data:`_DEFAULT_IGNORABLE`) or a blank glyph (:data:`_BLANK_GLYPHS`). Not every character a
    font draws blank. The account and role name rule in ``api.auth_models`` sets these aside
    before it asks whether a name is blank or folds to a built-in role's name (BACKLOG #5784,
    #5785)."""
    point = ord(ch)
    return (
        (unicodedata.category(ch) == "Cf" and point not in _VISIBLE_FORMAT)
        or point in _BLANK_GLYPHS
        or any(low <= point <= high for low, high in _DEFAULT_IGNORABLE)
    )


def _unprintable(ch: str) -> bool:
    return unicodedata.category(ch) in CONTROL_CATEGORIES or renders_as_nothing(ch)


def username_refusal(username: str) -> str | None:
    """Why a new account may not be named ``username``, or ``None`` when it may. The reason is
    fixed text that never echoes the value, which may hold a control character."""
    stripped = username.strip()
    if not stripped:
        return BLANK_USERNAME_REFUSAL
    if any(_unprintable(ch) for ch in username):
        return (
            "a username must not contain a control, format, invisible or line separator character"
        )
    if username != stripped:
        return "a username must not start or end with white space"
    if RESERVED_ACTOR_FORMS.fullmatch(_reserved_form_key(username)):
        return (
            "that username is reserved for the audit trail's own actors "
            '("system", "system:...", "cli:..." and "<...>")'
        )
    return None
