# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The rule a new local account's username must pass (BACKLOG #5521).

It imports only the standard library and the engine-free ``controlchars`` leaf, so the request
model ``api.auth_models.UserCreateRequest`` can apply the same rule the service does without
importing the service. ``AuthService.create_local_user`` checks it before anything is generated or
written, and the model mirrors it. It is not applied by ``provision-admin`` or by the directory
create paths.

A name is refused when it is blank or white space alone, when it starts or ends with white space
(refused rather than trimmed, so the duplicate check and the stored value are the same string),
when it holds a character of :data:`~messagefoundry.controlchars.CONTROL_CATEGORIES` (a C0 or C1
control, NUL included, a format or zero-width character, a line or paragraph separator, a lone
surrogate, a private-use or unassigned code point), a default-ignorable code point
(:data:`_DEFAULT_IGNORABLE`) or a blank glyph that renders as nothing (:data:`_BLANK_GLYPHS`,
U+2800 among them), or when it takes one of the forms the audit trail writes for its own
synthetic actors (:data:`RESERVED_ACTOR_FORMS`). An account named
``system`` would otherwise be indistinguishable from the engine in ``GET /audit?actor=system``
and in an audit export, and a NUL would reach a store that cannot hold one.

The ``directory`` name is NOT reserved: nothing at HEAD writes it as an audit actor.

What it admits, at least: a space separator inside the name (U+00A0, U+3000), a blank glyph
:data:`_BLANK_GLYPHS` does not list, and a lookalike letter from another script, so a Cyrillic
spelling that reads as ``system`` passes. It matches the reserved forms after NFKC and case
folding; it does not fold confusable letters across scripts.

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
#: ``<reconciler>``). Matched against the name's NFKC case fold, since a store whose name column
#: compares case- or width-insensitively would find ``SYSTEM`` or a fullwidth ``system`` as
#: ``system``. The literal actor sites are not rewritten to use this; it names their forms, so a
#: new synthetic actor form must be added here too.
RESERVED_ACTOR_FORMS: Final = re.compile(r"(?s)system(:.*)?|cli:.*|<.*>")

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


def _unprintable(ch: str) -> bool:
    point = ord(ch)
    return (
        unicodedata.category(ch) in CONTROL_CATEGORIES
        or point in _BLANK_GLYPHS
        or any(low <= point <= high for low, high in _DEFAULT_IGNORABLE)
    )


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
    if RESERVED_ACTOR_FORMS.fullmatch(unicodedata.normalize("NFKC", username).casefold()):
        return (
            "that username is reserved for the audit trail's own actors "
            '("system", "system:...", "cli:..." and "<...>")'
        )
    return None
