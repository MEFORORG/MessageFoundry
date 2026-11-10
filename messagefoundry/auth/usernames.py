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
surrogate, a private-use or unassigned code point), or when it takes one of the forms the audit
trail writes for its own synthetic actors (:data:`RESERVED_ACTOR_FORMS`). An account named
``system`` would otherwise be indistinguishable from the engine in ``GET /audit?actor=system``
and in an audit export, and a NUL would reach a store that cannot hold one.

The ``directory`` name is NOT reserved: nothing at HEAD writes it as an audit actor.
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


def username_refusal(username: str) -> str | None:
    """Why a new account may not be named ``username``, or ``None`` when it may. The reason is
    fixed text that never echoes the value, which may hold a control character."""
    stripped = username.strip()
    if not stripped:
        return "a username is required and must not be blank"
    if any(unicodedata.category(ch) in CONTROL_CATEGORIES for ch in username):
        return "a username must not contain a control, format or separator character"
    if username != stripped:
        return "a username must not start or end with white space"
    if RESERVED_ACTOR_FORMS.fullmatch(unicodedata.normalize("NFKC", username).casefold()):
        return (
            "that username is reserved for the audit trail's own actors "
            '("system", "system:...", "cli:..." and "<...>")'
        )
    return None
