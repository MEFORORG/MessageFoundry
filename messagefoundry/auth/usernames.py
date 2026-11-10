# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The rule a new local account's username must pass (BACKLOG #5521).

The standard library and the engine-free ``controlchars`` leaf only, so the request model ``api.auth_models.UserCreateRequest`` can apply the
same rule the service does without importing the service. ``AuthService.create_local_user`` is the
authority and checks it before anything is generated or written; the model mirrors it.

A name is refused when it is blank or white space alone, when it starts or ends with white space
(refused rather than trimmed, so the duplicate check and the stored value are the same string),
when it holds a C0 or C1 control character, NUL included, or when it takes one of the forms the
audit trail writes for its own synthetic actors (:data:`RESERVED_ACTOR_FORMS`). An account named
``system`` would otherwise be indistinguishable from the engine in ``GET /audit?actor=system``
and in an audit export, and a NUL would reach a store that cannot hold one.

The ``directory`` name is NOT reserved: nothing at HEAD writes it as an audit actor.
"""

from __future__ import annotations

import re
from typing import Final

from messagefoundry.controlchars import C0_C1_CONTROL_RANGE

#: The audit trail's synthetic actor forms, which no account may take: ``system`` exactly, any
#: ``system:`` form (``system:rotate-key``, ``system:cluster-convergence``) and any ``<...>`` form
#: (``<oidc>``, ``<kerberos>``, ``<reconciler>``). Matched case-insensitively, since a store whose
#: name column compares that way would find ``SYSTEM`` as ``system``. The literal actor sites are
#: not rewritten to use this; it names their forms.
RESERVED_ACTOR_FORMS: Final = re.compile(r"(?is)system(:.*)?|<.*>")

_CONTROL = re.compile(f"[{C0_C1_CONTROL_RANGE}]")


def username_refusal(username: str) -> str | None:
    """Why a new account may not be named ``username``, or ``None`` when it may. The reason is
    fixed text that never echoes the value, which may hold a control character."""
    stripped = username.strip()
    if not stripped:
        return "a username is required and must not be blank"
    if _CONTROL.search(username):
        return "a username must not contain a control character"
    if username != stripped:
        return "a username must not start or end with white space"
    if RESERVED_ACTOR_FORMS.fullmatch(username):
        return (
            'that username is reserved for the audit trail\'s own actors ("system", '
            '"system:..." and "<...>")'
        )
    return None
