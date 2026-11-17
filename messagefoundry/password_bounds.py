# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The password length bound the request models and the service settings share (BACKLOG #5397).

A neutral leaf with no imports, so the pure wire models in ``messagefoundry.api.auth_models``, which
clients load through ``messagefoundry.apiclient`` (ADR 0088), and ``messagefoundry.config.settings``
can both read one definition without either pulling in the other.
"""

from __future__ import annotations

#: The longest password, in characters, any sign-in, step-up or password-change request accepts. It
#: also bounds argon2 work.
PASSWORD_MAX = 1024

#: What an engine-generated temporary password appends to its random token when an opt-in
#: character-class rule is on and the bare token misses a class (``generate_policy_password``).
TEMPORARY_PASSWORD_CLASS_SUFFIX = "aA1!"  # nosec B105 - a fixed class suffix, not a credential

#: The highest ``[auth].password_min_length`` the settings accept. A temporary password is minted at
#: least that long, plus the class suffix, and must still fit :data:`PASSWORD_MAX`, or no request
#: would accept the credential the engine issued.
PASSWORD_MIN_LENGTH_MAX = PASSWORD_MAX - len(TEMPORARY_PASSWORD_CLASS_SUFFIX)
