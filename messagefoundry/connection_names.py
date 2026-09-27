# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The connection-name rule, written once (BACKLOG #1107, ASVS 1.2.2).

Two layers enforce it, and they must enforce the SAME rule:

* the operator API refuses a name that fails it on a path segment or a filter value
  (:data:`messagefoundry.api.validation.ConnectionName`, BACKLOG #1108);
* the config loader refuses to register a connection whose name fails it
  (:meth:`messagefoundry.config.wiring.Registry.add_inbound` and ``add_outbound``).

WHY THE LOADER HAS TO HOLD IT TOO. The web console builds URLs such as
``/ui/dead-letters/{channel_id}/{destination_name}/replay`` and percent-encodes each segment. That
is correct but not enough: the ASGI server decodes the path before routing, so a name carrying ``/``
would split across two path parameters, and both halves would read as valid names. Encoding at the
call site is safe only while no connection name can contain ``/``. The API rule alone did not make
that true, because a code-first ``inbound()`` call or a ``connections.toml`` entry naming ``A/B``
loaded cleanly. Refusing it at load makes the premise hold for every name the engine can run.

WHY THIS MODULE AND NOT EITHER CALLER. ``config/`` must not import ``api/`` (CLAUDE.md section 4),
and ``api/validation.py`` promises to depend on nothing but pydantic and the standard library, which
rules out importing the ``config`` package and everything its ``__init__`` pulls in. A top-level
module that imports nothing is the one place both can reach, the same arrangement as
:mod:`messagefoundry.controlchars`.

Why the rule is drawn where it is -- a hyphen admitted; ``.``, ``/``, backslash, whitespace and URL
metacharacters not -- stays beside the API's use of it in ``api/validation.py`` and in
``docs/API-INPUT-VALIDATION.md``.

ANCHORING. The pattern is written for pydantic, which compiles ``pattern=`` with the Rust ``regex``
crate, where ``$`` is end-of-input. Python's :mod:`re` lets ``$`` match before a trailing newline,
so a Python caller must use :func:`is_connection_name` (a full match), never ``re.match`` on the
pattern.
"""

from __future__ import annotations

import re
from typing import Final

#: The longest connection name the rule admits. Written again inside the pattern below, which stays a
#: literal so the static regex scanner can read it; tests/test_connection_name_rule.py pins the two.
CONNECTION_NAME_MAX_LENGTH: Final = 256

#: A connection name: a leading letter, then letters, digits, ``_`` and ``-``, at most 256 characters.
CONNECTION_NAME_PATTERN: Final = r"^[A-Za-z][A-Za-z0-9_-]{0,255}$"

_CONNECTION_NAME_RE: Final = re.compile(CONNECTION_NAME_PATTERN)


def is_connection_name(value: object) -> bool:
    """True when ``value`` is a string that fully matches :data:`CONNECTION_NAME_PATTERN`.

    A full match, so a trailing newline is refused as pydantic refuses it; see ANCHORING above."""
    return isinstance(value, str) and _CONNECTION_NAME_RE.fullmatch(value) is not None
