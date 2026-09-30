# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Which ``messagefoundry`` subcommands a production install carries (BACKLOG #1192, ASVS 15.2.3).

:data:`CLI_TIERS` is the single source of record for that question. Each subcommand the CLI
registers has one row, keyed by its full path as a user types it: ``"serve"``, ``"cert inventory"``,
``"lens parse"``. A row's value is its tier:

* ``"production"`` -- needed to run, operate or check a deployed engine, so it stays in the engine
  distribution.
* ``"toolkit"`` -- authoring and development tooling, which moves to a separate
  ``messagefoundry-toolkit`` distribution.

WHO DECIDED WHAT. On 2026-09-28 the owner named eight subcommands for the toolkit: ``impact``,
``generate``, ``lens``, ``import corepoint``, ``adr-analyze``, ``hl7schema``, ``hl7structures`` and
``init``. The other four toolkit rows follow from those by rule, not by name: the three ``lens``
children go with ``lens``, and the ``import`` group follows the group rule below. The owner also
named ten subcommands production, and those rows carry a comment saying so. The owner did NOT rule on
the remaining production rows one by one: they are production because the brief that relayed the
ruling put "everything else" there. Treat a doubt about one of those as open, not as settled by the
owner. The ruling is being recorded in the vault as ``ASVS-OWNER-RULINGS-2026-09-28-BATCH175.md``,
R4; when this module was written that file sat on an unmerged vault branch, not yet on ``main``.

A GROUP PARSER HAS A ROW TOO. A group, such as ``cert``, only holds child commands. A group is
production when any child is production, because a production install must carry the group to reach
that child. Otherwise it is toolkit. A group with mixed children passes the test, but nothing yet
exists that could move its toolkit child out while the group stays in the engine. Settle how before
you tag a child of a production group as toolkit.

MOVING A TOOLKIT ROW HAS A DOCUMENTATION HALF. At least ``init`` and ``generate`` are named in the
install and adopter guides as commands a deploying operator runs, so the change that takes a row
off the engine's entry point must change those guides in the same change.

WHICH COMMAND REGISTERS WHICH ROWS (ADR 0201). Two parsers register rows: the engine's
``messagefoundry`` command, and the separate ``messagefoundry-toolkit`` command from the
distribution of that name. A row's key is the same string on either command. ADR 0201 moves the
toolkit rows one slice at a time. Slice 2 moved ``adr-analyze``; every other toolkit row is still
registered on the engine's command and still packed in its wheel. The engine refuses a top-level
toolkit row it no longer registers, with a line naming the toolkit command.

``tests/test_cli_surface.py`` builds both real parsers and fails when a subcommand has no row, when a
row names no subcommand, when a group breaks the rule above, when the toolkit rows stop matching the
ruling, when the two parsers share a row, or when the toolkit parser registers a production row.

SO THIS TABLE IS NOT YET THE CONTROL THAT KEEPS DEVELOPMENT CODE OFF A PRODUCTION BOX. Until the last
toolkit row leaves the engine, which is ADR 0201 slice 4, do not cite it as one.

The module imports nothing from the engine and builds no parser, so a wheel build can read it cheaply.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, Literal

__all__ = ["CLI_TIERS", "Tier"]

Tier = Literal["production", "toolkit"]


CLI_TIERS: Final[Mapping[str, Tier]] = MappingProxyType(
    {
        # Run and supervise the engine.
        "serve": "production",
        "supervise": "production",
        "service": "production",
        "cluster-vip": "production",
        "verify": "production",
        "support-bundle": "production",
        # Owner-ruled production on 2026-09-28. Some check a config and some change it: `connection`,
        # `codeset`, `alert` and `security` can write config or settings files. `dryrun` must stay on the
        # operator's box, and `check` carries the security lint the deployment docs rely on.
        "validate": "production",
        "graph": "production",
        "dryrun": "production",
        "check": "production",
        "connection": "production",
        "codeset": "production",
        "alert": "production",
        "security": "production",
        "ai-policy": "production",
        # Keys and certificates.
        "gen-key": "production",
        "protect-key": "production",
        "rotate-key": "production",
        "cert": "production",
        "cert import": "production",
        "cert inventory": "production",  # owner-ruled production 2026-09-28
        # Owner-ruled production on 2026-09-29: R5 of vault
        # docs/security/ASVS-OWNER-RULINGS-2026-09-28-BATCH175.md, "Keep production". Its own help
        # still says "for NON-PROD TLS bring-up ONLY". The owner kept it anyway, because a first box
        # may need a self-signed cert before a real one exists, and the `cert` group stays whole.
        "cert self-signed": "production",
        # Accounts.
        "admin-unlock": "production",
        "provision-admin": "production",
        "admin-set-notify-email": "production",
        # Audit log.
        "audit-verify": "production",
        "audit-anchor": "production",
        "rekey-audit": "production",
        # Store, backup and restore.
        "store": "production",
        "store provision-schema": "production",
        "check-privileges": "production",
        "backup": "production",
        "restore-verify": "production",
        "restore": "production",
        # Authoring and development tooling. Owner-ruled toolkit on 2026-09-28, by name or by rule;
        # the module docstring says which.
        "impact": "toolkit",
        "generate": "toolkit",
        "lens": "toolkit",
        "lens parse": "toolkit",
        "lens rewrite": "toolkit",
        "lens schema": "toolkit",
        "import": "toolkit",
        "import corepoint": "toolkit",
        "adr-analyze": "toolkit",
        "hl7schema": "toolkit",
        "hl7structures": "toolkit",
        "init": "toolkit",
    }
)
