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
distribution of that name. A row's key is the same string on either command. Since ADR 0201 slice 4
the engine's command registers exactly the production rows and the toolkit's command exactly the
toolkit rows. The engine refuses a top-level toolkit row with a line naming the toolkit command.

``tests/test_cli_surface.py`` builds both real parsers and fails when a subcommand has no row, when a
row names no subcommand, when a group breaks the rule above, when the toolkit rows stop matching the
ruling, when the two parsers share a row, when the toolkit parser registers a production row, or when
either command registers a row outside its own tier. The engine's release smoke asserts the same
production set on the built wheel, installed without the toolkit (``.github/workflows/release.yml``).

WHAT THIS TABLE DOES NOT COVER. It governs the command surface, ASVS 15.2.3's clause (b). Clause (a),
what the engine wheel includes, is the physical move of each module into the toolkit package, which
ADR 0201 slice 6 finished for ``anon/`` and slice 7 finishes for ``generators/``, ``hl7schema.py``
and ``hl7structures.py``. Until slice 7 lands, do not cite this table as keeping that code off a production
box.

The module imports nothing from the engine and builds no parser, so a wheel build can read it cheaply.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, Literal

__all__ = ["CLI_TIERS", "TOOLKIT_COMMAND", "Tier"]

Tier = Literal["production", "toolkit"]

#: The command, and the distribution, that run the ``toolkit`` rows (ADR 0201). Hyphenated on purpose:
#: it is never the import package, which no file under ``messagefoundry/`` may name
#: (``tests/test_dependency_boundaries.py``). Both commands read it from here.
TOOLKIT_COMMAND: Final = "messagefoundry-toolkit"


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
        # said "for NON-PROD TLS bring-up ONLY" then. The owner kept it anyway, because a first box
        # may need a self-signed cert before a real one exists, and the `cert` group stays whole.
        # BACKLOG #1276 has since rewritten that help to call the pair a placeholder to replace.
        "cert self-signed": "production",
        # Accounts.
        "admin-unlock": "production",
        "provision-admin": "production",
        "admin-set-notify-email": "production",
        "admin-reset-totp": "production",
        "admin-revoke-sessions": "production",
        # Audit log.
        "audit-verify": "production",
        "audit-anchor": "production",
        # Store, backup and restore.
        "store": "production",
        "store provision-schema": "production",
        "store attest-transit-bound": "production",  # serve on vault_transit needs it (#2337)
        "store withdraw-transit-bound": "production",
        "check-privileges": "production",
        "cipher-audit": "production",  # reads the live store's sealed cells back (BACKLOG #1719)
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
