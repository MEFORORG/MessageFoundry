# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The service-environment refusal's remedy wording, pinned once for every test that reads it.

Each constant is a whole sentence ``messagefoundry/serviceenv.py`` prints, so a test that looks
for it fails when that sentence changes (the Lander's third hold on PR 3142, H3)."""

from __future__ import annotations

#: Always printed: what to remove, and the doc that says how.
REMOVE = (
    "Remove each refused variable, with its value, from the service's environment, leaving "
    "exactly one MEFOR_SECRETS_DIRECTORY entry, written as MEFOR_SECRETS_DIRECTORY=<path> on its "
    'own, where the service has a secrets directory. docs/SERVICE.md, "Start / stop / status", '
    "says how to change that environment"
)

#: Printed when a refused variable's value runs on into the entries after it.
RUNS_ON = (
    "The value of at least one of them runs on into the entries after it, so remove those with "
    "it, or the value stays in the registry key"
)

#: Printed when a setting goes to the secrets directory and no entry is read as naming it.
NO_DIRECTORY = (
    "No MEFOR_SECRETS_DIRECTORY entry is read here as naming the secrets directory. Where none "
    'exists yet, the bullet "The other secrets: a secrets directory" under docs/SERVICE.md, '
    '"Protect the store encryption key at rest", says how the directory is created'
)
