# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The service-environment refusal's remedy wording, pinned once for every test that reads it.

Each constant is the exact text ``messagefoundry/serviceenv.py`` prints, so a test that looks for
one fails when its own text changes (the Lander's third hold on PR 3142, H3). Text added beside
it is caught only where a test pins the remedy's start or end."""

from __future__ import annotations

#: Always printed, after every step that moves a value elsewhere: what to remove, and the doc to
#: see.
REMOVE = (
    "Remove each refused variable, with its value, from the service's environment. See "
    'docs/SERVICE.md, "Start / stop / status"'
)

#: Printed when a refused variable's value runs on into the entries after it.
RUNS_ON = (
    "At least one refused variable's value runs on past its own entry, so remove the entries it "
    "runs on into with it, or the value stays in the registry key"
)

#: Printed last, only where every refused variable that runs on takes only directory entries
#: that are blank or plainly a path, and one sets the directory to a path: that entry stays.
KEEP = (
    "Keep any of them that sets MEFOR_SECRETS_DIRECTORY to a path and nothing else, as its own "
    "entry"
)

#: Printed, as origin/main prints it, where a setting moves to the secrets directory, the lists
#: name none, and no joined path entry is kept (the Lander's hold on PR 3142, comment
#: 7085002242; the Lander's ruling on handback 7085947392, F1).
ADD_BACK = (
    "The service's lists set no MEFOR_SECRETS_DIRECTORY. Where install-service.ps1 already "
    "made the secrets directory, add MEFOR_SECRETS_DIRECTORY naming that existing path back to "
    "the service's AppEnvironmentExtra, beside its other entries, before any re-run of the "
    "installer, which refuses an existing directory the service does not name. `nssm set` "
    "replaces that whole list, so read it first with `nssm get`, running the service's own "
    "nssm.exe by its full path, and pass back every entry but those refused above: see "
    'docs/SERVICE.md, "Start / stop / status". Where none exists yet, the bullet "The other '
    'secrets: a secrets directory" under docs/SERVICE.md, "Protect the store encryption key '
    'at rest", says how the directory is created'
)

#: Printed when a setting goes to the secrets directory and no entry is read as naming it.
CREATE = (
    'Where no secrets directory exists yet, the bullet "The other secrets: a secrets directory" '
    'under docs/SERVICE.md, "Protect the store encryption key at rest", says how it is created'
)
