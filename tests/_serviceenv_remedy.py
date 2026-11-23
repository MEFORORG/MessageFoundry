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

#: The add-back step as origin/main prints it, where a refused name outside the key class
#: is listed, no value runs on, and no string in the lists sets MEFOR_SECRETS_DIRECTORY (the
#: Lander's holds on PR 3142, comments 7085002242 and 7088663896).
ADD_BACK_STEP = (
    "The service's lists set no MEFOR_SECRETS_DIRECTORY. Where install-service.ps1 already "
    "made the secrets directory, add MEFOR_SECRETS_DIRECTORY naming that existing path back to "
    "the service's AppEnvironmentExtra, beside its other entries, before any re-run of the "
    "installer, which refuses an existing directory the service does not name. `nssm set` "
    "replaces that whole list, so read it first with `nssm get`, running the service's own "
    "nssm.exe by its full path, and pass back every entry but those refused above: see "
    'docs/SERVICE.md, "Start / stop / status"'
)

#: Its opener, which the step leaves out wherever a string in the lists sets the directory
#: (the Lander's holds on PR 3142, comments 7088102723 and 7088663896).
SET_NO = "The service's lists set no MEFOR_SECRETS_DIRECTORY"

#: Main's wider pass-back exclusion, from its joined-directory step.
WIDER = "and the strings this step and any step above say to remove"

#: The step where a string in the lists sets the directory and a value runs on, or a joined
#: string sets it: no opener, and main's wider exclusion (the Lander's hold on PR 3142,
#: comments 7088102723 and 7088663896; the Lander's rulings on handback 7085947392, F1, and
#: comment 7087145957).
ADD_BACK_JOINED = (
    "Where install-service.ps1 already made the secrets directory, add MEFOR_SECRETS_DIRECTORY "
    "naming that existing path back to the service's AppEnvironmentExtra, beside its other "
    "entries, before any re-run of the installer, which refuses an existing directory the "
    "service does not name. `nssm set` replaces that whole list, so read it first with `nssm "
    "get`, running the service's own nssm.exe by its full path, and pass back every entry but "
    "those refused above and the strings this step and any step above say to remove: see "
    'docs/SERVICE.md, "Start / stop / status"'
)

#: The step where a value runs on and no string in the lists sets the directory: the opener,
#: and the wider exclusion, since the strings the run-on step removes may hold the refused
#: value (the Lander's hold on PR 3142, comment 7088663896).
ADD_BACK_RUN_ON = f"{SET_NO}. {ADD_BACK_JOINED}"

#: Text every form of the step carries, so a negative arm sees any.
ADD_BACK_ANY = "Where install-service.ps1 already made the secrets directory, add"

#: Its create clause, added only where a setting moves to the secrets directory (the Lander's
#: ruling on handback 7087574833, R1).
ADD_BACK_CREATE = (
    '. Where none exists yet, the bullet "The other secrets: a secrets directory" under '
    'docs/SERVICE.md, "Protect the store encryption key at rest", says how the directory is '
    "created"
)

#: The step with its create clause, as origin/main prints it.
ADD_BACK = ADD_BACK_STEP + ADD_BACK_CREATE

#: Printed when a setting goes to the secrets directory and no entry is read as naming it.
CREATE = (
    'Where no secrets directory exists yet, the bullet "The other secrets: a secrets directory" '
    'under docs/SERVICE.md, "Protect the store encryption key at rest", says how it is created'
)
