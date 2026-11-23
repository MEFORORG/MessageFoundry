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

#: Printed wherever a MEFOR_VALUE_* name is refused, whether it moves or is only told to go
#: (the Lander's hold on PR 3142, comment 7104660861, item 3).
COUNTED_ONCE = (
    "Each MEFOR_VALUE_* name is counted once, without regard to case, under the first registry "
    "value that sets it, so remove it from every value that sets it"
)

#: Printed when a refused variable's value runs on into the entries after it.
RUNS_ON = (
    "At least one refused variable's value runs on past its own entry, so remove the entries it "
    "runs on into with it, or the value stays in the registry key"
)

#: Printed last, only where a refused value runs on into a directory entry and no directory
#: entry is in doubt, as ``ServiceEnvPosture.directory_in_doubt``'s doc says: one entry stays, in
#: AppEnvironmentExtra, rewritten to the path, and every other directory line goes (the Lander's
#: holds on PR 3142, comment 7100710066, items 5 and 8, and its ruling B on the repair handback,
#: comment 7106776128).
KEEP = (
    "Leave exactly one entry that sets MEFOR_SECRETS_DIRECTORY in the service's lists: one in "
    "AppEnvironmentExtra, which NSSM applies last, added there where that list has none, written "
    "as MEFOR_SECRETS_DIRECTORY=<path> naming the secrets directory by its path, so it is the one "
    "the engine reads. Take each "
    "other line that sets MEFOR_SECRETS_DIRECTORY out of every list, keeping each other line no "
    "step above says to remove, before any re-run of the installer, which refuses an existing "
    "directory the service does not name. `nssm set` replaces a whole list, so read it first "
    "with `nssm get`, running the service's own nssm.exe by its full path, and pass back every "
    "entry but those refused above and the strings and lines this step and any step above say "
    'to remove: see docs/SERVICE.md, "Start / stop / status"'
)

#: The clause the removal and run-on steps carry wherever KEEP is printed, so neither removes a
#: directory line KEEP then keeps (the Lander's hold on PR 3142, comment 7100710066, item 8).
SPARE = ", but for each line that sets MEFOR_SECRETS_DIRECTORY, which a step below covers"

#: REMOVE and RUNS_ON as printed beside KEEP.
REMOVE_SPARING = REMOVE.replace(" environment. See", f" environment{SPARE}. See", 1)
RUNS_ON_SPARING = RUNS_ON.replace(" with it, or", f" with it{SPARE}, or", 1)

#: The add-back step as origin/main prints it, where a refused name outside the key class
#: is listed, no value runs on, and no line of any string in the lists sets
#: MEFOR_SECRETS_DIRECTORY (the Lander's holds on PR 3142, comments 7085002242, 7088663896
#: and 7089064404, B).
ADD_BACK_STEP = (
    "The service's lists set no MEFOR_SECRETS_DIRECTORY. Where install-service.ps1 already "
    "made the secrets directory, add MEFOR_SECRETS_DIRECTORY naming that existing path back to "
    "the service's AppEnvironmentExtra, beside its other entries, before any re-run of the "
    "installer, which refuses an existing directory the service does not name. `nssm set` "
    "replaces that whole list, so read it first with `nssm get`, running the service's own "
    "nssm.exe by its full path, and pass back every entry but those refused above: see "
    'docs/SERVICE.md, "Start / stop / status"'
)

#: Its opener, which the step leaves out wherever a line of any string in the lists sets the
#: directory (the Lander's holds on PR 3142, comments 7088102723, 7088663896 and 7089064404,
#: B).
SET_NO = "The service's lists set no MEFOR_SECRETS_DIRECTORY"

#: The step with no opener and no clause, the base the forms below are built from.
ADD_BACK_BARE = ADD_BACK_STEP.removeprefix(f"{SET_NO}. ")

#: Main's wider pass-back exclusion, from its joined-directory step.
WIDER = "and the strings this step and any step above say to remove"

#: The step printed wherever a directory entry is in doubt
#: (``ServiceEnvPosture.directory_in_doubt``), with no condition: every line that may name the
#: directory, in every list, comes out, a string that holds nothing else whole, and each other
#: line no step above removes stays. It replaces the two AppEnvironmentExtra clauses of the
#: Lander's holds on PR 3142, comments 7089064404, 7089400537 and 7090314503 (the Lander's
#: ruling B on PR 3142's repair handback, comment 7106776128).
DOUBT_STEP = (
    "At least one entry that may set MEFOR_SECRETS_DIRECTORY is not one line setting it plainly "
    "to a path under that name, in ASCII with no blank around it, so take each line that may set "
    "it out of every list, whatever its letter case, a blank around its name, or a letter outside "
    "ASCII that upper-cases to one of its letters, removing an entry that holds nothing else and "
    "keeping each other line no step above says to remove. `nssm set` replaces a whole list, so "
    "read AppEnvironment and AppEnvironmentExtra first with `nssm get`, running the service's own "
    "nssm.exe by its full path, and pass back every entry but the strings and lines this step and "
    "the steps above say to remove or take out. The service's own Environment value is no NSSM "
    'list and is edited in the registry key named above: see docs/SERVICE.md, "Start / stop / '
    'status"'
)

#: The add-back step's pass-back exclusion where a directory entry is in doubt, so no line the
#: step above takes out is written back (the Lander's hold on PR 3142, comment 7090314503).
DOUBT_PASS_BACK = "and the strings and lines the steps above say to remove or take out"

#: DOUBT_STEP and the add-back step after it, as printed wherever a directory entry is in doubt:
#: no opener, a condition on the directory existing however it was made, since DOUBT_STEP may
#: take out a working entry (code review round 2 on the repair of PR 3142), and the doubt
#: pass-back exclusion.
ADD_BACK_DOUBT = f"{DOUBT_STEP}. " + ADD_BACK_BARE.replace(
    "Where install-service.ps1 already made the secrets directory,",
    "Where the secrets directory already exists, however it was made,",
    1,
).replace("refused above: see", f"refused above {DOUBT_PASS_BACK}: see", 1)

#: The step where a value runs on and no line of any string sets the directory: the opener,
#: and the wider exclusion, since the strings the run-on step removes may hold the refused
#: value (the Lander's hold on PR 3142, comment 7088663896).
ADD_BACK_RUN_ON = (
    "The service's lists set no MEFOR_SECRETS_DIRECTORY. Where install-service.ps1 already "
    "made the secrets directory, add MEFOR_SECRETS_DIRECTORY naming that existing path back to "
    "the service's AppEnvironmentExtra, beside its other entries, before any re-run of the "
    "installer, which refuses an existing directory the service does not name. `nssm set` "
    "replaces that whole list, so read it first with `nssm get`, running the service's own "
    "nssm.exe by its full path, and pass back every entry but those refused above and the "
    'strings this step and any step above say to remove: see docs/SERVICE.md, "Start / stop / '
    'status"'
)

#: Text every form of the step carries, so a negative arm sees any.
ADD_BACK_ANY = "naming that existing path back to the service's AppEnvironmentExtra"

#: Its create clause, added only where a setting moves to the secrets directory (the Lander's
#: ruling on handback 7087574833, R1).
ADD_BACK_CREATE = (
    '. Where none exists yet, the bullet "The other secrets: a secrets directory" under '
    'docs/SERVICE.md, "Protect the store encryption key at rest", says how the directory is '
    "created"
)

#: The step with its create clause, as origin/main prints it.
ADD_BACK = ADD_BACK_STEP + ADD_BACK_CREATE

#: Printed when a setting goes to the secrets directory and no entry is read as naming it, or a
#: directory entry is in doubt, before the Put step (round-3 open finding 1 on PR 3142's repair
#: handback, comment 7110577570).
CREATE = (
    'Where no secrets directory exists yet, the bullet "The other secrets: a secrets directory" '
    'under docs/SERVICE.md, "Protect the store encryption key at rest", says how it is created'
)

#: CREATE as printed wherever a directory entry is in doubt: the installer drops whole each entry
#: that starts with the directory's name and may print the value it reads, so it runs only once
#: the doubt step has taken those lines out (code review round 1 on the repair of PR 3142's
#: round-3 open finding 1).
CREATE_DOUBT = (
    f"{CREATE}, but run the installer only once the steps below have taken out each line that "
    "may set MEFOR_SECRETS_DIRECTORY, since it drops whole each entry that starts with "
    "MEFOR_SECRETS_DIRECTORY= in any letter case, every line in it included, and may print the "
    "value it reads"
)
