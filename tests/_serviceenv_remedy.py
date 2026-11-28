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

#: How the refusal names a secret-class name an entry names with nothing set in it (vault
#: BACKLOG #5394), after the name and its source.
NAMED_EMPTY = "is named with nothing set in it"

#: Printed before ``REMOVE`` wherever such a name refuses (vault BACKLOG #5394).
EMPTY_CLASS_STEP = (
    "A secret-class name with nothing set in it refuses because a secret can be written apart "
    "from its name, into an entry or line after it, where the engine may not read it as that "
    "secret. Where an entry or line after such a name holds its secret, that entry or line is "
    "refused too: remove it with the name, and where it is one line of a string that sets other "
    "variables, take out that line alone. Each entry and line that names such a name with "
    "nothing set in it is refused, in every list and value, so remove each one. Where such an "
    "empty entry is there to keep a value set elsewhere, such as in the machine-wide "
    "environment, out of the service, remove that value where it is set too, since without the "
    "entry it reaches the service. Where the setting is wanted, keep a store key in a "
    "DPAPI-protected key file, a retired key only in the shell that runs `messagefoundry "
    "rotate-key`, never in the service, and any other secret in the secrets directory: see "
    'docs/SERVICE.md, "Protect the store encryption key at rest"'
)

#: Printed after ``EMPTY_CLASS_STEP`` where the OIDC client key, which takes either a key or its
#: path, is named empty and not listed as set (vault BACKLOG #5394).
EMPTY_PATH_FORM_STEP = (
    "Where an entry sets MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY to the path of its key file, that "
    "entry holds no secret and is not refused: keep it"
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

#: The step printed first wherever a directory entry is in doubt
#: (``ServiceEnvPosture.directory_in_doubt``), with no condition: every line that may name the
#: directory, in every list, comes out, and those lines alone, so every refused variable is still
#: where it was when the Put step reads it, and a string holding such a line beside others is
#: written back with only that line taken out (the Lander's ruling (a) on PR 3142's repair
#: handback, comment 7112155891). It replaces the two AppEnvironmentExtra clauses of the Lander's
#: holds on PR 3142, comments 7089064404, 7089400537 and 7090314503 (the Lander's ruling B on
#: PR 3142's repair handback, comment 7106776128).
DOUBT_STEP = (
    "At least one entry that may set MEFOR_SECRETS_DIRECTORY is not one line setting it plainly "
    "to a path under that name, in ASCII with no blank around it, so first, reading the lists as "
    "this step says below, note the path each such line names where it is plainly a path, then "
    "take each line that "
    "may set it out of every list, whatever its letter case, a blank around its name, or a letter "
    "outside ASCII that upper-cases to one of its letters, with each line below it in its string "
    "that the engine reads as part of its value, up to the next that names a refused variable, "
    "alone or set, or sets another variable: a name before its first equals sign with no run of "
    "43 letters, digits, plus signs, slashes, hyphens or underscores in it, and after that sign "
    "something besides equals signs and blanks. Take out those lines alone, and keep "
    "every refused variable and every other line where it is, for the steps below to move each "
    "value before its entry goes: where such a line shares a registry string with other lines, "
    "write that string back with its other lines as they were, in their order, and leave out "
    "only a string that holds nothing else. No refused value may be typed on a command line, "
    "where it reaches at least the shell's history, a transcript and process-creation audit "
    "events, so while a list holds one, do not pass it back with `nssm set`. Read AppEnvironment "
    "and AppEnvironmentExtra, under Parameters in the registry key named above, which PowerShell "
    "names under HKLM:, with `Get-ItemProperty` into a variable, printing nothing, edit those strings in that same "
    "session, and write each back with `Set-ItemProperty -Type MultiString`, every entry kept "
    "but those lines. The service's own Environment value is no NSSM list, and is read and "
    'written the same way on the registry key named above: see docs/SERVICE.md, "Start / stop / '
    'status"'
)

#: DOUBT_STEP's command-line rule: the lists it edits still hold every refused value, so it never
#: has them passed back on a command line (the Lander's hold on PR 3142, comment 7116005396, F2).
NO_COMMAND_LINE = "No refused value may be typed on a command line"

#: DOUBT_STEP's sentence where taking out the lines that may set the directory would change how
#: the reader reads a refused variable (``ServiceEnvPosture.directory_in_refused``): the strings
#: holding a refused variable or its run-on stay as they are until the step that removes it,
#: since such a line may be part of its value, a store key among them (code review round 1 on
#: the repair of PR 3142's round-3 open findings 1 and 2; its own sentence, after the take-out
#: it qualifies, under the Lander's hold on PR 3142, comment 7116005396, F5). It also leaves a
#: string whose take-out would join its neighbours into another reading of a refused variable
#: (the Lander's hold on PR 3142, comment 7119680463, item 3).
DOUBT_LEAVE = (
    ". Leave as it is each string that holds a refused variable or that a refused variable's "
    "value runs on into, since a line there that may set MEFOR_SECRETS_DIRECTORY may be part of "
    "that value, and each string whose take-out, alone or beside the others this step takes out, "
    "would change how the engine reads a refused variable, such as one between a refused name "
    "written alone or set to nothing and the string below it, which the take-out may join, until "
    "a step below removes that variable, then take such lines out with it"
)

#: DOUBT_STEP as printed where DOUBT_LEAVE applies.
DOUBT_STEP_LEAVING = DOUBT_STEP.replace(
    "holds nothing else. No refused", f"holds nothing else{DOUBT_LEAVE}. No refused", 1
)

#: The add-back step's pass-back exclusion where a directory entry is in doubt, so no line the
#: step above takes out is written back (the Lander's hold on PR 3142, comment 7090314503).
DOUBT_PASS_BACK = "and the strings and lines the steps above say to remove or take out"

#: The add-back step as printed wherever a directory entry is in doubt, after the removal
#: steps: no opener, a condition on the directory existing however it was made, since DOUBT_STEP
#: may take out a working entry (code review round 2 on the repair of PR 3142), and the doubt
#: pass-back exclusion.
ADD_BACK_DOUBT = ADD_BACK_BARE.replace(
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
#: directory entry is in doubt; there it prints after DOUBT_STEP and before the Put step, so the
#: installer it points at runs with no line left that may set the directory (round-3 open
#: finding 1 on PR 3142's repair handback, comment 7110577570, and the Lander's ruling (a) on
#: comment 7112155891).
CREATE = (
    'Where no secrets directory exists yet, the bullet "The other secrets: a secrets directory" '
    'under docs/SERVICE.md, "Protect the store encryption key at rest", says how it is created'
)

#: How the remedy opens wherever a directory entry is in doubt, a setting moves to the secrets
#: directory and no store key moves to a key file: the doubt step, then the create step, so the
#: Put step after them finds a directory and every refused value still in place (the Lander's
#: ruling (a) on PR 3142's repair handback, comment 7112155891).
DOUBT_CREATE = f"{DOUBT_STEP}. {CREATE}"

#: DOUBT_CREATE where DOUBT_LEAVE applies.
DOUBT_CREATE_LEAVING = f"{DOUBT_STEP_LEAVING}. {CREATE}"

#: CREATE's clause where a directory entry is in doubt, DOUBT_LEAVE applies and an
#: AppEnvironmentExtra string is one install-service.ps1 reads as setting the directory
#: (``ServiceEnvPosture.installer_reads_extra``). It states its own condition, and has the
#: operator read every line out before removing the string, since the registry may hold its
#: only copy, a retired store key among them, which protect-key never stores (code review round
#: 1 on the repair of PR 3142's round-3 open findings 1 and 2; the Lander's hold on PR 3142,
#: comment 7116005396, F1). It reads out, until none is left, each string whose refused
#: variable removing the others would read differently (the Lander's hold on PR 3142, comment
#: 7119680463, items 1 and 3; code review round 1 on that repair). It removes those strings
#: whole and adds no line back, so the ordinary lines they hold are lost (the Lander's hold
#: on PR 3142, comment 7125522135).
CREATE_INSTALLER = (
    ". Where a string the first step leaves as it is lies in AppEnvironmentExtra and starts with "
    "MEFOR_SECRETS_DIRECTORY= in any letter case, install-service.ps1, which `messagefoundry "
    "service install` also runs, may read that string as the directory the service names and "
    "print it, and drops it whole, so before you run the installer read out of that string, of "
    "each string that holds a refused variable, alone or set, whose reading removing the strings "
    "this sentence names would change, and of each string a refused value in them runs on into, "
    "every line they hold, remove those strings with each refused variable whose value they "
    "hold, put each refused value you read where the other steps say, and keep a retired key for "
    "the shell that runs `messagefoundry rotate-key`, writing the list back as the first step "
    "says"
)

#: How the Put step names the directory wherever a directory entry is in doubt, since the doubt
#: step has taken every directory line out (code review round 1 on that repair).
PUT_DOUBT = "in the secrets directory, the one the installer made or the one already there, as"
