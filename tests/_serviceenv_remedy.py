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

#: Main's clause from that step, narrowed by "and nothing else", printed wherever a string in
#: AppEnvironmentExtra sets the directory and nothing else (the Lander's holds on PR 3142,
#: comments 7089064404, 7089400537 and 7090314503).
REMOVE_OTHER = "and remove any other entry that sets MEFOR_SECRETS_DIRECTORY and nothing else"

#: The clause printed wherever a string in AppEnvironmentExtra holds a line that sets the
#: directory and a non-blank line that does not. It asks for each directory line to come out of
#: every such string, keeping each other line no step above removes, and removes no such
#: string whole (the Lander's hold on PR 3142, comment 7090314503).
TAKE_LINE = (
    "and take each line that sets MEFOR_SECRETS_DIRECTORY out of any other entry that holds "
    "other lines too, keeping each other line no step above says to remove"
)

#: Printed with TAKE_LINE, at the end of the pass-back, so the lines it takes out are not passed
#: back (the Lander's hold on PR 3142, comment 7090314503).
TAKE_OUT = ", leaving out the lines this step says to take out"

#: The step where a string in AppEnvironmentExtra holds a directory line and other lines, no
#: string there sets only the directory, and no value runs on: no opener, the take-line
#: clause and its pass-back phrase, and no wider exclusion (the Lander's holds on PR 3142,
#: comments 7089064404, B, 7089400537 and 7090314503).
ADD_BACK_MIXED = ADD_BACK_BARE.replace(
    "beside its other entries, ", f"beside its other entries, {TAKE_LINE}, ", 1
).replace("refused above: see", f"refused above{TAKE_OUT}: see", 1)

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

#: The step where a string sets the directory and nothing else, joined to a value or as its
#: own item in AppEnvironmentExtra, and for a store key alone: no opener, main's clause narrowed,
#: and main's wider exclusion, which then leaves out every other such string (the Lander's
#: holds on PR 3142, comments 7088102723, 7088663896, 7089064404 and 7089400537; the
#: Lander's rulings on handback 7085947392, F1, and comment 7087145957).
ADD_BACK_JOINED = (
    "Where install-service.ps1 already made the secrets directory, add MEFOR_SECRETS_DIRECTORY "
    "naming that existing path back to the service's AppEnvironmentExtra, beside its other "
    "entries, and remove any other entry that sets MEFOR_SECRETS_DIRECTORY and nothing else, "
    "before any re-run of the installer, which refuses an existing directory the service does "
    "not name. `nssm set` replaces that whole list, so read it first with `nssm get`, running "
    "the service's own nssm.exe by its full path, and pass back every entry but those refused "
    "above and the strings this step and any step above say to remove: see docs/SERVICE.md, "
    '"Start / stop / status"'
)

#: The step where, in AppEnvironmentExtra, one string sets only the directory and another
#: holds a directory line and other lines: both clauses, the wider exclusion, and the take-line
#: pass-back phrase (the Lander's hold on PR 3142, comment 7090314503).
ADD_BACK_JOINED_MIXED = ADD_BACK_JOINED.replace(
    f"{REMOVE_OTHER}, ", f"{REMOVE_OTHER}, {TAKE_LINE}, ", 1
).replace(f"{WIDER}: see", f"{WIDER}{TAKE_OUT}: see", 1)

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


#: The path of the directory that holds the files, as the take-out step and the step before
#: the move name it.
FILES_PATH = "the path of the directory that holds the secrets directory's files"


def target(stray: str | None, *, plain: bool = True) -> str:
    """The path the LEAVE ending and the step before the move name. ``stray`` is the words for
    the entry whose path may be the one, or None where none may be. A value that is not plainly a
    path is never offered (the Lander's hold on PR 3142, comment 7096232111, item 3)."""
    if stray is None:
        return FILES_PATH
    if plain:
        return f"{FILES_PATH}, which may be the path {stray} named"
    return f"{FILES_PATH}, not the value of {stray}, which is not plainly a path"


#: The ASCII entry a LEAVE step leaves, in the list NSSM sets last and install-service.ps1 reads.
LEFT = "the entry spelled in ASCII in AppEnvironmentExtra that sets MEFOR_SECRETS_DIRECTORY"

#: The take-out step's ending where the one ASCII item in AppEnvironmentExtra names the
#: directory, a look-alike the engine receives beside it, and no Put step prints, so it adds
#: none.
LOOKALIKE_LEAVE = (
    f", and leave {LEFT} as the one that names it, first setting it to "
    f"{target('a look-alike spelling this step takes out')}"
)


def repoint(stray: str | None = "a look-alike spelling a later step says to take out") -> str:
    """The step printed just before the Put step where LEAVE applies, so the files go where the
    final entry points (item 6)."""
    return f"Before moving anything into the secrets directory, set {LEFT} to {target(stray)}"


REPOINT = repoint()


def choose(*, plain: bool = True) -> str:
    """The step printed just before the Put step where the take-out step prints and LEAVE does
    not: it fixes the path a later step names, so the files go there (item 6)."""
    return (
        "Before moving anything into the secrets directory, choose its path: "
        f"{target('an entry a later step says to take out', plain=plain)}. A later step names that "
        "path under the ASCII spelling MEFOR_SECRETS_DIRECTORY, so move the files there, whatever "
        "MEFOR_SECRETS_DIRECTORY names now"
    )


CHOOSE = choose()

#: The LEAVE ending where the step before the move printed.
LOOKALIKE_LEAVE_MOVED = (
    f", and leave {LEFT} as the one that names it, set to the path the step before the move into "
    "the secrets directory gave it"
)

#: The path the NEXT and ADD endings name, where every look-alike or padded value is plain.
COPIED = "the path that entry named"

#: The same where one is not (item 3).
COPIED_UNPLAIN = f"{FILES_PATH}, not that entry's value, which is not plainly a path"

#: The same where the step before the move chose the path. The NEXT and ADD endings then name
#: it whether or not a stray entry was meant to name the directory, since the files are there.
CHOSEN = "the path the step before the move into the secrets directory chose"

#: The NEXT and ADD endings' opener where no step before the move chose the path.
_MEANT = ". Where an entry this step takes out was meant to name the secrets directory, "


def lookalike_next(copied: str = COPIED) -> str:
    """The ending where the add-back step prints next. It says to follow that step whether or not
    install-service.ps1 made the directory, which path to name, not to pass back what this step
    takes out, and to read the list first (item 8)."""
    follow = ". Follow" if copied == CHOSEN else f"{_MEANT}follow"
    return (
        f"{follow} the "
        f"next step even where install-service.ps1 did not make that directory, and name {copied}, "
        "in place of the path that step names, leaving out of what it passes back each entry and "
        "line this step takes out. As it says, `nssm set` replaces that whole list, so read "
        "AppEnvironmentExtra first with `nssm get`, running the service's own nssm.exe by its full "
        "path"
    )


LOOKALIKE_NEXT = lookalike_next()


def lookalike_add(
    copied: str = COPIED, *, remove_other: bool = False, take_line: bool = False
) -> str:
    """The ending where nothing else names the path under the ASCII spelling: the add-back step's
    clauses, gated as there, and its warning about the installer (items 2 and 7)."""
    add = ". Add" if copied == CHOSEN else f"{_MEANT}add"
    return (
        f"{add} "
        "MEFOR_SECRETS_DIRECTORY, spelled in ASCII, to the service's AppEnvironmentExtra, the list "
        f"install-service.ps1 reads, naming {copied}, as the only entry there that sets it, "
        + (f"{REMOVE_OTHER}, " if remove_other else "")
        + (f"{TAKE_LINE}, " if take_line else "")
        + "before any re-run of the installer, which refuses an existing directory the service "
        "does not name. `nssm set` replaces that whole list, so read it first with `nssm get`, "
        "running the service's own nssm.exe by its full path, and pass back every entry but those "
        "this remedy says to remove, leaving out the lines this step says to take out"
    )


LOOKALIKE_ADD = lookalike_add()

#: What the step says of the look-alikes, before ``named``.
_LOOKALIKE_SAID = (
    "At least one entry spells MEFOR_SECRETS_DIRECTORY with a character outside ASCII, written "
    "here with each such character as its code point: "
)

#: What the step says of a padded name (comment 7096232111, item 1).
PADDED = (
    "At least one entry spells MEFOR_SECRETS_DIRECTORY with a blank before or after the name, "
    "such as a space, a tab, a line break or U+00A0. Python's os.environ keeps that blank in the "
    "name, so the engine does not read it as the secrets directory, and install-service.ps1, "
    "which matches the name followed at once by an equals sign, does not see it either"
)

#: The take-out instruction itself, with item 5's qualifier.
TAKE_OUT_STEP = (
    "Take each such entry out of the service's environment, whether its value is blank or not, "
    "taking only its own line out of an entry that holds other lines too, keeping each other "
    "line no step above says to remove"
)


def lookalike_step(*named: str, ending: str, padded: bool = False) -> str:
    """The step printed wherever a line of any string in the lists sets a look-alike spelling of
    MEFOR_SECRETS_DIRECTORY, one ``os.environ`` folds to it that is not ASCII, or a padded one.
    ``named`` is each look-alike as the step writes it, every character outside ASCII as
    ``<U+XXXX>``, none for a padded name alone, and ``ending`` one of the endings above. It says
    to take each one out, blank or not, and never to keep one (the Lander's holds on PR 3142,
    comments 7092584745 and 7096232111)."""
    said: list[str] = []
    if named:
        said.append(
            f"{_LOOKALIKE_SAID}{', '.join(named)}. Windows was measured keeping a name with "
            "U+017F apart from the ASCII one, but the engine reads its environment through "
            "Python's os.environ, which folds such a name to MEFOR_SECRETS_DIRECTORY, so the "
            "engine may read such an entry, in a list it receives, as the secrets directory. "
            "install-service.ps1 does not match it, so a re-run of the installer may add a second "
            "entry beside it"
        )
    if padded:
        said.append(PADDED)
    return ". ".join([*said, TAKE_OUT_STEP]) + ending


#: The KEEP sentence wherever the take-out step also prints: it names its own antecedent, since
#: that step sits between, and keeps the ASCII spelling only.
KEEP_ASCII = (
    "Keep any entry a refused value runs on into that sets MEFOR_SECRETS_DIRECTORY, spelled in "
    "ASCII, to a path and nothing else, as its own entry"
)


#: Text every form of the look-alike step carries, so a negative arm sees any.
LOOKALIKE_ANY = "At least one entry spells MEFOR_SECRETS_DIRECTORY with a character outside ASCII"

#: Text every form of the take-out step carries.
TAKE_OUT_ANY = "Take each such entry out of the service's environment"
