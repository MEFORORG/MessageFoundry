# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The service-environment remedy, followed top to bottom where a directory entry is in doubt.

Round-3 open finding 1 on PR 3142's repair handback, comment 7110577570, and the Lander's ruling
(a) on comment 7112155891: an operator who applies the printed steps in order, against the
registry, must still find each refused value there when the step that moves it runs, the
protect-key step for a store key and the Put step for the rest. The walk below applies each step
it reaches to a simulated registry, models install-service.ps1 where the create step sends the
operator to it, and stops at the Put step. A sentence it does not know before the Put step fails
the test. It also reads 6c6b514's wording, the doubt step's old pass-back and the create step's
old installer clause, so the test fails on that revision rather than stopping at an unknown
sentence there. Synthetic values only.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from messagefoundry.serviceenv import (
    _LINE_BREAK,
    KEY_CLASS_NAMES,
    _installer_reads,
    _may_name_directory,
    _variables,
    read_service_env_posture,
    service_env_refusal,
)
from tests._serviceenv_remedy import NO_COMMAND_LINE

_DIR = "MEFOR_SECRETS_DIRECTORY"
_EXTRA = "Parameters\\AppEnvironmentExtra"
_APP = "Parameters\\AppEnvironment"
_END = '. [security].enforcement = "warn" does not change this refusal'
_KEY = KEY_CLASS_NAMES[0]
_RETIRED = "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED"
assert _RETIRED in KEY_CLASS_NAMES and _KEY != _RETIRED
_KEY_B64 = base64.b64encode(b"synthetic-store-key-for-tests-01").decode()
_KEY_B64_2 = base64.b64encode(b"synthetic-store-key-for-tests-02").decode()
_NEW_DIRECTORY = "C:\\synthetic-secrets"


@dataclass
class _Probe:
    entries: list[tuple[str, str]] = field(default_factory=list)

    def ancestor_images(self) -> Iterator[tuple[int, str]]:
        return iter([(200, "python.exe"), (100, "nssm.exe")])

    def service_at(self, pid: int) -> str | None:
        return "MessageFoundry" if pid == 100 else None

    def environment_entries(self, service_name: str) -> list[tuple[str, str]]:
        return list(self.entries)


@dataclass
class _Registry:
    """The service's lists as the operator edits them, string by string, in registry order."""

    entries: list[tuple[str, str]]
    #: The strings a refused value runs on into, as the run-on step names them to the operator.
    runs_on_into: frozenset[str] = frozenset()
    #: Whether a secrets directory already exists.
    directory: bool = False
    #: Each string install-service.ps1 read as setting the directory, and so dropped.
    installer_read: list[str] = field(default_factory=list)
    #: The refused names a step has already moved out, the store key to its key file.
    moved: set[str] = field(default_factory=set)
    #: The refused names whose value the operator read out of the registry, as the create step's
    #: installer clause says, before removing the string that held it.
    read_out: set[str] = field(default_factory=set)

    def readable(self, name: str, secret: str) -> bool:
        """Whether the registry still sets ``name`` to a value holding ``secret``, as the
        engine's own reader reads it, so the operator can still read it from there."""
        return any(
            variable.written.strip().upper() == name and secret in variable.value
            for variable in _variables(self.entries)
        )


def _names_refused(line: str, refused: frozenset[str]) -> bool:
    """Whether ``line`` sets, or names alone, a refused variable."""
    return line.partition("=")[0].strip().upper() in refused


def _holds_refused(string: str, refused: frozenset[str]) -> bool:
    return any(_names_refused(line, refused) for line in _LINE_BREAK.split(string))


def _doubt_step(steps: list[str]) -> str:
    """The doubt step's sentences, from its opener to the one on the Environment value."""
    start = next(
        i
        for i, s in enumerate(steps)
        if s.startswith(f"At least one entry that may set {_DIR} is not")
    )
    end = next(
        i
        for i in range(start, len(steps))
        if steps[i].startswith("The service's own Environment value")
    )
    return ". ".join(steps[start : end + 1])


_RUN = re.compile(r"[A-Za-z0-9+/_-]{43}")


def _ends_the_value(line: str, refused: frozenset[str]) -> bool:
    """The step's own rule for the line that ends a directory line's value: it names a refused
    variable, alone or set, or it sets another variable, a name before its first equals sign
    with no run of 43 such characters in it and something after that sign besides equals signs
    and blanks."""
    if _names_refused(line, refused):
        return True
    name, equals, value = line.partition("=")
    return bool(
        equals and name.strip() and not _RUN.search(name) and value.replace("=", "").strip()
    )


def _take_out(string: str, refused: frozenset[str], *, with_value: bool) -> list[str]:
    """The lines of ``string`` left once each line that may set the directory is out, with, as
    the step says where ``with_value``, each line below one that it reads as that value."""
    kept: list[str] = []
    dropping = False
    for line in _LINE_BREAK.split(string):
        if _may_name_directory(line):
            dropping = True
            continue
        if dropping and with_value and not _ends_the_value(line, refused):
            continue
        dropping = False
        kept.append(line)
    return kept


def _readings(
    entries: list[tuple[str, str]], refused: frozenset[str]
) -> frozenset[tuple[str, str, str]]:
    """How the engine's own reader reads each refused variable in ``entries``: its registry
    value, its upper-cased name and its value, line breaks written as one ``\\n``."""
    return frozenset(
        (v.where, v.written.strip().upper(), _LINE_BREAK.sub("\n", v.value))
        for v in _variables(entries)
        if v.written.strip().upper() in refused
    )


def _value_lines(entries: list[tuple[str, str]], refused: frozenset[str]) -> frozenset[str]:
    """Every non-blank line of each refused variable's value as the reader reads it."""
    return frozenset(
        line.strip()
        for _where, _name, value in _readings(entries, refused)
        for line in value.split("\n")
        if line.strip()
    )


def _apply_doubt_step(text: str, registry: _Registry, refused: frozenset[str]) -> None:
    """Take each line that may set the directory out of every list, as the step says, and pass
    back what its pass-back clause says to pass back."""
    # A clause after a comma before the Lander's hold on PR 3142, comment 7116005396, F5, and a
    # sentence of its own since.
    leave = (
        "leave as it is each string that holds a refused variable or that a refused" in text.lower()
    )
    # Since the Lander's hold on PR 3142, comment 7119680463, item 3: also each string whose
    # take-out would change how the engine reads a refused variable.
    rejoin = "whose take-out would change how the engine reads a refused variable" in text
    with_value = (
        "each line below it in its string that the engine reads as part of its value" in text
    )
    if "every entry kept but those lines" in text or (
        "pass back every entry, with only those lines taken out" in text
    ):
        also_removed = False
    elif "the strings and lines this step and the steps above say to remove or take out" in text:
        # 6c6b514's wording: the doubt step sat below the removal and run-on steps, and its
        # pass-back left out what those say to remove, every refused variable and the strings a
        # value runs on into.
        also_removed = True
    else:
        raise AssertionError(f"no pass-back clause the walk knows: {text!r}")
    before = _readings(registry.entries, refused)
    kept: list[tuple[str, str]] = []
    for index, (where, string) in enumerate(registry.entries):
        if also_removed and string in registry.runs_on_into:
            continue
        lines = [
            line
            for line in _take_out(string, refused, with_value=with_value)
            if not (also_removed and _names_refused(line, refused))
        ]
        taken = [(where, "\n".join(lines))] if any(line.strip() for line in lines) else []
        if leave and (string in registry.runs_on_into or _holds_refused(string, refused)):
            kept.append((where, string))
            continue
        if rejoin:
            alone = [*registry.entries[:index], *taken, *registry.entries[index + 1 :]]
            if _readings(alone, refused) != before:
                kept.append((where, string))
                continue
        kept.extend(taken)
    registry.entries = kept


def _run_installer(registry: _Registry) -> None:
    """install-service.ps1's Get-MergedEnvironmentList: it drops each empty AppEnvironmentExtra
    string and each that starts with the directory's name and an equals sign in any letter case,
    reading that one as the directory, and adds its own entry at the end."""
    kept: list[tuple[str, str]] = []
    for where, string in registry.entries:
        if where == _EXTRA and _installer_reads(string):
            registry.installer_read.append(string)
            continue
        if where == _EXTRA and not string:
            continue
        kept.append((where, string))
    registry.entries = [*kept, (_EXTRA, f"{_DIR}={_NEW_DIRECTORY}")]
    registry.directory = True


def _follow_installer_clause(
    clause: str, registry: _Registry, refused: frozenset[str], moves: dict[str, str]
) -> None:
    """The create step's clause: read out of each kept AppEnvironmentExtra string the installer
    reads what the clause says to read, then remove that string, with each refused variable
    whose value it holds, and add back what the clause says to add back."""
    # Every line since the Lander's hold on PR 3142, comment 7116005396, F1; before it, each
    # value the next step puts in the secrets directory, which no store key is.
    every_line = "every line it holds" in clause or "every line they hold" in clause
    # Since code review on that repair, with each string a refused value in it runs on into.
    with_run_on = (
        "and of each string a refused value in it runs on into" in clause
        or "and of each string a refused value in these runs on into" in clause
    )
    # Since the Lander's hold on PR 3142, comment 7119680463, item 3: also each string holding a
    # refused variable that removing the installer's string would read differently.
    with_changed = "whose reading removing that string would change" in clause
    # Before that hold, item 1, each other line; since, none that is part of a refused value,
    # which the walk takes as every line of each refused value as the reader reads it.
    add_back = (
        "add each other line back as an entry of its own" in clause
        or "add back as an entry of its own each other line" in clause
    )
    by_reading = "none that is part of a refused value" in clause
    for where, string in list(registry.entries):
        if (where, string) not in registry.entries:
            continue  # removed already, as a string a value ran on into
        if where != _EXTRA or not _installer_reads(string):
            continue
        holders = {
            name
            for name in refused
            if name not in registry.moved and registry.readable(name, moves[name])
        }
        value_lines = _value_lines(registry.entries, refused)
        was_read = _readings(registry.entries, refused)
        index = registry.entries.index((where, string))
        removed = [registry.entries.pop(index)]
        while (
            with_run_on
            and index < len(registry.entries)
            and registry.entries[index][0] == where
            and registry.entries[index][1] in registry.runs_on_into
        ):
            removed.append(registry.entries.pop(index))
        if with_changed:
            now_read = _readings(registry.entries, refused)
            changed = frozenset(name for _w, name, _v in was_read ^ now_read)
            # Each string of this list holding such a variable, and each string its value runs on
            # into, which the clause has read out with it.
            at = 0
            taking = False
            while at < len(registry.entries):
                entry_where, entry = registry.entries[at]
                taking = entry_where == where and (
                    _holds_refused(entry, changed) or (taking and entry in registry.runs_on_into)
                )
                if not taking:
                    at += 1
                    continue
                removed.append(registry.entries.pop(at))
                if at < index:
                    index -= 1
        lost = {name for name in holders if not registry.readable(name, moves[name])}
        # Read out only where its value was in a string the operator read, not left behind.
        read = {name for name in lost if any(moves[name] in text for _w, text in removed)}
        registry.read_out |= read if every_line else read - set(KEY_CLASS_NAMES)
        # A refused variable whose value it held goes with it: the string before it, when that
        # is the refused name set to nothing that ran on into it.
        if index and registry.entries[index - 1][1].partition("=")[2] == "":
            before = registry.entries[index - 1]
            if _names_refused(before[1], refused):
                registry.entries.remove(before)
                index -= 1
        if add_back:
            # Each line that is neither a refused variable nor part of a refused value, and, as
            # the clause says, none that may set the directory.
            others = [
                line
                for _where, text in removed
                for line in _LINE_BREAK.split(text)
                if line.strip()
                and not _names_refused(line, refused)
                and not (
                    line.strip() in value_lines
                    if by_reading
                    else any(secret in line for secret in moves.values())
                )
                and not ("but none that may set" in clause and _may_name_directory(line))
            ]
            registry.entries[index:index] = [(where, line) for line in others]


#: The create step's clause where a string the doubt step leaves as it is may be read by the
#: installer.
_INSTALLER_CLAUSE = "Where a string the first step leaves as it is lies in AppEnvironmentExtra"

_PASSIVE = (
    "Leave as it is each string",
    "Take out those lines alone",
    "`nssm set` replaces a whole list",
    "No refused value may be typed on a command line",
    "Read AppEnvironment and AppEnvironmentExtra",
    "The service's own Environment value",
    "A retired key belongs",
    'See docs/SERVICE.md, "Protect the store encryption key at rest"',
    _INSTALLER_CLAUSE,
)


def _walk(refusal: str, registry: _Registry, moves: dict[str, str]) -> str:
    """Follow the remedy's steps in order up to the Put step. Returns ``"ok"`` or the first
    value the steps lost before the step that moves it."""
    steps = refusal.split("each value refused here. ", 1)[1].removesuffix(_END).split(". ")
    refused = frozenset(moves)
    for index, sentence in enumerate(steps):
        if sentence.startswith(f"At least one entry that may set {_DIR} is not"):
            _apply_doubt_step(_doubt_step(steps), registry, refused)
        elif sentence.startswith("Keep the store key in a DPAPI-protected key file"):
            for name in KEY_CLASS_NAMES:
                if name in moves and not registry.readable(name, moves[name]):
                    return f"{name} lost before the protect-key step"
                # protect-key stores the current key only: a retired key stays where it is, for
                # the shell that runs rotate-key (the Lander's hold on PR 3142, comment
                # 7116005396, F1).
                if name in moves and name != _RETIRED:
                    registry.moved.add(name)
        elif sentence.startswith("Where no secrets directory exists yet"):
            if registry.directory:
                continue
            if "only once the steps below have taken out" in sentence:
                # 6c6b514's wording: the installer may run only after the doubt step below, so
                # that step goes first.
                _apply_doubt_step(_doubt_step(steps), registry, refused)
            if index + 1 < len(steps) and steps[index + 1].startswith(_INSTALLER_CLAUSE):
                _follow_installer_clause(steps[index + 1], registry, refused, moves)
            _run_installer(registry)
        elif sentence.startswith("Put "):
            if not registry.directory:
                return "no secrets directory at the Put step"
            for name, secret in moves.items():
                # A retired key is not moved yet, so it must still be readable here or read out.
                if name in registry.moved or name in registry.read_out:
                    continue
                if not registry.readable(name, secret):
                    return f"{name} lost before the Put step"
            return "ok"
        elif not sentence.startswith(_PASSIVE):
            raise AssertionError(f"a step the walk does not know: {sentence!r}")
    raise AssertionError("the remedy has no Put step")


#: Each case: the registry, the strings a refused value runs on into, the refused names with
#: the secret each holds, and whether a secrets directory already exists.
_CASES: dict[str, tuple[list[tuple[str, str]], frozenset[str], dict[str, str], bool]] = {
    # The round-3 example: the directory line shares its string with the password, whose value
    # runs on into the next string, and C:\d does not exist.
    "shared-string-run-on": (
        [(_EXTRA, "MEFOR_SECRETS_DIRECTORY=C:\\d\nMEFOR_STORE_PASSWORD="), (_EXTRA, "abc")],
        frozenset({"abc"}),
        {"MEFOR_STORE_PASSWORD": "abc"},
        False,
    ),
    "shared-string-run-on-directory-exists": (
        [(_EXTRA, "MEFOR_SECRETS_DIRECTORY=C:\\d\nMEFOR_STORE_PASSWORD="), (_EXTRA, "abc")],
        frozenset({"abc"}),
        {"MEFOR_STORE_PASSWORD": "abc"},
        True,
    ),
    "app-environment-shared-string-run-on": (
        [(_APP, "MEFOR_SECRETS_DIRECTORY=C:\\d\nMEFOR_STORE_PASSWORD="), (_APP, "abc")],
        frozenset({"abc"}),
        {"MEFOR_STORE_PASSWORD": "abc"},
        False,
    ),
    "padded-name": (
        [(_EXTRA, " MEFOR_SECRETS_DIRECTORY=C:\\d"), (_EXTRA, "MEFOR_VALUE_A=SEKRITvalueA")],
        frozenset(),
        {"MEFOR_VALUE_A": "SEKRITvalueA"},
        False,
    ),
    "padded-name-shared-string": (
        [(_EXTRA, "MEFOR_SECRETS_DIRECTORY\u00a0=C:\\d\nMEFOR_AUTH_AD_BIND_PASSWORD=SEKRITbindPw")],
        frozenset(),
        {"MEFOR_AUTH_AD_BIND_PASSWORD": "SEKRITbindPw"},
        False,
    ),
    "app-environment-later-line": (
        [
            (
                _APP,
                "MEFOR_AI_ENVIRONMENT=prod\nmefor_secrets_directory=C:\\d\n"
                "MEFOR_VALUE_A=SEKRITvalueA",
            )
        ],
        frozenset(),
        {"MEFOR_VALUE_A": "SEKRITvalueA"},
        False,
    ),
    "store-key-in-the-directory-string": (
        [
            (_EXTRA, f"MEFOR_SECRETS_DIRECTORY=C:\\d\n{_KEY}={_KEY_B64}"),
            (_EXTRA, "MEFOR_VALUE_A=SEKRITvalueA"),
        ],
        frozenset(),
        {_KEY: _KEY_B64, "MEFOR_VALUE_A": "SEKRITvalueA"},
        False,
    ),
    # Code review round 1 on this repair: the reader reads a directory line below an empty store
    # key in the same string as the key's value, so the doubt step leaves that string as it is.
    "store-key-value-on-a-directory-line": (
        [
            (_EXTRA, f"{_KEY}=\nMEFOR_SECRETS_DIRECTORY={_KEY_B64}"),
            (_EXTRA, "MEFOR_VALUE_A=SEKRITvalueA"),
        ],
        frozenset(),
        {_KEY: _KEY_B64, "MEFOR_VALUE_A": "SEKRITvalueA"},
        False,
    ),
    # The same review: a name broken by a line break, whose value sits on the directory line.
    "broken-name-value-on-a-directory-line": (
        [(_EXTRA, "MEFOR_VALUE_A\nMEFOR_SECRETS_DIRECTORY=SEKRITvalueA")],
        frozenset(),
        {"MEFOR_VALUE_A": "SEKRITvalueA"},
        False,
    ),
    # The store key runs on into a directory string holding key text: the doubt step leaves that
    # string as it is for the protect-key step, and the create step's installer clause has it
    # removed before the installer runs.
    "store-key-runs-on-into-an-installer-string": (
        [
            (_EXTRA, "MEFOR_VALUE_A=SEKRITvalueA"),
            (_EXTRA, f"{_KEY}="),
            (_EXTRA, f"MEFOR_SECRETS_DIRECTORY={_KEY_B64}"),
        ],
        frozenset({f"MEFOR_SECRETS_DIRECTORY={_KEY_B64}"}),
        {_KEY: _KEY_B64, "MEFOR_VALUE_A": "SEKRITvalueA"},
        False,
    ),
    # Code review round 2 on this repair: a name written alone above a directory string, which
    # the reader joins into the name's value, in a list the installer does not read and in one it
    # does.
    "value-name-alone-above-a-directory-string": (
        [(_APP, "MEFOR_VALUE_A"), (_APP, f"mefor_secrets_directory={_KEY_B64}")],
        frozenset({f"mefor_secrets_directory={_KEY_B64}"}),
        {"MEFOR_VALUE_A": _KEY_B64},
        False,
    ),
    "value-name-alone-above-an-installer-string": (
        [(_EXTRA, "MEFOR_VALUE_A"), (_EXTRA, f"mefor_secrets_directory={_KEY_B64}")],
        frozenset({f"mefor_secrets_directory={_KEY_B64}"}),
        {"MEFOR_VALUE_A": _KEY_B64},
        False,
    ),
    # A value bound for the secrets directory runs on into such a string, so the clause has the
    # operator read it out before removing the string.
    "password-runs-on-into-an-installer-string": (
        [(_EXTRA, "MEFOR_STORE_PASSWORD="), (_EXTRA, "mefor_secrets_directory=Summer!x")],
        frozenset({"mefor_secrets_directory=Summer!x"}),
        {"MEFOR_STORE_PASSWORD": "Summer!x"},
        False,
    ),
    # The Lander's hold on PR 3142, comment 7116005396, F1: a retired store key runs on into
    # such a string. protect-key never stores it, so the clause has the operator read it out
    # and keep it for the shell that runs rotate-key.
    "retired-key-runs-on-into-an-installer-string": (
        [
            (_EXTRA, "MEFOR_VALUE_A=SEKRITvalueA"),
            (_EXTRA, f"{_RETIRED}="),
            (_EXTRA, f"MEFOR_SECRETS_DIRECTORY={_KEY_B64}"),
        ],
        frozenset({f"MEFOR_SECRETS_DIRECTORY={_KEY_B64}"}),
        {_RETIRED: _KEY_B64, "MEFOR_VALUE_A": "SEKRITvalueA"},
        False,
    ),
    # The same hold, F3: a name written alone below a directory line, its value in the next
    # string. Taking the directory line out changes how the reader reads it, so the doubt step
    # leaves that string as it is, and the clause has it removed before the installer runs.
    "value-name-alone-below-a-directory-line": (
        [(_EXTRA, "MEFOR_SECRETS_DIRECTORY=C:\\d\nMEFOR_VALUE_A"), (_EXTRA, _KEY_B64)],
        frozenset({_KEY_B64}),
        {"MEFOR_VALUE_A": _KEY_B64},
        False,
    ),
    # Code review on that repair: the whole-string twin of a name broken by a line break holds
    # the directory line in its value. It is uncounted, since a later line sets a kept name, but
    # the engine may still load it, so the take-out changing it leaves the string as it is.
    "uncounted-twin-holds-a-directory-line": (
        [
            (
                _EXTRA,
                "MEFOR_VALUE_A\nMEFOR_SECRETS_DIRECTORY=SEKRITvalueA\nMEFOR_VALUE_B=SEKRITvalueB",
            )
        ],
        frozenset(),
        {"MEFOR_VALUE_A": "SEKRITvalueA", "MEFOR_VALUE_B": "SEKRITvalueB"},
        False,
    ),
    # Code review round 2 on that repair: a broken name's twin takes an installer string as its
    # value without being read as running on, so the clause prints wherever the doubt step may
    # leave such a string as it is.
    "twin-takes-an-installer-string": (
        [
            (_EXTRA, "MEFOR_VALUE_A\nMEFOR_VALUE_A\nMEFOR_VALUE_A"),
            (_EXTRA, "mefor_secrets_directory=SEKA\nSEKD"),
        ],
        frozenset({"mefor_secrets_directory=SEKA\nSEKD"}),
        {"MEFOR_VALUE_A": "SEKA"},
        False,
    ),
    # The Lander's hold on PR 3142, comment 7119680463, item 1: an empty retired key runs on into
    # an installer string whose value is a list of two keys on two lines. The clause bounds a
    # refused value's lines by the doubt step's rule, so the second key is not added back.
    "retired-key-list-on-two-lines-in-an-installer-string": (
        [
            (_EXTRA, "MEFOR_VALUE_A=SEKRITvalueA"),
            (_EXTRA, f"{_RETIRED}="),
            (_EXTRA, f"mefor_secrets_directory={_KEY_B64},\n{_KEY_B64_2}"),
        ],
        frozenset({f"mefor_secrets_directory={_KEY_B64},\n{_KEY_B64_2}"}),
        {_RETIRED: _KEY_B64, "MEFOR_VALUE_A": "SEKRITvalueA"},
        False,
    ),
    # The same hold, item 3: taking out a string that only sets the directory would join an empty
    # password above it to a name written alone below it, which then reads as the password's
    # value, so the doubt step leaves it as it is, and the clause takes that name's strings with it.
    "directory-string-between-an-empty-key-and-a-name-alone": (
        [
            (_EXTRA, "MEFOR_STORE_PASSWORD="),
            (_EXTRA, "MEFOR_SECRETS_DIRECTORY=C:\\d"),
            (_EXTRA, "MEFOR_VALUE_B"),
            (_EXTRA, "SEKRITb"),
            (_APP, " MEFOR_SECRETS_DIRECTORY=C:\\e"),
        ],
        frozenset({"SEKRITb"}),
        {"MEFOR_VALUE_B": "SEKRITb"},
        False,
    ),
    "directory-string-between-an-empty-key-and-a-name-alone-directory-exists": (
        [
            (_EXTRA, "MEFOR_STORE_PASSWORD="),
            (_EXTRA, "MEFOR_SECRETS_DIRECTORY=C:\\d"),
            (_EXTRA, "MEFOR_VALUE_B"),
            (_EXTRA, "SEKRITb"),
            (_APP, " MEFOR_SECRETS_DIRECTORY=C:\\e"),
        ],
        frozenset({"SEKRITb"}),
        {"MEFOR_VALUE_B": "SEKRITb"},
        True,
    ),
}


@pytest.mark.parametrize("case", sorted(_CASES))
def test_the_remedy_followed_in_order_keeps_each_value_until_the_step_that_moves_it(
    case: str,
) -> None:
    entries, runs_on_into, moves, exists = _CASES[case]
    posture = read_service_env_posture(probe=_Probe(entries), environ={})
    assert posture.directory_in_doubt
    refusal = service_env_refusal(posture)
    assert refusal is not None
    registry = _Registry(list(entries), runs_on_into, directory=exists)
    assert _walk(refusal, registry, moves) == "ok"
    # Where the installer ran, it found no string to read as the directory: the doubt step took
    # out each line that may set it, but in a string it left as it is for a refused variable,
    # and the installer clause had such a string removed first (the Lander's ruling (a),
    # comment 7112155891).
    assert registry.installer_read == []
    # Only a value the clause had read out before its string went is not read at the Put step.
    assert registry.read_out == _READ_OUT.get(case, set())
    # The Lander's hold on PR 3142, comment 7119680463, item 1: no line of a refused value is
    # left in the lists but one a refused variable still holds, for the removal step to take.
    assert _refused_text_left(entries, registry.entries, frozenset(moves)) == []


def _refused_text_left(
    entries: list[tuple[str, str]], now: list[tuple[str, str]], refused: frozenset[str]
) -> list[str]:
    """Each line of ``now`` that was a line of a refused value in ``entries``, as the reader read
    it, and that neither names a refused variable nor is a line of one's value in ``now``."""
    was = _value_lines(entries, refused)
    held = _value_lines(now, refused)
    return [
        line
        for _where, string in now
        for line in _LINE_BREAK.split(string)
        if line.strip() in was and line.strip() not in held and not _names_refused(line, refused)
    ]


#: The values the create step's installer clause has the operator read out, by case.
_READ_OUT = {
    "retired-key-list-on-two-lines-in-an-installer-string": {_RETIRED},
    "directory-string-between-an-empty-key-and-a-name-alone": {"MEFOR_VALUE_B"},
    "password-runs-on-into-an-installer-string": {"MEFOR_STORE_PASSWORD"},
    "value-name-alone-above-an-installer-string": {"MEFOR_VALUE_A"},
    "retired-key-runs-on-into-an-installer-string": {_RETIRED},
    "value-name-alone-below-a-directory-line": {"MEFOR_VALUE_A"},
    "twin-takes-an-installer-string": {"MEFOR_VALUE_A"},
}


#: Shapes beyond the walk's, with no entry in doubt: the add-back step, the run-on step and the
#: keep-one step each tell the operator to pass a list back with `nssm set`.
_NOT_IN_DOUBT = {
    "add-back": [(_EXTRA, "MEFOR_VALUE_A=SEKRITvalueA")],
    "run-on": [(_EXTRA, "MEFOR_STORE_PASSWORD="), (_EXTRA, "SEKRITpw")],
    "keep-one": [
        (_EXTRA, "MEFOR_STORE_PASSWORD="),
        (_EXTRA, "mefor_secrets_directory=C:\\d"),
        (_EXTRA, f"{_KEY}="),
        (_EXTRA, "synthetic-run-on"),
    ],
    "retired-key": [(_EXTRA, f"{_RETIRED}={_KEY_B64}"), (_EXTRA, "MEFOR_VALUE_A=x")],
}

#: The one pass-back clause a sentence naming `nssm set` may carry: every refused entry stays
#: out of what is typed back.
_PASSES_NO_REFUSED = "pass back every entry but those refused above"


@pytest.mark.parametrize("case", sorted([*_CASES, *_NOT_IN_DOUBT]))
def test_no_step_has_a_refused_value_passed_back_on_a_command_line(case: str) -> None:
    """The Lander's hold on PR 3142, comment 7116005396, F2: the doubt step comes first and
    keeps every refused variable, so passing its lists back with `nssm set` would have the
    operator type store keys, passwords and MEFOR_VALUE_* values on a command line, where they
    reach the shell's history, a transcript and process-creation audit events. Every sentence
    that names `nssm set` either forbids it for such a list or passes back no refused entry,
    and the doubt step says no refused value may be typed on a command line."""
    entries = _CASES[case][0] if case in _CASES else _NOT_IN_DOUBT[case]
    posture = read_service_env_posture(probe=_Probe(entries), environ={})
    refusal = service_env_refusal(posture)
    assert refusal is not None
    steps = refusal.split("each value refused here. ", 1)[1].removesuffix(_END).split(". ")
    naming = [s for s in steps if "`nssm set`" in s]
    assert naming or not posture.directory_in_doubt
    for sentence in naming:
        assert "while a list holds one, do not pass it back with `nssm set`" in sentence or (
            _PASSES_NO_REFUSED in sentence
        ), sentence
    if posture.directory_in_doubt:
        assert NO_COMMAND_LINE in _doubt_step(steps)
    # The installer clause edits a list that still holds the other refused values, so it writes
    # it back the first step's way (code review on that repair).
    for sentence in steps:
        if sentence.startswith(_INSTALLER_CLAUSE):
            assert sentence.endswith("writing the list back as the first step says"), sentence


def test_the_doubt_step_takes_key_text_below_a_directory_line_out_with_it() -> None:
    """Code review round 2 on this repair: the reader reads a padded store key below a directory
    line as that line's value, though the key ends in an equals sign, so the doubt step's own
    rule takes it out with the line, and no key text is left as a string of its own."""
    assert _KEY_B64.endswith("=")
    entries = [
        (_EXTRA, f"MEFOR_SECRETS_DIRECTORY=C:\\d\n{_KEY_B64}"),
        (_EXTRA, "MEFOR_VALUE_A=SEKRITvalueA"),
    ]
    posture = read_service_env_posture(probe=_Probe(entries), environ={})
    refusal = service_env_refusal(posture)
    assert refusal is not None
    registry = _Registry(list(entries))
    assert _walk(refusal, registry, {"MEFOR_VALUE_A": "SEKRITvalueA"}) == "ok"
    assert not any(_KEY_B64 in string for _where, string in registry.entries)
    # The reader agrees the key line was the directory's value, not a variable of its own.
    assert not any(_KEY_B64 in v.written for v in _variables(entries))


def test_the_installer_model_matches_install_service_ps1() -> None:
    """``_installer_reads`` restates how install-service.ps1 picks the strings that set the
    directory, so tie it to the script's own text: an AppEnvironmentExtra entry that starts with
    the name and an equals sign, ignoring case, which Get-MergedEnvironmentList drops with every
    empty entry before it adds its own."""
    script = (
        Path(__file__).resolve().parent.parent / "scripts" / "service" / "install-service.ps1"
    ).read_text(encoding="utf-8")
    assert 'return $Entry.StartsWith("$Name=", [StringComparison]::OrdinalIgnoreCase)' in script
    assert (
        "$kept = @($Existing | Where-Object { $_ -and -not (Test-EnvironmentEntryNames "
        "-Entry $_ -Name $Name) })"
    ) in script
    assert "GetValue('AppEnvironmentExtra', $null)" in script
    assert _installer_reads(f"{_DIR.lower()}=x") and not _installer_reads(f" {_DIR}=x")
