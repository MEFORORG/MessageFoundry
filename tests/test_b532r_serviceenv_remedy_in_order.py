# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The service-environment remedy, followed top to bottom where a directory entry is in doubt.

Round-3 open finding 1 on PR 3142's repair handback, comment 7110577570, and the Lander's ruling
(a) on comment 7112155891: an operator who applies the printed steps in order, against the
registry, must still find each refused value there when the step that moves it runs, the
protect-key step for a store key and the Put step for the rest. The walk below applies each step
it reaches to a simulated registry, models install-service.ps1 where the create step sends the
operator to it, and stops at the Put step. A sentence it does not know before the Put step fails
the test, so new wording cannot pass unread. Synthetic values only.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from messagefoundry.serviceenv import (
    KEY_CLASS_NAMES,
    _installer_reads,
    _variables,
    read_service_env_posture,
    service_env_refusal,
)

_DIR = "MEFOR_SECRETS_DIRECTORY"
_EXTRA = "Parameters\\AppEnvironmentExtra"
_APP = "Parameters\\AppEnvironment"
_LINE_BREAK = re.compile(r"\r\n|[\r\n]")
_END = '. [security].enforcement = "warn" does not change this refusal'
_KEY = KEY_CLASS_NAMES[0]
_KEY_B64 = base64.b64encode(b"synthetic-store-key-for-tests-01").decode()
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
    #: Whether a secrets directory exists. None does in any case here, as in the round-3 example.
    directory: bool = False
    #: Each string install-service.ps1 read as setting the directory, and so dropped.
    installer_read: list[str] = field(default_factory=list)
    #: The refused names a step has already moved out, the store key to its key file.
    moved: set[str] = field(default_factory=set)
    #: The refused names the create step's installer clause says to put in from where they came.
    put_from_source: set[str] = field(default_factory=set)

    def readable(self, name: str, secret: str) -> bool:
        """Whether the registry still sets ``name`` to a value holding ``secret``, as the
        engine's own reader reads it, so the operator can still read it from there."""
        return any(
            variable.written.strip().upper() == name and secret in variable.value
            for variable in _variables(self.entries)
        )


def _may_set_directory(line: str) -> bool:
    return line.partition("=")[0].strip().upper() == _DIR


def _sets_refused(line: str, refused: frozenset[str]) -> bool:
    return line.partition("=")[0].strip().upper() in refused


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


def _apply_doubt_step(text: str, registry: _Registry, refused: frozenset[str]) -> None:
    """Take each line that may set the directory out of every list, as the step says, and pass
    back what its pass-back clause says to pass back."""
    keep_run_on = "keep whole each string a refused variable's value runs on into" in text
    if "pass back every entry, with only those lines taken out" in text:
        also_removed = False
    elif "the strings and lines this step and the steps above say to remove or take out" in text:
        # Where the doubt step sits below the removal and run-on steps, its pass-back leaves out
        # what those say to remove: every refused variable, and the strings a value runs on into.
        also_removed = True
    else:
        raise AssertionError(f"no pass-back clause the walk knows: {text!r}")
    kept: list[tuple[str, str]] = []
    for where, string in registry.entries:
        if string in registry.runs_on_into:
            if also_removed:
                continue
            if keep_run_on:
                kept.append((where, string))
                continue
        lines = [
            line
            for line in _LINE_BREAK.split(string)
            if not _may_set_directory(line) and not (also_removed and _sets_refused(line, refused))
        ]
        if any(line.strip() for line in lines):
            kept.append((where, "\n".join(lines)))
    registry.entries = kept


def _run_installer(registry: _Registry) -> None:
    """install-service.ps1's Get-MergedEnvironmentList: it drops each empty AppEnvironmentExtra
    string and each that starts with the directory's name and an equals sign in any letter case,
    reading that one as the directory, and adds its own entry at the end."""
    kept: list[tuple[str, str]] = []
    for where, string in registry.entries:
        if where == _EXTRA and string[: len(_DIR) + 1].upper() == f"{_DIR}=":
            registry.installer_read.append(string)
            continue
        if where == _EXTRA and not string:
            continue
        kept.append((where, string))
    registry.entries = [*kept, (_EXTRA, f"{_DIR}={_NEW_DIRECTORY}")]
    registry.directory = True


#: The create step's clause where a refused value runs on into a string the installer reads.
_INSTALLER_CLAUSE = "Where a refused variable's value runs on into an AppEnvironmentExtra string"

_PASSIVE = (
    "Take out those lines alone",
    "`nssm set` replaces a whole list",
    "The service's own Environment value",
    "A retired key belongs",
    'See docs/SERVICE.md, "Protect the store encryption key at rest"',
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
                if name in moves:
                    registry.moved.add(name)
        elif sentence.startswith("Where no secrets directory exists yet"):
            if registry.directory:
                continue
            if "only once the steps below have taken out" in sentence:
                # The installer may run only after the doubt step below, so that step goes first.
                _apply_doubt_step(_doubt_step(steps), registry, refused)
            if index + 1 < len(steps) and steps[index + 1].startswith(_INSTALLER_CLAUSE):
                # Where none exists, the clause says to remove each run-on string the installer
                # reads before it runs, and to put the value that ran on into it in from where
                # it came, so the walk no longer looks for that value in the registry.
                for where, string in list(registry.entries):
                    if (
                        string in registry.runs_on_into
                        and where == _EXTRA
                        and string[: len(_DIR) + 1].upper() == f"{_DIR}="
                    ):
                        registry.entries.remove((where, string))
                        registry.put_from_source.update(
                            name
                            for name in refused
                            if not registry.readable(name, moves[name])
                            and name not in registry.moved
                        )
            _run_installer(registry)
        elif sentence.startswith("Put "):
            if not registry.directory:
                return "no secrets directory at the Put step"
            for name, secret in moves.items():
                if name in KEY_CLASS_NAMES or name in registry.put_from_source:
                    continue
                if not registry.readable(name, secret):
                    return f"{name} lost before the Put step"
            return "ok"
        elif not sentence.startswith((*_PASSIVE, _INSTALLER_CLAUSE)):
            raise AssertionError(f"a step the walk does not know: {sentence!r}")
    raise AssertionError("the remedy has no Put step")


_CASES = {
    # The round-3 example: the directory line shares its string with the password, whose value
    # runs on into the next string, and C:\d does not exist.
    "shared-string-run-on": (
        [(_EXTRA, "MEFOR_SECRETS_DIRECTORY=C:\\d\nMEFOR_STORE_PASSWORD="), (_EXTRA, "abc")],
        frozenset({"abc"}),
        {"MEFOR_STORE_PASSWORD": "abc"},
    ),
    "app-environment-shared-string-run-on": (
        [(_APP, "MEFOR_SECRETS_DIRECTORY=C:\\d\nMEFOR_STORE_PASSWORD="), (_APP, "abc")],
        frozenset({"abc"}),
        {"MEFOR_STORE_PASSWORD": "abc"},
    ),
    "padded-name": (
        [(_EXTRA, " MEFOR_SECRETS_DIRECTORY=C:\\d"), (_EXTRA, "MEFOR_VALUE_A=SEKRITvalueA")],
        frozenset(),
        {"MEFOR_VALUE_A": "SEKRITvalueA"},
    ),
    "padded-name-shared-string": (
        [(_EXTRA, "MEFOR_SECRETS_DIRECTORY\u00a0=C:\\d\nMEFOR_AUTH_AD_BIND_PASSWORD=SEKRITbindPw")],
        frozenset(),
        {"MEFOR_AUTH_AD_BIND_PASSWORD": "SEKRITbindPw"},
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
    ),
    "store-key-in-the-directory-string": (
        [
            (_EXTRA, f"MEFOR_SECRETS_DIRECTORY=C:\\d\n{_KEY}={_KEY_B64}"),
            (_EXTRA, "MEFOR_VALUE_A=SEKRITvalueA"),
        ],
        frozenset(),
        {_KEY: _KEY_B64, "MEFOR_VALUE_A": "SEKRITvalueA"},
    ),
    # The store key runs on into a directory string holding key text: the doubt step keeps that
    # string whole for the protect-key step, and the create step's installer clause has it
    # removed before the installer runs.
    "store-key-runs-on-into-an-installer-string": (
        [
            (_EXTRA, "MEFOR_VALUE_A=SEKRITvalueA"),
            (_EXTRA, f"{_KEY}="),
            (_EXTRA, f"MEFOR_SECRETS_DIRECTORY={_KEY_B64}"),
        ],
        frozenset({f"MEFOR_SECRETS_DIRECTORY={_KEY_B64}"}),
        {_KEY: _KEY_B64, "MEFOR_VALUE_A": "SEKRITvalueA"},
    ),
}


@pytest.mark.parametrize("case", sorted(_CASES))
def test_the_remedy_followed_in_order_keeps_each_value_until_the_step_that_moves_it(
    case: str,
) -> None:
    entries, runs_on_into, moves = _CASES[case]
    posture = read_service_env_posture(probe=_Probe(entries), environ={})
    assert posture.directory_in_doubt
    refusal = service_env_refusal(posture)
    assert refusal is not None
    registry = _Registry(list(entries), runs_on_into)
    assert _walk(refusal, registry, moves) == "ok"
    # The installer ran with no string left for it to read as the directory: the doubt step
    # took out every other line that may set it, and the create step's installer clause, where
    # it prints, the run-on string it keeps (the Lander's ruling (a), comment 7112155891).
    assert registry.installer_read == []
    assert (_INSTALLER_CLAUSE in refusal) is posture.installer_run_on


def test_the_installer_model_matches_install_service_ps1() -> None:
    """``_installer_reads`` and the walk's installer both restate how install-service.ps1 picks
    the strings that set the directory, so tie them to the script's own text: an
    AppEnvironmentExtra entry that starts with the name and an equals sign, ignoring case, which
    Get-MergedEnvironmentList drops with every empty entry before it adds its own."""
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
