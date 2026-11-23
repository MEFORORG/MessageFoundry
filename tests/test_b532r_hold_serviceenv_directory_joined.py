# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The refusal's remedy when ``MEFOR_SECRETS_DIRECTORY==`` is joined into an empty value
(vault BACKLOG #5394), whether or not the variable it is joined to is refused.

The join stays: the string still continues the empty value, and every input that refused before
still refuses. The remedy says to remove each refused variable and what a value runs on
into, and points at docs/SERVICE.md. An OIDC key empty on its own line runs on and refuses
(round-2 finding 1).
Synthetic values only.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator
from dataclasses import dataclass, field

import pytest

from messagefoundry.serviceenv import (
    KEY_CLASS_NAMES,
    ServiceEnvPosture,
    _sets_directory,
    read_service_env_posture,
    service_env_refusal,
)
from tests._serviceenv_remedy import (
    ADD_BACK_ANY,
    ADD_BACK_CREATE,
    ADD_BACK_DOUBT,
    ADD_BACK_RUN_ON,
    ADD_BACK_STEP,
    COUNTED_ONCE,
    CREATE,
    CREATE_INSTALLER,
    DOUBT_PASS_BACK,
    DOUBT_STEP,
    DOUBT_STEP_RUN_ON,
    KEEP,
    REMOVE,
    REMOVE_SPARING,
    RUNS_ON,
    RUNS_ON_SPARING,
    SET_NO,
    WIDER,
)

_EXTRA = "Parameters\\AppEnvironmentExtra"
_PLAIN = "Parameters\\AppEnvironment"
#: A synthetic stand-in for a store key: its ``=`` padding makes it look like ``NAME=``.
_KEY_B64 = base64.b64encode(b"synthetic-store-key-0123456789ab").decode()


@dataclass
class _Probe:
    entries: list[tuple[str, str]] = field(default_factory=list)

    def ancestor_images(self) -> Iterator[tuple[int, str]]:
        return iter([(200, "python.exe"), (100, "nssm.exe")])

    def service_at(self, pid: int) -> str | None:
        return "MessageFoundry" if pid == 100 else None

    def environment_entries(self, service_name: str) -> list[tuple[str, str]]:
        return list(self.entries)


def _read_pairs(pairs: list[tuple[str, str]]) -> ServiceEnvPosture:
    return read_service_env_posture(probe=_Probe(pairs), environ={})


def _read(entries: list[str]) -> ServiceEnvPosture:
    return _read_pairs([(_EXTRA, e) for e in entries])


@pytest.mark.parametrize("directory", ["MEFOR_SECRETS_DIRECTORY==", "mefor_secrets_directory =="])
@pytest.mark.parametrize("refused", [f"{KEY_CLASS_NAMES[0]}=", "MEFOR_VALUE_A="])
def test_a_joined_directory_entry_is_removed_with_the_value(refused: str, directory: str) -> None:
    posture = _read([refused, directory])
    refusal = service_env_refusal(posture)
    assert refusal is not None  # the join is not narrowed: this still refuses
    assert posture.value_runs_on
    assert REMOVE in refusal and RUNS_ON in refusal
    assert refusal.index(REMOVE) < refusal.index(RUNS_ON)
    # A name whose only value is the joined directory entry has nothing to move (the fifth
    # hold on PR 3142, H2; the Lander's hold in comment 7085002242). The spaced spelling is no
    # directory entry, so a MEFOR_VALUE_* name joined to it is moved.
    moved = refused.startswith("MEFOR_VALUE_") and " " in directory
    assert (CREATE in refusal) is moved and ("Put " in refusal) is moved
    # The joined entry is not plainly a path, so it is in doubt: the remedy says to take every
    # directory line out and add one back (the Lander's ruling B on PR 3142's repair handback,
    # comment 7106776128), for a store key alone too (the Lander's ruling on comment 7087145957,
    # F1 on H3's terms). No "set no" opener, and the pass-back leaves out what the steps above
    # say to remove (the Lander's hold on PR 3142, comment 7088102723).
    assert refusal.count(ADD_BACK_DOUBT) == 1 and SET_NO not in refusal
    assert ADD_BACK_STEP not in refusal
    assert refusal.index(RUNS_ON) < refusal.index(ADD_BACK_DOUBT)
    # The create clause only where a setting moves (the Lander's ruling on handback
    # 7087574833, R1), and next to the step it qualifies.
    assert (ADD_BACK_DOUBT + ADD_BACK_CREATE in refusal) is moved
    assert (ADD_BACK_CREATE in refusal) is moved
    assert ("An empty or blank MEFOR_VALUE_* entry is refused too: delete it" in refusal) is (
        refused.startswith("MEFOR_VALUE_") and " " not in directory
    )


def test_the_bare_prefix_joined_to_the_directory_is_deleted() -> None:
    """The bare prefix names no env() key, so the refusal says to delete that entry, and never
    to write an empty override in the value file."""
    refusal = service_env_refusal(_read(["MEFOR_VALUE_=", "MEFOR_SECRETS_DIRECTORY=="]))
    assert refusal is not None
    assert "The bare name MEFOR_VALUE_ sets no env() key, so delete that entry" in refusal
    assert "An empty or blank MEFOR_VALUE_* entry" not in refusal
    # Its only value is the directory entry, so nothing goes to the directory (comment
    # 7085002242).
    assert CREATE not in refusal and "Put " not in refusal


@pytest.mark.parametrize(
    "pairs",
    [
        pytest.param(
            [(_PLAIN, "MEFOR_VALUE_A="), (_EXTRA, "MEFOR_VALUE_A=synthetic-a-value")],
            id="two-values",
        ),
        pytest.param(
            [(_EXTRA, "MEFOR_VALUE_A=\nmefor_value_a=synthetic-a-value")], id="one-string"
        ),
    ],
)
def test_a_name_set_empty_in_one_entry_and_with_content_in_another_is_moved(
    pairs: list[tuple[str, str]],
) -> None:
    """The Lander's sixth hold on PR 3142, H2: the empty entry is told to go, and the name is
    still told to go to the secrets directory."""
    refusal = service_env_refusal(_read_pairs(pairs))
    assert refusal is not None
    assert "Put each MEFOR_VALUE_* variable in the secrets directory" in refusal
    assert "An empty or blank MEFOR_VALUE_* entry is refused too: delete it" in refusal
    assert "synthetic-a-value" not in refusal


#: Text in the shapes below that is a value, or could be: the refusal must echo none of it.
_VALUE_TEXT = (
    "hunter2",
    "AAAA",
    "Winter",
    "2026!",
    "synthetic-other-line",
    "foo",
    "C:\\x",
    _KEY_B64[:43],
)


#: Each shape, with whether the refusal adds the empty-entry delete clause and the rename.
_SHAPES = [
    pytest.param([(_EXTRA, "MEFOR_VALUE_A=\nOTHER=1")], True, False, id="assignment"),
    pytest.param(
        [(_EXTRA, "MEFOR_VALUE_A=\nMEFOR_SECRETS_DIRECTORY=C:\\d")], True, False, id="dir-line"
    ),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A=\n   ")], True, False, id="blank-line"),
    pytest.param(
        [(_EXTRA, f"MEFOR_VALUE_A=\nOTHER={_KEY_B64}")], True, False, id="assignment-to-a-key"
    ),
    pytest.param(
        [(_EXTRA, "MEFOR_VALUE_A=\nOTHER=1\nsynthetic-other-line")], True, False, id="after-it"
    ),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A=\nMEFOR_VALUE_B")], True, False, id="name-alone"),
    pytest.param(
        [(_EXTRA, "MEFOR_VALUE_A=\nProgramFiles(x86)=C:\\x")],
        True,
        False,
        id="assignment-with-parentheses",
    ),
    # The value holds the directory line, so as on main it is not empty, and no delete prints.
    pytest.param(
        [(_EXTRA, "MEFOR_VALUE_A=\nMEFOR_SECRETS_DIRECTORY==")], False, False, id="blank-dir-line"
    ),
    pytest.param(
        [(_EXTRA, "MEFOR_VALUE_A="), (_EXTRA, KEY_CLASS_NAMES[0]), (_EXTRA, "=" + _KEY_B64)],
        True,
        False,
        id="key-name-alone",
    ),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A=\nhunter2")], False, False, id="next-line"),
    pytest.param(
        [(_EXTRA, "MEFOR_VALUE_A=\n-----BEGIN X-----\nAAAA\n-----END X-----")],
        False,
        False,
        id="pem-from-line-2",
    ),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A="), (_EXTRA, "hunter2")], False, False, id="next-item"),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A=\n#x")], False, False, id="comment-only-line"),
    pytest.param([(_EXTRA, f"MEFOR_VALUE_A=\n{_KEY_B64}")], False, False, id="key-with-padding"),
    pytest.param(
        [(_EXTRA, "MEFOR_VALUE_A=\nhunter2=")], False, False, id="text-then-an-equals-sign"
    ),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A=\n==")], False, False, id="equals-only-line"),
    pytest.param(
        [(_EXTRA, "MEFOR_VALUE_A=\nOTHER=")], False, False, id="name-with-nothing-after-it"
    ),
    pytest.param(
        [(_EXTRA, "MEFOR_VALUE_A"), (_EXTRA, "="), (_EXTRA, "Winter=2026!")],
        False,
        False,
        id="name-alone-split-value",
    ),
    pytest.param(
        [(_EXTRA, "X=1\nMEFOR_VALUE_A\nWinter=2026!")], False, False, id="name-alone-in-a-string"
    ),
    pytest.param(
        [
            (_PLAIN, "MEFOR_VALUE_A="),
            (_EXTRA, "MEFOR_VALUE_A="),
            (_EXTRA, "MEFOR_SECRETS_DIRECTORY=="),
        ],
        True,
        False,
        id="empty-twice-and-a-directory",
    ),
    # Review round 3's O1 to O3 shapes, which a content reading of the value misjudged.
    pytest.param([(_EXTRA, "MEFOR_VALUE_A\n=")], True, False, id="O1-separator-line"),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A"), (_EXTRA, "=")], True, False, id="O1-separator-item"),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A\nX=1")], False, True, id="O2-assignment-line"),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A\nWinter=2026!")], False, True, id="O2-split-secret-line"),
    pytest.param(
        [(_EXTRA, "MEFOR_VALUE_A"), (_EXTRA, "Winter=2026!")], False, False, id="O3-split-item"
    ),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A\nfoo\n=")], True, True, id="O1-name-line-then-separator"),
    pytest.param([(_EXTRA, "MEFOR_VALUE_A\nPath=C:\\x")], False, True, id="O2-windows-name-line"),
    pytest.param(
        [(_EXTRA, "MEFOR_VALUE_A"), (_EXTRA, "OTHER=hunter2")],
        False,
        False,
        id="O3-assignment-item",
    ),
]


#: The shapes above in which every entry that sets the name is empty or blank, so the remedy says
#: to delete it and has nothing to move (the Lander's hold on PR 3142, comment 7100710066, item
#: 10).
_EMPTY_IDS = frozenset(
    {
        "blank-line",
        "empty-twice-and-a-directory",
        "O1-separator-line",
        "O1-separator-item",
        "O1-name-line-then-separator",
    }
)


@pytest.mark.parametrize(
    ("pairs", "delete", "rename"), [p for p in _SHAPES if p.id not in _EMPTY_IDS]
)
def test_every_value_name_gets_one_generic_put_sentence(
    pairs: list[tuple[str, str]], delete: bool, rename: bool
) -> None:
    """The Lander's decision d20261122T181059560-3bac03 on PR 3142: no reading of which line is
    content gates the steps. Each shape prints the one Put sentence, naming no variable, the
    create step, the value-file alternative and the ``provider = "env"`` sentence. An empty
    entry adds the delete clause, and a name the secrets directory refuses adds the rename."""
    refusal = service_env_refusal(_read_pairs(pairs))
    assert refusal is not None
    assert refusal.count("Put each MEFOR_VALUE_* variable in the secrets directory") == 1
    assert CREATE in refusal and "environments/<env>.toml" in refusal
    assert '[secrets].provider = "env"' in refusal
    assert "leaves the secret in the registry key" in refusal
    assert ("An empty or blank MEFOR_VALUE_* entry is refused too: delete it" in refusal) is delete
    assert ("rename that env() key" in refusal) is rename
    assert KEEP not in refusal  # no shape here joins a path into a refused value
    assert "MEFOR_VALUE_A" not in refusal and "MEFOR_VALUE_B" not in refusal
    assert not any(text in refusal for text in _VALUE_TEXT)


@pytest.mark.parametrize(("pairs", "delete", "rename"), [p for p in _SHAPES if p.id in _EMPTY_IDS])
def test_an_empty_value_name_is_told_to_go_and_not_to_move(
    pairs: list[tuple[str, str]], delete: bool, rename: bool
) -> None:
    """The Lander's hold on PR 3142, comment 7100710066, item 10: where every entry that sets
    the name is empty, the remedy says to delete it, so it prints no Put step, no create step
    and no rename, which would send an empty file to a directory that refuses one. It is still
    removed and refused."""
    assert delete
    refusal = service_env_refusal(_read_pairs(pairs))
    assert refusal is not None
    assert "An empty or blank MEFOR_VALUE_* entry is refused too: delete it" in refusal
    assert "Put " not in refusal and CREATE not in refusal
    assert "rename that env() key" not in refusal
    assert "Remove each refused variable, with its value, from" in refusal
    assert "MEFOR_VALUE_A" not in refusal and "MEFOR_VALUE_B" not in refusal
    assert not any(text in refusal for text in _VALUE_TEXT)


@pytest.mark.parametrize(
    "pairs",
    [
        pytest.param([(_PLAIN, "MEFOR_VALUE_A="), (_EXTRA, "MEFOR_VALUE_A=")], id="empty-in-both"),
        # Only the empty copy is told to go; the other moves.
        pytest.param([(_PLAIN, "MEFOR_VALUE_A=1"), (_EXTRA, "mefor_value_a=")], id="mixed"),
        # The control: a name that moves printed the clause before the fix too.
        pytest.param([(_PLAIN, "MEFOR_VALUE_A=1"), (_EXTRA, "mefor_value_a=2")], id="moving"),
    ],
)
def test_a_duplicate_value_name_is_told_to_go_from_every_value(
    pairs: list[tuple[str, str]],
) -> None:
    """The Lander's hold on PR 3142, comment 7104660861, item 3: the name is counted once, so
    the remedy says to remove it from every value that sets it whether it moves or is only told
    to go, as origin/main does, or the copy left behind refuses the next start."""
    refusal = service_env_refusal(_read_pairs(pairs))
    assert refusal is not None and refusal.count(COUNTED_ONCE) == 1


def test_an_oddly_spelled_name_told_only_to_go_gets_no_rename() -> None:
    """Code review on the repair of the Lander's hold on PR 3142, comment 7100710066, item 10:
    the rename sentence is about moving a name, so an empty one, which is only told to go, does
    not print it beside a name that moves. The control spells the moving name oddly."""
    pairs = [(_EXTRA, "MEFOR_VALUE_A=1"), (_EXTRA, "MEFOR_VALUE_B-X=")]
    refusal = service_env_refusal(_read_pairs(pairs))
    assert refusal is not None and "Put each MEFOR_VALUE_*" in refusal
    assert "rename that env() key" not in refusal
    control = service_env_refusal(_read_pairs([(_EXTRA, "MEFOR_VALUE_B-X=1")]))
    assert control is not None and "rename that env() key" in control


def test_a_value_name_alone_joined_to_a_directory_path_keeps_the_path_entry() -> None:
    """The KEEP path (the Lander's hold in comment 7085002242): a MEFOR_VALUE_* name whose
    only value is a joined plain-path directory entry has nothing to move, so neither the
    create step nor Put prints, and the delete clause comes before the removal, the run-on
    and KEEP sentences after it, as at da3fb43a7e4."""
    refusal = service_env_refusal(
        _read_pairs([(_EXTRA, "MEFOR_VALUE_A"), (_EXTRA, "mefor_secrets_directory=C:\\d")])
    )
    assert refusal is not None
    assert CREATE not in refusal and "Put " not in refusal
    # The kept entry still sets the directory, so nothing says to add one back (the Lander's
    # ruling on handback 7085947392, F1).
    assert ADD_BACK_STEP not in refusal
    order = [
        refusal.index(text)
        for text in (
            "An empty or blank MEFOR_VALUE_* entry is refused too: delete it",
            REMOVE_SPARING,
            RUNS_ON_SPARING,
            KEEP,
        )
    ]
    assert order == sorted(order)


def test_a_plain_path_beside_a_run_on_into_other_text_is_kept() -> None:
    """U1, under the per-entry rule (the Lander's ruling B on PR 3142's repair handback, comment
    7106776128; round 3's finding 6): the store password's only value is a joined path entry,
    which moves nothing, and the store key beside it runs on into other text. The path entry is
    plainly a path on its own and no directory entry is in doubt, so the removal and run-on
    steps spare it, the run-on step removes the other text, and the keep-one step names the
    path."""
    refusal = service_env_refusal(
        _read(
            [
                "MEFOR_STORE_PASSWORD=",
                "mefor_secrets_directory=C:\\d",
                "MEFOR_STORE_ENCRYPTION_KEY=",
                "synthetic-run-on",
            ]
        )
    )
    assert refusal is not None
    assert "Put " not in refusal and ADD_BACK_ANY not in refusal
    assert refusal.endswith(f'{KEEP}. [security].enforcement = "warn" does not change this refusal')
    assert refusal.index(REMOVE_SPARING) < refusal.index(RUNS_ON_SPARING) < refusal.index(KEEP)
    assert "synthetic-run-on" not in refusal and "C:\\d" not in refusal


@pytest.mark.parametrize(
    "entries",
    [
        pytest.param([f"{KEY_CLASS_NAMES[0]}=", "MEFOR_SECRETS_DIRECTORY=="], id="key-alone"),
        # The directory string is the second the value takes: U6.
        pytest.param(
            [f"{KEY_CLASS_NAMES[0]}=", "MEFOR_VALUE_A", "MEFOR_SECRETS_DIRECTORY=="],
            id="key-then-name-alone",
        ),
    ],
)
def test_a_store_key_alone_run_on_into_the_directory_is_added_back(entries: list[str]) -> None:
    """The Lander's ruling on comment 7087145957, F1 on H3's terms: only a store key is refused,
    but the run-on step removes the directory string its value runs on into, so the remedy says
    to add the directory back, after the run-on sentence, and nothing says to keep the string."""
    refusal = service_env_refusal(_read(entries))
    assert refusal is not None
    assert CREATE not in refusal and KEEP not in refusal
    assert refusal.count(ADD_BACK_DOUBT) == 1 and SET_NO not in refusal
    assert refusal.index(REMOVE) < refusal.index(RUNS_ON) < refusal.index(ADD_BACK_DOUBT)
    # A store key alone needs no secrets directory: no create clause (third hold, H2; the
    # Lander's ruling on handback 7087574833, R1).
    assert ADD_BACK_CREATE not in refusal


def test_a_lower_case_directory_item_is_not_said_to_be_absent() -> None:
    """The Lander's hold on PR 3142, comment 7088102723, fix 2: the store key runs on into
    ``mefor_secrets_directory=C:\\d``, which NSSM may read as its own item, and a second key runs
    on into other text. The item is plainly a path on its own, so under the per-entry rule (the
    Lander's ruling B on PR 3142's repair handback, comment 7106776128) the keep-one step names
    it, and nothing says the lists set none."""
    refusal = service_env_refusal(
        _read(
            [
                "MEFOR_STORE_ENCRYPTION_KEY=",
                "mefor_secrets_directory=C:\\d",
                "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED=",
                "synthetic-run-on",
            ]
        )
    )
    assert refusal is not None
    assert refusal.count(KEEP) == 1 and SET_NO not in refusal and ADD_BACK_ANY not in refusal
    assert refusal.index(REMOVE_SPARING) < refusal.index(RUNS_ON_SPARING) < refusal.index(KEEP)
    assert "synthetic-run-on" not in refusal


def test_no_opener_while_a_list_string_sets_the_directory() -> None:
    """The Lander's hold on PR 3142, comment 7088663896, finding 1: the password runs on past
    its name, written alone, into ``mefor_secrets_directory=C:\\d``, which NSSM may read as its
    own item. The first string the value takes does not set the directory, so origin/main said
    the lists set none. The item is plainly a path on its own, so under the per-entry rule (the
    Lander's ruling B on PR 3142's repair handback, comment 7106776128) the keep-one step names
    it, and nothing says the lists set none."""
    refusal = service_env_refusal(
        _read(["MEFOR_STORE_PASSWORD=", "MEFOR_STORE_PASSWORD", "mefor_secrets_directory=C:\\d"])
    )
    assert refusal is not None
    assert SET_NO not in refusal and ADD_BACK_ANY not in refusal
    assert refusal.index(REMOVE_SPARING) < refusal.index(RUNS_ON_SPARING) < refusal.index(KEEP)


def test_a_value_that_runs_on_is_not_passed_back() -> None:
    """The Lander's hold on PR 3142, comment 7088663896, finding 4: the password runs on into
    ``synthetic-run-on``, which the run-on step says to remove. No string sets the directory, so
    the step keeps origin/main's opener, but the entries it says to pass back leave out the
    strings the steps above say to remove, so the value is not written back."""
    refusal = service_env_refusal(
        _read(["MEFOR_STORE_PASSWORD=", "synthetic-run-on", "MEFOR_VALUE_B=1"])
    )
    assert refusal is not None
    assert ADD_BACK_STEP not in refusal
    assert refusal.count(ADD_BACK_RUN_ON + ADD_BACK_CREATE) == 1
    assert refusal.index(REMOVE) < refusal.index(RUNS_ON) < refusal.index(ADD_BACK_RUN_ON)
    assert "synthetic-run-on" not in refusal


def test_no_opener_while_a_later_line_sets_the_directory() -> None:
    """The Lander's hold on PR 3142, comment 7089064404, B: the directory is set on the second
    line of a string, which NSSM may read as its own variable, so the step never says the lists
    set none. The string's first line sets MEFOR_VALUE_A, so the directory line is in doubt (the
    Lander's ruling B on PR 3142's repair handback, comment 7106776128), and the step says to
    take it out and keep each other line no step above removes (comments 7089400537 and
    7090314503)."""
    refusal = service_env_refusal(_read(["MEFOR_VALUE_A=\nMEFOR_SECRETS_DIRECTORY=C:\\d"]))
    assert refusal is not None
    assert SET_NO not in refusal
    assert refusal.count(ADD_BACK_DOUBT + ADD_BACK_CREATE) == 1


@pytest.mark.parametrize(
    "mixed",
    ["PATH=C:\\x\nMEFOR_SECRETS_DIRECTORY=C:\\d", "MEFOR_SECRETS_DIRECTORY=\nPATH=C:\\x"],
    ids=["directory-line-later", "directory-line-first"],
)
def test_a_string_that_also_sets_another_variable_is_not_removed_whole(mixed: str) -> None:
    """The Lander's hold on PR 3142, comment 7089400537, finding 5 and the review's finding 6:
    ``PATH=C:\\x`` and a directory line share one string, either line first. The directory line
    is in doubt, so the step says to take it out of every list and keep each other line no step
    above removes, which keeps PATH, and never that the lists set none (comments 7089064404, B,
    and 7090314503)."""
    refusal = service_env_refusal(_read(["MEFOR_VALUE_A=x", mixed]))
    assert refusal is not None
    assert SET_NO not in refusal
    step = ADD_BACK_DOUBT + ADD_BACK_CREATE
    assert refusal.count(step) == 1
    assert refusal.index("Put ") < refusal.index(REMOVE) < refusal.index(step)


@pytest.mark.parametrize(
    "mixed",
    ["MEFOR_SECRETS_DIRECTORY=\nPATH=C:\\x", "PATH=C:\\x\nMEFOR_SECRETS_DIRECTORY=C:\\d"],
    ids=["directory-line-first", "directory-line-later"],
)
def test_a_string_that_sets_the_directory_and_more_has_its_directory_line_taken_out(
    mixed: str,
) -> None:
    """The Lander's hold on PR 3142, comment 7090314503, item 1: the store password runs on
    into a string that sets only the directory, and a string sets the directory along with
    PATH. One step says to take every directory line out of every list, removing a string that
    holds nothing else and keeping PATH, so, read line by line, the entry the operator adds is
    the only one (the Lander's ruling B on PR 3142's repair handback, comment 7106776128)."""
    refusal = service_env_refusal(
        _read(["MEFOR_STORE_PASSWORD=", "MEFOR_SECRETS_DIRECTORY==", "MEFOR_VALUE_B=1", mixed])
    )
    assert refusal is not None
    assert SET_NO not in refusal
    assert refusal.count(DOUBT_STEP_RUN_ON) == 1 and refusal.count(DOUBT_PASS_BACK) == 1
    step = ADD_BACK_DOUBT + ADD_BACK_CREATE
    assert refusal.count(step) == 1
    assert refusal.index(REMOVE) < refusal.index(RUNS_ON) < refusal.index(step)
    # The password runs on into an AppEnvironmentExtra string the installer reads as the
    # directory, which the doubt step keeps for it, so the create step says so.
    assert refusal.count(CREATE + CREATE_INSTALLER) == 1


def test_a_string_a_value_runs_on_into_is_left_to_the_run_on_step() -> None:
    """The review of the repair for the Lander's hold on PR 3142, comment 7090314503, finding
    1, and round 2's finding 3: the store password runs on into a string that holds a
    directory line and a PATH line. The doubt step now comes first and keeps that string whole,
    since it may hold the password, for the Put step (the Lander's ruling (a) on comment
    7112155891); the run-on step below the Put step removes it, and the add-back step passes
    back none of it."""
    refusal = service_env_refusal(
        _read(["MEFOR_STORE_PASSWORD=", "MEFOR_SECRETS_DIRECTORY=\nPATH=C:\\x"])
    )
    assert refusal is not None
    assert refusal.count(RUNS_ON) == 1 and refusal.count(DOUBT_STEP_RUN_ON) == 1
    assert refusal.count(DOUBT_PASS_BACK) == 1 and WIDER not in refusal
    assert refusal.index(DOUBT_STEP_RUN_ON) < refusal.index("Put ") < refusal.index(RUNS_ON)


@pytest.mark.parametrize("where", [_PLAIN, "Environment"], ids=["AppEnvironment", "Environment"])
@pytest.mark.parametrize(
    "plain",
    ["MEFOR_SECRETS_DIRECTORY=", "MEFOR_SECRETS_DIRECTORY=\nPATH=C:\\x"],
    ids=["directory-only", "directory-and-more"],
)
def test_a_directory_entry_in_doubt_outside_the_extra_list_is_taken_out_too(
    plain: str, where: str
) -> None:
    """The Lander's ruling B on PR 3142's repair handback, comment 7106776128: a directory
    entry in doubt is taken out whatever list holds it, so the doubt step names every list, says
    `nssm set` replaces a whole list and to read AppEnvironment and AppEnvironmentExtra first
    with `nssm get`, and says the service's own Environment value is edited in its registry key
    (the Lander's hold on PR 3142, comment 7090314503, item 3, read under that ruling; code
    review round 2 on the repair). The lists still set the directory, so the step never says
    they set none."""
    refusal = service_env_refusal(_read_pairs([(_EXTRA, "MEFOR_VALUE_A=x"), (where, plain)]))
    assert refusal is not None
    assert SET_NO not in refusal
    assert refusal.count(ADD_BACK_DOUBT + ADD_BACK_CREATE) == 1
    assert "read AppEnvironment and AppEnvironmentExtra first with `nssm get`" in DOUBT_STEP
    assert "Environment value is no NSSM list and is edited in the registry key" in DOUBT_STEP


@pytest.mark.parametrize(
    "name",
    [
        "MEFOR_\u017fECRETS_DIRECTORY",
        "MEFOR_SECRETS_D\u0131RECTORY",
        "\u00a0MEFOR_SECRETS_DIRECTORY",
    ],
)
def test_a_non_ascii_name_does_not_set_the_directory_but_is_in_doubt(name: str) -> None:
    """The Lander's hold on PR 3142, comment 7090314503, item 4: ``str.upper`` maps U+017F
    onto S and U+0131 onto I, and ``str.strip`` removes a U+00A0 blank, so ``_sets_directory``
    holds a name to ASCII. Python's ``os.environ`` on Windows upper-cases names, so the engine
    may read a U+017F or U+0131 name as the directory (the Lander's hold on PR 3142, comment
    7104660861); it does not strip a U+00A0 blank, but the reader's whole-string reading does.
    Under ruling B (comment 7106776128) each entry is in doubt, and the remedy says to take it
    out and add the directory back, as for the blank ASCII control."""
    assert not _sets_directory(f"{name}=") and _sets_directory("MEFOR_SECRETS_DIRECTORY=")
    for spelled in (name, "MEFOR_SECRETS_DIRECTORY"):
        refusal = service_env_refusal(_read(["MEFOR_VALUE_A=x", f"{spelled}="]))
        assert refusal is not None
        assert SET_NO not in refusal and refusal.count(ADD_BACK_DOUBT + ADD_BACK_CREATE) == 1


def test_a_blank_directory_item_is_not_passed_back() -> None:
    """The Lander's hold on PR 3142, comment 7089064404, A: the blank
    ``MEFOR_SECRETS_DIRECTORY=`` is no refused variable, and no value runs on into it. It is not
    plainly a path, so it is in doubt, the doubt step says to take it out, and the add-back
    step passes back none of what the steps above remove or take out (finding C)."""
    refusal = service_env_refusal(_read(["MEFOR_VALUE_A=x", "MEFOR_SECRETS_DIRECTORY="]))
    assert refusal is not None
    assert SET_NO not in refusal and RUNS_ON not in refusal
    assert refusal.count(ADD_BACK_DOUBT + ADD_BACK_CREATE) == 1
    assert refusal.index("Put ") < refusal.index(REMOVE) < refusal.index(ADD_BACK_DOUBT)


def test_an_empty_value_beside_a_listed_directory_path_is_told_to_go_and_not_to_move() -> None:
    """``[MEFOR_VALUE_A=, mefor_secrets_directory=C:\\d]``: the directory entry is its own
    variable, not joined to the value, so this is not the KEEP path. The empty value is told
    to go, and gets no Put step, since the remedy says to delete it (the Lander's hold on PR
    3142, comment 7100710066, item 10); the listed directory takes no create step and no KEEP
    sentence."""
    refusal = service_env_refusal(
        _read_pairs([(_EXTRA, "MEFOR_VALUE_A="), (_EXTRA, "mefor_secrets_directory=C:\\d")])
    )
    assert refusal is not None
    assert "Put " not in refusal
    assert "An empty or blank MEFOR_VALUE_* entry is refused too: delete it" in refusal
    assert CREATE not in refusal and KEEP not in refusal and RUNS_ON not in refusal


def test_a_directory_set_elsewhere_too_gets_no_create_guidance() -> None:
    """A joined ``==`` directory entry in AppEnvironmentExtra would override the AppEnvironment
    one. It is not plainly a path, so it is in doubt and no step keeps or spares it: the removal
    and run-on steps take it out with the value. That changes the entry the engine reads, so the
    add-back step names the directory again, last, with no create clause, since nothing moves
    there (the Lander's hold on PR 3142, comment 7104660861, item 1, and its ruling B on the
    repair handback, comment 7106776128)."""
    posture = _read_pairs(
        [
            (_PLAIN, "MEFOR_SECRETS_DIRECTORY=C:\\synthetic-secrets"),
            (_EXTRA, "MEFOR_VALUE_A="),
            (_EXTRA, "MEFOR_SECRETS_DIRECTORY=="),
        ]
    )
    assert "MEFOR_SECRETS_DIRECTORY" in posture.listed
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert REMOVE in refusal and RUNS_ON in refusal and CREATE not in refusal
    assert refusal.endswith(
        f'{RUNS_ON}. {ADD_BACK_DOUBT}. [security].enforcement = "warn" does not change this refusal'
    )


def test_a_directory_joined_to_an_empty_pem_key_is_removed_with_it() -> None:
    """The key, empty on its own line, refuses and runs on (round-2 finding 1), so the run-on
    sentence covers the directory string joined to it."""
    posture = _read_pairs(
        [
            (_EXTRA, "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY="),
            (_EXTRA, "MEFOR_SECRETS_DIRECTORY=="),
            (_PLAIN, "MEFOR_VALUE_B=1"),
        ]
    )
    assert posture.listed == ("MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY", "MEFOR_VALUE_B")
    assert posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert REMOVE in refusal and RUNS_ON in refusal and CREATE in refusal


def test_with_nothing_joined_the_run_on_sentence_follows_the_run_on() -> None:
    """Control: a value alone gets the removal and the create guidance and no run-on
    sentence, and a run-on into key material gets the run-on sentence."""
    value_only = service_env_refusal(_read(["MEFOR_VALUE_A=1"]))
    assert value_only is not None
    assert REMOVE in value_only and CREATE in value_only and RUNS_ON not in value_only
    run_on = _read([f"{KEY_CLASS_NAMES[0]}=", "abc=="])
    assert run_on.value_runs_on
    refusal = service_env_refusal(run_on)
    assert refusal is not None
    assert RUNS_ON in refusal and CREATE not in refusal


def test_two_joined_groups_in_one_registry_value_both_refuse_and_run_on() -> None:
    """A store key running on into key material, then an OIDC key running on into a directory
    string: both keys are listed and the value runs on. This pins the reader, not the remedy."""
    posture = _read(
        [
            f"{KEY_CLASS_NAMES[0]}=",
            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGk=",
            "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=",
            "MEFOR_SECRETS_DIRECTORY==",
        ]
    )
    assert posture.listed == (KEY_CLASS_NAMES[0], "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY")
    assert posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None and RUNS_ON in refusal
