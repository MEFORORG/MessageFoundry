# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Key material below an empty secret is that secret's value (vault BACKLOG #5394, added items 6
and 12).

Synthetic values only: each stand-in is ASCII text, never a real key.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

import pytest

from messagefoundry.serviceenv import (
    KEY_CLASS_NAMES,
    ServiceEnvPosture,
    read_service_env_posture,
    service_env_refusal,
)
from tests._serviceenv_remedy import (
    ADD_BACK_ANY,
    ADD_BACK_CREATE,
    ADD_BACK_DOUBT,
    CREATE,
    DOUBT_CREATE_RUN_ON,
    DOUBT_PASS_BACK,
    DOUBT_STEP_RUN_ON,
    KEEP,
    REMOVE,
    REMOVE_SPARING,
    RUNS_ON,
    RUNS_ON_SPARING,
    SET_NO,
)

_KEY_B64 = base64.b64encode(b"synthetic-store-key-0123456789ab").decode()
#: A base64url stand-in of a 32-byte secret's length, with one ``=``, a "-" and a "_" in it, and
#: letters of both cases, as a random secret has.
_URL_ONE_PAD = "Synthetic-Store_Key-0123456789AbCdEfGhIjKlm="
_EXTRA = "Parameters\\AppEnvironmentExtra"
_KEY = "MEFOR_STORE_ENCRYPTION_KEY"


@dataclass
class _Probe:
    entries: list[tuple[str, str]] = field(default_factory=list)

    def ancestor_images(self) -> Iterator[tuple[int, str]]:
        return iter([(200, "python.exe"), (100, "nssm.exe")])

    def service_at(self, pid: int) -> str | None:
        return "MessageFoundry" if pid == 100 else None

    def environment_entries(self, service_name: str) -> list[tuple[str, str]]:
        return list(self.entries)


def _read(entries: Sequence[str]) -> ServiceEnvPosture:
    return read_service_env_posture(probe=_Probe([(_EXTRA, e) for e in entries]), environ={})


def test_the_stand_ins_have_a_secrets_shape() -> None:
    assert _KEY in KEY_CLASS_NAMES
    assert len(_URL_ONE_PAD) == 44 and _URL_ONE_PAD.endswith("=")
    assert not _URL_ONE_PAD.endswith("==") and "-" in _URL_ONE_PAD and "_" in _URL_ONE_PAD


#: Each as the line or the item below an empty store key. Every case above the Windows-name ones
#: already refused on main at 895925f2d3a; the Windows-name cases did not, on a later line or in
#: the next item, so only they show this change (Lander hold on PR 3142, finding 2).
_SHAPES = (
    pytest.param(f"x={_KEY_B64}", id="ordinary-name-set-to-a-key"),
    pytest.param(_URL_ONE_PAD, id="base64url-one-pad"),
    pytest.param(f"={_KEY_B64}", id="equals-led"),
    pytest.param(f"={_URL_ONE_PAD}", id="equals-led-base64url"),
    # Review round 2: a retired-keys list and a quoted key as an ordinary variable's value.
    pytest.param(f"x={_KEY_B64},{_KEY_B64}", id="ordinary-name-set-to-a-key-list"),
    pytest.param(f'x="{_KEY_B64}"', id="ordinary-name-set-to-a-quoted-key"),
    # Names that may end an empty secret-class value (``serviceenv._ends_blank_class``), each
    # set to a key, so only the value's key shape makes the empty key read as set.
    pytest.param(f"Path={_KEY_B64}", id="windows-name-set-to-a-key"),
    pytest.param(f"TEMP={_URL_ONE_PAD}", id="windows-name-set-to-a-base64url-key"),
    pytest.param(f"MEFOR_SECRETS_DIRECTORY={_KEY_B64}", id="directory-name-set-to-a-key"),
)


@pytest.mark.parametrize("shape", _SHAPES)
def test_key_material_on_the_next_line_makes_the_empty_key_read_as_set(shape: str) -> None:
    posture = _read([f"MEFOR_AI_ENVIRONMENT=prod\n{_KEY}=\n{shape}"])
    assert posture.listed_keys == (_KEY,), posture.listed
    assert service_env_refusal(posture) is not None


@pytest.mark.parametrize("shape", _SHAPES)
def test_key_material_in_the_next_item_makes_the_empty_key_read_as_set(shape: str) -> None:
    posture = _read([f"{_KEY}=", shape])
    assert posture.listed_keys == (_KEY,), posture.listed
    assert service_env_refusal(posture) is not None


@pytest.mark.parametrize("shape", _SHAPES)
def test_key_material_in_the_next_item_below_a_later_empty_line_reads_as_set(shape: str) -> None:
    """The empty key on a later line of its own item, not the item's first."""
    posture = _read([f"MEFOR_AI_ENVIRONMENT=prod\n{_KEY}=", shape])
    assert posture.listed_keys == (_KEY,), posture.listed
    assert service_env_refusal(posture) is not None


@pytest.mark.parametrize("shape", _SHAPES)
def test_key_material_below_the_name_alone_makes_the_key_read_as_set(shape: str) -> None:
    """The key's name written alone, with no equals sign, as ``nssm set ... NAME =value`` writes
    it, on the line or in the item above."""
    for entries in ([f"{_KEY}\n{shape}"], [_KEY, shape]):
        posture = _read(entries)
        assert posture.listed_keys == (_KEY,), (entries, posture.listed)
        assert service_env_refusal(posture) is not None


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (_KEY, base64.b64encode(b"synthetic-store-key-abcdefghij01").decode()),
        ("MEFOR_STORE_PASSWORD", "hunter2"),
    ],
    ids=["store-key", "store-password"],
)
def test_a_secret_alone_below_an_ordinary_name_set_to_a_key_is_named(name: str, value: str) -> None:
    """A line of an ordinary variable's shape whose value is a key, ``x=<key>``, still starts a
    variable, so a secret's name alone below it, with its value on the next line, is read as that
    secret and the refusal names it, with that secret's remedy, rather than the ``MEFOR_VALUE_*``
    name the string opens with (Lander hold on PR 3142, finding 1)."""
    posture = _read([f"MEFOR_VALUE_A\nx={_KEY_B64}\n{name}\n={value}"])
    assert posture.listed == (name,), posture.listed
    refusal = service_env_refusal(posture)
    assert refusal is not None and refusal.startswith(name), refusal
    if name == _KEY:
        assert "DPAPI-protected key file" in refusal


@pytest.mark.parametrize(
    "entries",
    [
        pytest.param(["MEFOR_VALUE_A=", f"x={_KEY_B64}"], id="item"),
        pytest.param([f"MEFOR_VALUE_A=\nx={_KEY_B64}"], id="line"),
        pytest.param([f"MEFOR_VALUE_A=\nPath={_KEY_B64}"], id="line-windows-name"),
    ],
)
def test_an_ordinary_name_set_to_a_key_does_not_join_an_empty_value(entries: list[str]) -> None:
    """An ordinary variable whose value is a key, as the next item or on the next line, is a
    variable of its own, so below an empty ``MEFOR_VALUE_*`` value the empty entry is named, and
    the remedy does not say to remove the item below it (Lander holds on PR 3142: the first's
    finding 3, the item form, and the second's H1, the line form)."""
    posture = _read(entries)
    assert posture.empty_value_names == ("MEFOR_VALUE_A",)
    assert not posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert "An empty or blank MEFOR_VALUE_* entry is refused too: delete it" in refusal
    assert RUNS_ON not in refusal


_DIRECTORY_KEY = f"MEFOR_SECRETS_DIRECTORY={_KEY_B64}"
#: How every refusal ends, after its remedy.
_END = '. [security].enforcement = "warn" does not change this refusal'


@pytest.mark.parametrize(
    "entries",
    [
        pytest.param([f"{_KEY}=", _DIRECTORY_KEY], id="item"),
        pytest.param(
            [f"MEFOR_AI_ENVIRONMENT=prod\n{_KEY}=", _DIRECTORY_KEY], id="item-below-a-later-line"
        ),
        pytest.param([_KEY, _DIRECTORY_KEY], id="item-below-the-name"),
        pytest.param([f"{_KEY}=", f"mefor_secrets_directory= ={_KEY_B64}"], id="item-blank-led"),
        pytest.param([f"{_KEY}=", f"MEFOR_SECRETS_DIRECTORY==\n{_KEY_B64}"], id="item-key-below"),
        pytest.param(
            [f"{_KEY}=", f"mefor_secrets_directory=C:\\d\nx={_KEY_B64}"], id="item-path-and-key"
        ),
        pytest.param(
            [f"{_KEY}=", f"mefor_secrets_directory=C:\\d;{_KEY_B64}"], id="item-key-beside-a-path"
        ),
        pytest.param([f"{_KEY}=", "mefor_secrets_directory=C:\\d"], id="item-path-only"),
        pytest.param(
            [f"{_KEY}=", "MEFOR_VALUE_A", "mefor_secrets_directory=C:\\d"],
            id="item-past-a-name-alone",
        ),
        pytest.param([f"{_KEY}=", _KEY, _DIRECTORY_KEY], id="item-past-the-key-alone"),
        pytest.param(
            [f"{_KEY}=", "MEFOR_STORE_PASSWORD", "mefor_secrets_directory=C:\\d"],
            id="item-past-a-secret-alone",
        ),
    ],
)
def test_a_joined_directory_string_is_removed_with_the_value(entries: list[str]) -> None:
    """A ``MEFOR_SECRETS_DIRECTORY`` string joined below an empty store key may hold the key, so
    the remedy says to remove what the value runs on into, but for a path alone (the Lander's
    second hold on PR 3142, H3). It names no list or string to do it in (the third hold, H1)."""
    posture = _read(entries)
    assert posture.listed_keys == (_KEY,), posture.listed
    assert posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None
    # Beside the keep-one step, both spare the directory line it keeps.
    spares = KEEP in refusal
    assert (REMOVE_SPARING if spares else REMOVE) in refusal
    assert (RUNS_ON_SPARING if spares else RUNS_ON) in refusal


def test_the_create_guidance_is_printed_only_where_a_setting_goes_to_the_directory() -> None:
    """The third hold's H2. For the store key alone, which goes to a key file, the refusal says
    nothing of creating a secrets directory, even with a directory string joined to it. The
    run-on step removes that string, so the remedy ends by saying to add the directory back,
    with no create clause (the Lander's rulings on comment 7087145957 and on handback
    7087574833, R1). Beside a secret the directory takes, with no entry read as naming it, it
    says how one is created. The joined entry holds the key, so nothing says to keep it (the
    fifth hold, H2)."""
    key_alone = service_env_refusal(_read([f"{_KEY}=", _DIRECTORY_KEY]))
    assert key_alone is not None
    remedy = key_alone.split("each value refused here. ", 1)[1]
    # The doubt step comes first, keeping the joined string that may hold the key whole, then the
    # key file, and the removal last (fourth hold, H1; the Lander's ruling (a) on PR 3142's
    # repair handback, comment 7112155891).
    assert remedy.startswith(
        f"{DOUBT_STEP_RUN_ON}. Keep the store key in a DPAPI-protected key file instead"
    )
    assert remedy.endswith(f"{REMOVE}. {RUNS_ON}. {ADD_BACK_DOUBT}{_END}")
    # The directory item may still be read as its own variable, so no "set no" opener, and the
    # pass-back leaves out the strings the run-on step removes, which hold the key (the
    # Lander's hold on PR 3142, comment 7088102723).
    assert DOUBT_PASS_BACK in remedy and SET_NO not in remedy
    # No create guidance anywhere, the add-back step included (the third hold, H2).
    assert "how it is created" not in remedy and "how the directory is created" not in remedy
    assert "The other secrets: a secrets directory" not in remedy
    assert CREATE not in remedy and KEEP not in remedy
    beside = service_env_refusal(
        _read([f"{_KEY}=", _DIRECTORY_KEY, "MEFOR_AUTH_AD_BIND_PASSWORD=synthetic"])
    )
    assert beside is not None and CREATE in beside


def test_a_path_alone_joined_into_an_empty_key_is_kept() -> None:
    """The fourth hold's H2. A path-only directory entry joined into the empty key is the
    service's directory entry, so the remedy ends by saying to keep it."""
    posture = _read([f"{_KEY}=", "mefor_secrets_directory=C:\\d"])
    assert posture.listed_keys == (_KEY,) and posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert refusal.endswith(f"{REMOVE_SPARING}. {RUNS_ON_SPARING}. {KEEP}{_END}")
    # The key's only value is that path, so there is no key to protect (the fifth hold, H2).
    assert "protect-key" not in refusal


@pytest.mark.parametrize(
    "entry", ["mefor_secrets_directory=C:\\d\r\n", " mefor_secrets_directory=C:\\d"]
)
def test_only_an_entry_the_engine_reads_as_the_directory_is_kept(entry: str) -> None:
    """A line break after the path is stripped as the engine strips the value, so the entry is
    still kept. A blank before the name makes it another variable, so the key is protected and
    nothing says to keep the entry."""
    refusal = service_env_refusal(_read([f"{_KEY}=", entry]))
    assert refusal is not None
    kept = not entry.startswith(" ")
    assert (KEEP in refusal) is kept
    assert ("protect-key" in refusal) is not kept


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        pytest.param(f"C:\\d;{_URL_ONE_PAD}", False, id="base64url-key"),
        pytest.param(f"C:\\d\\{_URL_ONE_PAD.rstrip('=')}", False, id="base64url-key-as-a-folder"),
        pytest.param(f"C:\\d;{_KEY_B64}", False, id="standard-key"),
        pytest.param(f"C:\\d\\{_KEY_B64.rstrip('=')}", False, id="standard-key-as-a-folder"),
        pytest.param(
            "D:/MessageFoundrySecrets/ProductionEngineSecretsDirectory", False, id="slash-path-run"
        ),
        pytest.param("Summer!2026", False, id="not-a-path"),
        pytest.param("C:\\d;Summer!2026", False, id="path-then-text"),
        pytest.param("C:\\Summer!2026 hunter2", False, id="path-start-with-a-bang"),
        pytest.param(r"\\srv\share\secrets", True, id="unc-path"),
        pytest.param("/srv/secrets", False, id="posix-path"),
        pytest.param("\\\\srv\\", False, id="unc-without-a-share"),
        pytest.param("\\\\srv\\..", False, id="unc-share-of-dots"),
        pytest.param("\\\\.\\pipe\\x", False, id="unc-device-namespace"),
        pytest.param("   ", False, id="blank"),
        pytest.param("C:\\d", True, id="plain-path"),
    ],
)
def test_only_a_plain_absolute_path_is_kept(value: str, kept: bool) -> None:
    """The Lander's sixth hold on PR 3142, H1: the keep sentence fails closed. Only a whole value
    that is plainly an absolute path, with no key run in either base64 alphabet, is kept. Anything
    else is read as key material: the key is protected and nothing says to keep the entry. A
    forward-slash path with a long run of letters is refused the keep sentence too."""
    refusal = service_env_refusal(_read([f"{_KEY}=", f"mefor_secrets_directory={value}"]))
    assert refusal is not None
    assert (KEEP in refusal) is kept
    # A blank value holds no key either, so nothing says to protect one.
    assert ("protect-key" in refusal) is not (kept or not value.strip())
    assert (REMOVE_SPARING if kept else REMOVE) in refusal
    assert (RUNS_ON_SPARING if kept else RUNS_ON) in refusal


def test_one_joined_value_that_is_no_plain_path_keeps_nothing() -> None:
    """The sixth hold's H1, failing closed: a plain path joined to one secret is not kept when
    another secret runs on into a directory entry that is no plain path."""
    refusal = service_env_refusal(
        _read(
            [
                "MEFOR_AUTH_AD_BIND_PASSWORD=",
                "mefor_secrets_directory=C:\\d",
                f"{_KEY}=",
                f"mefor_secrets_directory=C:\\d\\{_KEY_B64.rstrip('=')}",
            ]
        )
    )
    assert refusal is not None
    assert KEEP not in refusal and "protect-key" in refusal


@pytest.mark.parametrize("name", ["mefor_secrets_d\u0131rectory", "mefor_\u017fecrets_directory"])
def test_a_name_that_only_upper_cases_to_the_directory_is_not_kept(name: str) -> None:
    refusal = service_env_refusal(_read([f"{_KEY}=", f"{name}=C:/d"]))
    assert refusal is not None
    assert KEEP not in refusal and "protect-key" in refusal


def test_a_secret_joined_to_a_directory_value_that_is_no_path_is_moved() -> None:
    """The same rule beside a password: a value that is no plain path may be the password, so it
    is sent to the secrets directory, and nothing says to keep it."""
    refusal = service_env_refusal(
        _read(["MEFOR_AUTH_AD_BIND_PASSWORD=", "mefor_secrets_directory=Summer!2026"])
    )
    assert refusal is not None
    assert "Put MEFOR_AUTH_AD_BIND_PASSWORD in the secrets directory" in refusal
    assert KEEP not in refusal


def test_a_path_alone_joined_into_an_empty_key_beside_a_secret_is_kept() -> None:
    """The same shape beside a secret the directory takes: the secret goes to the directory and
    the path entry stays, so the keep sentence ends the remedy and contradicts nothing before."""
    posture = _read(
        [f"{_KEY}=", "mefor_secrets_directory=C:\\d", "MEFOR_AUTH_AD_BIND_PASSWORD=synthetic"]
    )
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert refusal.endswith(f"{REMOVE_SPARING}. {RUNS_ON_SPARING}. {KEEP}{_END}")
    assert refusal.index(CREATE) < refusal.index("Put MEFOR_AUTH_AD_BIND_PASSWORD")
    assert refusal.index("Put MEFOR_AUTH_AD_BIND_PASSWORD in the secrets directory") < (
        refusal.index(REMOVE_SPARING)
    )


def test_a_key_bearing_directory_entry_still_gets_the_remove_guidance() -> None:
    """The control for the two above: a directory entry holding the key is not a path alone,
    so the run-on sentence says to remove it with the key."""
    refusal = service_env_refusal(_read([f"{_KEY}=", _DIRECTORY_KEY]))
    assert refusal is not None
    assert f"{REMOVE}. {RUNS_ON}" in refusal
    assert KEEP not in refusal


def test_protect_key_and_the_secrets_directory_come_before_the_removal_step() -> None:
    """The fourth hold's H1: protect-key reads the key from the shell, and a secret is copied
    to its file, before the step that says to remove each refused variable, with its value
    (the fifth hold, H1)."""
    refusal = service_env_refusal(
        _read([f"{_KEY}=", _KEY_B64, "MEFOR_AUTH_AD_BIND_PASSWORD=synthetic", "MEFOR_VALUE_A=1"])
    )
    assert refusal is not None
    first_removal = refusal.index(REMOVE)
    assert refusal.index("protect-key") < first_removal
    assert refusal.index("Put MEFOR_AUTH_AD_BIND_PASSWORD") < first_removal
    assert "Remove each refused variable, with its value, from" in refusal


@pytest.mark.parametrize(
    ("entry", "creates"),
    [
        pytest.param("MEFOR_VALUE_A=", False, id="empty-value"),
        pytest.param("MEFOR_VALUE_=synthetic", True, id="bare-prefix"),
        pytest.param("MEFOR_VALUE_A=1", True, id="value"),
        pytest.param("MEFOR_AUTH_AD_BIND_PASSWORD=synthetic", True, id="secret"),
        pytest.param(f"{_KEY}={_KEY_B64}", False, id="store-key"),
    ],
)
def test_the_create_guidance_comes_with_the_put_step(entry: str, creates: bool) -> None:
    """A MEFOR_VALUE_* name, the bare prefix among them, gets the Put step and how a directory
    is created (the Lander's decision d20261122T181059560-3bac03 on PR 3142). An empty one has
    nothing to move, since the remedy says to delete it, so it gets neither (the Lander's hold
    on PR 3142, comment 7100710066, item 10). A store key alone goes to a key file, so it gets
    neither."""
    refusal = service_env_refusal(_read([entry]))
    assert refusal is not None
    assert (CREATE in refusal) is creates and ("Put " in refusal) is creates


def test_the_removal_step_says_with_its_value_for_a_single_item_key() -> None:
    """The fifth hold's H1, for the store key written in one item with the key on its next
    line: the removal step comes last and says to remove the variable with its value."""
    refusal = service_env_refusal(_read([f"{_KEY}=\n{_KEY_B64}"]))
    assert refusal is not None
    assert refusal.endswith(f"{REMOVE}{_END}")
    assert "Remove each refused variable, with its value, from" in refusal
    assert _KEY_B64 not in refusal


def test_a_joined_path_and_a_joined_key_print_different_remedies() -> None:
    """The fifth hold's H2 pair. A path joined into the empty key is no key, so nothing says to
    protect one and the entry is kept. A key joined in the same place is protected, and nothing
    says to keep it. Both refuse alike."""
    path = service_env_refusal(_read([f"{_KEY}=", "mefor_secrets_directory=C:\\d"]))
    key = service_env_refusal(_read([f"{_KEY}=", f"mefor_secrets_directory={_KEY_B64}"]))
    assert path is not None and key is not None and path != key
    assert KEEP in path and "protect-key" not in path
    assert KEEP not in key and "protect-key" in key
    assert path.split(". ", 1)[0] == key.split(". ", 1)[0]


def test_a_secret_whose_only_value_is_a_joined_path_moves_nothing() -> None:
    """The fifth hold's H2: the bind password's only value is the directory path below it,
    so nothing says to put it in the directory or how one is created, and the path is kept."""
    posture = _read(["MEFOR_AUTH_AD_BIND_PASSWORD=", "mefor_secrets_directory=C:\\d"])
    assert posture.listed == ("MEFOR_AUTH_AD_BIND_PASSWORD",) and posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert CREATE not in refusal and "Put " not in refusal and "protect-key" not in refusal
    assert refusal.endswith(f"{REMOVE_SPARING}. {RUNS_ON_SPARING}. {KEEP}{_END}")


def test_a_directory_named_on_its_own_gets_no_create_guidance() -> None:
    """The control for the arm above: a directory entry read as naming the directory."""
    refusal = service_env_refusal(
        _read(["MEFOR_SECRETS_DIRECTORY=C:\\d", "MEFOR_AUTH_AD_BIND_PASSWORD=synthetic"])
    )
    assert refusal is not None
    assert REMOVE in refusal and CREATE not in refusal


def test_a_refused_variable_inside_the_directorys_own_string_names_no_string() -> None:
    """A refused variable on a later line of the directory's own string: the removal step says
    to remove that variable and names no string to remove (the third hold, H1). The directory
    line shares its string with other lines, so it is in doubt, and removing the variable may
    change the directory the engine reads, so the add-back step names it again (the Lander's
    ruling B on PR 3142's repair handback, comment 7106776128). The directory is listed only by
    that entry, so the doubt step, then the create step, print before the Put step (the
    Lander's ruling (a) on that handback's round-3 open findings 1 and 2, comment 7112155891)."""
    posture = _read(["MEFOR_SECRETS_DIRECTORY=C:\\d\nMEFOR_STORE_PASSWORD=", "abc"])
    assert posture.value_runs_on and posture.directory_in_doubt
    assert "MEFOR_SECRETS_DIRECTORY" in posture.listed
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert REMOVE in refusal and RUNS_ON in refusal
    remedy = refusal.split("each value refused here. ", 1)[1]
    assert remedy.startswith(
        f"{DOUBT_CREATE_RUN_ON}. Put MEFOR_STORE_PASSWORD in the secrets directory"
    )
    # The password moves to the secrets directory, so the step carries its create clause.
    assert remedy.endswith(f"{REMOVE}. {RUNS_ON}. {ADD_BACK_DOUBT}{ADD_BACK_CREATE}{_END}")
    # The third hold's H1: no step between the doubt step and the add-back step names a string.
    # Those two read and pass back a list, so they name the strings they keep or leave out.
    assert "string" not in remedy.split(DOUBT_STEP_RUN_ON, 1)[1].split(ADD_BACK_DOUBT, 1)[0]


def test_a_store_key_alone_beside_a_directory_entry_in_doubt_gets_the_add_back_step() -> None:
    """The Lander's ruling B on PR 3142's repair handback, comment 7106776128: where any
    directory entry is in doubt, the remedy says to take every directory line out and add one
    back, for a store key alone too, though no step above removes the entry. A store key alone
    goes to a key file, so the step carries no create clause (the third hold, H2)."""
    refusal = service_env_refusal(
        _read([f"{_KEY}={_KEY_B64}", "TZ=UTC\nMEFOR_SECRETS_DIRECTORY=C:\\d"])
    )
    assert refusal is not None
    assert refusal.endswith(f"{REMOVE}. {ADD_BACK_DOUBT}{_END}"), refusal
    assert ADD_BACK_CREATE not in refusal and CREATE not in refusal and KEEP not in refusal


@pytest.mark.parametrize("prefix", ["", "MEFOR_AI_ENVIRONMENT=prod\n"], ids=["line", "later-line"])
def test_a_directory_line_in_the_key_string_refuses_as_the_key_alone(prefix: str) -> None:
    """A key-valued directory line inside the empty key's own string is read as the key's
    value: it refuses as the key, runs on into nothing, and says nothing of the directory. The
    rule for joined strings does not reach this form, which is left as it stands (H3, item
    (c))."""
    posture = _read([f"{prefix}{_KEY}=\n{_DIRECTORY_KEY}"])
    assert posture.listed_keys == (_KEY,), posture.listed
    assert not posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert REMOVE in refusal and RUNS_ON not in refusal and CREATE not in refusal


def test_a_nameless_key_item_joins_an_empty_value_item() -> None:
    """An item with no name before its equals sign, ``=<key>``, is read as the empty
    ``MEFOR_VALUE_*`` item's value split from it, so the remedy says to remove it too. This
    pins the ``_is_key_value(rest)`` clause of ``serviceenv._continues_string`` (BACKLOG #5394
    items 6 and 12); main at 895925f2d3a named the empty entry instead."""
    posture = _read(["MEFOR_VALUE_A=", f"={_KEY_B64}"])
    assert posture.value_runs_on
    assert posture.empty_value_names == ()
    refusal = service_env_refusal(posture)
    assert refusal is not None and RUNS_ON in refusal


@pytest.mark.parametrize(
    "line",
    [
        "Path=C:\\Windows\\system32;C:\\Windows",
        "MEFOR_SECRETS_DIRECTORY=D:/MessageFoundrySecrets/ProductionEngineSecretsDirectory",
        # Mixed case alone does not make these secrets.
        "PSModulePath=C:/Program Files/WindowsPowerShell/Modules/MessageFoundryProduction",
        "ProgramData=D:/MessageFoundryProductionData/ServiceEnvironmentProgramData",
    ],
)
def test_an_ordinary_line_still_ends_the_empty_key(line: str) -> None:
    """Control: a line with no key material, under one of the few names that may end an empty
    secret-class value (``serviceenv._ends_blank_class``), still ends the empty key, on a later
    line and in the next item alike, so the secret reads as unset. Every other name refuses there
    since BACKLOG #5394 wave 3 (``tests/test_b532w3_serviceenv_split_shapes.py``). Each form the
    positive tests above use is here."""
    for entries in (
        [f"MEFOR_AI_ENVIRONMENT=prod\n{_KEY}=\n{line}"],
        [f"{_KEY}=", line],
        [f"MEFOR_AI_ENVIRONMENT=prod\n{_KEY}=", line],
        [f"{_KEY}\n{line}"],
        [_KEY, line],
    ):
        assert _read(entries).listed_keys == (), (entries, _read(entries).listed)


_RETIRED = "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED"


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(f"{_KEY_B64},", id="trailing-comma"),
        pytest.param(f"{_KEY_B64},,{_KEY_B64}", id="doubled-comma"),
        pytest.param(f",{_KEY_B64}", id="leading-comma"),
        pytest.param(f"'{_KEY_B64}, '", id="quoted-trailing-blank"),
    ],
)
def test_a_retired_key_list_with_a_blank_entry_below_an_empty_secret_refuses(value: str) -> None:
    """The Lander's hold on PR 3142, comment 7100710066, item 3: the engine's retired-keys reader
    skips a blank entry, so a key list with a trailing or doubled comma is key material, and a
    Windows name set to it does not end the empty secret above it."""
    posture = _read([f"{_RETIRED}=", f"Path={value}"])
    assert posture.listed_keys == (_RETIRED,), posture.listed
    refusal = service_env_refusal(posture)
    assert refusal is not None and _KEY_B64 not in refusal


@pytest.mark.parametrize("value", [",", " , ", "C:\\Windows,"])
def test_a_list_of_blanks_or_a_path_still_ends_the_empty_secret(value: str) -> None:
    """Control for the test above: with no key in it, the Windows name still ends the empty
    value, so nothing refuses."""
    assert _read([f"{_RETIRED}=", f"Path={value}"]).listed_keys == ()


def test_a_store_key_in_this_process_keeps_the_protect_key_step() -> None:
    """The Lander's hold on PR 3142, comment 7100710066, item 4: the listed key's only value is a
    joined directory path, but the key reaches this process anyway, so the remedy still says to
    keep it in a protected key file. The control, with no key in the process, prints no such
    step."""
    entries = [(_EXTRA, f"{_KEY}="), (_EXTRA, "mefor_secrets_directory=C:\\s")]
    reached = read_service_env_posture(probe=_Probe(entries), environ={_KEY: _KEY_B64})
    assert reached.keys_in_environment == (_KEY,) and reached.listed_keys == (_KEY,)
    refusal = service_env_refusal(reached)
    assert refusal is not None and "messagefoundry protect-key" in refusal
    assert _KEY_B64 not in refusal
    control = service_env_refusal(read_service_env_posture(probe=_Probe(entries), environ={}))
    assert control is not None and "protect-key" not in control


_PLAIN = "Parameters\\AppEnvironment"


@pytest.mark.parametrize(
    "entries",
    [
        pytest.param(
            [
                (_PLAIN, "MEFOR_SECRETS_DIRECTORY=C:\\real"),
                (_EXTRA, f"{_KEY}="),
                (_EXTRA, "mefor_secrets_directory=C:\\other"),
            ],
            id="joined-path-beside-a-listed-one",
        ),
        pytest.param(
            [
                (_EXTRA, "MEFOR_VALUE_A=synthetic"),
                (_EXTRA, f"{_KEY}="),
                (_EXTRA, "mefor_secrets_directory=C:\\d"),
            ],
            id="joined-lower-case-path",
        ),
        # Review round 2 on the repair: the only directory entry is in AppEnvironment, so the
        # step says to add the one it keeps to AppEnvironmentExtra.
        pytest.param(
            [
                (_PLAIN, "MEFOR_STORE_PASSWORD="),
                (_PLAIN, "mefor_secrets_directory=C:\\d"),
                (_EXTRA, "MEFOR_VALUE_B=synthetic"),
            ],
            id="joined-path-in-appenvironment-only",
        ),
    ],
)
def test_a_joined_directory_entry_keeps_one_entry_and_spares_it_from_removal(
    entries: list[tuple[str, str]],
) -> None:
    """The Lander's hold on PR 3142, comment 7100710066, items 5 and 8. A joined directory entry
    the engine may read, beside another or alone, would win over the path the service should
    name, so the remedy keeps exactly one entry, in AppEnvironmentExtra, written as the path, and
    takes every other directory line out. The removal and run-on steps spare the directory lines,
    so no step removes an entry a later one keeps."""
    posture = read_service_env_posture(probe=_Probe(entries), environ={})
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert refusal.endswith(f"{KEEP}{_END}"), refusal
    assert REMOVE_SPARING in refusal and RUNS_ON_SPARING in refusal
    assert REMOVE not in refusal and RUNS_ON not in refusal
    assert "Keep any of them that sets" not in refusal
    assert refusal.index(REMOVE_SPARING) < refusal.index(RUNS_ON_SPARING) < refusal.index(KEEP)
    assert "synthetic" not in refusal and "C:\\other" not in refusal


@pytest.mark.parametrize(
    "entries",
    [
        # The hold's scenario: the joined entry's value is key-shaped, not a path.
        pytest.param(
            [
                (_PLAIN, "MEFOR_SECRETS_DIRECTORY=C:\\x"),
                (_EXTRA, f"{_KEY}="),
                (_EXTRA, f"MEFOR_SECRETS_DIRECTORY={_KEY_B64}"),
            ],
            id="joined-key-text-beside-a-listed-path",
        ),
        pytest.param(
            [
                (_PLAIN, "MEFOR_SECRETS_DIRECTORY=C:\\real"),
                (_EXTRA, "MEFOR_VALUE_A="),
                (_EXTRA, "MEFOR_SECRETS_DIRECTORY=="),
            ],
            id="joined-equals-beside-a-listed-one",
        ),
        pytest.param(
            [
                (_PLAIN, "MEFOR_VALUE_A=synthetic"),
                (_PLAIN, "MEFOR_VALUE_A="),
                (_PLAIN, " MEFOR_SECRETS_DIRECTORY=="),
                ("Environment", "MEFOR_SECRETS_DIRECTORY=C:\\real"),
            ],
            id="joined-padded-beside-the-scm-one",
        ),
    ],
)
def test_a_joined_directory_entry_that_is_not_plainly_a_path_is_removed_and_named_again(
    entries: list[tuple[str, str]],
) -> None:
    """The Lander's hold on PR 3142, comment 7104660861, item 1, its first param the hold's
    scenario, under the Lander's ruling B on the repair handback, comment 7106776128. A joined
    directory entry whose value is not plainly a path is in doubt, so no step spares or keeps
    it, and the removal and run-on steps take it out with the value. That changes the entry the
    engine reads, so a step of its own says to take every directory line out and the add-back
    step names the path again, never a silent change of directory. The parametrized control
    ``joined-path-beside-a-listed-one`` above, the same lists with a joined path, still keeps one
    entry."""
    posture = read_service_env_posture(probe=_Probe(entries), environ={})
    assert posture.directory_in_doubt and posture.directory_joined
    refusal = service_env_refusal(posture)
    assert refusal is not None
    # The create clause follows only where a setting moves, as MEFOR_VALUE_A=synthetic does.
    moves = any(value == "MEFOR_VALUE_A=synthetic" for _where, value in entries)
    create = ADD_BACK_CREATE if moves else ""
    assert refusal.endswith(f"{RUNS_ON}. {ADD_BACK_DOUBT}{create}{_END}"), refusal
    assert "a step below covers" not in refusal and REMOVE in refusal and KEEP not in refusal
    assert refusal.index(REMOVE) < refusal.index(RUNS_ON)
    assert SET_NO not in refusal
    assert _KEY_B64 not in refusal and "C:\\x" not in refusal


def _remedy(entries: list[tuple[str, str]]) -> str:
    refusal = service_env_refusal(read_service_env_posture(probe=_Probe(entries), environ={}))
    assert refusal is not None
    return refusal


@pytest.mark.parametrize(
    "string",
    [
        # Round 3's open finding 1: a key-text directory line absorbed into a broken whole-string
        # name, MEFOR_VALUE_A with no equals sign on its own line.
        pytest.param(f"MEFOR_VALUE_A\nMEFOR_SECRETS_DIRECTORY={_KEY_B64}", id="absorbed"),
        # Round 3's open finding 2: the same line where a later line sets a name ``_names``
        # keeps, so only the uncounted whole-string twin holds it.
        pytest.param(
            f"MEFOR_VALUE_A\nMEFOR_VALUE_B=synthetic\nMEFOR_SECRETS_DIRECTORY={_KEY_B64}",
            id="uncounted-twin",
        ),
        pytest.param(
            f"MEFOR_VALUE_A=synthetic\nMEFOR_SECRETS_DIRECTORY={_KEY_B64}", id="refused-value"
        ),
        pytest.param(f"\nMEFOR_SECRETS_DIRECTORY={_KEY_B64}", id="blank-led-directory-string"),
        pytest.param(f"TZ=UTC\nMEFOR_SECRETS_DIRECTORY={_KEY_B64}", id="ordinary-variable-string"),
        # Round 3's open finding 4: a padded ``==`` second line under a directory entry.
        pytest.param(
            "MEFOR_SECRETS_DIRECTORY=C:\\real\n MEFOR_SECRETS_DIRECTORY==", id="padded-equals-line"
        ),
    ],
)
def test_a_directory_line_in_doubt_beside_a_joined_path_keeps_no_entry(string: str) -> None:
    """The Lander's ruling B on PR 3142's repair handback, comment 7106776128, round 3's open
    findings 1, 2 and 4: a joined plain path would be kept, but another registry string holds a
    directory line that is not, alone, plainly a path. The rule reads every string as written,
    whatever the line reading made of it, so that line is in doubt: no step spares or keeps a
    directory line, a step of its own says to take every one out, and the add-back step names
    the path."""
    refusal = _remedy(
        [
            (_EXTRA, f"{_KEY}="),
            (_EXTRA, "mefor_secrets_directory=C:\\d"),
            (_EXTRA, string),
        ]
    )
    assert KEEP not in refusal and "a step below covers" not in refusal
    assert refusal.count(ADD_BACK_DOUBT) == 1 and RUNS_ON in refusal
    assert refusal.index(RUNS_ON) < refusal.index(ADD_BACK_DOUBT)
    assert _KEY_B64 not in refusal and "C:\\d" not in refusal


def test_a_joined_plain_path_that_differs_from_a_listed_one_is_kept_not_dropped() -> None:
    """Round 3's open finding 5: a joined plain path, the entry the engine reads since it is in
    AppEnvironmentExtra, beside a different path listed in AppEnvironment, while another refused
    value runs on into other text. At 2ff1f095 the run-on step removed the joined path with no
    keep-one and no add-back step, a silent change of directory. No entry is in doubt, so the
    keep-one step now names the path and the removal steps spare the directory lines."""
    refusal = _remedy(
        [
            (_PLAIN, "MEFOR_SECRETS_DIRECTORY=C:\\real"),
            (_EXTRA, f"{_KEY}="),
            (_EXTRA, "mefor_secrets_directory=C:\\d"),
            (_EXTRA, "MEFOR_STORE_PASSWORD="),
            (_EXTRA, "synthetic-run-on"),
        ]
    )
    assert refusal.endswith(f"{KEEP}{_END}"), refusal
    assert REMOVE_SPARING in refusal and RUNS_ON_SPARING in refusal
    assert ADD_BACK_ANY not in refusal and "synthetic-run-on" not in refusal


def test_a_look_alike_directory_name_joined_to_a_key_is_added_back() -> None:
    """The Lander's hold on PR 3142, comment 7104660861: Python's ``os.environ`` on Windows
    upper-cases names and ``'\\u017f'.upper() == 'S'``, so the engine reads
    ``MEFOR_\\u017fECRETS_DIRECTORY`` as the directory. Joined to an empty store key, the run-on
    step removes it; under ruling B (comment 7106776128) it is in doubt, so the add-back step
    names the directory again. At 2ff1f095 nothing did."""
    posture = read_service_env_posture(
        probe=_Probe([(_EXTRA, f"{_KEY}="), (_EXTRA, "MEFOR_\u017fECRETS_DIRECTORY=C:\\d")]),
        environ={},
    )
    assert posture.directory_in_doubt
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert refusal.endswith(f"{RUNS_ON}. {ADD_BACK_DOUBT}{_END}"), refusal
    assert KEEP not in refusal and "C:\\d" not in refusal


def test_a_single_plain_path_entry_is_kept() -> None:
    """The control for the per-entry rule (the Lander's ruling B on PR 3142's repair handback,
    comment 7106776128): the only directory entry is its own string and plainly a path, and no
    value runs on into it, so it is not in doubt and no step touches it, and the remedy says
    nothing about the directory."""
    posture = read_service_env_posture(
        probe=_Probe(
            [(_EXTRA, "MEFOR_VALUE_A=synthetic"), (_EXTRA, "MEFOR_SECRETS_DIRECTORY=C:\\real")]
        ),
        environ={},
    )
    assert not posture.directory_in_doubt and "MEFOR_SECRETS_DIRECTORY" in posture.listed
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert ADD_BACK_ANY not in refusal and KEEP not in refusal and RUNS_ON not in refusal
    assert "a step below covers" not in refusal and "C:\\real" not in refusal
