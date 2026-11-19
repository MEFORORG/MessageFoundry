# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The service-environment reader's added items under vault BACKLOG #5394.

Each test drives :func:`messagefoundry.serviceenv.read_service_env_posture` through a probe, so
every one runs on every platform. Synthetic values only: the base64 stand-in below decodes to 32
bytes of plain ASCII text, never a real key.
"""

from __future__ import annotations

import base64
import inspect
import re
import tracemalloc
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

import pytest

from messagefoundry import serviceenv
from messagefoundry.serviceenv import (
    KEY_CLASS_NAMES,
    ServiceEnvPosture,
    read_service_env_posture,
    service_env_refusal,
)

#: A store-key-shaped stand-in: 32 bytes of ASCII, so 44 base64 characters ending in one ``=``.
_KEY_B64 = base64.b64encode(b"synthetic-store-key-0123456789ab").decode()
_EXTRA = "Parameters\\AppEnvironmentExtra"
_PLAIN = "Parameters\\AppEnvironment"


@dataclass
class _Probe:
    entries: list[tuple[str, str]] = field(default_factory=list)

    def ancestor_images(self) -> Iterator[tuple[int, str]]:
        return iter([(200, "python.exe"), (100, "nssm.exe")])

    def service_at(self, pid: int) -> str | None:
        return "MessageFoundry" if pid == 100 else None

    def environment_entries(self, service_name: str) -> list[tuple[str, str]]:
        return list(self.entries)


def _read(entries: Sequence[str | tuple[str, str]]) -> ServiceEnvPosture:
    pairs = [e if isinstance(e, tuple) else (_EXTRA, e) for e in entries]
    return read_service_env_posture(probe=_Probe(pairs), environ={})


def test_the_stand_in_has_a_store_keys_shape() -> None:
    assert len(_KEY_B64) == 44 and _KEY_B64.endswith("=") and not _KEY_B64.endswith("==")


# --- item 1: an empty store key continued on the next line or the next item ----------------------


@pytest.mark.parametrize("key", KEY_CLASS_NAMES)
def test_an_empty_store_key_item_whose_key_is_the_next_item_refuses(key: str) -> None:
    """``nssm set`` makes one ``REG_MULTI_SZ`` item per argument, so a key split from its name
    lands in the next item. That item starts no variable, so it is the key's value."""
    posture = _read([f"{key}=", _KEY_B64])
    assert posture.listed_keys == (key,)
    assert service_env_refusal(posture) is not None


@pytest.mark.parametrize("key", KEY_CLASS_NAMES)
def test_a_retired_keys_list_on_the_line_below_an_empty_name_refuses(key: str) -> None:
    """``<key>,<key>`` reads as ``NAME=value`` with the first key as the name. A name of 43
    base64 characters is a key, not an ordinary variable, so it does not end the value above."""
    listing = f"{_KEY_B64},{_KEY_B64}"
    later = _read([f"MEFOR_AI_ENVIRONMENT=prod\n{key}=\n{listing}"])
    assert later.listed_keys == (key,)
    items = _read(["MEFOR_AI_ENVIRONMENT=prod", f"{key}=", listing])
    assert items.listed_keys == (key,)


@pytest.mark.parametrize("key", KEY_CLASS_NAMES)
def test_an_empty_store_key_item_above_an_ordinary_item_does_not_refuse(key: str) -> None:
    """The control: an empty key is harmless when the next item's first line sets an ordinary
    variable, even to nothing, under a name that could not be key material, or is empty-named
    like Windows' own ``=C:`` entries."""
    followers = (
        "MEFOR_AI_ENVIRONMENT=prod",
        "ProgramFiles(x86)=C:\\x",
        "=C:=C:\\x",
        "HTTP_PROXY=",  # an ordinary variable set to nothing still ends the value above
        "NO_PROXY=",
        "MEFOR_SECRETS_DIRECTORY=",
        "A" * 42 + "_B=1",  # a base64 run one short of a key's, so this is a name
    )
    for follower in followers:
        posture = _read([f"{key}=", follower])
        assert posture.listed_keys == (), follower
        assert service_env_refusal(posture) is None, follower


@pytest.mark.parametrize("item", [f'"{_KEY_B64}"', f",{_KEY_B64},{_KEY_B64}"])
def test_a_quoted_or_comma_led_key_item_continues_the_empty_key(item: str) -> None:
    key = KEY_CLASS_NAMES[1]
    assert _read([f"{key}=", item]).listed_keys == (key,)
    assert _read([f"MEFOR_AI_ENVIRONMENT=prod\n{key}=\n{item}"]).listed_keys == (key,)


@pytest.mark.parametrize("name", ["MEFOR_STORE_PASSWORD", "MEFOR_AUTH_OIDC_CLIENT_SECRET"])
def test_a_padded_secret_split_into_the_next_item_refuses(name: str) -> None:
    """A padded base64 secret reads as ``NAME==``-shaped text, as it does on the next line of one
    string, where it already refused."""
    padded = base64.b64encode(b"synthetic-tok-16").decode()
    assert padded.endswith("==")
    assert _read([f"{name}=", padded]).listed_directory_names == (name,)
    assert _read([f"MEFOR_AI_ENVIRONMENT=prod\n{name}=\n{padded}"]).listed_directory_names == (
        name,
    )


def test_a_name_whose_equals_sign_is_on_the_next_line_takes_the_next_item() -> None:
    key = KEY_CLASS_NAMES[0]
    assert _read([f"{key}\n=", _KEY_B64]).listed_keys == (key,)


def test_a_later_empty_key_whose_key_is_the_next_item_is_counted_once() -> None:
    """The joined strings read as the one string they would be, so the broken ``MEFOR_VALUE_A``
    name above the key is counted once, under the key, and is not called empty."""
    key = KEY_CLASS_NAMES[0]
    split = _read([f"MEFOR_VALUE_A\n{key}=", _KEY_B64])
    whole = _read([f"MEFOR_VALUE_A\n{key}={_KEY_B64}"])
    assert split.listed == whole.listed == (key,)
    assert split.empty_value_names == whole.empty_value_names == ()


def test_the_refusal_says_to_remove_the_strings_a_value_runs_on_into() -> None:
    key = KEY_CLASS_NAMES[0]
    posture = _read([f"{key}=", _KEY_B64])
    assert posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert "runs on into the strings after it in the same registry value" in refusal
    one_line = _read([f"{key}={_KEY_B64}"])
    assert not one_line.value_runs_on
    assert "runs on into" not in str(service_env_refusal(one_line))


def test_a_broken_value_name_item_does_not_continue_an_empty_key() -> None:
    """``MEFOR_VALUE_A<LF>MEFOR_VALUE_B=1`` starts a variable under the whole-string reading, so
    the empty store key above it stays empty."""
    posture = _read([f"{KEY_CLASS_NAMES[0]}=", "MEFOR_VALUE_A\nMEFOR_VALUE_B=1"])
    assert posture.listed_keys == ()
    assert posture.listed_value_names == ("MEFOR_VALUE_B",)


def test_a_path_form_oidc_key_does_not_take_the_next_item_as_its_value() -> None:
    """Only an empty value runs on, so a path stays a path, as before vault BACKLOG #5394."""
    pem = "-----BEGIN " + "PRIVATE KEY-----"
    posture = _read(["MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=C:\\k.pem", f"{pem} x"])
    assert posture.listed == ()
    empty = _read(["MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=", f"{pem} x"])
    assert empty.listed_directory_names == ("MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY",)


def test_an_empty_env_value_whose_value_is_the_next_item_is_not_called_empty() -> None:
    posture = _read(["MEFOR_VALUE_X=", "synthetic"])
    assert posture.listed_value_names == ("MEFOR_VALUE_X",)
    assert posture.empty_value_names == ()


def test_a_later_line_of_a_continuing_item_is_still_read() -> None:
    key = KEY_CLASS_NAMES[0]
    posture = _read([f"{key}=", f"{_KEY_B64}\nMEFOR_VALUE_X=1"])
    assert posture.listed_keys == (key,)
    assert posture.listed_value_names == ("MEFOR_VALUE_X",)


def test_a_continued_variable_replaces_its_empty_reading_in_place() -> None:
    key = KEY_CLASS_NAMES[0]
    read = serviceenv._variables([(_EXTRA, f"{key}="), (_EXTRA, _KEY_B64)])
    keyed = [v for v in read if v.written == key]
    assert len(keyed) == 2  # the line reading and the whole-string reading, each once
    assert all(v.value.strip() and v.runs_on for v in keyed)


def test_an_item_continues_only_the_value_its_own_registry_value_ends_on() -> None:
    key = KEY_CLASS_NAMES[0]
    posture = _read([(_PLAIN, f"{key}="), (_EXTRA, _KEY_B64)])
    assert posture.listed_keys == ()


def test_a_long_run_of_continuing_items_is_read_in_linear_memory() -> None:
    """A key split one line per item: each item adds to one gathered value, not to a copy."""
    items = [f"{KEY_CLASS_NAMES[0]}="] + [f"{n:064d}" for n in range(4000)]
    started_here = not tracemalloc.is_tracing()
    if started_here:
        tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        before, _peak = tracemalloc.get_traced_memory()
        posture = _read(items)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        if started_here:
            tracemalloc.stop()
    assert posture.listed_keys == (KEY_CLASS_NAMES[0],)
    assert peak - before < 16 * 1024 * 1024, f"peak {peak - before} bytes"


def test_a_blank_item_between_does_not_end_the_value() -> None:
    key = KEY_CLASS_NAMES[0]
    assert _read([f"{key}=", "", _KEY_B64]).listed_keys == (key,)


# --- item 2: key material never reaches ``listed`` -------------------------------------------------


def test_a_line_of_key_material_that_starts_an_item_is_not_listed() -> None:
    """A PEM key split one line per item: the padded base64 item reads as ``NAME=value``."""
    pem = "-----BEGIN " + "PRIVATE KEY-----"
    posture = _read(
        [f"MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY={pem}", "MIIBsyntheticBody==", "-----END x"]
    )
    assert posture.listed == ("MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY",)
    assert not any("MIIB" in name for name, _where in posture.sources)


def test_only_a_name_the_refusal_reads_is_listed() -> None:
    posture = _read(["PATH=C:\\x", "MEFOR_AI_ENVIRONMENT=prod", "MEFOR_SECRETS_DIRECTORY=C:\\s"])
    assert posture.listed == ("MEFOR_SECRETS_DIRECTORY",)


# --- item 4: a broken MEFOR_VALUE_* name keeps its rename step -------------------------------------


def test_a_broken_value_name_counted_under_a_later_line_still_asks_for_a_rename() -> None:
    """Under the whole-string reading the engine loads ``MEFOR_VALUE_A<LF>MEFOR_VALUE_B``, a name
    the secrets directory refuses, so the remedy keeps the rename step while counting one."""
    posture = _read(["MEFOR_VALUE_A\nMEFOR_VALUE_B=1"])
    assert posture.listed_value_names == ("MEFOR_VALUE_B",)
    assert posture.unplain_value_names == ("MEFOR_VALUE_A",)
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert "1 MEFOR_VALUE_* variable(s)" in refusal
    assert "rename that env() key" in refusal


# --- item 5: the refusal does not grow with the line count -----------------------------------------


def test_the_value_count_is_grouped_by_registry_value_not_by_line() -> None:
    entry = "\n".join(f"MEFOR_VALUE_K{n}=synthetic-{n}" for n in range(500))
    refusal = service_env_refusal(_read([entry]))
    assert refusal is not None
    assert f"500 MEFOR_VALUE_* variable(s) (in {_EXTRA})" in refusal
    assert "line 2" not in refusal


# --- item 7: no value in a repr --------------------------------------------------------------------


def test_a_variable_repr_holds_no_value_and_no_name() -> None:
    """The text before an equals sign may be key material, as a line of ``<key>,<key>`` is."""
    variable = serviceenv._Variable(_EXTRA, _KEY_B64[:43], "synthetic-repr-value")
    assert "synthetic-repr-value" not in repr(variable)
    assert _KEY_B64[:43] not in repr(variable)


def test_a_posture_repr_holds_no_registry_name() -> None:
    """A ``MEFOR_VALUE_*`` name may be a value typed where the name goes."""
    posture = _read(["MEFOR_VALUE_synthetictypedvalue=x"])
    assert posture.listed_value_names == ("MEFOR_VALUE_SYNTHETICTYPEDVALUE",)
    assert "SYNTHETICTYPEDVALUE" not in repr(posture).upper()


# --- item 8: the line label is accurate for every shape --------------------------------------------


@pytest.mark.parametrize(
    ("entry", "line"),
    [
        ("MEFOR_AI_ENVIRONMENT=prod\n{key}=v", 2),
        ("MEFOR_VALUE_A\n{key}=v", 2),  # the first line is not an entry
        ("\n\nMEFOR_AI_ENVIRONMENT=prod\n{key}=v", 4),  # blank lines above count
        ("\n{key}=v", 2),  # the key is the first non-blank line
        # Empty on its own line, so the whole-string reading is the one kept.
        ("\n{key}=\nMEFOR_AI_ENVIRONMENT=prod", 2),
    ],
)
def test_the_refusal_names_the_line_of_the_string_that_sets_the_key(entry: str, line: int) -> None:
    key = KEY_CLASS_NAMES[0]
    refusal = service_env_refusal(_read([entry.format(key=key)]))
    assert refusal is not None
    assert f"{key} (in {_EXTRA}, line {line} of the registry string that sets it)" in refusal
    assert "whose first line is another entry" not in refusal


def test_a_key_on_its_strings_first_line_names_no_line() -> None:
    key = KEY_CLASS_NAMES[0]
    refusal = service_env_refusal(_read([f"{key}=v\nMEFOR_AI_ENVIRONMENT=prod"]))
    assert refusal is not None
    assert f"{key} (in {_EXTRA})" in refusal


# --- item 10: the ordinary-line pattern says what its comment says ---------------------------------


@pytest.mark.parametrize("tail", ["X= =", "X= ", "X=\t=\t"])
def test_a_line_whose_value_is_only_equals_signs_and_blanks_continues_the_value(tail: str) -> None:
    key = KEY_CLASS_NAMES[0]
    posture = _read([f"MEFOR_AI_ENVIRONMENT=prod\n{key}=\n{tail}"])
    assert posture.listed_keys == (key,)


# --- item 11: no wording that goes stale on merge --------------------------------------------------


#: ``main`` as a baseline, and "the head" as a version: what goes stale on merge, and not "the
#: head of a list", which does not.
_STALE_BASELINE = re.compile(r"``main``|\b(?:at|on|than) main\b|\bthe head\b(?! of\b)", re.I)


def test_the_module_names_no_branch_or_head_as_its_baseline() -> None:
    # The positive control: the pattern finds the wording it is for, and only that.
    assert _STALE_BASELINE.search("as ``main`` read it")
    assert _STALE_BASELINE.search("The head read the rest")
    assert _STALE_BASELINE.search("refused as on main")
    assert not _STALE_BASELINE.search("the head of the walk")
    assert not _STALE_BASELINE.search(inspect.getsource(serviceenv))


# --- one line rule for a later line and for the next item (review of 3085e1d5c55) -------------

#: A secret whose base64 carries exactly one ``=`` of padding: 17 bytes make 24 characters.
_ONE_PAD = base64.b64encode(b"synthetic-tok-017").decode()
_KEY_RUN = "A" * 43
_RUNS_ON = "runs on into the strings after it in the same registry value"


def test_the_one_pad_stand_in_has_one_padding_character() -> None:
    assert _ONE_PAD.endswith("=") and not _ONE_PAD.endswith("==")
    assert not serviceenv._holds_key_run(_ONE_PAD)


@pytest.mark.parametrize("name", ["MEFOR_STORE_PASSWORD", "MEFOR_AUTH_OIDC_CLIENT_SECRET"])
def test_a_one_padded_secret_split_into_the_next_item_refuses(name: str) -> None:
    """Its text reads as ``NAME=`` with an empty value. Below the name in one string that line
    already continued the value; as the next item it now does too."""
    one_string = _read([f"MEFOR_AI_ENVIRONMENT=prod\n{name}=\n{_ONE_PAD}"])
    assert one_string.listed_directory_names == (name,)
    split = _read([f"{name}=", _ONE_PAD])
    assert split.listed_directory_names == (name,)
    assert service_env_refusal(split) is not None


#: Items, each read as the next item below an empty store key and as the lines below it in one
#: string. None has a first line of the shapes the readings differ on.
_FOLLOWERS = (
    _ONE_PAD,
    base64.b64encode(b"synthetic-tok-16").decode(),  # two ``=`` of padding
    "PATH=",  # a name of base64 letters alone, set to nothing
    "X= =",
    "mefor_value_synthetic",  # no equals sign, so no name starts it
    f"{_KEY_RUN}=x",
    f"{_KEY_RUN},x\nPATH=C:\\x",
    "foo",
    "foo\nPATH=C:\\x",
    "\n-----BEGIN " + "PRIVATE KEY-----",
    "PATH=C:\\x",
    "ProgramFiles(x86)=C:\\x",
    "MEFOR_AI_ENVIRONMENT=prod",
    "A" * 42 + "_B=1",
    "MEFOR_VALUE_B=1",
    "foo\nMEFOR_VALUE_B=1",
)


@pytest.mark.parametrize("follower", _FOLLOWERS)
def test_the_next_item_is_read_as_the_same_lines_below_the_key_in_one_string(
    follower: str,
) -> None:
    """The prefix line keeps the whole-string reading of the one string off the key, so only the
    line rule decides there, as it does for the joined items."""
    one_string = _read([f"MEFOR_AI_ENVIRONMENT=prod\n{KEY_CLASS_NAMES[0]}=\n{follower}"])
    split = _read([f"{KEY_CLASS_NAMES[0]}=", follower])
    assert split.listed == one_string.listed, follower
    assert split.empty_value_names == one_string.empty_value_names, follower
    assert split.unplain_value_names == one_string.unplain_value_names, follower


@pytest.mark.parametrize(
    "item", ["=C:=C:\\x", "MEFOR_SECRETS_DIRECTORY=", "HTTP_PROXY=", "ProgramFiles(x86)= ="]
)
def test_the_first_line_shapes_the_readings_differ_on(item: str) -> None:
    """Below the key in one string each line belongs to the key's value, so it refuses; as the
    next item each ends the value above, since NSSM reads the item as its own variable and its
    name could not be key material."""
    key = KEY_CLASS_NAMES[0]
    assert _read([f"MEFOR_AI_ENVIRONMENT=prod\n{key}=\n{item}"]).listed_keys == (key,)
    assert _read([f"{key}=", item]).listed_keys == ()


def test_an_item_that_sets_the_secrets_directory_is_not_taken_into_the_value_above() -> None:
    posture = _read(["MEFOR_STORE_PASSWORD=", "MEFOR_SECRETS_DIRECTORY=\nC:\\s"])
    assert posture.listed == ("MEFOR_SECRETS_DIRECTORY",)
    assert "The service's lists set no" not in str(service_env_refusal(posture))


def test_a_key_shaped_item_with_an_ordinary_later_line_continues_the_empty_key() -> None:
    key = KEY_CLASS_NAMES[0]
    posture = _read([f"{key}=", f"{_KEY_RUN},x\nPATH=C:\\x"])
    assert posture.listed_keys == (key,)
    assert service_env_refusal(posture) is not None


# --- the runs-on remedy step follows only the variable that ran on -------------------------------


@pytest.mark.parametrize("value", ["x", ""])
def test_no_runs_on_step_when_the_variable_that_ran_on_is_not_refused(value: str) -> None:
    """The path-form OIDC key runs on into a path, which is not a secret, so only the
    ``MEFOR_VALUE_A`` above it refuses, and its value did not run on, empty or not."""
    entries = [f"MEFOR_VALUE_A={value}\nMEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=", "C:\\k.pem"]
    posture = _read(entries)
    assert posture.listed == ("MEFOR_VALUE_A",)
    assert not posture.value_runs_on
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert _RUNS_ON not in refusal


def test_a_broken_value_name_whose_value_is_the_next_item_says_to_remove_it() -> None:
    """``MEFOR_VALUE_A<LF>X=`` is one variable under the whole-string reading, empty in its own
    string, so the next item is its value and the step says to remove that item too."""
    posture = _read(["MEFOR_VALUE_A\nX=", "synthetic"])
    assert posture.listed_value_names == ("MEFOR_VALUE_A",)
    assert posture.empty_value_names == ()
    assert posture.value_runs_on
    assert _RUNS_ON in str(service_env_refusal(posture))


def test_a_broken_name_is_not_counted_away_by_a_name_in_the_next_item() -> None:
    """Read alone the first item counts ``MEFOR_VALUE_A``; joined, a name the next item sets
    does not describe the same variable, so it is still counted, and its value ran on."""
    posture = _read(["MEFOR_VALUE_A\nX=", "foo\nMEFOR_VALUE_B=1"])
    assert posture.listed_value_names == ("MEFOR_VALUE_A", "MEFOR_VALUE_B")
    assert posture.value_runs_on


def test_a_string_ending_in_a_lone_carriage_return_keeps_the_next_items_line_numbers() -> None:
    posture = _read(["MEFOR_VALUE_A=\r", "abc\nq\nMEFOR_STORE_PASSWORD=x"])
    assert dict(posture.source_lines) == {"MEFOR_STORE_PASSWORD": 3}
