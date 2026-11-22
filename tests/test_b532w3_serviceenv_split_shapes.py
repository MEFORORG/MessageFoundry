# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Split secrets that the service-environment reader let through (vault BACKLOG #5394, added
items 6 and 12).

A secret split from its empty secret-class name, into the next ``REG_MULTI_SZ`` item or onto a
later line of one string below another variable, refuses unless the line below the name is
one of the few shapes ``serviceenv._ends_blank_class`` names: the reader fails closed. The
controls are those shapes, and the ``MEFOR_VALUE_*`` and secrets-directory values, which keep
the plain line rule so their remedy text stays true. Each test drives
:func:`messagefoundry.serviceenv.read_service_env_posture` through a probe, so every one runs on
every platform. Synthetic values only: the stand-ins decode to synthetic text, never a real key.
"""

from __future__ import annotations

import base64
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
from tests._serviceenv_remedy import NO_DIRECTORY

_EXTRA = "Parameters\\AppEnvironmentExtra"

#: A store-key-sized base64url stand-in: 32 bytes, so 43 characters and one ``=``, with ``-`` and
#: ``_`` in it, so it is outside the standard alphabet and holds no standard 43-character run.
_URL_KEY = base64.urlsafe_b64encode(b"\xfb\xffsynthetic-store-key-0123456789").decode()
#: A short base64url stand-in with one ``=`` of padding.
_URL_SHORT = base64.urlsafe_b64encode(b"\xfb\xffsynthetic").decode()
#: A store-key-sized standard base64 stand-in with one ``=`` of padding.
_STD_KEY = base64.b64encode(b"synthetic-store-key-0123456789ab").decode()

#: The split shapes item 12 names, at least: one-``=`` base64url, quoted, comma-trailed and
#: ``=``-led, each with a store-key-sized and a short body where the shape allows one.
_SHAPES = {
    "one-pad url key": _URL_KEY,
    "one-pad url short": _URL_SHORT,
    "double-quoted url key": f'"{_URL_KEY}"',
    "double-quoted std key": f'"{_STD_KEY}"',
    "single-quoted url key": f"'{_URL_KEY}'",
    "double-quoted url short": f'"{_URL_SHORT}"',
    "comma-trailed url key": f"{_URL_KEY},",
    "comma-trailed std key": f"{_STD_KEY},",
    "comma-trailed std two-pad": base64.b64encode(b"synthetic-tok-16").decode() + ",",
    "retired-keys list url": f"{_URL_KEY},{_URL_KEY}",
    "retired-keys list std": f"{_STD_KEY},{_STD_KEY}",
    "comma-trailed url short": f"{_URL_SHORT},",
    "equals-led url key": f"={_URL_KEY}",
    "equals-led std key": f"={_STD_KEY}",
    "equals-led short": "=AbCdEf",
    "double-equals-led url key": f"=={_URL_KEY}",
}


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


def test_the_stand_ins_have_the_shapes_they_stand_for() -> None:
    assert len(_URL_KEY) == 44 and _URL_KEY.endswith("=") and not _URL_KEY.endswith("==")
    assert "-" in _URL_KEY and "_" in _URL_KEY
    # No store-key-sized run of the standard alphabet in it; since BACKLOG #5394 items 6 and 12
    # read a whole base64url secret as key material too, ``_holds_key_run`` reads it as one, which
    # only refuses more.
    assert serviceenv._KEY_SHAPED_RUN.search(_URL_KEY) is None
    assert serviceenv._holds_key_run(_URL_KEY)
    assert _URL_SHORT.endswith("=") and not _URL_SHORT.endswith("==") and "-" in _URL_SHORT
    assert len(_STD_KEY) == 44 and _STD_KEY.endswith("=") and not _STD_KEY.endswith("==")


@pytest.mark.parametrize("shape", sorted(_SHAPES))
@pytest.mark.parametrize("name", [KEY_CLASS_NAMES[0], "MEFOR_AUTH_OIDC_CLIENT_SECRET"])
def test_a_split_secret_in_the_next_item_refuses(name: str, shape: str) -> None:
    """``nssm set`` writes each argument as its own string, so a secret split from its name lands
    in the next item. On origin/main 9421dcbf27 most shapes here ended the empty value above it,
    the ``=``-led standard key among them; the quoted and comma-trailed standard keys already
    refused through the key-run rule, and stay as pins."""
    posture = _read([f"{name}=", _SHAPES[shape]])
    assert posture.listed == (name,), shape
    assert posture.value_runs_on, shape
    assert service_env_refusal(posture) is not None


@pytest.mark.parametrize("shape", sorted(_SHAPES))
@pytest.mark.parametrize("name", [KEY_CLASS_NAMES[0], "MEFOR_AUTH_OIDC_CLIENT_SECRET"])
def test_a_split_secret_in_the_next_item_below_another_variable_refuses(
    name: str, shape: str
) -> None:
    """The empty name on a later line of its own item, so only the line reading can keep it."""
    posture = _read([f"MEFOR_AI_ENVIRONMENT=prod\n{name}=", _SHAPES[shape]])
    assert posture.listed == (name,), shape
    assert service_env_refusal(posture) is not None


@pytest.mark.parametrize("shape", sorted(_SHAPES))
@pytest.mark.parametrize("name", [KEY_CLASS_NAMES[0], "MEFOR_AUTH_OIDC_CLIENT_SECRET"])
def test_a_split_secret_on_a_later_line_below_another_variable_refuses(
    name: str, shape: str
) -> None:
    """One string, the empty name below another variable, so the whole-string reading names the
    other variable and only the line reading can keep the secret's name."""
    posture = _read([f"MEFOR_AI_ENVIRONMENT=prod\n{name}=\n{_SHAPES[shape]}"])
    assert posture.listed == (name,), shape
    assert service_env_refusal(posture) is not None


#: Items and lines that still end an empty secret-class value above them: a variable Windows
#: itself sets, spelled exactly as Windows spells it, and the secrets directory in upper case.
#: Windows' own nameless entries no longer do: see ``_WINDOWS_NAMELESS`` below.
_ORDINARY_ITEMS = (
    "ProgramFiles(x86)=C:\\x",
    "CommonProgramFiles(x86)=C:\\x",
    "Path=C:\\x",
    "Path=,C:\\x",
    "SystemRoot=C:\\Windows",
    "windir=C:\\Windows",
    "TEMP=C:\\t",
    "PUBLIC=C:\\Users\\Public",
    "NUMBER_OF_PROCESSORS=8",
    "MEFOR_SECRETS_DIRECTORY=C:\\s",
)

#: Windows' own nameless entries, spelled as Windows spells them. Below an empty secret-class value
#: on a later line of one string, origin/main 9421dcbf27 read each as that value, and so refused;
#: the reader must refuse every shape origin/main refused, so they refuse as items too, and the
#: two readings still agree.
_WINDOWS_NAMELESS = (
    "=C:=C:\\x",
    "=::=::\\",
    "=ExitCode=00000000",
    "=ExitCode=0",
    "=ExitCodeAscii=A",
)


@pytest.mark.parametrize("item", _ORDINARY_ITEMS)
def test_an_ordinary_item_still_ends_the_empty_value_above_it(item: str) -> None:
    """As the next item and as a later line of one string alike."""
    for posture in (
        _read([f"{KEY_CLASS_NAMES[0]}=", item]),
        _read([f"MEFOR_AI_ENVIRONMENT=prod\n{KEY_CLASS_NAMES[0]}=\n{item}"]),
    ):
        assert posture.listed_keys == (), item
        assert service_env_refusal(posture) is None, item


#: Lines below an empty secret-class value that are not positively a variable of their own, so
#: the reader cannot tell them from the secret and fails closed. Typographic quotes are written as
#: escapes, so this file holds no glyph. Among them: conventionally spelled names, a ``MEFOR_``
#: name that is no secret, names without an underscore that Windows does not set, such as ``TZ``
#: and ``HOME``, Windows' names in another case, such as ``Public`` and ``PATH``, a long s that
#: ``str.upper`` folds onto ``SYSTEMROOT``, a name led by a blank, and equals-led text that is not
#: one of Windows' own nameless entries, such as ``=orphan``, ``=letmein`` and a bare ``=``.
_FAIL_CLOSED = (
    "x=y",
    "Winter=2026!",
    "Http_Proxy=",
    "Http_Proxy=x",
    "HTTP_PROXY=",
    "HTTP_PROXY=x",
    "NO_PROXY=,localhost",
    "no_proxy=\t",
    "A" * 42 + "_B=1",
    "MEFOR_AI_ENVIRONMENT=prod",
    "MEFOR_SECRETS_DIRECTORY=",
    "Mefor_Secrets_Directory=C:\\s",
    "TZ=UTC",
    "HOME=C:\\x",
    "PYTHONUTF8=1",
    "ProgramFile=C:\\x",
    "Public=Summer!",
    "Temp=Summer!",
    "Os=Summer!",
    "username=bob",
    "PATH=C:\\x",
    "PATH=,C:\\x",
    "\u017fystemroot=x",
    " Path=C:\\x",
    "Path=",
    "\u201cabc\u201d=x",
    "\u2018abc\u2019=x",
    "`abc`=x",
    "abc`=x",
    "p@ss=word",
    "=abc123",
    "=AbCdEf",
    "=orphan",
    "=letmein",
    "=PASSWORD",
    "=exitcode=0",
    "=c:=c:\\x",
    "=",
    *_WINDOWS_NAMELESS,
)


@pytest.mark.parametrize("line", _WINDOWS_NAMELESS)
@pytest.mark.parametrize("prefix", ["PATH=C:\\x", "MEFOR_SECRETS_DIRECTORY=C:\\s", "HTTP_PROXY="])
@pytest.mark.parametrize("name", [KEY_CLASS_NAMES[0], "MEFOR_STORE_PASSWORD"])
def test_an_empty_secret_on_a_later_line_above_a_windows_nameless_entry_refuses(
    name: str, prefix: str, line: str
) -> None:
    """The 172 shapes the round-2 differential found that origin/main 9421dcbf27 refused and
    round 2 let through: an empty secret-class value on a later line of one string, above one of
    Windows' own nameless entries. Failed on b532w3-serviceenv-r2 fc3ebdef6c9."""
    posture = _read([f"{prefix}\n{name}=\n{line}"])
    assert name in posture.listed, line
    assert service_env_refusal(posture) is not None


@pytest.mark.parametrize("line", _FAIL_CLOSED)
@pytest.mark.parametrize("name", [KEY_CLASS_NAMES[0], "MEFOR_AUTH_AD_BIND_PASSWORD"])
def test_a_line_that_may_be_the_secret_refuses_as_an_item_and_on_a_later_line(
    name: str, line: str
) -> None:
    """``Winter=2026!`` below the bind password once escaped. Each reading refuses, and the two
    read the same."""
    items = _read([f"{name}=", line])
    later = _read([f"Path=x\n{name}=\n{line}"])
    assert items.listed == later.listed == (name,), line
    assert items.value_runs_on, line
    assert service_env_refusal(items) is not None
    assert service_env_refusal(later) is not None


@pytest.mark.parametrize("line", ["TZ=UTC", "HTTP_PROXY=x", "MEFOR_AI_ENVIRONMENT=prod"])
def test_an_ordinary_line_below_a_non_secret_value_still_ends_it(line: str) -> None:
    """The control for the fail-closed rows above: below an empty value that is not a secret,
    here the secrets directory's, the plain line rule still ends it, so the directory reads as
    unset. Read under the fail-closed rule, the line would set the directory instead."""
    posture = _read([f"MEFOR_SECRETS_DIRECTORY=\n{line}", "MEFOR_VALUE_A=1"])
    assert posture.listed == ("MEFOR_VALUE_A",), line


@pytest.mark.parametrize(
    "items",
    [
        ["MEFOR_AUTH_AD_BIND_PASSWORD", "=Winter2026"],
        ["MEFOR_AUTH_AD_BIND_PASSWORD", "=", "Winter2026"],
        ["MEFOR_AUTH_AD_BIND_PASSWORD=", "=", "Winter2026"],
        ["MEFOR_AUTH_AD_BIND_PASSWORD ", "Winter=2026!"],
        ["MEFOR_AUTH_AD_BIND_PASSWORD\nWinter=2026!"],
        ["Path=x\nMEFOR_AUTH_AD_BIND_PASSWORD\n=Winter2026"],
        ["junk\nMEFOR_AUTH_AD_BIND_PASSWORD\n=Winter2026"],
        ["MEFOR_AUTH_AD_BIND_PASSWORD\n=", "Winter2026"],
        ["Path=x\nMEFOR_AUTH_AD_BIND_PASSWORD", "=Winter2026"],
        ["MEFOR_AUTH_AD_BIND_PASSWORD=\n=\nWinter=2026!"],
        ["Path=x", "MEFOR_AUTH_AD_BIND_PASSWORD", "=Winter2026"],
    ],
)
def test_a_name_written_alone_above_its_value_refuses(items: list[str]) -> None:
    """``nssm set <svc> AppEnvironmentExtra NAME =value`` writes the name as an item of its own,
    with no equals sign, and the value led by one in the next item; ``NAME = value`` puts a bare
    ``=`` between them. A secret-class name alone is read as that name set to nothing so far, so
    the value below it refuses, and the remedy names every item it ran on into."""
    posture = _read(items)
    assert posture.listed == ("MEFOR_AUTH_AD_BIND_PASSWORD",), items
    refusal = service_env_refusal(posture)
    assert refusal is not None
    if len(items) > 1:
        assert posture.value_runs_on, items


def test_a_name_alone_below_an_empty_secret_is_read_into_its_value() -> None:
    """A secret-class name alone below an empty secret-class value is that value's text, as it
    was on origin/main 9421dcbf27, so the empty key above still refuses. Below a first line that
    starts no variable it is not kept either, so the whole-string reading still names the
    ``MEFOR_VALUE_*`` variable above it."""
    key = KEY_CLASS_NAMES[0]
    assert _read([f"Path=x\n{key}=\nMEFOR_STORE_PASSWORD"]).listed == (key,)
    assert _read(["MEFOR_VALUE_A\nMEFOR_STORE_PASSWORD\nX=1"]).listed == ("MEFOR_VALUE_A",)


def test_a_name_written_alone_with_nothing_below_it_does_not_refuse() -> None:
    """The control: a secret-class name alone carries no value, so it is not listed."""
    assert _read(["MEFOR_AUTH_AD_BIND_PASSWORD"]).listed == ()
    assert _read(["MEFOR_AUTH_AD_BIND_PASSWORD", "Path=C:\\x"]).listed == ()


def test_a_long_name_below_an_empty_secret_reads_in_linear_time() -> None:
    """The name rule once backtracked quadratically, about 0.13 s for one name of 8,000
    characters, so the three 32,000-character items below took about 6 s together. Read
    linearly, they take milliseconds. The bound counts this process's CPU time, not the wall
    clock, so other pytest-xdist workers on a busy runner do not inflate it, and at 2 s it is
    generous for the linear reading while still under the quadratic one."""
    import time

    long_items = ["_" * 32_000 + "a=x", "A" * 32_000 + "a=x", "a_" * 16_000 + "!=x"]
    started = time.process_time()
    for item in long_items:
        posture = _read([f"{KEY_CLASS_NAMES[0]}=", item])
        assert posture.listed_keys == (KEY_CLASS_NAMES[0],)
    assert time.process_time() - started < 2.0


def test_an_empty_secret_kept_on_a_later_line_reads_the_line_below_it_too() -> None:
    """The fail-closed rule follows a kept variable, not only a string's first line."""
    name = "MEFOR_STORE_PASSWORD"
    posture = _read([f"PATH=x\n{KEY_CLASS_NAMES[0]}=\n{name}=\nWinter=2026!"])
    assert posture.listed == (name,)


def test_an_ordinary_comma_led_value_on_a_later_line_is_still_its_own_variable() -> None:
    """A conventional name with a comma-led value still ends the empty directory above it, which
    then reads as unset."""
    posture = _read(["MEFOR_SECRETS_DIRECTORY=\nNO_PROXY=,localhost", "MEFOR_VALUE_A=1"])
    assert posture.listed == ("MEFOR_VALUE_A",)
    refusal = service_env_refusal(posture)
    assert refusal is not None and NO_DIRECTORY in refusal


@pytest.mark.parametrize("line", ['"x"=y', "PATH=,C:\\x", "Http_Proxy=,x", "\u201cx\u201d=y"])
def test_an_empty_directory_above_an_ordinary_line_still_reads_as_unset(line: str) -> None:
    """A regression an earlier repair of this item made: the directory's name is no secret, so
    a later line ends its empty value under the plain line rule, and the remedy still
    says no entry names the directory."""
    posture = _read([f"MEFOR_SECRETS_DIRECTORY=\n{line}", "MEFOR_VALUE_A=1"])
    assert posture.listed == ("MEFOR_VALUE_A",), line
    refusal = service_env_refusal(posture)
    assert refusal is not None and NO_DIRECTORY in refusal, line


@pytest.mark.parametrize("item", ["Http_Proxy=", "=ExitCode=0", "=abc123", "ab-c_dE="])
def test_an_empty_value_name_does_not_take_the_next_item(item: str) -> None:
    """A regression an earlier repair of this item made: an empty ``MEFOR_VALUE_*``
    name refuses whatever it holds, so the next item keeps the plain rule, the empty entry is
    still named, and the remedy does not say to remove the item."""
    posture = _read(["MEFOR_VALUE_X=", item])
    assert posture.listed == ("MEFOR_VALUE_X",), item
    assert posture.empty_value_names == ("MEFOR_VALUE_X",), item
    assert not posture.value_runs_on, item
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert "An empty or blank MEFOR_VALUE_* entry is refused too" in refusal
    assert "runs on into" not in refusal


def test_a_hex_secret_led_by_an_equals_sign_in_the_next_item_refuses() -> None:
    """Lower-case hex, as ``openssl rand -hex`` mints, is of one case but holds digits."""
    name = "MEFOR_AUTH_OIDC_CLIENT_SECRET"
    assert _read([f"{name}=", "=deadbeefcafebabe0123456789abcdef"]).listed == (name,)


def test_an_empty_key_on_its_strings_first_line_above_an_ordinary_line_refuses() -> None:
    """The control for the item 6 pin below: on the string's first line the whole-string reading
    keeps the key, so it refuses."""
    key = KEY_CLASS_NAMES[0]
    assert _read([f"{key}=\nx=y"]).listed_keys == (key,)


def test_a_later_empty_secret_above_an_ordinary_line_refuses() -> None:
    """Added item 6: the same empty key below another variable refuses too, as one string and as
    items, since the reader cannot tell whether ``x=y`` is the key. Failed on origin/main
    9421dcbf27."""
    key = KEY_CLASS_NAMES[0]
    assert _read([f"PATH=x\n{key}=\nx=y"]).listed_keys == (key,)
    assert _read([f"PATH=x\n{key}=", "x=y"]).listed_keys == (key,)
    assert _read([f"{key}=", "x=y"]).listed_keys == (key,)


# --- round 3: findings 1, 2, 5 and 6 of the round-2 report -------------------------------------

_PEM = "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY"


@pytest.mark.parametrize(
    "items",
    [
        [f"{_PEM}=", "MEFOR_STORE_PASSWORD", "=hunter2"],
        [f"{_PEM}=\nMEFOR_STORE_PASSWORD\n=hunter2"],
        [f"{_PEM}= ", "MEFOR_AUTH_AD_BIND_PASSWORD", "=", "hunter2"],
        [f"{_PEM}=", "C:\\k.pem"],
    ],
)
def test_an_empty_pem_key_does_not_hide_what_it_runs_on_into(items: list[str]) -> None:
    """Finding 1: a key that takes either PEM or a path was exempted as a path by the text it ran
    on into, so a password split from its name below it escaped. The exemption now judges only the
    key's own line, which is blank here, so the key refuses. Failed on fc3ebdef6c9."""
    posture = _read(items)
    assert _PEM in posture.listed, items
    assert service_env_refusal(posture) is not None


def test_a_pem_key_set_to_a_path_on_its_own_line_is_still_a_path() -> None:
    """The control for the pins above: a path on the key's own line is no secret."""
    assert _read([f"{_PEM}=C:\\k.pem"]).listed == ()
    assert _read([f"{_PEM}=C:\\k.pem\nPath=C:\\x"]).listed == ()
    assert _read([f"{_PEM}=C:\\k.pem", "Path=C:\\x"]).listed == ()


@pytest.mark.parametrize(
    "items",
    [
        ["MEFOR_VALUE_X", "=abc"],
        ["MEFOR_VALUE_X", "Winter=2026!"],
        ["MEFOR_VALUE_X", "=", "abc"],
        ["Path=x\nMEFOR_VALUE_X\n=abc"],
        ["Path=x", "MEFOR_VALUE_X", "=abc"],
    ],
)
def test_a_value_name_written_alone_above_its_value_refuses(items: list[str]) -> None:
    """Finding 2: ``nssm set ... MEFOR_VALUE_X =abc`` writes the name as an item of its own and
    the value as the next. The name alone is read as set to nothing so far, under the fail-closed
    rule a secret-class name alone is read under, so the value below it refuses, and the remedy
    names the items it ran on into. Failed on fc3ebdef6c9."""
    posture = _read(items)
    assert posture.listed == ("MEFOR_VALUE_X",), items
    assert service_env_refusal(posture) is not None
    if len(items) > 1:
        assert posture.value_runs_on, items


def test_a_value_name_written_alone_with_nothing_below_it_does_not_refuse() -> None:
    """The control, as ``tests/test_service_env_secrets.py`` pins it: an entry with no ``=`` and
    no value read into it sets no variable."""
    for items in (["MEFOR_VALUE_X"], ["MEFOR_VALUE_X", "Path=C:\\x"]):
        posture = _read(items)
        assert posture.listed == (), items
        assert posture.empty_value_names == posture.unplain_value_names == (), items


@pytest.mark.parametrize("name", ["MEFOR_STORE_PASSWORD", _PEM])
def test_a_value_of_equals_signs_alone_refuses(name: str) -> None:
    """Finding 5: equals signs alone are read on the side that refuses. A secret-class value of
    ``=`` is set, so it refuses alone; for the PEM-or-path key it is no path either, so that key
    refuses too. The PEM case failed on fc3ebdef6c9."""
    for items in ([f"{name}=="], [f"{name}==", "Path=C:\\x"]):
        posture = _read(items)
        assert posture.listed == (name,), items
        assert service_env_refusal(posture) is not None


@pytest.mark.parametrize("item", ["abc==", "QUJD==", "MEFOR_STORE_PASSWORD"])
def test_a_value_name_set_to_equals_signs_does_not_run_on(item: str) -> None:
    """Finding 6: ``MEFOR_VALUE_X==`` sets the value ``=``, which refuses whatever it holds, so the
    next item is its own, as on origin/main 9421dcbf27, and the remedy does not say to remove it.
    Failed on fc3ebdef6c9."""
    posture = _read(["MEFOR_VALUE_X==", item])
    assert posture.listed == ("MEFOR_VALUE_X",), item
    assert not posture.value_runs_on, item


def test_an_empty_value_name_still_runs_on_into_a_key_like_item() -> None:
    """The control: ``MEFOR_VALUE_X=`` with nothing after it runs on as on origin/main."""
    assert _read(["MEFOR_VALUE_X=", "abc=="]).value_runs_on


def test_a_value_name_alone_joined_to_the_next_item_is_not_taken_as_misspelled() -> None:
    """Round-3 review finding 1: the join puts a line break into the whole-string name, but NSSM
    reads the name's own item alone, so the remedy must not say to rename the key."""
    for items in (["MEFOR_VALUE_X", "Winter=2026!"], ["MEFOR_VALUE_X", "HTTP_PROXY=x"]):
        posture = _read(items)
        assert posture.listed == ("MEFOR_VALUE_X",), items
        assert posture.unplain_value_names == (), items
        assert posture.empty_value_names == (), items


@pytest.mark.parametrize(
    "items",
    [
        ["MEFOR_STORE_PASSWORD=", "mefor_auth_oidc_client_private_key=C:\\k.pem"],
        ["MEFOR_STORE_PASSWORD=", "Mefor_Auth_Oidc_Client_Private_Key=Summer!"],
        ["Path=x\nMEFOR_STORE_PASSWORD=\nmefor_auth_oidc_client_private_key=x"],
    ],
)
def test_a_mixed_case_refused_name_below_an_empty_secret_is_its_value(items: list[str]) -> None:
    """Round-3 review finding 4: below an empty secret-class value, only an upper-case refused
    name starts a variable of its own. Read as the path-form OIDC key, mixed-case secret text was
    dropped, and the empty password above it with it, so nothing refused."""
    posture = _read(items)
    assert "MEFOR_STORE_PASSWORD" in posture.listed, items
    assert service_env_refusal(posture) is not None


def test_an_upper_case_path_form_key_still_ends_an_empty_secret() -> None:
    """The control: the engine's own name in upper case is a variable of its own, a path."""
    posture = _read(["MEFOR_STORE_PASSWORD=", f"{_PEM}=C:\\k.pem"])
    assert posture.listed == ()


def test_a_secret_name_alone_in_a_later_item_below_a_value_name_alone_is_kept() -> None:
    """Round-3 review finding 6: once joined, the whole-string reading names the
    ``MEFOR_VALUE_*`` name, but NSSM reads the store key's item as its own, so the key is still
    listed and the remedy keeps its key-file step."""
    posture = _read(["MEFOR_VALUE_X", KEY_CLASS_NAMES[0], "=QUJDREVG"])
    assert posture.listed_keys == (KEY_CLASS_NAMES[0],)
    refusal = service_env_refusal(posture)
    assert refusal is not None and "DPAPI-protected key file" in refusal


def test_a_secret_set_to_equals_signs_on_its_own_line_does_not_run_on() -> None:
    """Round-3 review round 2, finding 2: ``NAME==`` sets ``=`` in its own string, so it refuses
    as set, and the remedy does not say its value runs on into the next item. ``NAME<LF>=`` is the
    gap ``nssm set ... NAME = value`` leaves, and still runs on: the control."""
    posture = _read(["MEFOR_STORE_PASSWORD==", "TZ=UTC"])
    assert posture.listed == ("MEFOR_STORE_PASSWORD",)
    assert not posture.value_runs_on
    assert _read(["MEFOR_STORE_PASSWORD\n=", "Winter2026"]).value_runs_on


def test_a_lower_case_secret_name_below_an_empty_key_is_still_named() -> None:
    """Round-3 review round 2, finding 3: the upper-case rule below an empty secret value covers
    only the path-form key's name. Any other refused name in any case is its own variable, as
    Windows compares names, so the refusal names it and gives its own remedy."""
    posture = _read([f"{KEY_CLASS_NAMES[0]}=", "mefor_store_password=hunter2"])
    assert posture.listed == ("MEFOR_STORE_PASSWORD",)
