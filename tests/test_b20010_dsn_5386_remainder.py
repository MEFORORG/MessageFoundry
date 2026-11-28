# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5386's remainder (batch 20010): the DSN password shapes, read through public entry
points only.

Synthetic values only. This file imports no private name, so it collects and runs on the code
before each pull request that built part of the row, and each group below names the first-parent
commit it fails on. A test file a pull request added could not show that: each reads a private
name the same pull request adds, so on its parent it fails to collect rather than failing on the
shape. The groups:

* ``_ROW_SHAPES``, the row's own two claims, an empty user and a password holding an unencoded
  "@", fail on ``0198c09b6cb``, the parent of engine PR 3019.
* ``_PERCENT_SHAPES``, added item 3's "%", fail on ``c4a75b6d489``, the parent of engine PR 3127.
* ``_WAVE3_SHAPES``, added item 3's "[" and "]", a user holding one "@" and a password's leading
  "@", fail on ``175a588a137``, the parent of engine PR 3134.
* ``_ITEM4_SHAPES``, added item 4's ";" tail after a user's placeholder, fail on ``95845c9d306``,
  the parent of engine PR 3142.
* ``_THIS_CHANGE_SHAPES`` fail on ``4ad697da713``, the ``origin/main`` this change was built on: a
  user holding two "@", a password after ``user@host:`` that opens with "@", and the JDBC no-user
  member tail. The comments on ``secretscrub._WIDE_DSN_PASSWORD`` and ``_DSN_MEMBER_TAIL`` say how
  each is read, and what each leaves.

Each later group's shapes are hidden on every later commit, so a group fails on its own parent and
every commit before it that the shape printed on, and passes from its merge on.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from messagefoundry.logging_setup import scrub_log_text
from messagefoundry.secretscrub import scrub_credentials
from messagefoundry.support.redact import redact_log_line


def _chain_then_bundle(line: str) -> str:
    return redact_log_line(scrub_log_text(line))


_ENTRY_POINTS: tuple[Callable[[str], str], ...] = (
    scrub_credentials,
    scrub_log_text,
    redact_log_line,
    _chain_then_bundle,
)
_IDS = ("scrub_credentials", "write-time chain", "redact_log_line", "chain then bundle")

#: Each line, the pieces of its secret that must not print, and text that must survive so an
#: operator can still tell which store it was.
_Shape = tuple[str, tuple[str, ...], str]

_ROW_SHAPES: tuple[_Shape, ...] = (
    ("connect postgres://:Kv9Sec@db.example.invalid/x failed", ("Kv9Sec",), "postgres://:"),
    ("connect redis://:Kv9xZq7w@cache.invalid failed", ("Kv9xZq7w",), "@cache.invalid failed"),
    (
        "connect postgres://svc:p@ss_Kv9@db.example.invalid/x failed",
        ("ss_Kv9",),
        "postgres://svc:",
    ),
    ("connect redis://:p@ss_Kv9@db.example.invalid failed", ("ss_Kv9",), "redis://:"),
)
_PERCENT_SHAPES: tuple[_Shape, ...] = (
    ("connect redis://:p%40Kv9x@db.invalid failed", ("Kv9x",), "redis://:"),
    ("connect redis://:Kv9x%25Zq7@db.invalid failed", ("Kv9x", "Zq7"), "redis://:"),
)
_WAVE3_SHAPES: tuple[_Shape, ...] = (
    ("connect redis://:p[Kv9x]@db.invalid failed", ("Kv9x",), "redis://:"),
    ("connect redis://:Kv9x]Zq7@db.invalid failed", ("Kv9x", "Zq7"), "redis://:"),
    (
        "connect postgres://ops@srv:Kv9_Az@srv.example.invalid/x failed",
        ("Kv9_Az",),
        "://ops@srv:",
    ),
    ("store dsn postgres://svc:@Lead_At-74@db.invalid/m", ("Lead_At-74",), "://svc:@"),
)
_ITEM4_SHAPES: tuple[_Shape, ...] = (
    (
        "connect postgres://svc:Kv9x@Zq7;w@db.example.invalid/x failed",
        ("Kv9x", "Zq7"),
        "@db.example.invalid/x failed",
    ),
    ("connect postgres://svc:Kv9x@Zq7;w;Mx4@db failed", ("Kv9x", "Zq7", "Mx4"), "@db failed"),
)
_THIS_CHANGE_SHAPES: tuple[_Shape, ...] = (
    # A user holding two "@": an e-mail login on a hosted database's user@server form.
    (
        "connect postgres://ops@corp.example@srv:Kv9Sec@srv.example.invalid/x failed",
        ("Kv9Sec",),
        "://ops@corp.example@srv:",
    ),
    ("postgres://a@b@srv:Kv9_Az@srv.example.invalid/x", ("Kv9_Az",), "://a@b@srv:"),
    # A password after user@host that opens with "@"; the "@" signs are kept, as after a plain user.
    ("x postgres://ops@srv:@Kv9x@db.invalid", ("Kv9x",), "://ops@srv:@"),
    ("x postgres://ops@srv:@@Kv9x_Lead@db.invalid", ("Kv9x_Lead",), "://ops@srv:@@"),
    # The JDBC no-user member tail: the narrow match took the member's key, and the tail printed.
    ("jdbc:sqlserver://db.invalid:1433;user=svc;sslpassword=P@ss_Sec9;", ("ss_Sec9",), "jdbc:"),
    ("jdbc:sqlserver://db.invalid:1433;dbpwd=Kv9@Zq7_Sec failed", ("Kv9", "Zq7_Sec"), " failed"),
    ("jdbc:sqlserver://db.invalid:1433;AccessToken=T@Zq7_Sec", ("Zq7_Sec",), "jdbc:"),
)

_GROUPS = (
    ("row", _ROW_SHAPES),
    ("percent", _PERCENT_SHAPES),
    ("wave3", _WAVE3_SHAPES),
    ("item4", _ITEM4_SHAPES),
    ("this", _THIS_CHANGE_SHAPES),
)
_ALL = [
    pytest.param(*shape, id=f"{prefix}-{i}")
    for prefix, group in _GROUPS
    for i, shape in enumerate(group)
]


@pytest.mark.parametrize("call", _ENTRY_POINTS, ids=_IDS)
@pytest.mark.parametrize(("line", "secrets", "kept"), _ALL)
def test_the_dsn_password_is_hidden_on_every_entry_point(
    line: str, secrets: tuple[str, ...], kept: str, call: Callable[[str], str]
) -> None:
    out = call(line)
    for secret in secrets:
        assert secret not in out, out
    assert kept in out, out


#: Lines with no password the new readings may take, each printing whole on every entry point: a
#: port after user@host, a user@host list with no password, a JDBC string with no "@", and a JDBC
#: member that names no credential.
#: Lines the JDBC member-tail pass reads, each with what the PHI surfaces must not print: the tail
#: is the first word of a name, which the PHI pass must still read as one with the next word. A
#: draft that deleted the tail printed ``Doe`` and ``JANE`` here (code review).
_NAME_AFTER_TAIL = (
    ("jdbc:sqlserver://db.invalid:1433;sslpassword=P@Jane Doe;", ("Jane", "Doe")),
    ("jdbc:sqlserver://db.invalid:1433;sslpassword=P@DOE JANE 19800102;", ("DOE", "JANE")),
)


@pytest.mark.parametrize("call", _ENTRY_POINTS[1:], ids=_IDS[1:])
@pytest.mark.parametrize(("line", "names"), _NAME_AFTER_TAIL)
def test_a_name_after_a_member_tail_stays_hidden_on_the_phi_surfaces(
    line: str, names: tuple[str, ...], call: Callable[[str], str]
) -> None:
    out = call(line)
    for name in names:
        assert name not in out, out


#: A member whose key does not END in a credential word is no key the member pass reads, so the
#: tail pass declines it and the host after the "@" stays as the narrow pass leaves it.
_NOT_A_KEY = (
    "jdbc:sqlserver://db.invalid:1433;passive=true;user=ops@corp.example;",
    "jdbc:sqlserver://db.invalid:1433;passport=x;user=ops@corp.example;",
)


@pytest.mark.parametrize("call", _ENTRY_POINTS, ids=_IDS)
@pytest.mark.parametrize("line", _NOT_A_KEY)
def test_a_member_whose_key_names_no_credential_keeps_the_host(
    line: str, call: Callable[[str], str]
) -> None:
    out = call(line)
    assert out.endswith("@corp.example;") and "ops" not in out, out


_PRINTS_WHOLE = (
    "connect http://user@host:8080,admin@corp.example failed",
    "connect postgres://ops@corp.example@srv:5432/x failed",
    "jdbc:sqlserver://db.invalid:1433;user=svc;database=d",
)


@pytest.mark.parametrize("call", _ENTRY_POINTS, ids=_IDS)
@pytest.mark.parametrize("line", _PRINTS_WHOLE)
def test_a_line_with_no_password_prints_whole(line: str, call: Callable[[str], str]) -> None:
    assert call(line) == line


#: KNOWN RESIDUALS of the JDBC member-tail reading, pinned as printed: a tail that ends at a
#: quote, a separator or a "/" rather than at a ";", whitespace or the end. A red means the
#: reading changed, and the comment on ``secretscrub._DSN_MEMBER_TAIL`` must change with it.
_MEMBER_TAIL_RESIDUALS = (
    ("url='jdbc:sqlserver://db.invalid:1433;sslpassword=P@ss_Sec9' refused", "ss_Sec9"),
    ("jdbc:sqlserver://db.invalid:1433;sslpassword=P@ss_Sec9|x", "ss_Sec9"),
    ("jdbc:sqlserver://db.invalid:1433;sslpassword=P@ss_Sec9/x", "ss_Sec9"),
)


@pytest.mark.parametrize("call", _ENTRY_POINTS, ids=_IDS)
@pytest.mark.parametrize(("line", "printed"), _MEMBER_TAIL_RESIDUALS)
def test_known_residual_a_member_tail_that_ends_at_a_quote_or_separator_prints(
    line: str, printed: str, call: Callable[[str], str]
) -> None:
    assert printed in call(line)


def test_known_residual_a_key_material_member_tail_prints_on_the_bundle_reading() -> None:
    """Pinned as printed: no word of the member pass names a key-material key, so the tail pass
    declines it, and the bundle's own reading prints the tail, as ``origin/main`` does. The
    write-time reading hides it through the camelCase key-material label."""
    line = "jdbc:sqlserver://db.invalid:1433;encryptionKey=P@ss_Sec9;"
    assert "ss_Sec9" in redact_log_line(line)
    assert "ss_Sec9" not in scrub_credentials(line)
