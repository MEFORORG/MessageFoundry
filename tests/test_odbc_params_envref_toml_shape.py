# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1806 -- the odbc_params env-ref refusal must see BOTH spellings of an env ref.

`_reject_envref_odbc_params` tested `isinstance(v, EnvRef)` and nothing else, which is only the
CODE-FIRST shape. A `connections.toml` `[settings.odbc_params]` inline table arrives as a RAW DICT,
because `parse_env_setting` decodes only top-level settings values and does not descend -- so that
raw dict reached the connector factory unrefused and stringified into the DSN with its fallback
value attached.

The TOML arms go through the REAL loader, and they cover BOTH odbc_params-taking transports, so the
claim that each is reachable from a TOML table is gated rather than asserted in prose: drop either
from the loader's transport table and an arm here goes red.

At least one further position exists: `odbc_params = { env = "..." }` names the whole table, which IS
a top-level settings value, so it decodes to an `EnvRef`, which has no `items()`; the resulting
`AttributeError` escaped the loader as a bare traceback. Its arms are below.

"At least", not a closed set. A marker ONE CONTAINER DEEP -- `env` plus an unrecognised key, or a
marker inside a list -- still reaches the DSN with its `default` attached. Closing that means
refusing every non-scalar odbc_params value, a wider rule than mirroring the decoder, and it is
deliberately NOT folded in here; the over-widening arms below pin the current boundary, so whoever
takes that on should expect to move them rather than read them as a false positive.

The "still passes" arms are over-widening controls: the predicate must not start refusing an
ordinary nested mapping that is not an env marker. The code-first `EnvRef` spelling already had its
factory-level pin at `tests/test_database_transport.py::test_database_odbc_params_reject_envref`;
this module pins it at the unit instead of restating that call.
"""

from __future__ import annotations

import inspect
import re
import textwrap
from pathlib import Path
from typing import Any, cast

import pytest

from messagefoundry.config.wiring import (
    Database,
    DatabasePoll,
    EnvRef,
    WiringError,
    _reject_envref_odbc_params,
    env,
    load_config,
)

# An inert, low-entropy fixture value standing in for a fallback secret. It is published in test
# source by construction (an arm below asserts it does NOT survive into the refusal message), so it
# is written as dictionary words to stay clear of the entropy rules rather than buy an allowlist
# entry in .gitleaks.toml.
FALLBACK_PROBE = "fallback-value-must-not-be-echoed"


def _database_kwargs(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "server": "db.example",
        "statement": "INSERT INTO t (a) VALUES (:a)",
        "dialect": "generic",
        "odbc_driver": "PostgreSQL Unicode",
    }
    base.update(over)
    return base


# --- the defect: the connections.toml raw-dict spelling --------------------------------------


#: One `connections.toml` per odbc_params-taking transport, each with a nested env marker. Both are
#: loaded through `load_config`, so the pair is what gates "every such transport is covered" --
#: `database` is an outbound write, `database_poll` an inbound source, and they take different
#: statement settings, which is why this is two documents rather than one parametrized string.
_TOML_ARMS: dict[str, str] = {
    "database": f"""
        [[outbound]]
        name = "OB_PG"
        transport = "database"

        [outbound.settings]
        server = "db.example"
        statement = "INSERT INTO t (a) VALUES (:a)"
        dialect = "generic"
        odbc_driver = "PostgreSQL Unicode"

        [outbound.settings.odbc_params]
        PORT = "5432"
        SSLmode = {{ env = "pg_sslmode", default = "{FALLBACK_PROBE}" }}
        """,
    "database_poll": f"""
        [[inbound]]
        name = "IB_PG"
        transport = "database_poll"
        router = "r"

        [inbound.settings]
        server = "db.example"
        poll_statement = "SELECT 1"
        dialect = "generic"
        odbc_driver = "PostgreSQL Unicode"

        [inbound.settings.odbc_params]
        PORT = "5432"
        SSLmode = {{ env = "pg_sslmode", default = "{FALLBACK_PROBE}" }}
        """,
}


@pytest.mark.parametrize("transport", sorted(_TOML_ARMS))
def test_a_toml_inline_env_table_in_odbc_params_is_refused(transport: str, tmp_path: Path) -> None:
    """The arm that was red before #1806. Goes through the REAL loader, not a hand-built dict."""
    (tmp_path / "connections.toml").write_text(
        textwrap.dedent(_TOML_ARMS[transport]), encoding="utf-8"
    )
    with pytest.raises(WiringError, match="may not use env"):
        load_config(tmp_path)


def test_every_odbc_params_taking_transport_has_a_toml_arm() -> None:
    """A coverage gate, so adding a third odbc_params-taking transport cannot ship untested here."""
    from messagefoundry.config.connections_file import _TRANSPORTS

    taking_odbc_params = {
        name
        for name, factory in _TRANSPORTS.items()
        if "odbc_params" in inspect.signature(factory).parameters
    }
    assert taking_odbc_params == set(_TOML_ARMS)


def test_the_toml_shape_is_refused_by_the_unit_too() -> None:
    """The same offender against the predicate directly, so a loader change cannot hide a regression."""
    with pytest.raises(WiringError, match="may not use env"):
        _reject_envref_odbc_params({"SSLmode": {"env": "pg_sslmode", "default": FALLBACK_PROBE}})


def test_a_toml_inline_env_table_with_no_default_is_refused() -> None:
    """`default` is optional in the marker; `env` alone is the minimal offending shape."""
    with pytest.raises(WiringError, match="may not use env"):
        _reject_envref_odbc_params({"SSLmode": {"env": "pg_sslmode"}})


def test_a_toml_inline_env_table_with_a_cast_is_refused() -> None:
    """`cast` is the third key `_ENVREF_KEYS` admits, so the marker still decodes with it present."""
    with pytest.raises(WiringError, match="may not use env"):
        _reject_envref_odbc_params({"Timeout": {"env": "pg_timeout", "cast": "int"}})


def test_database_refuses_the_toml_shape_at_the_factory() -> None:
    # The annotation says dict[str, str | EnvRef]; TOML carries no annotations, which is exactly how
    # this shape reaches the factory at runtime. The cast records that, it does not excuse it.
    params = cast("dict[str, str | EnvRef]", {"PORT": "5432", "SSLmode": {"env": "pg_sslmode"}})
    with pytest.raises(WiringError, match="may not use env"):
        Database(**_database_kwargs(odbc_params=params))


def test_database_poll_refuses_the_toml_shape_at_the_factory() -> None:
    """DatabasePoll calls the same guard; #1806 is not fixed if only the write factory is covered."""
    params = cast("dict[str, str | EnvRef]", {"SSLmode": {"env": "pg_sslmode"}})
    with pytest.raises(WiringError, match="may not use env"):
        DatabasePoll(
            server="db.example",
            poll_statement="SELECT 1",
            dialect="generic",
            odbc_driver="PostgreSQL Unicode",
            odbc_params=params,
        )


# --- the third position: an env ref on the odbc_params TABLE itself --------------------------


def _write_whole_table_ref(tmp_path: Path, marker: str) -> None:
    (tmp_path / "connections.toml").write_text(
        textwrap.dedent(
            f"""
            [[outbound]]
            name = "OB_PG"
            transport = "database"

            [outbound.settings]
            server = "db.example"
            statement = "INSERT INTO t (a) VALUES (:a)"
            dialect = "generic"
            odbc_driver = "PostgreSQL Unicode"
            odbc_params = {marker}
            """
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    ("label", "marker"),
    [
        ("no default", '{ env = "pg_params" }'),
        ("a cast and no default", '{ env = "pg_params", cast = "str" }'),
        ("a TABLE default", '{ env = "pg_params", default = { PORT = "5432" } }'),
    ],
)
def test_an_env_ref_on_the_odbc_params_table_itself_is_refused(
    label: str, marker: str, tmp_path: Path
) -> None:
    """`parse_env_setting` DOES decode this one -- it is a top-level settings value -- so the factory
    used to receive an `EnvRef`, call `.items()` on it, and die with a bare `AttributeError` that
    `connections_file._build_spec` does not convert (it catches only TypeError/ValueError). The fix
    makes it a typed WiringError; it stays un-located, because `_build_spec` re-raises a factory
    WiringError ahead of the arm that adds the connection and file.

    Every arm here is a marker the loader's type check does NOT refuse first: it judges an env ref
    only through an inline `default`, so it skips one with no default and passes one whose default
    is a table. Those are the shapes that reach the factory, so they are the ones this refusal owns.
    A NON-table default is refused earlier; see the next test."""
    _write_whole_table_ref(tmp_path, marker)
    with pytest.raises(WiringError, match="must be a table of ODBC keyword"):
        load_config(tmp_path)


def test_a_whole_table_env_ref_with_a_string_default_is_refused_by_the_type_check(
    tmp_path: Path,
) -> None:
    """The loader's type check (BACKLOG #1809) judges an env ref's inline `default` against the
    `odbc_params` annotation, a table, so a STRING default is refused before the factory runs. That
    refusal names the connection; the factory's does not. This arm pins which refusal owns the shape,
    so a change to either one shows up here rather than as a silent hand-off to the other.

    The default is the probe, so the last assertion is a live control on value echo."""
    _write_whole_table_ref(tmp_path, f'{{ env = "pg_params", default = "{_NON_MAPPING_PROBE}" }}')
    with pytest.raises(WiringError) as exc:
        load_config(tmp_path)
    message = str(exc.value)
    assert message.startswith("outbound connection 'OB_PG': invalid 'database' settings")
    assert "'odbc_params' env() default must be a table, got a string" in message
    assert _NON_MAPPING_PROBE not in message


#: Every arm carries `_NON_MAPPING_PROBE` somewhere inside it, so the value-echo assertion below is
#: a LIVE control on each: a refusal that interpolated the value would fail all three, not just the
#: one whose repr happens to contain the probe.
_NON_MAPPING_PROBE = "PORT=5432"


@pytest.mark.parametrize(
    ("label", "value"),
    [
        (
            "an EnvRef, from a decoded top-level marker",
            env("pg_params", default=_NON_MAPPING_PROBE),
        ),
        ("a bare string", _NON_MAPPING_PROBE),
        ("a list", [_NON_MAPPING_PROBE]),
        ("an empty string, which is falsy AND not a table", ""),
    ],
)
def test_a_non_mapping_odbc_params_is_refused_at_authoring(label: str, value: Any) -> None:
    """`_build_odbc_dsn` already refuses a non-mapping at CONNECT; this moves the same refusal to
    authoring time as a typed WiringError instead of a bare AttributeError. It does NOT name the
    connection or the file -- `_build_spec` re-raises a factory WiringError unwrapped.

    The empty-string arm is why the mapping check sits ABOVE the empty-table short-circuit: `""` is
    falsy, so an earlier `if not odbc_params: return` accepted it and `_build_odbc_dsn`'s `or {}`
    then read it as no params at all, with no diagnostic from either end.

    The message must carry the TYPE, never the value. That last assertion is a live control on the
    first three arms; the empty-string arm carries no probe and does not test it."""
    with pytest.raises(WiringError, match="must be a table of ODBC keyword") as exc:
        _reject_envref_odbc_params(cast("Any", value))
    assert _NON_MAPPING_PROBE not in str(exc.value)
    assert type(value).__name__ in str(exc.value)


# --- pins: the code-first spelling was already refused and must stay refused -----------------


def test_the_code_first_envref_spelling_is_still_refused_at_the_unit() -> None:
    """PIN, not new coverage -- this arm passed before #1806 and must not regress on the widening.
    The factory-level twin lives at
    `tests/test_database_transport.py::test_database_odbc_params_reject_envref`."""
    with pytest.raises(WiringError, match="may not use env"):
        _reject_envref_odbc_params({"SSLmode": env("pg_sslmode", default=FALLBACK_PROBE)})


# --- over-widening controls: what must STILL pass --------------------------------------------


def test_static_odbc_params_still_pass() -> None:
    """PIN. The ordinary case -- static driver keywords -- must be untouched by the widening."""
    spec = Database(**_database_kwargs(odbc_params={"PORT": "5432", "SSLmode": "verify-full"}))
    assert spec.settings["odbc_params"] == {"PORT": "5432", "SSLmode": "verify-full"}


def test_no_odbc_params_at_all_still_passes() -> None:
    _reject_envref_odbc_params(None)
    _reject_envref_odbc_params({})


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("no env key", {"host": "db.example", "default": "x"}),
        ("a key outside _ENVREF_KEYS", {"env": "pg_sslmode", "nonsense": 1}),
        ("a list, not a mapping", ["env", "pg_sslmode"]),
        ("a plain string that says env", "env(pg_sslmode)"),
    ],
)
def test_a_value_that_is_not_an_env_marker_still_passes(label: str, value: Any) -> None:
    """The widening must mirror `parse_env_setting` exactly, refusing only what it would DECODE.

    Each of these reaches the connector verbatim today, so refusing one would be a new false
    positive rather than a fix -- and `parse_env_setting` leaves every one of them alone.
    """
    _reject_envref_odbc_params({"Keyword": value})


# --- message hygiene --------------------------------------------------------------------------


def test_the_refusal_names_the_key_and_never_the_fallback_value() -> None:
    """The offender list is KEYS only. A refusal that echoed the value would print the very fallback
    secret the refusal exists to keep out of the DSN, into a log and a CI transcript."""
    with pytest.raises(WiringError) as exc:
        _reject_envref_odbc_params(
            {
                "PORT": "5432",
                "SSLmode": {"env": "pg_sslmode", "default": FALLBACK_PROBE},
            }
        )
    message = str(exc.value)
    assert "SSLmode" in message
    assert FALLBACK_PROBE not in message
    assert "pg_sslmode" not in message
    # The pointer to the env-resolved, redacted home for a credential is the actionable half.
    assert "username/password" in message


def test_the_refusal_lists_every_offending_key_sorted() -> None:
    with pytest.raises(WiringError) as exc:
        _reject_envref_odbc_params(
            {
                "Zeta": {"env": "z"},
                "Alpha": env("a"),
                "Static": "keep-me",
            }
        )
    # Assert against the PARENTHESISED offender list, not the whole message. `"Static" not in
    # message` would be green only by letter case -- the refusal's own prose ends "only static
    # driver keywords", so capitalising that word there would red this test for an unrelated reason.
    listed = re.search(r"may not use env\(\) \(([^)]*)\)", str(exc.value))
    assert listed is not None
    assert listed.group(1) == "Alpha, Zeta"
