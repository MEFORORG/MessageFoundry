# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1806 -- the odbc_params env-ref refusal must see BOTH spellings of an env ref.

`_reject_envref_odbc_params` tested `isinstance(v, EnvRef)` and nothing else, which is only the
CODE-FIRST shape. A `connections.toml` `[settings.odbc_params]` inline table arrives as a RAW DICT,
because `parse_env_setting` decodes only top-level settings values and does not descend. Since
`"database"` and `"database_poll"` are both live in `connections_file._TRANSPORTS`, that raw dict
reached `Database()` unrefused and stringified into the DSN with its fallback value attached.

The arms below are deliberately mixed. The TOML arm goes through the real loader, so it fails if the
transport table ever stops routing `database` here. The EnvRef arms are PINS on behaviour that
already worked. The two "still passes" arms are over-widening controls: the new predicate must not
start refusing an ordinary nested mapping that is not an env marker.
"""

from __future__ import annotations

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


def test_a_toml_inline_env_table_in_odbc_params_is_refused(tmp_path: Path) -> None:
    """The arm that was red before #1806. Goes through the REAL loader, not a hand-built dict."""
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

            [outbound.settings.odbc_params]
            PORT = "5432"
            SSLmode = {{ env = "pg_sslmode", default = "{FALLBACK_PROBE}" }}
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match="may not use env"):
        load_config(tmp_path)


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


# --- pins: the code-first spelling was already refused and must stay refused -----------------


def test_the_code_first_envref_spelling_is_still_refused() -> None:
    """PIN, not new coverage -- this arm passed before #1806 and must not regress on the widening."""
    with pytest.raises(WiringError, match="may not use env"):
        Database(**_database_kwargs(odbc_params={"SSLmode": env("pg_sslmode")}))


def test_the_code_first_envref_spelling_is_still_refused_at_the_unit() -> None:
    """PIN."""
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
    message = str(exc.value)
    assert "Alpha, Zeta" in message
    assert "Static" not in message
