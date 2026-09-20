# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Code-first wiring: the registry + loader for inbound/outbound/router/handler."""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import (
    API_LISTENER_LABEL,
    MLLP,
    ConnectionSpec,
    File,
    Ftp,
    InboundConnection,
    PortConflictError,
    Registry,
    Sftp,
    WiringError,
    build_inbound_connection,
    build_outbound_connection,
    inbound_binding_conflicts,
    load_config,
    validate_config,
)
from messagefoundry.parsing import Message

_MSG = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01^ADT_A01|MSG1|P|2.5.1\rEVN|A01|20260101\r"


def _write(directory: Path, body: str) -> Path:
    (directory / "cfg.py").write_text(textwrap.dedent(body), encoding="utf-8")
    return directory


def test_load_config_missing_dir_raises(tmp_path: Path) -> None:
    # M-24: a missing/typo'd config dir must fail loudly, not silently load an empty graph.
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "nope")


def test_validate_config_missing_dir_reports_error(tmp_path: Path) -> None:
    diags = validate_config(tmp_path / "nope")
    assert diags and "not found" in diags[0].message


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership check (CONFIG-2 / review M-21)")
def test_load_config_refuses_foreign_owned_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # M-21: a config dir owned by a different (non-root) user is refused — the engine would otherwise
    # execute code that user can rewrite. Simulate by making the running uid differ from the owner.
    _write(
        tmp_path, "from messagefoundry import outbound, File\noutbound('o', File(directory='.'))\n"
    )
    owner_uid = os.stat(tmp_path).st_uid
    monkeypatch.setattr(os, "getuid", lambda: owner_uid + 1)  # pretend we run as a different user
    with pytest.raises(WiringError, match="owned by uid"):
        load_config(tmp_path)


def test_load_config_populates_registry(tmp_path: Path) -> None:
    d = _write(
        tmp_path,
        """
        from messagefoundry import inbound, outbound, router, handler, Send, MLLP, File
        inbound("adt_in", MLLP(port=2575), router="adt_router")
        outbound("adt_archive", File(directory="./out/adt"))

        @router("adt_router")
        def route(msg):
            return ["archive"] if msg["MSH-9.1"] == "ADT" else []

        @handler("archive")
        def handle(msg):
            msg["MSH-3"] = "FOUNDRY"
            return Send("adt_archive", msg)
        """,
    )
    reg = load_config(d)

    assert set(reg.inbound) == {"adt_in"}
    assert reg.inbound["adt_in"].router == "adt_router"
    assert reg.inbound["adt_in"].spec.type.value == "mllp"
    assert reg.inbound["adt_in"].spec.settings["port"] == 2575
    assert set(reg.outbound) == {"adt_archive"}
    assert set(reg.routers) == {"adt_router"}
    assert set(reg.handlers) == {"archive"}

    # the registered scripts actually run
    assert reg.routers["adt_router"](Message.parse(_MSG)) == ["archive"]
    send = reg.handlers["archive"](Message.parse(_MSG))
    assert send is not None and send.to == "adt_archive"
    assert send.message["MSH-3"] == "FOUNDRY"  # handler transformed the message


def test_unknown_router_reference_raises(tmp_path: Path) -> None:
    d = _write(
        tmp_path,
        """
        from messagefoundry import inbound, MLLP
        inbound("i", MLLP(port=1234), router="missing")
        """,
    )
    with pytest.raises(WiringError):
        load_config(d)


def test_duplicate_name_raises(tmp_path: Path) -> None:
    d = _write(
        tmp_path,
        """
        from messagefoundry import outbound, File
        outbound("o", File(directory="."))
        outbound("o", File(directory="."))
        """,
    )
    with pytest.raises(WiringError):
        load_config(d)


def test_declaration_outside_load_raises() -> None:
    from messagefoundry import File, outbound

    with pytest.raises(WiringError):
        outbound("x", File(directory="."))


def test_loader_skips_underscore_modules(tmp_path: Path) -> None:
    (tmp_path / "_helpers.py").write_text("raise RuntimeError('must not load')\n", encoding="utf-8")
    _write(
        tmp_path,
        """
        from messagefoundry import outbound, File
        outbound("o", File(directory="."))
        """,
    )
    reg = load_config(tmp_path)
    assert set(reg.outbound) == {"o"}


def test_config_module_can_import_sibling_helper(tmp_path: Path) -> None:
    # low-10: CLAUDE.md §4 documents sharing `_`-prefixed helpers imported from sibling config
    # modules. A scoped finder resolves the import against the config dir; it isn't left in sys.modules.
    (tmp_path / "_shared.py").write_text("ROUTER = 'adt_router'\n", encoding="utf-8")
    _write(
        tmp_path,
        """
        import _shared
        from messagefoundry import inbound, router, MLLP
        inbound("adt_in", MLLP(port=2575), router=_shared.ROUTER)

        @router(_shared.ROUTER)
        def route(msg):
            return []
        """,
    )
    reg = load_config(tmp_path)
    assert reg.inbound["adt_in"].router == "adt_router"
    assert "_shared" not in sys.modules  # not leaked into the global module table after load


def test_duplicate_inbound_port_raises(tmp_path: Path) -> None:
    # low-13: two inbound connections on the same literal port abort the engine at bind with a bare
    # OSError naming neither; catch it statically naming both.
    _write(
        tmp_path,
        """
        from messagefoundry import inbound, MLLP, router
        inbound("a", MLLP(port=2575), router="r")
        inbound("b", MLLP(port=2575), router="r")

        @router("r")
        def route(msg):
            return []
        """,
    )
    with pytest.raises(WiringError, match="both bind port 2575"):
        load_config(tmp_path)


def test_validate_config_reports_port_collision(tmp_path: Path) -> None:
    _write(
        tmp_path,
        """
        from messagefoundry import inbound, MLLP, router
        inbound("a", MLLP(port=2575), router="r")
        inbound("b", MLLP(port=2575), router="r")

        @router("r")
        def route(msg):
            return []
        """,
    )
    diags = validate_config(tmp_path)
    assert any("both bind port 2575" in d.message for d in diags)


def test_same_port_different_bind_address_is_not_a_collision(tmp_path: Path) -> None:
    # Interface-aware (low-13): two listeners share a port but bind DIFFERENT explicit interfaces
    # (a multi-NIC host) — they don't actually contend, so this must load cleanly. The old port-only
    # check false-positived here.
    _write(
        tmp_path,
        """
        from messagefoundry import inbound, MLLP, router
        inbound("a", MLLP(port=2575), router="r", bind_address="127.0.0.1")
        inbound("b", MLLP(port=2575), router="r", bind_address="10.0.0.5")

        @router("r")
        def route(msg):
            return []
        """,
    )
    reg = load_config(tmp_path)  # no WiringError
    assert reg.port_collisions() == []


def test_wildcard_bind_overlaps_a_specific_interface_on_the_same_port(tmp_path: Path) -> None:
    # A wildcard (0.0.0.0 = every interface) DOES contend with a specific-interface bind on the same
    # port — flag it even though the host strings differ.
    _write(
        tmp_path,
        """
        from messagefoundry import inbound, MLLP, router
        inbound("a", MLLP(port=2575), router="r", bind_address="0.0.0.0")
        inbound("b", MLLP(port=2575), router="r", bind_address="127.0.0.1")

        @router("r")
        def route(msg):
            return []
        """,
    )
    with pytest.raises(WiringError, match="both bind port 2575"):
        load_config(tmp_path)


def test_database_poll_sources_sharing_the_sql_port_are_not_flagged(tmp_path: Path) -> None:
    # A DATABASE poll source carries a `port` (the SQL server's) but DIALS OUT — it never binds a
    # listener, so two of them on 1433 must NOT be mistaken for a bind collision.
    _write(
        tmp_path,
        """
        from messagefoundry import inbound, DatabasePoll, router
        inbound("a", DatabasePoll(server="db1", database="d", poll_statement="SELECT 1"), router="r")
        inbound("b", DatabasePoll(server="db2", database="d", poll_statement="SELECT 1"), router="r")

        @router("r")
        def route(msg):
            return []
        """,
    )
    reg = load_config(tmp_path)
    assert reg.port_collisions() == []


def test_inbound_binding_conflicts_resolves_env_ports(tmp_path: Path) -> None:
    # env() ports are invisible to the literal-only static check, but the runner's authoritative pass
    # resolves them against the instance's values: two listeners that resolve to the SAME port collide.
    _write(
        tmp_path,
        """
        from messagefoundry import inbound, MLLP, router, env
        inbound("a", MLLP(port=env("p1", cast=int)), router="r")
        inbound("b", MLLP(port=env("p2", cast=int)), router="r")

        @router("r")
        def route(msg):
            return []
        """,
    )
    reg = load_config(tmp_path)
    assert reg.port_collisions() == []  # literal-only static check can't see env() ports
    same = inbound_binding_conflicts(
        reg, bind_host="127.0.0.1", env_values={"p1": "2575", "p2": "2575"}
    )
    assert any("both bind port 2575" in m for m in same)
    # Distinct resolved ports → no conflict.
    assert (
        inbound_binding_conflicts(
            reg, bind_host="127.0.0.1", env_values={"p1": "2575", "p2": "2576"}
        )
        == []
    )


def test_inbound_binding_conflicts_reserves_the_api_port() -> None:
    # An inbound wired onto the engine's own API listener port is caught here, naming the reservation —
    # rather than surfacing as a bare bind OSError once uvicorn already holds it.
    reg = Registry()
    reg.add_inbound(build_inbound_connection("a", MLLP(port=8765), router="r"))
    msgs = inbound_binding_conflicts(
        reg,
        bind_host="127.0.0.1",
        env_values={},
        reserved=((API_LISTENER_LABEL, "127.0.0.1", 8765),),
    )
    assert msgs and "reserved for" in msgs[0] and API_LISTENER_LABEL in msgs[0]
    # A listener on a different port doesn't touch the reservation.
    other = Registry()
    other.add_inbound(build_inbound_connection("a", MLLP(port=2575), router="r"))
    assert (
        inbound_binding_conflicts(
            other,
            bind_host="127.0.0.1",
            env_values={},
            reserved=((API_LISTENER_LABEL, "127.0.0.1", 8765),),
        )
        == []
    )


def test_build_check_registry_raises_port_conflict_error_on_api_port() -> None:
    # The authoritative reload/start pass raises PortConflictError (a WiringError subclass → API 422).
    from messagefoundry.config.settings import EgressSettings
    from messagefoundry.pipeline.wiring_runner import build_check_registry

    reg = Registry()
    reg.add_inbound(build_inbound_connection("a", MLLP(port=8765), router="r"))
    reg.add_router("r", lambda m: [])
    with pytest.raises(PortConflictError, match="reserved for"):
        build_check_registry(
            reg,
            inbound_bind_host="127.0.0.1",
            env_values={},
            egress=EgressSettings(),
            reserved_bindings=((API_LISTENER_LABEL, "127.0.0.1", 8765),),
        )


# --- declared text-encoding validation (BACKLOG #1613) -----------------------
# See Registry.encoding_problems in messagefoundry/config/wiring.py for the failure these pin.


def _encoding_cfg(directory: Path, body: str) -> Path:
    return _write(
        directory,
        "from messagefoundry import inbound, outbound, router, MLLP, File, env\n"
        + body
        + "\n@router('r')\ndef route(msg):\n    return []\n",
    )


@pytest.mark.parametrize(
    ("body", "match"),
    [
        (
            "inbound('i', MLLP(port=2575, encoding='not-a-real-codec'), router='r')",
            "inbound connection 'i'",
        ),
        # Same setting, same class of failure: an outbound encodes every payload with it.
        (
            "outbound('o', File(directory='.', encoding='not-a-real-codec'))",
            "outbound connection 'o'",
        ),
        # `base64` IS a registered codec, so codecs.lookup() accepts it — but str.encode/bytes.decode
        # refuse it ("not a text encoding"), and those are what the transports actually call.
        ("inbound('i', MLLP(port=2575, encoding='base64'), router='r')", "'base64' is not"),
    ],
)
def test_unusable_encoding_refuses_to_load(tmp_path: Path, body: str, match: str) -> None:
    _encoding_cfg(tmp_path, body)
    with pytest.raises(WiringError, match=match):
        load_config(tmp_path)


def test_validate_config_reports_invalid_inbound_encoding(tmp_path: Path) -> None:
    _encoding_cfg(tmp_path, "inbound('i', MLLP(port=2575, encoding='utf8-8'), router='r')")
    diags = [d for d in validate_config(tmp_path) if d.severity == "error"]
    assert any("'i'" in d.message and "'utf8-8'" in d.message for d in diags)


def test_check_validate_fails_on_invalid_encoding(tmp_path: Path) -> None:
    # The `messagefoundry check` gate must go red BEFORE the connection is ever started.
    from messagefoundry.checks import _check_validate

    _encoding_cfg(tmp_path, "inbound('i', MLLP(port=2575, encoding='utf8-8'), router='r')")
    result = _check_validate(tmp_path)
    assert result.ok is False and result.required is True
    assert "not a Python text codec" in result.detail


# "UTF_8" is the load-bearing row: Python normalizes case and underscores, so a probe stricter than
# str.encode would false-positive on it. The other two are the ordinary spellings.
@pytest.mark.parametrize("encoding", ["utf-8", "latin-1", "UTF_8"])
def test_real_encodings_validate_cleanly(tmp_path: Path, encoding: str) -> None:
    _encoding_cfg(
        tmp_path,
        f"inbound('i', MLLP(port=2575, encoding={encoding!r}), router='r')\n"
        f"outbound('o', File(directory='.', encoding={encoding!r}))",
    )
    reg = load_config(tmp_path)  # no WiringError
    assert reg.encoding_problems() == []
    assert validate_config(tmp_path) == []


def test_env_supplied_encoding_is_deferred_by_the_literal_pass_without_masking_a_literal_typo(
    tmp_path: Path,
) -> None:
    # An env() ref carries no value at load time (resolve_env_settings needs the instance's
    # environment values), so THIS pass skips it deliberately — and probing the EnvRef object itself
    # would raise TypeError, not LookupError, so this also pins that the skip happens before any probe.
    # "Deferred", not "unchecked": since #1767 the resolved pass in build_check_registry probes it.
    # The bad literal beside it is the positive control: without it this test would pass just as well
    # if the check never ran at all.
    _encoding_cfg(
        tmp_path,
        "inbound('i', MLLP(port=2575, encoding=env('charset')), router='r')\n"
        "outbound('o', File(directory='.', encoding='not-a-real-codec'))",
    )
    flagged = [d.message for d in validate_config(tmp_path) if "text codec" in d.message]
    assert len(flagged) == 1  # the env()-supplied inbound encoding produced nothing
    assert "outbound connection 'o'" in flagged[0]  # the literal typo still did


def test_encoding_census_counts_what_was_probed(tmp_path: Path) -> None:
    # Three literals probed — the fourth connection never set one, so its factory wrote the "utf-8"
    # default into settings — and one env ref on a deployed entry, deferred to the resolved pass.
    _encoding_cfg(
        tmp_path,
        "inbound('i', MLLP(port=2575, encoding='utf-8'), router='r')\n"
        "outbound('a', File(directory='.', encoding='latin-1'))\n"
        "outbound('b', File(directory='.', encoding=env('charset')))\n"
        "outbound('c', MLLP(host='h', port=1234))",
    )
    assert load_config(tmp_path).encoding_census() == (3, 1, 0)


def test_an_all_env_config_is_counted_as_deferred_not_reported_as_clean(tmp_path: Path) -> None:
    # The failure this guards: every encoding deferred, nothing probed HERE, and this pass reporting
    # no problems — indistinguishable from a pass that checked everything. The census is what
    # separates them, so pin the zero in the `checked` column. Both entries are deployed, so both are
    # deferred and the `unchecked` column is zero too: nothing here is beyond every pass's reach.
    _encoding_cfg(
        tmp_path,
        "inbound('i', MLLP(port=2575, encoding=env('charset')), router='r')\n"
        "outbound('o', File(directory='.', encoding=env('charset', default='utf-8')))",
    )
    reg = load_config(tmp_path)  # no WiringError, no TypeError
    assert validate_config(tmp_path) == []
    assert reg.encoding_census() == (0, 2, 0)


def test_check_validate_detail_reports_the_encoding_census(tmp_path: Path) -> None:
    # The count reaches an operator: `messagefoundry check`'s validate line says how many were probed.
    from messagefoundry.checks import _check_validate

    _encoding_cfg(
        tmp_path,
        "inbound('i', MLLP(port=2575, encoding=env('charset')), router='r')\n"
        "outbound('o', File(directory='.', encoding='utf-8'))",
    )
    result = _check_validate(tmp_path)
    assert result.ok is True
    assert (
        "encodings checked: 1, env() refs deferred to build-check: 1, unchecked: 0" in result.detail
    )


# --- the RESOLVED env() encoding pass (BACKLOG #1767) ------------------------
# The second half of the pass above: an env()-supplied encoding is legible only once this instance's
# environment values are in hand, so it is probed in build_check_registry. See
# resolved_encoding_problems in messagefoundry/config/wiring.py.


def _build_check(reg: Registry, env_values: dict[str, object]) -> None:
    from messagefoundry.config.settings import EgressSettings
    from messagefoundry.pipeline.wiring_runner import build_check_registry

    build_check_registry(
        reg, inbound_bind_host="127.0.0.1", env_values=env_values, egress=EgressSettings()
    )


def test_env_supplied_encoding_naming_a_real_codec_builds_clean(tmp_path: Path) -> None:
    _encoding_cfg(tmp_path, "outbound('o', File(directory='.', encoding=env('charset')))")
    _build_check(load_config(tmp_path), {"charset": "latin-1"})  # no WiringError


def test_env_supplied_encoding_naming_no_codec_is_refused_at_build_check(tmp_path: Path) -> None:
    # The whole point of #1767: this config LOADS clean (the literal pass has nothing to probe) and is
    # caught only once the environment values resolve it.
    _encoding_cfg(tmp_path, "outbound('o', File(directory='.', encoding=env('charset')))")
    reg = load_config(tmp_path)  # no WiringError at load
    assert reg.encoding_problems() == []  # ... and nothing for the literal pass to say
    with pytest.raises(WiringError) as exc:
        _build_check(reg, {"charset": "not-a-real-codec"})
    assert "outbound connection 'o'" in str(exc.value)
    assert "'charset'" in str(exc.value)  # names the env key, so the operator knows where to fix it
    assert "not a Python text codec" in str(exc.value)


def test_a_non_text_codec_from_the_environment_is_refused_too(tmp_path: Path) -> None:
    # `base64` IS a registered codec, so codecs.lookup() accepts it — str.encode/bytes.decode do not,
    # and those are what the transports call. Same probe as the literal pass, same verdict.
    # The message names the KEY and not the value (see the secret test below), so 'charset' is what
    # there is to match on; matching 'base64' here would pin the leak instead of the diagnostic.
    _encoding_cfg(tmp_path, "outbound('o', File(directory='.', encoding=env('charset')))")
    with pytest.raises(WiringError) as ei:
        _build_check(load_config(tmp_path), {"charset": "base64"})
    # Both halves, because the key ALONE is satisfied by any WiringError quoting it — including
    # resolve_env_settings' uncastable message from a different pass entirely. The diagnostic phrase
    # is what says THIS pass produced it.
    assert "'charset'" in str(ei.value)
    assert "not a Python text codec" in str(ei.value)


def test_the_undefined_codec_from_the_environment_is_a_wiringerror_not_a_unicodeerror(
    tmp_path: Path,
) -> None:
    # "undefined" is a REGISTERED codec that refuses every conversion, so codecs.lookup() finds it and
    # "".encode() raises UnicodeError — a ValueError, NOT a LookupError. Measured: with _is_text_codec
    # catching LookupError alone, this escaped build_check_registry as a bare UnicodeError, which
    # `messagefoundry check` (catching WiringError) turned into a traceback and reload/upsert into a
    # 500 instead of a 422. The exception TYPE is the whole assertion here.
    _encoding_cfg(tmp_path, "outbound('o', File(directory='.', encoding=env('charset')))")
    with pytest.raises(WiringError) as ei:
        _build_check(load_config(tmp_path), {"charset": "undefined"})
    assert "'charset'" in str(ei.value)
    assert "not a Python text codec" in str(ei.value)


@pytest.mark.parametrize("declared", ["None", "''"])
def test_an_env_encoding_that_declines_to_set_a_value_is_not_a_bad_codec(
    tmp_path: Path, declared: str
) -> None:
    # `env("charset", default=None)` is an opt-out, not a typo: ingress_guards.ingress_encoding
    # documents an explicit None as "not declared" and falls back to utf-8. Refusing it would
    # hard-fail `check`, every reload and every unrelated `connection upsert` on a config that runs
    # correctly. Measured: the first cut of this pass did exactly that.
    _encoding_cfg(
        tmp_path,
        f"outbound('o', File(directory='.', encoding=env('charset', default={declared})))",
    )
    _build_check(load_config(tmp_path), {})  # no WiringError


def test_a_non_string_environment_value_names_its_type(tmp_path: Path) -> None:
    # `charset = 8859` in a TOML value file types as an int. With the value withheld, "not a text
    # codec" alone sends the operator hunting for a misspelling that is not there — the TYPE is the
    # other half of the diagnostic and is safe to name.
    # The value is 8859 and not the obvious 1252 because the message's own example codec is 'cp1252',
    # so a withholding assertion against 1252 fails on the example rather than on a leak — measured,
    # and the kind of instrument error that otherwise reads as a real finding.
    _encoding_cfg(tmp_path, "outbound('o', File(directory='.', encoding=env('charset')))")
    with pytest.raises(WiringError) as ei:
        _build_check(load_config(tmp_path), {"charset": 8859})
    assert "type int" in str(ei.value)
    assert "8859" not in str(ei.value), "the value is withheld even when its type is named"


def test_the_undefined_codec_as_a_literal_is_refused_at_load_too(tmp_path: Path) -> None:
    # The literal pass shares _is_text_codec, so it had the same hole and the same fix closes it:
    # before it, load_config raised a bare UnicodeError instead of the WiringError callers expect.
    _encoding_cfg(tmp_path, "outbound('o', File(directory='.', encoding='undefined'))")
    with pytest.raises(WiringError, match="not a Python text codec"):
        load_config(tmp_path)


def test_the_resolved_pass_never_echoes_the_environment_value(tmp_path: Path) -> None:
    # A MEFOR_VALUE_* value can be a secret and the env KEY is operator-authored, so a copy-pasted
    # `encoding=env('store_password')` would print the password into the operator log, the support
    # bundle, GET /logs/tail and a 422 body. BACKLOG #1183 stripped exactly that carriage out of
    # resolve_env_settings; this pass must not put it back. Measured: the pre-fix message rendered
    # the value verbatim.
    secret = "pw-C4st_Val-66"
    _encoding_cfg(tmp_path, "outbound('o', File(directory='.', encoding=env('store_password')))")
    with pytest.raises(WiringError) as ei:
        _build_check(load_config(tmp_path), {"store_password": secret})
    msg = str(ei.value)
    assert secret not in msg, f"the raw env value survived into the error text: {msg!r}"
    # Positive control: the diagnostic an operator acts on must survive the redaction, or this test
    # would pass just as well against a message that said nothing at all.
    assert "store_password" in msg, f"the key is the operator's whole diagnostic: {msg!r}"
    assert "value withheld" in msg, f"a silent redaction reads as a truncated error: {msg!r}"


def test_every_bad_env_encoding_is_reported_not_just_the_first(tmp_path: Path) -> None:
    # build_check_registry joins the whole list, and the comment there promises "all of them at once,
    # not the first" — the caller is usually rendering a 422 an operator reads once. Two entries in
    # two different tables, so this also pins that the pass walks past the outbound table.
    _encoding_cfg(
        tmp_path,
        "inbound('i', MLLP(port=2575, encoding=env('in_charset')), router='r')\n"
        "outbound('o', File(directory='.', encoding=env('out_charset')))",
    )
    with pytest.raises(WiringError) as ei:
        _build_check(
            load_config(tmp_path),
            {"in_charset": "not-a-real-codec", "out_charset": "also-not-a-codec"},
        )
    msg = str(ei.value)
    assert "inbound connection 'i'" in msg
    assert "outbound connection 'o'" in msg


def test_env_supplied_encoding_on_a_not_deployed_connection_is_skipped(tmp_path: Path) -> None:
    # ADR 0111: a not-deployed connection's env() values are NEVER resolved, on any path — so the
    # resolved pass cannot follow the literal pass there, and the bad value goes unchecked. That is
    # the accepted cost of the owner ruling, and this pins it rather than leaving it to drift.
    # The deployed sibling carrying the SAME bad key is the positive control: without it this test
    # would pass just as well if the resolved pass never ran at all.
    _encoding_cfg(
        tmp_path,
        "outbound('parked', File(directory='.', encoding=env('charset')), deployed=False)\n"
        "outbound('live', File(directory='.', encoding=env('charset')))",
    )
    reg = load_config(tmp_path)
    with pytest.raises(WiringError) as exc:
        _build_check(reg, {"charset": "not-a-real-codec"})
    assert "'live'" in str(exc.value)
    assert "'parked'" not in str(exc.value)  # the not-deployed one produced nothing


def test_a_literal_typo_on_a_not_deployed_connection_is_still_caught(tmp_path: Path) -> None:
    # The other half of the split, and the half that did NOT change: the literal pass reads the codec
    # name straight off the graph, resolving nothing, so ADR 0111 does not reach it and declaring a
    # feed not-deployed still does not make a typo'd codec name correct. Without this the diff's
    # headline claim — that only the env() half loses coverage — rests on prose alone.
    _encoding_cfg(
        tmp_path,
        "outbound('parked', File(directory='.', encoding='not-a-real-codec'), deployed=False)",
    )
    with pytest.raises(WiringError, match="'parked'"):
        load_config(tmp_path)


def test_a_not_deployed_env_encoding_with_no_value_at_all_does_not_raise(tmp_path: Path) -> None:
    # ADR 0111 AC-1, at this seam: an entirely-absent value set must not raise for a not-deployed
    # connection. Probing its encoding would have resolved the ref and broken exactly that.
    _encoding_cfg(
        tmp_path,
        "outbound('parked', File(directory='.', encoding=env('charset')), deployed=False)",
    )
    _build_check(load_config(tmp_path), {})  # no WiringError


def test_an_unresolvable_env_encoding_is_left_to_the_connector_build(tmp_path: Path) -> None:
    # A DEPLOYED connection whose env key has no value is already reported loud by
    # resolve_env_settings. The resolved pass must not pre-empt that with a second, vaguer message —
    # the first error an operator reads should be the one naming the missing key.
    _encoding_cfg(tmp_path, "outbound('o', File(directory='.', encoding=env('charset')))")
    with pytest.raises(WiringError) as exc:
        _build_check(load_config(tmp_path), {})
    assert "missing: charset" in str(exc.value)
    assert "not a Python text codec" not in str(exc.value)


def test_encoding_census_separates_deferred_from_unchecked(tmp_path: Path) -> None:
    # The three populations, each with exactly one member, so a collapse of any pair is visible.
    _encoding_cfg(
        tmp_path,
        "outbound('lit', File(directory='.', encoding='utf-8'))\n"
        "outbound('live', File(directory='.', encoding=env('charset')))\n"
        "outbound('parked', File(directory='.', encoding=env('charset')), deployed=False)",
    )
    assert load_config(tmp_path).encoding_census() == (1, 1, 1)


def test_check_validate_detail_reports_the_three_populations_distinctly(tmp_path: Path) -> None:
    # A census that folded "deferred" into "unchecked" would report an env() ref the build-check line
    # DOES probe as one nothing looks at, and vice versa. The operator-visible line keeps them apart.
    from messagefoundry.checks import _check_validate

    _encoding_cfg(
        tmp_path,
        "outbound('lit', File(directory='.', encoding='utf-8'))\n"
        "outbound('live', File(directory='.', encoding=env('charset')))\n"
        "outbound('parked', File(directory='.', encoding=env('charset')), deployed=False)",
    )
    result = _check_validate(tmp_path)
    assert result.ok is True
    assert (
        "encodings checked: 1, env() refs deferred to build-check: 1, unchecked: 1" in result.detail
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership check (CONFIG-2 / review M-21)")
def test_validate_config_refuses_unsafe_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # low-11: validate_config must apply the same safe-source check as load_config before executing
    # any config Python — it executes code too.
    _write(tmp_path, "raise RuntimeError('must not execute from an unsafe source')\n")
    owner_uid = os.stat(tmp_path).st_uid
    monkeypatch.setattr(os, "getuid", lambda: owner_uid + 1)
    diags = validate_config(tmp_path)
    assert diags and "owned by uid" in diags[0].message


# --- the empty graph is refused on every loading path (BACKLOG #1648) --------
#
# A config dir that declares no connections used to load, validate and `check` clean: only the
# engine RELOAD refused it. An operator could therefore serve a graph that binds no listener and
# drains no destination, with every surface reporting a healthy engine. The rule now lives in
# Registry.graph_problems, so load_config raises it and validate_config reports it.

_EMPTY_MARKER = "declares no connections"


def _helper_only(directory: Path) -> Path:
    """A config dir that LOADS cleanly and declares no connection at all.

    Deliberately not an empty directory: a router and a handler make it the case the rule is for --
    real config modules that simply wire nothing -- rather than the trivial no-modules case, which a
    weaker rule keyed on "no *.py files" would also catch."""
    return _write(
        directory,
        """
        from messagefoundry import router, handler, Send

        @router("r")
        def route(msg):
            return ["h"]

        @handler("h")
        def handle(msg):
            return Send("nowhere", msg)
        """,
    )


def test_load_config_refuses_a_config_that_declares_no_connections(tmp_path: Path) -> None:
    _helper_only(tmp_path)
    with pytest.raises(WiringError, match=_EMPTY_MARKER):
        load_config(tmp_path)


def test_load_config_allow_empty_opt_out_loads_the_same_directory(tmp_path: Path) -> None:
    # The opt-out `messagefoundry check --allow-empty-config` rides on. Paired with the test above so
    # neither can pass alone: a rule that never fires reds the first, one with no escape reds this.
    _helper_only(tmp_path)
    registry = load_config(tmp_path, allow_empty=True)
    assert not registry.inbound and not registry.outbound
    assert "r" in registry.routers  # the modules really did execute


def test_load_config_accepts_an_outbound_only_graph(tmp_path: Path) -> None:
    # The predicate is inbound AND outbound, matching Engine.reload_detail -- NOT inbound alone. A
    # half-built or outbound-only graph must keep loading, or this rule would newly refuse configs
    # that work today. RED if the predicate is tightened to `not registry.inbound`.
    _write(
        tmp_path,
        """
        from messagefoundry import outbound, File
        outbound("o", File(directory="."))
        """,
    )
    assert "o" in load_config(tmp_path).outbound


def test_load_config_accepts_an_inbound_only_graph(tmp_path: Path) -> None:
    # The other arm of the same predicate, pinned so its shape is stated by a test and not only by a
    # comment. An inbound-only graph receives and delivers nowhere, which is a real half-built
    # config -- and the one Engine.reload_detail's post-filter check exists for, since the shard
    # filter KEEPS outbound connections and so can only empty a graph that had none. RED if the
    # predicate is ever widened to `not registry.outbound`.
    _write(
        tmp_path,
        """
        from messagefoundry import inbound, router, MLLP
        inbound("i", MLLP(port=2731), router="r")

        @router("r")
        def route(msg):
            return []
        """,
    )
    assert "i" in load_config(tmp_path).inbound


def test_validate_config_reports_a_config_that_declares_no_connections(tmp_path: Path) -> None:
    _helper_only(tmp_path)
    diags = validate_config(tmp_path)
    assert len(diags) == 1 and _EMPTY_MARKER in diags[0].message


def test_validate_config_allow_empty_reports_nothing(tmp_path: Path) -> None:
    _helper_only(tmp_path)
    assert validate_config(tmp_path, allow_empty=True) == []


def test_validate_config_does_not_report_emptiness_beside_its_own_cause(tmp_path: Path) -> None:
    # A module that fails to load leaves an empty registry, so the empty-graph rule would fire as a
    # DERIVED symptom and send the reader after the wrong problem. Exactly one diagnostic, the cause.
    (tmp_path / "cfg.py").write_text("import nonexistent_module_xyz\n", encoding="utf-8")
    diags = validate_config(tmp_path)
    assert len(diags) == 1 and _EMPTY_MARKER not in diags[0].message


def test_validate_config_still_reports_emptiness_beside_a_diagnostic_that_cannot_cause_it(
    tmp_path: Path,
) -> None:
    """The suppressor is scoped to the sources that DECLARE connections, not to any diagnostic.

    A malformed ``codesets/`` table is a real diagnostic and no explanation at all for an empty
    graph -- the modules loaded, they simply wired nothing. Suppressing on the whole diagnostics
    list would hide the empty graph behind it and make the operator fix the CSV, re-run, and only
    then learn the real problem. Both are reported in one pass instead.

    Falsified by restoring ``allow_empty=allow_empty or bool(diagnostics)``."""
    codesets = tmp_path / "codesets"
    codesets.mkdir()
    (codesets / "bad.csv").write_text("code,value\nA,1\nA,2\n", encoding="utf-8")  # duplicate key
    _helper_only(tmp_path)

    messages = [d.message for d in validate_config(tmp_path)]

    assert len(messages) == 2, messages
    assert any(_EMPTY_MARKER in m for m in messages)
    assert any(_EMPTY_MARKER not in m for m in messages)  # the code-set problem, still reported


def test_registry_validate_and_validate_config_agree_on_the_empty_graph(tmp_path: Path) -> None:
    # BACKLOG #1656: the two validators are one rule list now, so the message an editor shows and the
    # message the loader raises are the same string, not two hand-kept copies that can drift.
    _helper_only(tmp_path)
    (diagnostic,) = validate_config(tmp_path)
    with pytest.raises(WiringError) as raised:
        load_config(tmp_path)
    assert str(raised.value) == diagnostic.message


def test_graph_problems_reports_every_problem_while_validate_raises_the_first() -> None:
    """The contract difference #1656 exists to preserve: one rule list, two behaviours.

    ``Registry.validate`` stops at the first problem (the loader has nothing to hand the engine);
    ``graph_problems`` yields them all (the editor must show the full set). RED if a refactor makes
    either caller raise on behalf of the other."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection("i1", ConnectionSpec(ConnectorType.MLLP, {"port": 1}), router="missing_a")
    )
    reg.add_inbound(
        InboundConnection("i2", ConnectionSpec(ConnectorType.MLLP, {"port": 2}), router="missing_b")
    )
    problems = list(reg.graph_problems())
    assert len(problems) == 2
    assert "missing_a" in problems[0] and "missing_b" in problems[1]
    with pytest.raises(WiringError) as raised:
        reg.validate()
    assert str(raised.value) == problems[0]


# --- structured validation (validate_config) ---------------------------------


def test_validate_config_clean_returns_no_diagnostics(tmp_path: Path) -> None:
    _write(
        tmp_path,
        """
        from messagefoundry import inbound, MLLP, router
        inbound("i", MLLP(port=1), router="r")

        @router("r")
        def route(msg):
            return []
        """,
    )
    assert validate_config(tmp_path) == []


def test_validate_config_reports_unknown_router(tmp_path: Path) -> None:
    _write(
        tmp_path,
        """
        from messagefoundry import inbound, MLLP
        inbound("i", MLLP(port=1), router="missing")
        """,
    )
    diags = validate_config(tmp_path)
    assert len(diags) == 1 and "unknown router" in diags[0].message


def test_validate_config_reports_module_error_with_file(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text("import does_not_exist_xyz\n", encoding="utf-8")
    diags = validate_config(tmp_path)
    assert len(diags) == 1
    assert diags[0].file is not None and diags[0].file.endswith("bad.py")


# --- the deployed flag (#233, ADR 0111) --------------------------------------


def test_factories_thread_deployed_and_default_it_true() -> None:
    """The four build_*/inbound/outbound factories are the single choke point shared by code-first
    authoring AND the connections.toml loader, so threading the kwarg here covers both surfaces."""
    ib_spec = MLLP(port=2600)
    ob_spec = File(directory="./out")
    assert build_inbound_connection("IB", ib_spec, router="r").deployed is True  # default
    assert build_inbound_connection("IB", ib_spec, router="r", deployed=False).deployed is False
    assert build_outbound_connection("OB", ob_spec).deployed is True  # default
    assert build_outbound_connection("OB", ob_spec, deployed=False).deployed is False


def test_code_first_declares_a_not_deployed_connection(tmp_path: Path) -> None:
    """A not-deployed connection stays IN the graph — the whole point (#233): the config repo keeps it,
    ``validate``/``check``/``graph --json`` keep seeing it, and its already-queued rows are never swept.
    ``deployed=False`` is also independent of ``auto_start`` (it wins over it; enforcement is a later
    layer — this pins only that both flags are representable together)."""
    _write(
        tmp_path,
        """
        from messagefoundry import inbound, outbound, router, handler, Send, MLLP, File
        inbound("IB", MLLP(port=2600), router="r")
        inbound("IB_OFF", MLLP(port=2601), router="r", deployed=False, auto_start=False)
        outbound("OB", File(directory="./out"))
        outbound("OB_OFF", File(directory="./out"), deployed=False)

        @router("r")
        def route(msg):
            return ["h"]

        @handler("h")
        def handle(msg):
            return Send("OB", msg)
        """,
    )
    reg = load_config(tmp_path)
    assert validate_config(tmp_path) == []  # a not-deployed connection is not a config error
    assert "IB_OFF" in reg.inbound and "OB_OFF" in reg.outbound  # still in the graph
    assert reg.inbound["IB_OFF"].deployed is False
    assert reg.inbound["IB_OFF"].auto_start is False
    assert reg.outbound["OB_OFF"].deployed is False
    assert reg.outbound["OB_OFF"].auto_start is True  # untouched by deployed
    assert reg.inbound["IB"].deployed is True  # the default is unchanged
    assert reg.outbound["OB"].deployed is True


def test_validate_config_collects_multiple_problems(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text("raise ValueError('boom')\n", encoding="utf-8")
    (tmp_path / "ok.py").write_text(
        textwrap.dedent(
            """
            from messagefoundry import inbound, MLLP
            inbound("i", MLLP(port=1), router="missing")
            """
        ),
        encoding="utf-8",
    )
    diags = validate_config(tmp_path)
    assert len(diags) == 2  # one module error + one unknown-router reference


# --- module isolation: sys.modules registration (CONFIG-4) -------------------

_MINIMAL = """
    from messagefoundry import inbound, router, File
    inbound({name!r}, File(directory="./in", pattern="*.hl7"), router="r")

    @router("r")
    def route(msg):
        return []
"""


def test_load_config_registers_module_in_sys_modules(tmp_path: Path) -> None:
    _write(tmp_path, _MINIMAL.format(name="in"))
    before = {k for k in sys.modules if k.startswith("mefor_config_")}
    load_config(tmp_path)
    new = {k for k in sys.modules if k.startswith("mefor_config_")} - before
    # Registered under a path-hash-suffixed name (not the bare stem), so same-stem files don't clash.
    assert any(name.startswith("mefor_config_cfg_") for name in new)


def test_same_stem_different_dirs_do_not_collide(tmp_path: Path) -> None:
    d1, d2 = tmp_path / "a", tmp_path / "b"
    d1.mkdir()
    d2.mkdir()
    _write(d1, _MINIMAL.format(name="in_a"))
    _write(d2, _MINIMAL.format(name="in_b"))
    reg1 = load_config(d1)
    reg2 = load_config(d2)
    assert set(reg1.inbound) == {"in_a"}
    assert set(reg2.inbound) == {"in_b"}  # distinct modules, no clobber despite same stem "cfg"
    assert len({k for k in sys.modules if k.startswith("mefor_config_cfg_")}) >= 2


def test_failed_module_not_left_in_sys_modules(tmp_path: Path) -> None:
    _write(tmp_path, "raise RuntimeError('boom')\n")
    before = {k for k in sys.modules if k.startswith("mefor_config_")}
    with pytest.raises(WiringError):
        load_config(tmp_path)
    assert {k for k in sys.modules if k.startswith("mefor_config_")} == before  # cleaned up


# --- config source trust (CONFIG-2) ------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits; Windows uses NTFS ACLs")
def test_load_config_refuses_group_or_world_writable_dir(tmp_path: Path) -> None:
    _write(tmp_path, _MINIMAL.format(name="in"))
    os.chmod(tmp_path, 0o777)  # world-writable: anyone could drop a malicious module to be exec'd
    with pytest.raises(WiringError, match="writable"):
        load_config(tmp_path)


# --- very-large-document streaming knobs (#149, ADR 0105 Phase 1a) -----------


def test_stream_threshold_must_be_positive() -> None:
    with pytest.raises(WiringError, match="stream_threshold_bytes must be > 0"):
        build_inbound_connection("in", MLLP(port=2575), router="r", stream_threshold_bytes=0)


def test_stream_threshold_hl7_only() -> None:
    # The detach targets OBX-5 documents, so it is meaningless on a non-HL7 content_type.
    with pytest.raises(WiringError, match="stream_threshold_bytes is HL7-specific"):
        build_inbound_connection(
            "in", MLLP(port=2575), router="r", content_type="json", stream_threshold_bytes=1024
        )


def test_max_message_bytes_must_be_positive() -> None:
    with pytest.raises(WiringError, match="max_message_bytes must be > 0"):
        build_inbound_connection("in", MLLP(port=2575), router="r", max_message_bytes=0)


def test_max_message_bytes_below_threshold_rejected() -> None:
    # A cap below the detach threshold would reject every message the threshold would detach.
    with pytest.raises(WiringError, match="must be >= stream_threshold_bytes"):
        build_inbound_connection(
            "in",
            MLLP(port=2575),
            router="r",
            stream_threshold_bytes=2048,
            max_message_bytes=1024,
        )


def test_streaming_knobs_accepted() -> None:
    ic = build_inbound_connection(
        "in",
        MLLP(port=2575),
        router="r",
        stream_threshold_bytes=1024,
        max_message_bytes=100 * 1024 * 1024,
    )
    assert ic.stream_threshold_bytes == 1024
    assert ic.max_message_bytes == 100 * 1024 * 1024


# --- #114: validate_directory works in BOTH directions ------------------------
#
# It was inbound-only for one reason — no destination read it, and DestinationConnector had no
# validate_startup hook — so an outbound carrying validate_directory=True was first silently ignored
# and then (2026-08-03) rejected outright. Both halves are built now, so the rejection is gone and the
# option is honoured on an outbound: the destination hook fails start on a missing target directory.


def _spec_with_validate_directory(kind: str, directory: str) -> ConnectionSpec:
    if kind == "file":
        return File(directory=directory, validate_directory=True)
    if kind == "sftp":
        return Sftp(host="sftp.example.org", remote_dir=directory, validate_directory=True)
    return Ftp(host="ftp.example.org", remote_dir=directory, validate_directory=True)


@pytest.mark.parametrize("kind", ["file", "sftp", "ftp"])
def test_outbound_validate_directory_now_builds(kind: str, tmp_path: Path) -> None:
    spec = _spec_with_validate_directory(kind, str(tmp_path / "out"))
    oc = build_outbound_connection("OB_X", spec)
    assert oc.spec.settings["validate_directory"] is True  # reaches the connector, not rejected


@pytest.mark.parametrize("kind", ["file", "sftp", "ftp"])
def test_inbound_validate_directory_still_builds(kind: str, tmp_path: Path) -> None:
    # The guard must not over-reject: the inbound half (ADR 0031 amendment) still honours the option.
    spec = _spec_with_validate_directory(kind, str(tmp_path / "in"))
    ic = build_inbound_connection("IB_X", spec, router="r")
    assert ic.spec.settings["validate_directory"] is True


@pytest.mark.parametrize("kind", ["file", "sftp", "ftp"])
def test_outbound_without_validate_directory_is_unaffected(kind: str, tmp_path: Path) -> None:
    # The factories write validate_directory=False into settings unconditionally, so the toggle has to
    # be truthy-only — every outbound authored today must keep building byte-identically.
    directory = str(tmp_path / "out")
    spec = (
        File(directory=directory)
        if kind == "file"
        else Sftp(host="h", remote_dir=directory)
        if kind == "sftp"
        else Ftp(host="h", remote_dir=directory)
    )
    assert spec.settings["validate_directory"] is False  # present, but false
    oc = build_outbound_connection("OB_X", spec)
    assert oc.name == "OB_X"
