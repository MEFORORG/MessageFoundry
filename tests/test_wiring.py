# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Code-first wiring: the registry + loader for inbound/outbound/router/handler."""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.wiring import (
    API_LISTENER_LABEL,
    MLLP,
    PortConflictError,
    Registry,
    WiringError,
    build_inbound_connection,
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
