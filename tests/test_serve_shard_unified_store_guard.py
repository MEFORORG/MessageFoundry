# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ADR 0063 no-split-store guard is reachable from the `serve --shard` entrypoint (BACKLOG #1112).

``require_unified_store`` refuses a >1-engine-shard config on a single-file store. It had exactly two
call sites, both on the supervisor path (``discover_shard_specs``), so ``supervise`` refused a config
that a hand-run ``serve --shard a`` + ``serve --shard b`` over one SQLite file ran happily. This file
pins the entrypoint arm.

NOT in ``tests/test_sharding.py``: that file owns ``messagefoundry/pipeline/sharding.py``, the pure
module (shard tag, filter, discovery, and the guard's own unit behaviour). The subject here is the
CLI's WIRING of that guard into the registry filter it hands the engine, which is ``__main__.py``
behaviour. ``test_sharding.py`` imports no ``main``.

**Scope, stated so nobody reads more into a green run than is here.** This arm narrows the defect; it
does not close it. Two plain ``serve`` processes over one SQLite file remain unguarded (and are
worse: an unsharded registry yields ``owned=None``, so the second process's startup
``reset_stale_inflight`` re-pends every in-flight row store-wide). Closing that needs a single-writer
guard at store open, a different mechanism and a separate subject.

Every test names its red mutation, because the negative controls are what carry this file: a change
that refuses EVERY sharded start passes every positive assertion here on its own.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import StoreBackend
from messagefoundry.config.wiring import (
    MLLP,
    File,
    Registry,
    WiringError,
    build_inbound_connection,
    build_outbound_connection,
)
from messagefoundry.pipeline.sharding import require_unified_store, shard_ids
from messagefoundry.pipeline.supervisor import discover_shard_specs

_SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"

# `[cluster]` is not involved here, but a server-DB backend needs its connection essentials to pass
# settings validation. Nothing is dialed: create_managed_app is stubbed, so no store is ever opened.
#
# Both bodies carried `handles_real_patient_data = false` until BACKLOG #1279 retired it. These
# fixtures need a `serve` that REACHES create_managed_app, so they now satisfy the PHI gates
# per-gate instead. `tests/_phi_gate_provisions.py` documents what each line stands down.
_PHI_GATES = (
    "security.block_unlisted_outbound = true\n"
    "security.allow_unencrypted_phi = true\n"
    "security.allow_unencrypted_phi_under_strict_enforcement = true\n"
    "alerts.security_notifications_required = false\n"
)
_SQLITE_TOML = _PHI_GATES
_POSTGRES_TOML = (
    _PHI_GATES
    + '[store]\nbackend = "postgres"\nserver = "127.0.0.1"\ndatabase = "mf"\nusername = "mf"\n'
)


def _inb(name: str, port: int, *, shard: str | None = None) -> Any:
    return build_inbound_connection(name, MLLP(port=port), router="r", shard=shard)


def _registry(*shards: str | None) -> Registry:
    """A registry whose inbounds carry ``shards`` (``None`` = untagged -> the default shard)."""
    reg = Registry()
    for index, shard in enumerate(shards):
        reg.add_inbound(_inb(f"ib_{index}", 2575 + index, shard=shard))
    reg.add_outbound(build_outbound_connection("ob", File(directory=".")))
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: None)
    return reg


def _serve_registry_filter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    toml_body: str,
    shard: str | None,
) -> Callable[[Registry], Registry] | None:
    """Run the real `serve` gate and return the ``registry_filter`` it hands ``create_managed_app``.

    Capturing the production object is the point: a reimplementation of the closure here would pass
    while the entrypoint stayed unguarded, which is exactly the bug under test.
    """
    from messagefoundry.__main__ import main

    monkeypatch.chdir(tmp_path)
    (tmp_path / "messagefoundry.toml").write_text(toml_body, encoding="utf-8")
    captured: dict[str, Any] = {}

    def _fake_create_managed_app(**kwargs: Any) -> object:
        captured["registry_filter"] = kwargs.get("registry_filter")
        return object()

    monkeypatch.setattr("messagefoundry.api.create_managed_app", _fake_create_managed_app)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)

    argv = ["serve", "--config", str(_SAMPLES_CONFIG), "--env", "dev"]
    if shard is not None:
        argv += ["--shard", shard]
    assert main(argv) == 0, "the serve gate must reach create_managed_app for this fixture"
    assert "registry_filter" in captured, "create_managed_app was never called"
    result: Callable[[Registry], Registry] | None = captured["registry_filter"]
    return result


# --- the entrypoint arm ------------------------------------------------------


def test_serve_shard_refuses_multi_engine_shard_config_on_sqlite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # THE ROW. Two hand-run `serve --shard` processes over one SQLite file would be two writers on a
    # store ADR 0063 forbids splitting, and the direct entrypoint reached no call site of the guard
    # that exists to refuse exactly that. Now it does, and it fails CLOSED (the process cannot build
    # its graph).
    # RED MUTATION: drop the require_unified_store call from the __main__ --shard closure. The filter
    # then returns a filtered Registry and this raises nothing.
    filt = _serve_registry_filter(tmp_path, monkeypatch, toml_body=_SQLITE_TOML, shard="a")
    assert filt is not None
    with pytest.raises(WiringError) as excinfo:
        filt(_registry("a", "b"))
    message = str(excinfo.value)
    # Names what is wrong and both ways out — the register require_unified_store already sets.
    assert "requires a server-DB" in message
    assert "postgres" in message and "sqlserver" in message
    assert "run a single un-sharded engine" in message
    # And the entrypoint-specific half: why one shard of a multi-shard config is not a workaround.
    assert "serve --shard a" in message
    assert "no delivery consumer" in message


def test_serve_shard_refusal_is_a_wiring_error_not_a_bare_value_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # WiringError is the type the engine already raises for "this config cannot run in this process"
    # (Engine.reload's ADR 0073 shard-set refusal), and /config/reload catches WiringError
    # SPECIFICALLY to return a clean 422. The filter is re-applied on EVERY reload, so a bare
    # ValueError escaping here would fall through that handler and surface as a 500.
    #
    # The catch is deliberately the WIDE type. `WiringError` subclasses `ValueError`
    # (config/wiring.py), so `pytest.raises(WiringError)` alone would still discriminate, but
    # catching ValueError and asserting the narrow type states the contract the route depends on:
    # what is raised must be the subclass, not merely the base.
    # RED MUTATION: drop the `raise WiringError(...) from exc` wrapper and let require_unified_store's
    # ValueError escape. `pytest.raises(ValueError)` still passes; the isinstance assertion reds.
    filt = _serve_registry_filter(tmp_path, monkeypatch, toml_body=_SQLITE_TOML, shard="a")
    assert filt is not None
    with pytest.raises(ValueError) as excinfo:  # noqa: PT011 (narrowed by the assertion below)
        filt(_registry("a", "b"))
    assert isinstance(excinfo.value, WiringError), (
        "the reload route catches WiringError specifically; a bare ValueError would be a 500"
    )
    # The original guard message is preserved as the cause, not swallowed.
    assert isinstance(excinfo.value.__cause__, ValueError)
    assert "requires a server-DB" in str(excinfo.value.__cause__)


# --- negative controls: these carry the file ---------------------------------
#
# Without both, a closure that refused EVERY sharded start would pass every assertion above.


def test_serve_shard_still_starts_a_single_engine_shard_on_sqlite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # NEGATIVE CONTROL 1. One engine shard on SQLite is one writer on one store — the guard's own
    # allowed case, and byte-identical to plain serve: filter_registry_for_shard attaches NO shard
    # identity below two shards, so none of the ADR 0073 sharded behaviours arm.
    # RED MUTATION: make the closure refuse on len(shard_ids) >= 1 (or drop the distinct-count test
    # inside require_unified_store). This reds; the positive test above stays green.
    filt = _serve_registry_filter(tmp_path, monkeypatch, toml_body=_SQLITE_TOML, shard="a")
    assert filt is not None
    filtered = filt(_registry("a", "a"))  # one DISTINCT shard, two inbounds on it
    assert sorted(filtered.inbound) == ["ib_0", "ib_1"]
    assert filtered.shard_id is None
    assert filtered.all_shard_ids is None


def test_serve_shard_still_starts_an_untagged_config_on_sqlite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # NEGATIVE CONTROL 1b. An UNTAGGED config resolves to the implicit DEFAULT_SHARD, so
    # `serve --shard default` against it is a single engine shard and must start unchanged. This is
    # the shape `supervise` spawns for an unsharded config, and the shape a shard-count-blind guard
    # would break first.
    # RED MUTATION: have the closure key on args.shard being set rather than on the config's distinct
    # shard count. This reds immediately.
    filt = _serve_registry_filter(tmp_path, monkeypatch, toml_body=_SQLITE_TOML, shard="default")
    assert filt is not None
    filtered = filt(_registry(None, None))
    assert sorted(filtered.inbound) == ["ib_0", "ib_1"]
    assert filtered.shard_id is None


def test_serve_shard_still_starts_a_multi_engine_shard_config_on_a_server_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # NEGATIVE CONTROL 2. The SUPPORTED multi-engine-shard deployment: every shard on ONE unified
    # server-DB store. It must start, and it must arm the ADR 0073 shard identity (the guard is about
    # the store backend, never about disabling sharding).
    # RED MUTATION: make the closure refuse whenever more than one shard is declared, ignoring the
    # backend. This reds; the SQLite positive test stays green.
    filt = _serve_registry_filter(tmp_path, monkeypatch, toml_body=_POSTGRES_TOML, shard="a")
    assert filt is not None
    filtered = filt(_registry("a", "b"))
    assert sorted(filtered.inbound) == ["ib_0"]
    assert filtered.shard_id == "a"
    assert filtered.all_shard_ids == ("a", "b")


def test_plain_serve_installs_no_registry_filter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # NEGATIVE CONTROL 3. Without --shard there is no closure at all, so the unsharded engine is
    # untouched by this change — no guard, no filter, the whole graph.
    # RED MUTATION: hoist the guard out of the --shard branch into the unconditional serve path. The
    # filter stops being None and this reds.
    assert _serve_registry_filter(tmp_path, monkeypatch, toml_body=_SQLITE_TOML, shard=None) is None


# --- the supervisor path must not have moved ---------------------------------


def test_supervisor_path_still_refuses_multi_engine_shard_on_sqlite(tmp_path: Path) -> None:
    # REGRESSION PIN. The entrypoint arm must not have changed the path that already worked:
    # discover_shard_specs still refuses before it builds a single ShardSpec.
    # RED MUTATION: remove the require_unified_store call from discover_shard_specs.
    config = tmp_path / "config"
    config.mkdir()
    (config / "graph.py").write_text(
        "from messagefoundry import MLLP, Send, handler, inbound, outbound, router\n"
        "\n"
        'inbound("IB_A", MLLP(port=2575), router="r", shard="a")\n'
        'inbound("IB_B", MLLP(port=2576), router="r", shard="b")\n'
        'outbound("OB", MLLP(host="127.0.0.1", port=2600))\n'
        "\n"
        '@router("r")\n'
        "def route(msg):\n"
        '    return ["h"]\n'
        "\n"
        '@handler("h")\n'
        "def handle(msg):\n"
        '    return Send("OB", msg)\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="requires a server-DB"):
        discover_shard_specs(
            str(config),
            store_backend=StoreBackend.SQLITE,
            db_base=str(tmp_path / "mf.db"),
            base_port=8765,
        )
    # And the same config on a server DB still builds both specs (the supervisor's own control).
    specs = discover_shard_specs(
        str(config),
        store_backend=StoreBackend.POSTGRES,
        db_base=str(tmp_path / "mf.db"),
        base_port=8765,
    )
    assert sorted(s.shard for s in specs) == ["a", "b"]


def test_guard_and_entrypoint_agree_on_the_same_inputs() -> None:
    # The entrypoint passes require_unified_store the WHOLE config's shard ids, not the filtered
    # slice — a filtered registry names one shard, which would silently never refuse.
    # RED MUTATION: pass shard_ids(filter_registry_for_shard(reg, shard)) instead. The distinct count
    # drops to 1 and the guard becomes inert; this test states the input contract it would break.
    reg = _registry("a", "b")
    assert shard_ids(reg) == ["a", "b"]
    with pytest.raises(ValueError, match="2 shards"):
        require_unified_store(StoreBackend.SQLITE, shard_ids(reg))
