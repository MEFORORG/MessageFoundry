# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5391, S19-75: a ``serve`` boot runs the operator's config modules once.

With a project root set and no ``environments/<env>.toml``, the ADR 0050 AC-3 check loads the graph
to ask whether it references ``env()``, and ``load_config`` executes every config module. The API
lifespan's first load then executed them again. ``serve`` now hands the AC-3 graph to the lifespan.

The module under test appends one line to a counter file each time it runs. The real
``create_managed_app`` runs, and its lifespan runs in a ``TestClient`` in place of ``uvicorn.run``.
The control drops the handed-over graph, as the code before the fix had none, and counts two.
"""

from __future__ import annotations

import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import messagefoundry.api as api_mod
from messagefoundry.__main__ import main
from messagefoundry.config.wiring import Registry

_COUNTING_GRAPH = """
    from pathlib import Path

    from messagefoundry import inbound, outbound, MLLP, router, handler, Send

    with Path({counter!r}).open("a", encoding="utf-8") as _f:
        _f.write("ran" + chr(10))

    inbound("IB_T", MLLP(port=0), router="r")
    outbound("OB_T", MLLP(host="10.0.0.1", port=6000))

    @router(name="r")
    def r(msg):
        return ["h"]

    @handler(name="h")
    def h(msg):
        return [Send("OB_T", msg.raw)]
"""


def _boot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    keep: Callable[[Registry | None], Registry | None],
) -> tuple[int, int, list[Registry | None]]:
    counter = tmp_path / "ran.txt"
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text(
        textwrap.dedent(_COUNTING_GRAPH.format(counter=str(counter))), encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_SECURITY_BLOCK_UNLISTED_OUTBOUND", "true")
    # Comma-separated: a JSON list here is refused at load (BACKLOG #5915).
    monkeypatch.setenv("MEFOR_EGRESS_ALLOWED_MLLP", "10.0.0.1")
    monkeypatch.setenv("MEFOR_SECURITY_ENFORCEMENT", "warn")
    monkeypatch.setenv("MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI", "true")
    monkeypatch.setenv("MEFOR_ALERTS_SECURITY_NOTIFICATIONS_REQUIRED", "false")
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    real = api_mod.create_managed_app
    handed: list[Registry | None] = []

    def app(**kwargs: object) -> object:
        # Passed on only when kept, so the same harness runs against a create_managed_app that
        # has no such parameter, the code before the fix.
        graph = kwargs.pop("start_registry", None)
        assert graph is None or isinstance(graph, Registry)
        handed.append(graph)
        if (kept := keep(graph)) is not None:
            kwargs["start_registry"] = kept
        return real(**kwargs)  # type: ignore[arg-type]

    def run(asgi: object, *args: object, **kwargs: object) -> None:
        with TestClient(asgi):  # type: ignore[arg-type]
            pass

    monkeypatch.setattr(api_mod, "create_managed_app", app)
    monkeypatch.setattr("uvicorn.run", run)
    monkeypatch.setattr("messagefoundry.last_resort.install_excepthook", lambda: None)
    rc = main(
        [
            "serve",
            "--project-root",
            str(tmp_path),
            "--config",
            str(cfg),
            "--env",
            "dev",
            "--db",
            "mf.db",
        ]
    )
    runs = counter.read_text(encoding="utf-8").splitlines() if counter.exists() else []
    return rc, len(runs), handed


def test_a_serve_boot_runs_the_config_modules_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rc, runs, handed = _boot(tmp_path, monkeypatch, keep=lambda graph: graph)
    assert rc == 0
    assert runs == 1
    assert [type(graph) for graph in handed] == [Registry]


def test_control_without_the_handed_graph_the_modules_run_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The shape before the fix: the lifespan loads the directory itself.
    rc, runs, _handed = _boot(tmp_path, monkeypatch, keep=lambda graph: None)
    assert rc == 0
    assert runs == 2


def test_create_managed_app_refuses_a_handed_graph_on_a_clustered_start(tmp_path: Path) -> None:
    # vault BACKLOG #3076: the refusal sits beside the lifespan's seed, not only in serve.
    from messagefoundry.config.settings import ClusterSettings, EgressSettings

    egress = EgressSettings(deny_by_default=False)

    with pytest.raises(ValueError, match="clustered start"):
        api_mod.create_managed_app(
            db_path=tmp_path / "mf.db",
            config_dir=tmp_path,
            start_registry=Registry(),
            egress_settings=egress,
            cluster_settings=ClusterSettings(enabled=True, node_id="n1"),
        )
    # The control: the same call on a single node builds the app.
    api_mod.create_managed_app(
        db_path=tmp_path / "mf.db",
        config_dir=tmp_path,
        start_registry=Registry(),
        egress_settings=egress,
    )
