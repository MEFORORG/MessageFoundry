# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The container image has a variant that can open the Postgres store (BACKLOG #5933).

The Postgres store imports ``asyncpg`` at open, and ``asyncpg`` is the ``[postgres]`` extra. The slim
default image installs ``docker/locks/requirements-core.lock``, which carries no ``asyncpg``, so the
``ha`` compose profile and ``docker/k8s/ha-postgres.yaml``, which both run the Postgres store, could
not start on it. These assertions read the files only. The build itself and the import of
``asyncpg`` inside the built image run in ci.yml's ``docker-smoke`` job, which only a hosted runner
executes.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[1]
_DOCKERFILE = _ROOT / "docker" / "Dockerfile"
_LOCK = "docker/locks/requirements-postgres.lock"
_STAGE = "runtime-postgres"


def _stages() -> dict[str, list[str]]:
    """Each named stage's instruction lines, continuation lines joined."""
    joined = re.sub(r"\\\n", " ", _DOCKERFILE.read_text(encoding="utf-8"))
    stages: dict[str, list[str]] = {}
    current: list[str] | None = None
    for raw in joined.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if match := re.match(r"FROM\s+(?:--\S+\s+)*\S+\s+AS\s+(\S+)$", line, re.IGNORECASE):
            current = stages.setdefault(match.group(1).lower(), [])
        if current is not None:
            current.append(line)
    return stages


def _parent(stage: list[str]) -> str:
    return stage[0].split()[1].lower()


def test_the_postgres_lock_pins_asyncpg_with_hashes() -> None:
    text = (_ROOT / _LOCK).read_text(encoding="utf-8")
    assert re.search(r"^asyncpg==\S+", text, re.MULTILINE), f"{_LOCK} pins no asyncpg"
    assert "--hash=sha256:" in text, f"{_LOCK} carries no hashes"
    assert f"-o {_LOCK}" in text.splitlines()[1], "the header must name the path DEP-1 exports"


def test_the_postgres_runtime_stage_installs_the_postgres_lock() -> None:
    stages = _stages()
    assert _STAGE in stages, f"docker/Dockerfile has no {_STAGE} stage"
    runtime = stages[_STAGE]
    assert _parent(runtime) == "runtime-base", f"{_STAGE} must build on the hardened runtime-base"
    copies = [ln for ln in runtime if ln.upper().startswith("COPY") and "/opt/venv" in ln]
    assert len(copies) == 1, f"{_STAGE} must copy exactly one venv, found {copies}"
    source = re.search(r"--from=(\S+)", copies[0])
    assert source, copies[0]
    assert "--chown=0:0" in copies[0], (
        "the venv must stay root-owned, as the other runtimes copy it"
    )
    builder = stages[source.group(1).lower()]
    lock_copies = [ln for ln in builder if ln.upper().startswith("COPY") and _LOCK in ln]
    assert lock_copies, f"the {source.group(1)} stage never copies {_LOCK}"
    assert any("--require-hashes" in ln for ln in builder), "the lock must install hash-checked"


def test_the_slim_default_stays_the_last_stage() -> None:
    """A bare ``docker build`` must still produce the slim image."""
    assert list(_stages())[-1] == "runtime"


def test_the_ha_compose_engines_run_the_postgres_variant() -> None:
    compose = yaml.safe_load((_ROOT / "docker" / "compose.yaml").read_text(encoding="utf-8"))
    ha = compose["x-ha-engine"]
    assert compose["x-ha-engine-env"]["MEFOR_STORE_BACKEND"] == "postgres"
    assert ha["image"] == "messagefoundry:postgres", (
        "the ha engines run the Postgres store, which the slim messagefoundry:latest cannot open"
    )


def test_the_ha_manifest_names_the_postgres_variant() -> None:
    text = (_ROOT / "docker" / "k8s" / "ha-postgres.yaml").read_text(encoding="utf-8")
    assert "FROM messagefoundry:postgres" in text
    assert "the Postgres store needs only the slim default" not in text
