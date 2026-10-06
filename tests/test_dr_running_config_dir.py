# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A DR activation follows the running config dir, and fingerprints it off the event loop.

vault BACKLOG #2840: ``Engine._dr_activate_profile`` reloaded the STARTUP config dir. After an
operator reload from a second allowed directory, a DR activation would have swapped the older graph
back in, with nothing telling anyone. It now reloads :attr:`Engine.running_config_dir`.

vault BACKLOG #2839: the ``Engine.dr_coordinator`` property fingerprinted the startup dir itself,
synchronously on the event loop, catching only ``OSError``. A config file name that cannot be
encoded as UTF-8 raises ``UnicodeEncodeError`` (a ``ValueError``) in the fold, so the first
``POST /dr/activate`` or ``/dr/release`` would have failed. The seed marker's digest now comes from
``Engine.fingerprint_bundle`` at activation, over the directory the activation reloads.
"""

from __future__ import annotations

import json
import shutil
import threading
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from messagefoundry.config import fingerprint as fp
from messagefoundry.config.settings import DrSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.dr import DrActivationError
from tests.test_dr_activation import _seed

# A name that cannot be encoded as UTF-8: a lone surrogate. NTFS stores it as UTF-16, and on a
# POSIX file system Python writes it as the raw byte 0x80. Under environments/ it is fingerprinted
# (environments/*.toml is in the fold) but never loaded, so the graph still builds.
_BAD_NAME = "x\udc80.toml"


def _write_graph(cfg: Path, tmp_path: Path, inbound: str) -> None:
    inbox = tmp_path / f"in-{inbound}"
    outdir = tmp_path / f"out-{inbound}"
    for d in (cfg, inbox, outdir):
        d.mkdir(parents=True, exist_ok=True)
    (cfg / "cfg.py").write_text(
        "from messagefoundry import inbound, outbound, router, handler, Send, File\n"
        f"inbound({inbound!r}, File(directory={str(inbox)!r}, pattern='*.hl7', "
        "poll_seconds=1.0), router='r')\n"
        f"outbound('FILE-OUT_T_ADT', File(directory={str(outdir)!r}))\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('FILE-OUT_T_ADT', msg)\n",
        encoding="utf-8",
    )


class _Box(NamedTuple):
    engine: Engine
    live: Path
    staging: Path


@pytest.fixture
async def box(tmp_path: Path) -> AsyncIterator[_Box]:
    """A DR box started from ``live``, with ``staging`` as a second allowed reload root. The store
    is encrypted and carries a cold-seed archive of itself, so an activation clears its gates."""
    live = tmp_path / "live"
    staging = tmp_path / "staging"
    _write_graph(live, tmp_path, "IB_LIVE_ADT")
    _write_graph(staging, tmp_path, "IB_STAGING_ADT")
    store, archive, ss = await _seed(tmp_path)
    engine = Engine(
        store,
        poll_interval=0.05,
        config_dir=live,
        config_reload_roots=[str(staging)],
        store_settings=ss,
        dr_settings=DrSettings(enabled=True, activate=False, seed_archive=archive),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        yield _Box(engine, live, staging)
    finally:
        await engine.stop()


def _inbound_names(engine: Engine) -> set[str]:
    rr = engine.registry_runner
    assert rr is not None
    return set(rr.registry.inbound)


async def _seed_marker(engine: Engine) -> dict[str, object]:
    rows = await engine.store.list_audit(action="dr_seed")
    assert len(rows) == 1
    marker: dict[str, object] = json.loads(rows[0]["detail"])
    return marker


async def test_a_dr_activation_keeps_the_graph_an_operator_reloaded(box: _Box) -> None:
    """Red before #2840: the activation reloaded ``live`` and IB_LIVE_ADT came back."""
    engine = box.engine
    await engine.reload_detail(box.live)
    assert _inbound_names(engine) == {"IB_LIVE_ADT"}  # control: the startup graph went live
    await engine.reload_detail(box.staging)  # the operator's deliberate reload
    assert _inbound_names(engine) == {"IB_STAGING_ADT"}

    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")

    assert engine.dr_active is True
    assert _inbound_names(engine) == {"IB_STAGING_ADT"}
    assert engine.last_reload_dir == box.staging.resolve()


async def test_convergence_still_reloads_the_startup_dir(box: _Box) -> None:
    """#2840 changes only the DR reload. Each node converges on its own startup dir, so a
    convergence after an operator reload from another root still loads ``live``."""
    engine = box.engine
    await engine.reload_detail(box.staging)
    assert _inbound_names(engine) == {"IB_STAGING_ADT"}  # control: the operator's graph runs

    await engine._converge_reload()

    assert _inbound_names(engine) == {"IB_LIVE_ADT"}


async def test_a_removed_reload_dir_aborts_the_activation(box: _Box) -> None:
    """With the operator's directory gone, the activation aborts at the profile step with a
    recorded reason rather than falling back to the startup dir. The latch goes back off, and the
    seed marker records no digest rather than the digest of an empty bundle."""
    engine = box.engine
    await engine.reload_detail(box.staging)
    shutil.rmtree(box.staging)
    coord = engine.dr_coordinator
    assert coord is not None

    with pytest.raises(DrActivationError) as caught:
        await coord.activate(actor="alice")

    assert caught.value.kind == "profile"
    assert coord.active is False and engine.dr_active is False
    assert _inbound_names(engine) == {"IB_STAGING_ADT"}  # the running graph was not swapped
    assert len(await engine.store.list_audit(action="dr_activation_aborted")) == 1
    assert (await _seed_marker(engine))["config_fingerprint"] is None


async def test_the_seed_marker_fingerprints_the_directory_the_activation_reloads(
    box: _Box,
) -> None:
    """Red before #2839: the marker carried the startup dir's digest after a reload elsewhere."""
    engine = box.engine
    await engine.reload_detail(box.staging)
    coord = engine.dr_coordinator
    assert coord is not None
    await coord.activate(actor="alice")

    marker = await _seed_marker(engine)
    assert marker["config_fingerprint"] == fp.config_fingerprint(box.staging)
    assert marker["config_fingerprint"] != fp.config_fingerprint(box.live)  # the two differ


async def test_a_file_name_that_is_not_utf8_does_not_fail_dr(
    box: _Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red before #2839: reading ``dr_coordinator`` raised UnicodeEncodeError."""
    engine = box.engine

    async def drained() -> None:
        # The seeded store holds a row for a destination this graph lacks, so a real drain would
        # wait out its whole timeout. The release path under test is the coordinator, not the drain.
        return None

    monkeypatch.setattr(engine, "_drain_pipeline", drained)
    try:
        (box.live / "environments").mkdir()
        (box.live / "environments" / _BAD_NAME).write_text("", encoding="utf-8")
    except (OSError, UnicodeEncodeError) as exc:
        pytest.skip(f"this file system refuses a name that is not UTF-8: {type(exc).__name__}")
    with pytest.raises(UnicodeEncodeError):
        fp.config_fingerprint(box.live)  # control: the fold really refuses this bundle

    await engine.reload_detail(box.live)  # a reload tolerates it already (#2597)
    coord = engine.dr_coordinator
    assert coord is not None
    result = await coord.activate(actor="alice")
    assert result.active is True
    assert (await _seed_marker(engine))["config_fingerprint"] is None

    released = await coord.release(actor="alice")
    assert released.active is False


async def test_the_dr_fingerprint_is_not_taken_on_the_event_loop(
    box: _Box, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red before #2839: the property called config_fingerprint on the loop's own thread."""
    engine = box.engine
    await engine.reload_detail(box.live)
    loop_thread = threading.get_ident()
    seen: list[tuple[str, int]] = []

    def spy(name: str) -> Callable[[str | Path], Any]:
        real = getattr(fp, name)

        def wrapped(directory: str | Path) -> Any:
            seen.append((name, threading.get_ident()))
            return real(directory)

        return wrapped

    # Both: the old property called the plain one, fingerprint_bundle calls the detail one.
    for name in ("config_fingerprint", "config_fingerprint_detail"):
        monkeypatch.setattr(fp, name, spy(name))

    coord = engine.dr_coordinator
    assert coord is not None
    seen_before_activation = list(seen)
    await coord.activate(actor="alice")

    assert seen_before_activation == []  # building the coordinator read no file
    # Control: the marker carries a digest, which only the provider supplies, so the provider ran
    # and its fold is among the calls checked below (the reload's own fold is there too).
    assert isinstance((await _seed_marker(engine))["config_fingerprint"], str)
    assert all(thread != loop_thread for _name, thread in seen), seen
