# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The compose engines name what an enforcing ``serve --env prod`` start needs (BACKLOG #5400 item 7).

The parity target is the k8s manifests' block *what an enforcing start needs* (BACKLOG #5934,
#5935), pinned by ``tests/test_k8s_enforce_start_inputs.py``. ``[security].enforcement`` defaults
to ``enforce`` and nothing in ``docker/compose.yaml`` lowers it, so the default ``engine`` and the
two ``ha`` engines are refused until at least an alert channel, verified-TLS log forwarding to an
allowlisted collector with a writable spool, bounded retention, and, on the Postgres hop, a store
CRL are set. Before this item the compose file named none of them.

As in the manifests, the inputs only a site can supply ship as COMMENTED entries, because a
placeholder would pass these gates and start an engine whose notices and logs go nowhere. So two
things are pinned: each engine as shipped still fails those gates closed, and with the block
filled in it passes them. The same predicates ``serve`` uses are called; ``serve`` itself is not
started, so a gate that reads the host is not exercised here.
"""

from __future__ import annotations

import copy
import functools
import posixpath
import re
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from messagefoundry.config.retention_classification import evaluate_retention_gate
from messagefoundry.config.settings import ServiceSettings, forwarding_gate_refusal
from messagefoundry.pipeline.alert_sinks import (
    alert_host_allowed,
    configured_alert_transport_names,
)
from messagefoundry.transports.egress import syslog_forward_refusal
from tests.test_compose_revocation_attestation import _all_services, _serving_engines
from tests.test_k8s_enforce_start_inputs import (
    _channel_ready,
    _image_store_path,
    _load,
)
from tests.test_k8s_enforce_start_inputs import (
    _site_entries as _k8s_site_entries,
)

_ROOT = Path(__file__).resolve().parents[1]
_COMPOSE = _ROOT / "docker" / "compose.yaml"
_ENGINES = ("engine", "engine-ha", "engine-standby")
#: The ha engines share x-ha-engine-env, and only they run the Postgres store.
_HA_BLOCK = "x-ha-engine-env: &ha-engine-env\n"
_MANIFEST = {"engine": "statefulset.yaml"}  # the k8s parity target; the ha engines' is ha-postgres


def _postgres(service: str) -> bool:
    return service != "engine"


_BLOCK = "# --- what an enforcing start needs"
_COMMENTED_ENTRY = re.compile(r'^\s*# (MEFOR_[A-Z0-9_]+): "([^"]*)"\s*$', re.MULTILINE)
_FILLED = {"REPLACE-days": "30"}


def _literal_env(service: str) -> dict[str, str]:
    """The service's environment, less compose substitutions, which serve never sees as written."""
    env = _all_services()[service].get("environment") or {}
    return {k: str(v) for k, v in env.items() if not str(v).startswith("${")}


@functools.cache
def _block_entries(service: str) -> tuple[tuple[str, str], ...]:
    text = _COMPOSE.read_text(encoding="utf-8")
    opener = "  engine:\n" if service == "engine" else _HA_BLOCK
    start = text.index(_BLOCK, text.index(opener))
    lines = text[start:].splitlines()
    block: list[str] = []
    for n, line in enumerate(lines):
        if not line.strip().startswith("#") or (n and line.strip().startswith("# ---")):
            break  # the first live line, or the next section's header, ends the block
        block.append(line)
    found = tuple(_COMMENTED_ENTRY.findall("\n".join(block)))
    assert found, f"{service}: the enforcing-start block holds no commented entries"
    return found


def _site_entries(service: str) -> dict[str, str]:
    """The commented entries of the service's enforcing-start block, as a site would fill them."""
    return {key: _FILLED.get(value, value) for key, value in _block_entries(service)}


def _settings(service: str, fill: bool) -> Iterator[tuple[str, ServiceSettings]]:
    env = {**_literal_env(service), **(_site_entries(service) if fill else {})}
    with tempfile.TemporaryDirectory() as tmp:
        yield service, _load(env, tmp)


@pytest.fixture(params=_ENGINES)
def shipped(request: pytest.FixtureRequest) -> Iterator[tuple[str, ServiceSettings]]:
    yield from _settings(str(request.param), fill=False)


@pytest.fixture(params=_ENGINES)
def filled(request: pytest.FixtureRequest) -> Iterator[tuple[str, ServiceSettings]]:
    yield from _settings(str(request.param), fill=True)


def _retention_refusal(settings: ServiceSettings) -> str | None:
    outcome = evaluate_retention_gate(
        copy.deepcopy(settings), enforcing=True, production=True, env_name="prod"
    )
    return outcome.refusal


def test_every_serving_engine_is_covered() -> None:
    assert set(_serving_engines()) == set(_ENGINES)


def test_the_shipped_engine_still_fails_closed(shipped: tuple[str, ServiceSettings]) -> None:
    """No placeholder passes a gate: an unedited compose file is refused, as before this item."""
    name, settings = shipped
    assert not _channel_ready(settings), f"{name}: an unedited engine has an alert channel"
    assert forwarding_gate_refusal(settings.logging) is not None, name
    assert _retention_refusal(settings) is not None, f"{name}: passes the retention gate unedited"


def test_the_security_notice_channel_and_recipient_are_named(
    filled: tuple[str, ServiceSettings],
) -> None:
    name, settings = filled
    alerts = settings.alerts
    assert _channel_ready(settings), f"{name}: no out-of-band security-notification channel"
    assert alert_host_allowed(alerts.email_smtp_host or "", alerts.smtp_allowed_hosts), name
    assert configured_alert_transport_names(alerts), f"{name}: no [alerts] recipient"


def test_log_forwarding_is_verified_tls_to_an_allowlisted_collector(
    filled: tuple[str, ServiceSettings],
) -> None:
    name, settings = filled
    log = settings.logging
    assert forwarding_gate_refusal(log) is None, f"{name}: {forwarding_gate_refusal(log)}"
    assert log.forward_host is not None
    refusal = syslog_forward_refusal(log.forward_host, log.forward_port, settings.egress)
    assert refusal is None, f"{name}: {refusal}"


def _writable_mounts(service: str) -> list[str]:
    """Container paths of the service's volumes that are not read-only. A bare path is an
    anonymous volume, private to the container."""
    out: list[str] = []
    for vol in _all_services()[service].get("volumes") or []:
        if isinstance(vol, dict):
            if not vol.get("read_only"):
                out.append(str(vol["target"]))
            continue
        parts = str(vol).split(":")
        if len(parts) == 1:
            out.append(parts[0])
        elif len(parts) == 2 or "ro" not in parts[2].split(","):
            out.append(parts[1])
    return out


def test_the_forwarding_spool_is_on_a_writable_mount(
    filled: tuple[str, ServiceSettings],
) -> None:
    """The root file system is read-only, so the spool needs a volume the engine can write."""
    name, settings = filled
    root = settings.logging.forward_spool_dir or posixpath.join(
        posixpath.dirname(_image_store_path()), "log-spool"
    )
    writable = _writable_mounts(name)
    assert any(root == p or root.startswith(p.rstrip("/") + "/") for p in writable), (
        f"{name}: the spool root {root!r} is under no writable mount ({writable})"
    )


def test_the_ha_engines_do_not_share_a_spool_volume() -> None:
    # The spool locks its directory, so two engines on one named volume would leave one without
    # a spool. A bare container path is an anonymous volume each container gets its own of.
    root = posixpath.dirname(_image_store_path())
    for name in ("engine-ha", "engine-standby"):
        parts = [str(v).split(":", 2) for v in _all_services()[name].get("volumes") or []]
        named = [p[0] for p in parts if len(p) > 1 and p[1] == root]
        assert not named, f"{name} mounts a shared volume at {root}: {named}"


def test_retention_is_bounded(filled: tuple[str, ServiceSettings]) -> None:
    name, settings = filled
    refusal = _retention_refusal(settings)
    assert refusal is None, f"{name}: {refusal}"


def test_the_postgres_store_hop_names_a_crl(filled: tuple[str, ServiceSettings]) -> None:
    name, settings = filled
    if not _postgres(name):
        pytest.skip(f"{name} runs the SQLite store, which has no network hop")
    assert settings.store.backend.value == "postgres"
    assert settings.store.ssl_crl_file is not None, name


def test_the_trust_files_are_under_the_read_only_config() -> None:
    """The engine checks who can replace a CA, and /config is the root-owned read-only mount."""
    for name in _ENGINES:
        env = _site_entries(name)
        for key in ("MEFOR_LOGGING_FORWARD_TLS_CA_FILE", "MEFOR_LOGGING_FORWARD_TLS_CRL_FILE"):
            assert env.get(key, "").startswith("/config/"), f"{name}: {key}"
        if _postgres(name):
            assert env.get("MEFOR_STORE_SSL_CRL_FILE", "").startswith("/config/"), name


def test_the_block_matches_the_k8s_manifests() -> None:
    # Parity: the compose block names the same inputs as the manifest with the same store.
    for name in _ENGINES:
        manifest = _MANIFEST.get(name, "ha-postgres.yaml")
        expected = _k8s_site_entries(manifest)
        got = _site_entries(name)
        assert got == expected, f"{name} vs {manifest}: {set(got.items()) ^ set(expected.items())}"
