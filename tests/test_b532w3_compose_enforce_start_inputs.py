# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The compose engines name what an enforcing ``serve --env prod`` start needs (BACKLOG #5400 item 7).

The parity target is the k8s manifests' block *what an enforcing start needs* (BACKLOG #5934,
#5935), pinned by ``tests/test_k8s_enforce_start_inputs.py``. ``[security].enforcement`` defaults
to ``enforce`` and nothing in ``docker/compose.yaml`` lowers it, so the default ``engine`` and the
two ``ha`` engines are refused until at least an alert channel, verified-TLS log forwarding to an
allowlisted collector, bounded retention, and, on the Postgres hop, a store CRL are set. Before
this item the compose file named none of them. The parity target's docstring says why
the writable spool mount is pinned apart from those gates.

As in the manifests, the inputs only a site can supply ship as COMMENTED entries, because a
placeholder would pass these gates and start an engine whose notices and logs go nowhere. So two
things are pinned: each engine as shipped still fails those gates closed, and with the block
filled in it passes them. The same predicates ``serve`` uses are called; ``serve`` itself is not
started, so a gate that reads the host is not exercised here.
"""

from __future__ import annotations

import copy
import functools
import itertools
import posixpath
import re
import tempfile
from collections.abc import Iterator
from typing import Any

import pytest

from messagefoundry.config.retention_classification import evaluate_retention_gate
from messagefoundry.config.settings import ServiceSettings, forwarding_gate_refusal
from messagefoundry.pipeline.alert_sinks import (
    alert_host_allowed,
    configured_alert_transport_names,
)
from messagefoundry.transports.egress import syslog_forward_refusal
from tests.test_compose_revocation_attestation import (
    _COMPOSE,
    _all_services,
    _compose_doc,
    _serving_engines,
)
from tests.test_k8s_enforce_start_inputs import (
    _BLOCK,
    _FILLED,
    _channel_ready,
    _image_store_path,
    _load,
)
from tests.test_k8s_enforce_start_inputs import (
    _site_entries as _k8s_site_entries,
)

_HA_POSTGRES = "ha-postgres.yaml"
#: Each serving engine -> (the text that opens its environment block, its k8s parity manifest).
#: The ha engines share x-ha-engine-env; only they, like ha-postgres.yaml, run the Postgres store.
_ENGINES = {
    "engine": ("  engine:\n", "statefulset.yaml"),
    "engine-ha": ("x-ha-engine-env: &ha-engine-env\n", _HA_POSTGRES),
    "engine-standby": ("x-ha-engine-env: &ha-engine-env\n", _HA_POSTGRES),
}
_COMMENTED_ENTRY = re.compile(r'^\s*# (MEFOR_[A-Z0-9_]+): "([^"]*)"\s*$', re.MULTILINE)


def _postgres(service: str) -> bool:
    return _ENGINES[service][1] == _HA_POSTGRES


def _literal_env(service: str) -> dict[str, str]:
    """The service's environment, less compose substitutions, which serve never sees as written."""
    env = _all_services()[service].get("environment") or {}
    return {k: str(v) for k, v in env.items() if not str(v).startswith("${")}


@functools.cache
def _block_entries(service: str) -> tuple[tuple[str, str], ...]:
    text = _COMPOSE.read_text(encoding="utf-8")
    start = text.index(_BLOCK, text.index(_ENGINES[service][0]))
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


@pytest.fixture(params=sorted(_ENGINES))
def shipped(request: pytest.FixtureRequest) -> Iterator[tuple[str, ServiceSettings]]:
    yield from _settings(str(request.param), fill=False)


@pytest.fixture(params=sorted(_ENGINES))
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


def _writable_sources(service: str) -> set[str]:
    """The named volumes and bind sources the service mounts writable."""
    out: set[str] = set()
    for vol in _all_services()[service].get("volumes") or []:
        if isinstance(vol, dict):
            if vol.get("source") and not vol.get("read_only"):
                out.add(str(vol["source"]))
            continue
        parts = str(vol).split(":")
        if len(parts) > 1 and (len(parts) == 2 or "ro" not in parts[2].split(",")):
            out.add(parts[0])
    return out


_ANCHOR = _compose_doc().get("x-ha-engine") or {}


def _anchored(doc: dict[str, Any]) -> list[str]:
    """The services built on x-ha-engine: the ha profile's services that run the anchor's image and
    read its env_file. revocation-attestation-check-ha runs that image too, but merges the default
    check, not the anchor, and deliberately mounts nothing."""
    anchor = doc.get("x-ha-engine") or {}
    return sorted(
        name
        for name, svc in doc["services"].items()
        if "ha" in (svc.get("profiles") or [])
        and svc.get("image") == anchor.get("image")
        and svc.get("env_file") == anchor.get("env_file")
    )


def _dropped_anchor_mounts(doc: dict[str, Any]) -> dict[str, list[Any]]:
    """Per service built on x-ha-engine, the anchor mounts its own ``volumes`` no longer carries."""
    anchor = (doc.get("x-ha-engine") or {}).get("volumes") or []
    assert anchor, "positive control: x-ha-engine declares mounts"
    out: dict[str, list[Any]] = {}
    for name in _anchored(doc):
        mounts = doc["services"][name].get("volumes") or []
        out[name] = [m for m in anchor if m not in mounts]
    return out


def test_every_anchored_service_keeps_every_anchor_mount() -> None:
    # The ha engines replace x-ha-engine's volumes to add their spools, so each must still carry
    # every mount the anchor declares; schema-provision inherits them.
    doc = _compose_doc()
    assert {"schema-provision", "engine-ha", "engine-standby"} <= set(_anchored(doc)), (
        "positive control: the anchored services are found"
    )
    dropped = _dropped_anchor_mounts(doc)
    assert not any(dropped.values()), f"a service dropped an anchor mount: {dropped}"


@pytest.mark.parametrize("index", range(len(_ANCHOR.get("volumes") or [])))
@pytest.mark.parametrize("name", ("schema-provision", "engine-ha", "engine-standby"))
def test_the_anchor_mount_check_sees_a_dropped_mount(name: str, index: int) -> None:
    """Negative control: the check above fails once a service's copy of any anchor mount is gone."""
    doc = copy.deepcopy(_compose_doc())
    removed = doc["x-ha-engine"]["volumes"][index]
    # A new list: schema-provision's inherited list is the anchor's own object, even deep-copied.
    svc = doc["services"][name]
    svc["volumes"] = [m for m in svc["volumes"] if m != removed]
    assert _dropped_anchor_mounts(doc)[name] == [removed]


def test_no_two_serving_engines_share_a_writable_volume() -> None:
    # The spool locks its directory, so two engines writing one volume, at the spool path or
    # anywhere above it, would leave the second without a spool. The default engine has no
    # profile, so it runs beside the ha pair under --profile ha and is compared too.
    sources = {n: _writable_sources(n) for n in sorted(_ENGINES)}
    assert all(sources.values()), "positive control: each engine mounts a writable volume"
    for a, b in itertools.combinations(sources, 2):
        shared = sources[a] & sources[b]
        assert not shared, f"{a} and {b} share a writable volume: {sorted(shared)}"


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
        manifest = _ENGINES[name][1]
        expected = _k8s_site_entries(manifest)
        got = _site_entries(name)
        assert got == expected, f"{name} vs {manifest}: {set(got.items()) ^ set(expected.items())}"
