# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The k8s manifests name what an enforcing ``serve --env prod`` start needs (BACKLOG #5934, #5935).

``[security].enforcement`` defaults to ``enforce``, and neither ``--env prod`` nor either manifest
lowers it, so ``serve`` refuses to start until at least these hold: the API revocation attestation,
a security-notice channel with a recipient, verified-TLS log forwarding to an allowlisted
collector with a writable spool, bounded retention, and, on the Postgres hop, a store CRL. Before
these rows neither manifest named any of them.

Each manifest now carries a block of COMMENTED env entries for the inputs only a site can supply.
They are commented because a placeholder value would pass these gates and start an engine whose
notices and logs go nowhere. So two things are pinned here: the manifest as shipped still fails
those gates closed, and the manifest with the block filled in passes them.

The settings come from ``load_settings`` and go through the predicates ``serve`` uses where one
exists as a function: ``forwarding_gate_refusal``, ``syslog_forward_refusal``,
``evaluate_retention_gate``, ``alert_host_allowed``, ``configured_alert_transport_names`` and
``in_process_tls_revocation_refused``. The security-notice channel condition is restated from
``serve``, which keeps it inline. It does not start ``serve``, so a gate that reads the host, such
as the CA owner check or the store CRL load, is not exercised here.
"""

from __future__ import annotations

import copy
import posixpath
import re
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from messagefoundry.config.retention_classification import evaluate_retention_gate
from messagefoundry.config.settings import ServiceSettings, forwarding_gate_refusal, load_settings
from messagefoundry.config.tls_policy import in_process_tls_revocation_refused
from messagefoundry.pipeline.alert_sinks import (
    alert_host_allowed,
    configured_alert_transport_names,
)
from messagefoundry.transports.egress import syslog_forward_refusal

_ROOT = Path(__file__).resolve().parents[1]
_K8S = _ROOT / "docker" / "k8s"
_MANIFESTS = {"ha-postgres.yaml": True, "statefulset.yaml": False}  # name -> Postgres store
_ATTEST = "MEFOR_TLS_REVOCATION_ATTESTED"
_BLOCK = "# --- what an enforcing start needs"
_COMMENTED_ENTRY = re.compile(
    r'^\s*# - \{ name: (MEFOR_[A-Z0-9_]+), value: "([^"]*)" \}\s*$', re.MULTILINE
)
#: What a site would write for the one placeholder that is not a host name.
_FILLED = {"REPLACE-days": "30"}


def _pod_spec(name: str) -> dict[str, Any]:
    docs = [d for d in yaml.safe_load_all((_K8S / name).read_text(encoding="utf-8")) if d]
    workloads = [d for d in docs if d.get("kind") in {"Deployment", "StatefulSet"}]
    assert len(workloads) == 1, f"{name}: expected one workload, found {len(workloads)}"
    spec: dict[str, Any] = workloads[0]["spec"]["template"]["spec"]
    return spec


def _engine(name: str) -> dict[str, Any]:
    engines = [c for c in _pod_spec(name)["containers"] if c["name"] == "engine"]
    assert len(engines) == 1, f"{name}: expected one engine container"
    return engines[0]


def _image_store_path() -> str:
    """``MEFOR_STORE_PATH`` as the image sets it; the spool defaults beside it."""
    found = re.search(
        r"MEFOR_STORE_PATH=(\S+)", (_ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
    )
    assert found, "docker/Dockerfile no longer sets MEFOR_STORE_PATH"
    return found.group(1)


def _iter_env(name: str) -> Iterator[dict[str, Any]]:
    yield from _engine(name).get("env", [])


def _literal_env(name: str) -> dict[str, str]:
    return {e["name"]: str(e["value"]) for e in _iter_env(name) if "value" in e}


def _site_entries(name: str) -> dict[str, str]:
    """The commented entries of the manifest's enforcing-start block, as a site would fill them."""
    text = (_K8S / name).read_text(encoding="utf-8")
    start = text.index(_BLOCK)
    end = text.index("\n            - ", start)  # the first live entry after the block
    found: dict[str, str] = dict(_COMMENTED_ENTRY.findall(text[start:end]))
    assert found, f"{name}: the enforcing-start block holds no commented entries"
    return {key: _FILLED.get(value, value) for key, value in found.items()}


def _load(env: dict[str, str], tmp: str) -> ServiceSettings:
    """``env`` loaded, every absolute path but the spool's a file that exists here.

    The paths are rewritten because the settings load checks that a CA or CRL file exists; the
    file's content is not what these gates read."""
    environ: dict[str, str] = {}
    for key, value in env.items():
        if value.startswith("/") and not key.endswith("_SPOOL_DIR"):
            stand_in = Path(tmp) / key
            stand_in.write_text("stand-in\n", encoding="utf-8")
            value = str(stand_in)
        environ[key] = value
    environ["MEFOR_STORE_PATH"] = str(Path(tmp) / "messagefoundry.db")
    return load_settings(environ=environ, default_file=False)


@pytest.fixture(params=sorted(_MANIFESTS))
def shipped(request: pytest.FixtureRequest) -> Iterator[tuple[str, ServiceSettings]]:
    """A manifest's name and its engine settings as shipped."""
    name = str(request.param)
    with tempfile.TemporaryDirectory() as tmp:
        yield name, _load(_literal_env(name), tmp)


@pytest.fixture(params=sorted(_MANIFESTS))
def filled(request: pytest.FixtureRequest) -> Iterator[tuple[str, ServiceSettings]]:
    """A manifest's name and its engine settings with the enforcing-start block filled in."""
    name = str(request.param)
    with tempfile.TemporaryDirectory() as tmp:
        yield name, _load({**_literal_env(name), **_site_entries(name)}, tmp)


def _channel_ready(settings: ServiceSettings) -> bool:
    """``serve``'s ``security_channel_ready``, restated: it is inline there."""
    alerts = settings.alerts
    return bool(
        settings.auth.notify_security_events and alerts.email_smtp_host and alerts.email_from
    )


def test_the_shipped_manifest_still_fails_closed(shipped: tuple[str, ServiceSettings]) -> None:
    """No placeholder passes a gate: an unedited manifest is refused, as before these rows."""
    name, settings = shipped
    assert not _channel_ready(settings), f"{name}: an unedited manifest has an alert channel"
    assert forwarding_gate_refusal(settings.logging) is not None, name
    outcome = evaluate_retention_gate(
        copy.deepcopy(settings), enforcing=True, production=True, env_name="prod"
    )
    assert outcome.refusal is not None, f"{name}: an unedited manifest passes the retention gate"


def test_the_revocation_attestation_is_wired_and_not_optional(
    shipped: tuple[str, ServiceSettings],
) -> None:
    """The value is the operator's, so the manifest takes it from the Secret, never optional."""
    name, settings = shipped
    # The positive control: this manifest's bind is one the gate refuses without the attestation.
    assert in_process_tls_revocation_refused(
        tls_enabled=settings.api.tls_enabled, is_loopback=settings.api.is_loopback, attested=False
    ), f"{name}: the bind no longer needs the attestation, so this test checks nothing"
    entries = [e for e in _iter_env(name) if e["name"] == _ATTEST]
    assert len(entries) == 1, f"{name} does not wire {_ATTEST}"
    ref = entries[0].get("valueFrom", {}).get("secretKeyRef")
    assert ref is not None, f"{name}: {_ATTEST} must come from the Secret, not a literal"
    assert ref.get("optional") is not True, f"{name}: {_ATTEST} must not be optional"
    secret = (_K8S / "secret.example.yaml").read_text(encoding="utf-8")
    assert f"{ref['key']}:" in secret, f"secret.example.yaml does not name {ref['key']}"


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


def test_the_forwarding_spool_is_on_a_writable_mount(
    filled: tuple[str, ServiceSettings],
) -> None:
    """The root file system is read-only, so the spool needs a mount the engine can write."""
    name, settings = filled
    root = settings.logging.forward_spool_dir or posixpath.join(
        posixpath.dirname(_image_store_path()), "log-spool"
    )
    writable = [
        m["mountPath"]
        for m in _engine(name).get("volumeMounts", [])
        if not m.get("readOnly") and m["mountPath"] != "/tmp"
    ]
    assert any(root == p or root.startswith(p.rstrip("/") + "/") for p in writable), (
        f"{name}: the spool root {root!r} is under no writable mount ({writable})"
    )


def test_retention_is_bounded(filled: tuple[str, ServiceSettings]) -> None:
    name, settings = filled
    outcome = evaluate_retention_gate(
        copy.deepcopy(settings), enforcing=True, production=True, env_name="prod"
    )
    assert outcome.refusal is None, f"{name}: {outcome.refusal}"


def test_the_postgres_store_hop_names_a_crl(filled: tuple[str, ServiceSettings]) -> None:
    name, settings = filled
    if not _MANIFESTS[name]:
        pytest.skip(f"{name} runs the SQLite store, which has no network hop")
    assert settings.store.backend.value == "postgres"
    assert settings.store.ssl_crl_file is not None, (
        f"{name}: a verified Postgres hop with no CRL refuses at store open under enforce"
    )


def test_the_trust_files_are_baked_into_the_config_image() -> None:
    """The engine checks who can replace a CA, and /config is the root-owned path both manifests use."""
    for name in _MANIFESTS:
        env = _site_entries(name)
        for key in ("MEFOR_LOGGING_FORWARD_TLS_CA_FILE", "MEFOR_LOGGING_FORWARD_TLS_CRL_FILE"):
            assert env.get(key, "").startswith("/config/"), f"{name}: {key}"
        if _MANIFESTS[name]:
            assert env.get("MEFOR_STORE_SSL_CRL_FILE", "").startswith("/config/"), name
