# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``ha`` profile's store hop is verified TLS to a Postgres that serves it (BACKLOG #5827).

The engine refuses a store login over ``encrypt=false`` or ``trust_server_certificate=true`` at
every posture, and ``MEFOR_ALLOW_INSECURE_TLS`` never lifts that (vault BACKLOG #3533 item 2). The
``ha`` engines in ``docker/compose.yaml`` set that escape anyway, against a Postgres container with
no TLS, so their verified store hop could not succeed and the shipped HA template would not start.
Now the Postgres container serves a site certificate, the engines pin its CA, and no service sets
the escape. The engine is not started here; the store's own TLS builder is called on the settings
the compose env loads to, under the enforcing posture ``serve --env prod`` runs at.
"""

from __future__ import annotations

import copy
import ssl
import tempfile
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization

from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.store.postgres import _build_ssl
from tests._crl_pki import empty_crl, throwaway_ca
from tests.test_b532w3_compose_enforce_start_inputs import _literal_env, _site_entries
from tests.test_compose_revocation_attestation import _compose_doc
from tests.test_k8s_enforce_start_inputs import _load

_ESCAPE = "MEFOR_ALLOW_INSECURE_TLS"
_HA_STORE_USERS = ("schema-provision", "engine-ha", "engine-standby")
_ENFORCING = HopPosture(enforcing=True)


def _env_keys(svc: dict[str, Any]) -> set[str]:
    """The variable names a service sets, in either compose ``environment`` syntax."""
    env = svc.get("environment") or {}
    if isinstance(env, dict):
        return set(env)
    return {str(entry).partition("=")[0] for entry in env}


def _services_setting_escape(doc: dict[str, Any]) -> list[str]:
    return sorted(n for n, svc in doc["services"].items() if _ESCAPE in _env_keys(svc))


def _postgres_args(doc: dict[str, Any]) -> dict[str, str]:
    """The ``-c name=value`` settings the Postgres service's command passes."""
    command = [str(a) for a in doc["services"]["postgres"].get("command") or []]
    if command[:1] != ["postgres"]:
        return {}
    out: dict[str, str] = {}
    for flag, value in zip(command[1::2], command[2::2], strict=True):
        assert flag == "-c", command
        name, _, setting = value.partition("=")
        out[name] = setting
    return out


def _read_only_targets(svc: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for vol in svc.get("volumes") or []:
        if isinstance(vol, dict):
            if vol.get("read_only"):
                out.append(str(vol["target"]))
            continue
        parts = str(vol).split(":")
        if len(parts) == 3 and "ro" in parts[2].split(","):
            out.append(parts[1])
    return out


def _tls_refusal(doc: dict[str, Any]) -> str | None:
    """Why the doc's Postgres would not serve TLS from read-only files, or None when it would."""
    args = _postgres_args(doc)
    if args.get("ssl") != "on":
        return f"ssl is not on: {args}"
    mounts = _read_only_targets(doc["services"]["postgres"])
    for key in ("ssl_cert_file", "ssl_key_file"):
        path = args.get(key, "")
        if not any(path.startswith(m.rstrip("/") + "/") for m in mounts):
            return f"{key}={path!r} is under no read-only mount ({mounts})"
    return None


def test_no_service_sets_the_insecure_tls_escape() -> None:
    doc = _compose_doc()
    assert set(_HA_STORE_USERS) <= set(doc["services"]), "positive control: the ha services"
    assert not _services_setting_escape(doc)


@pytest.mark.parametrize("form", ("mapping", "list"))
def test_the_escape_check_sees_a_planted_escape(form: str) -> None:
    doc = copy.deepcopy(_compose_doc())
    svc = doc["services"]["engine-ha"]
    env = dict(svc["environment"])
    env[_ESCAPE] = "1"
    svc["environment"] = env if form == "mapping" else [f"{k}={v}" for k, v in env.items()]
    assert _services_setting_escape(doc) == ["engine-ha"]


def test_the_ha_postgres_serves_tls_from_a_read_only_mount() -> None:
    assert _tls_refusal(_compose_doc()) is None


@pytest.mark.parametrize("change", ("no-ssl", "writable-mount", "no-command"))
def test_the_tls_check_sees_a_postgres_without_it(change: str) -> None:
    doc = copy.deepcopy(_compose_doc())
    svc = doc["services"]["postgres"]
    if change == "no-ssl":
        svc["command"] = [a for a in svc["command"] if a != "ssl=on"]
        svc["command"].remove("-c")
    elif change == "writable-mount":
        svc["volumes"] = [str(v).removesuffix(":ro") for v in svc["volumes"]]
    else:
        del svc["command"]
    assert _tls_refusal(doc) is not None


def test_every_ha_store_user_pins_the_store_ca_under_config() -> None:
    for name in _HA_STORE_USERS:
        env = _literal_env(name)
        assert env.get("MEFOR_STORE_SERVER") == "postgres", name
        pin = env.get("MEFOR_STORE_SSL_ROOT_CERT", "")
        assert pin.startswith("/config/"), f"{name}: no store pin under the read-only /config"


@pytest.mark.parametrize("name", ("engine-ha", "engine-standby"))
def test_the_ha_store_settings_pass_the_store_tls_builder_once_filled(name: str) -> None:
    """Filled in, the env builds a verifying, CRL-checking context under enforce; as shipped,
    with no CRL, the revocation guard refuses it.

    The settings load replaces each absolute path with a stand-in file; the pin and the CRL are
    then swapped for a real CA and its CRL, so the builder reads real files."""
    key, ca = throwaway_ca("postgres-ca")
    crl = empty_crl(key, ca)
    with tempfile.TemporaryDirectory() as tmp:
        shipped = _load(_literal_env(name), tmp).store
        assert shipped.ssl_root_cert and shipped.ssl_crl_file is None, name
        Path(shipped.ssl_root_cert).write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        with pytest.raises(ValueError, match=r"(?i)revocation|crl"):
            _build_ssl(shipped, posture=_ENFORCING)
    with tempfile.TemporaryDirectory() as tmp:
        store = _load({**_literal_env(name), **_site_entries(name)}, tmp).store
        assert store.encrypt and not store.trust_server_certificate, name
        assert store.ssl_root_cert and store.ssl_crl_file, name
        Path(store.ssl_root_cert).write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        Path(store.ssl_crl_file).write_bytes(crl.public_bytes(serialization.Encoding.PEM))
        ctx = _build_ssl(store, posture=_ENFORCING)
    assert ctx.verify_mode is ssl.CERT_REQUIRED and ctx.check_hostname, name
    assert ctx.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF, name
