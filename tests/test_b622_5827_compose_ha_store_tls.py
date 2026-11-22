# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``ha`` profile's store hop is verified TLS to a Postgres that serves it (BACKLOG #5827).

The engine refuses a store login over ``encrypt=false`` or ``trust_server_certificate=true`` at
every posture, and ``MEFOR_ALLOW_INSECURE_TLS`` never lifts that (vault BACKLOG #3533 item 2). The
``ha`` engines in ``docker/compose.yaml`` set that escape anyway, against a Postgres container with
no TLS, so their verified store hop could not succeed and the shipped HA template would not start.
Now the Postgres container serves a site certificate, the engines pin its CA, and no service sets
the escape. The engine is not started here; the store's own TLS builder is called on the settings
the compose env loads to.
"""

from __future__ import annotations

import ssl
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from messagefoundry.store.postgres import _build_ssl
from tests._crl_pki import empty_crl, throwaway_ca
from tests.test_b532w3_compose_enforce_start_inputs import _literal_env, _site_entries
from tests.test_compose_revocation_attestation import _all_services
from tests.test_k8s_enforce_start_inputs import _load

_ESCAPE = "MEFOR_ALLOW_INSECURE_TLS"
_HA_STORE_USERS = ("schema-provision", "engine-ha", "engine-standby")


def _postgres_args() -> dict[str, str]:
    """The ``-c name=value`` settings the Postgres service's command passes."""
    command = [str(a) for a in _all_services()["postgres"].get("command") or []]
    assert command[:1] == ["postgres"], f"the postgres command does not start postgres: {command}"
    out: dict[str, str] = {}
    for flag, value in zip(command[1::2], command[2::2], strict=True):
        assert flag == "-c", command
        name, _, setting = value.partition("=")
        out[name] = setting
    return out


def _read_only_targets(service: str) -> list[str]:
    out: list[str] = []
    for vol in _all_services()[service].get("volumes") or []:
        parts = str(vol).split(":")
        if len(parts) == 3 and "ro" in parts[2].split(","):
            out.append(parts[1])
    return out


def test_no_service_sets_the_insecure_tls_escape() -> None:
    services = _all_services()
    assert set(_HA_STORE_USERS) <= set(services), "positive control: the ha services are found"
    for name, svc in services.items():
        assert _ESCAPE not in (svc.get("environment") or {}), f"{name} sets {_ESCAPE}"


def test_the_ha_postgres_serves_tls_from_a_read_only_mount() -> None:
    args = _postgres_args()
    assert args.get("ssl") == "on", args
    mounts = _read_only_targets("postgres")
    for key in ("ssl_cert_file", "ssl_key_file"):
        path = args.get(key, "")
        assert any(path.startswith(m.rstrip("/") + "/") for m in mounts), (
            f"{key}={path!r} is under no read-only mount ({mounts})"
        )


def test_every_ha_store_user_pins_the_store_ca_under_config() -> None:
    for name in _HA_STORE_USERS:
        env = _literal_env(name)
        assert env.get("MEFOR_STORE_SERVER") == "postgres", name
        pin = env.get("MEFOR_STORE_SSL_ROOT_CERT", "")
        assert pin.startswith("/config/"), f"{name}: no store pin under the read-only /config"


def test_the_filled_ha_store_settings_pass_the_store_tls_builder() -> None:
    """The env as shipped, with its enforcing-start block filled, builds a verifying context.

    The settings load replaces each absolute path with a stand-in file; the pin and the CRL are
    then swapped for a real CA and its CRL, so the builder reads real files."""
    key, ca = throwaway_ca("postgres-ca")
    crl = empty_crl(key, ca)
    for name in ("engine-ha", "engine-standby"):
        env = {**_literal_env(name), **_site_entries(name)}
        with tempfile.TemporaryDirectory() as tmp:
            settings = _load(env, tmp)
            store = settings.store
            assert store.encrypt and not store.trust_server_certificate, name
            assert store.ssl_root_cert and store.ssl_crl_file, name
            Path(store.ssl_root_cert).write_bytes(ca.public_bytes(serialization.Encoding.PEM))
            Path(store.ssl_crl_file).write_bytes(crl.public_bytes(serialization.Encoding.PEM))
            ctx = _build_ssl(store)
        assert ctx.verify_mode is ssl.CERT_REQUIRED and ctx.check_hostname, name
