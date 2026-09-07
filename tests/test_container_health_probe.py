# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Structural policy tests for the shipped container liveness probes (BACKLOG #1179, ASVS 12.3.3).

The image ``HEALTHCHECK`` used to try https on 8443 and then fall back to plaintext http on 8765
(that probe is kept verbatim as :data:`_PRE_FIX_PROBE`). Any TLS failure moved it onto a cleartext
socket, so a container whose TLS was broken still reported healthy. It is a DOWNGRADE-limb defect
and not a PHI exposure -- ``/health`` is tokenless and carries no PHI -- but it failed on a SHIPPED
ARTIFACT rather than on an operator's configuration, which is what makes it a product bug. Why the
probe now looks the way it does is recorded once, in ``docker/Dockerfile`` and BACKLOG #1179.

Two invariants are pinned here:

* the image probe is a SINGLE https arm, and its shell default equals the LIVE ``ApiSettings().port``
  rather than a copy of it, so moving the engine default cannot leave the probe on a dead port;
* every shipped topology AGREES about the port. compose and the k8s manifests both move the API to
  8443 with ``MEFOR_API_PORT``, which is the only expression of the port the image can read at probe
  time, and each k8s manifest declares its own https probe on that same port.

``_PRE_FIX_PROBE`` is the positive control for the two predicates that can be run against a string:
the cleartext check and the arm count. Both are asserted to FIRE on it before the tree is checked,
because a predicate that fires on nothing is indistinguishable from a clean tree.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from messagefoundry.config.settings import ApiSettings, _env_overrides

_DOCKER_DIR = Path(__file__).resolve().parent.parent / "docker"
_DOCKERFILE = _DOCKER_DIR / "Dockerfile"
_COMPOSE = _DOCKER_DIR / "compose.yaml"
_K8S_MANIFESTS = (
    _DOCKER_DIR / "k8s" / "statefulset.yaml",
    _DOCKER_DIR / "k8s" / "ha-postgres.yaml",
)

#: The probe exactly as it shipped before this item, and the positive control for the two
#: string predicates below.
_PRE_FIX_PROBE = (
    "curl -fsS -k https://127.0.0.1:8443/health || curl -fsS http://127.0.0.1:8765/health || exit 1"
)

#: ``${MEFOR_API_PORT:-8765}`` -- the shell default the probe falls back to when the operator has not
#: moved the port. MEFOR_API_PORT is the settings env override for ``[api].port``.
_PORT_DEFAULT = re.compile(r"\$\{MEFOR_API_PORT:-(\d+)\}")
#: The port compose and the k8s manifests both move the API to.
_TOPOLOGY_PORT = "8443"


def _healthcheck_instructions() -> list[str]:
    """Every ``HEALTHCHECK`` instruction, backslash continuations joined into one line each.

    The ``(?m)^`` anchor is what excludes the word where it appears in a comment, so no separate
    comment-stripping pass is needed.
    """
    joined = re.sub(r"\\\n\s*", " ", _DOCKERFILE.read_text(encoding="utf-8"))
    return re.findall(r"(?m)^HEALTHCHECK\b.*$", joined)


def _probe_command() -> str:
    """The shell command the single HEALTHCHECK runs (everything after ``CMD``)."""
    instructions = _healthcheck_instructions()
    assert len(instructions) == 1, f"expected exactly one HEALTHCHECK, found {len(instructions)}"
    _flags, sep, command = instructions[0].partition(" CMD ")
    assert sep, f"HEALTHCHECK carries no CMD: {instructions[0]!r}"
    return command.strip()


def _arms(command: str) -> list[str]:
    return [seg.strip() for seg in command.split("||")]


def _compose_services() -> dict[str, dict]:
    doc = yaml.safe_load(_COMPOSE.read_text(encoding="utf-8"))
    return {n: s for n, s in (doc.get("services") or {}).items() if isinstance(s, dict)}


def _k8s_containers(manifest: Path) -> list[dict]:
    """Every workload container in a manifest, with its ``env`` flattened to a mapping."""
    out: list[dict] = []
    for doc in yaml.safe_load_all(manifest.read_text(encoding="utf-8")):
        if not isinstance(doc, dict):
            continue
        pod = doc.get("spec", {}).get("template", {}).get("spec", {})
        for container in pod.get("containers", []) if isinstance(pod, dict) else []:
            env = {e["name"]: e.get("value") for e in container.get("env", []) if "name" in e}
            out.append({**container, "_env": env})
    return out


def test_both_string_predicates_fire_on_the_pre_fix_probe() -> None:
    """Positive control. Without it the two tests below pass on a Dockerfile with no probe at all."""
    assert "http://" in _PRE_FIX_PROBE
    assert len(_arms(_PRE_FIX_PROBE)) == 3  # two curls plus the exit


def test_the_dockerfile_declares_exactly_one_healthcheck() -> None:
    """Its own test, so a second HEALTHCHECK is reported here and not blamed on another assertion."""
    instructions = _healthcheck_instructions()
    assert len(instructions) == 1, f"expected exactly one HEALTHCHECK, found {instructions!r}"


def test_the_healthcheck_pins_its_cadence() -> None:
    flags = _healthcheck_instructions()[0].partition(" CMD ")[0]
    for flag in ("--interval=", "--timeout=", "--start-period=", "--retries="):
        assert flag in flags, f"{flag} is unpinned: {flags!r}"


def test_the_image_probe_has_no_cleartext_arm() -> None:
    command = _probe_command()
    assert "http://" not in command, (
        f"the image HEALTHCHECK may not fall back to an unencrypted socket: {command!r}"
    )
    assert "https://" in command


def test_the_image_probe_is_a_single_arm() -> None:
    """One request, then ``exit 1``. A second request arm is how the cleartext fallback got in."""
    arms = _arms(_probe_command())
    assert len(arms) == 2, f"expected one request arm plus `exit 1`, got {arms!r}"
    assert arms[0].count("://") == 1, f"the request arm must make ONE request: {arms[0]!r}"
    assert arms[1] == "exit 1"


def test_the_probe_port_default_tracks_the_live_engine_default() -> None:
    """Imported, never copied: moving ``[api].port`` must not leave the probe on a dead port."""
    match = _PORT_DEFAULT.search(_probe_command())
    assert match, (
        "the probe must read ${MEFOR_API_PORT:-<default>} so it follows the configured port"
    )
    assert int(match.group(1)) == ApiSettings().port


def test_the_variable_the_probe_reads_still_routes_to_api_port() -> None:
    """The NAME is a literal in the probe, so pin it behaviourally, not by spelling.

    ``[api].host`` has already been relocated to ``[security].listen_address``, so a relocation of
    ``port`` is live precedent. If it happened, the probe would read a variable the settings layer no
    longer routes to ``[api]``, and the digits assertion above would still pass.
    """
    assert _env_overrides({"MEFOR_API_PORT": "9999"}) == {"api": {"port": "9999"}}


def test_every_compose_engine_service_sets_the_variable_the_probe_reads() -> None:
    """Asserted against the PARSED environment: a mention in a comment must not satisfy this."""
    services = _compose_services()
    engines = {
        name: svc
        for name, svc in services.items()
        if isinstance(svc.get("environment"), dict) and "MEFOR_API_PORT" in svc["environment"]
    }
    assert engines, f"no compose service declares MEFOR_API_PORT; found {sorted(services)}"
    for name, svc in engines.items():
        assert svc["environment"]["MEFOR_API_PORT"] == _TOPOLOGY_PORT, name


def test_each_k8s_manifest_declares_one_https_probe_on_the_port_it_configures() -> None:
    """Per manifest, so two probes in one file and none in the other cannot pass as a pair."""
    for manifest in _K8S_MANIFESTS:
        probes = [
            (c["livenessProbe"], c["_env"])
            for c in _k8s_containers(manifest)
            if "livenessProbe" in c
        ]
        assert len(probes) == 1, f"{manifest.name}: expected one livenessProbe, found {len(probes)}"
        probe, env = probes[0]
        http_get = probe.get("httpGet")
        assert http_get, f"{manifest.name}: a non-httpGet livenessProbe needs its own review"
        assert http_get.get("scheme") == "HTTPS", f"{manifest.name}: {http_get!r}"
        assert env.get("MEFOR_API_PORT") == _TOPOLOGY_PORT, f"{manifest.name}: {env!r}"
        assert str(http_get.get("port")) == _TOPOLOGY_PORT, f"{manifest.name}: {http_get!r}"
