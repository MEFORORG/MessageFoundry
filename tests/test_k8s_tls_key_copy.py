# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The shipped Kubernetes manifests hand the engine a TLS key its key-file gate accepts (BACKLOG #3402).

Under ``[security].enforcement = "enforce"`` the engine refuses an ``[api].tls_key_file`` whose POSIX
mode carries a group or other bit, :func:`messagefoundry.restricted_file._posix_access_problem`. A
Secret volume serves its files root-owned, so the engine could read one only through ``fsGroup`` and a
group-read mode, which that rule refuses. The manifests therefore mount the Secret on a ``copy-tls``
initContainer, which installs the pair into a memory-backed ``emptyDir`` at ``0600`` as the engine's
uid, and the engine mounts that ``emptyDir``. Why is recorded once, in ``docs/PHI.md`` section 2,
*Key files*.

:func:`_engine_tls_modes` works out, from a pod spec alone, the mode the engine would see on each file
its ``MEFOR_API_TLS_*_FILE`` variables name. :data:`_PRE_FIX_POD` is the pod spec as it shipped before
this change, trimmed to the parts the resolver reads, and the positive control: the same resolver and
the same rule must refuse it before the shipped manifests are judged.
"""

from __future__ import annotations

import shlex
import stat
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
import yaml

from messagefoundry.restricted_file import _posix_access_problem

_K8S_DIR = Path(__file__).resolve().parent.parent / "docker" / "k8s"
_TLS_VARS = ("MEFOR_API_TLS_CERT_FILE", "MEFOR_API_TLS_KEY_FILE")

#: The pod spec as both manifests shipped before this change: the Secret mounted on the engine at
#: ``defaultMode: 0440``, readable through ``fsGroup``. YAML 1.1 reads ``0440`` as octal, as the
#: kubelet does.
_PRE_FIX_POD = """
securityContext: { runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, fsGroup: 10001 }
containers:
  - name: engine
    image: REPLACE_WITH_YOUR_CONFIG_BAKED_IMAGE
    env:
      - { name: MEFOR_API_TLS_CERT_FILE, value: "/etc/mefor/tls/api.crt" }
      - { name: MEFOR_API_TLS_KEY_FILE, value: "/etc/mefor/tls/api.key" }
    volumeMounts:
      - { name: tls, mountPath: /etc/mefor/tls, readOnly: true }
volumes:
  - name: tls
    secret:
      secretName: mefor-secrets
      defaultMode: 0440
      items:
        - { key: api.crt, path: api.crt }
        - { key: api.key, path: api.key }
"""


def _shipped_pods() -> list[tuple[str, dict[str, Any]]]:
    """``(file name, pod spec)`` for every Deployment and StatefulSet under ``docker/k8s``."""
    pods = [
        (path.name, doc["spec"]["template"]["spec"])
        for path in sorted(_K8S_DIR.glob("*.yaml"))
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and doc.get("kind") in {"Deployment", "StatefulSet"}
    ]
    assert len(pods) >= 2, "expected at least statefulset.yaml and ha-postgres.yaml"
    return pods


_PODS = _shipped_pods()
_IDS = [name for name, _ in _PODS]


def _container(pod: dict[str, Any], name: str) -> dict[str, Any]:
    found = [
        c for c in pod.get("containers", []) + pod.get("initContainers", []) if c["name"] == name
    ]
    assert len(found) == 1, f"expected one container named {name!r}, found {len(found)}"
    return found[0]


def _volumes(pod: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {v["name"]: v for v in pod.get("volumes", [])}


def _mount_at(container: dict[str, Any], directory: PurePosixPath) -> dict[str, Any]:
    found = [
        m for m in container.get("volumeMounts", []) if PurePosixPath(m["mountPath"]) == directory
    ]
    assert len(found) == 1, f"{container['name']} mounts nothing at {directory}"
    return found[0]


def _secret_mode(volume: dict[str, Any], name: str) -> int:
    """The mode the kubelet gives ``name`` in a Secret volume, or fail if the volume lacks it."""
    secret = volume["secret"]
    for item in secret.get("items", []):
        if item["path"] == name:
            return int(item.get("mode", secret.get("defaultMode", 0o644)))
    raise AssertionError(f"Secret volume {volume['name']} serves no {name}")


def _installed_mode(pod: dict[str, Any], volume_name: str, name: str) -> int:
    """The mode copy-tls's ``install -m MODE SRC... DIR/`` gives ``name`` in ``volume_name``.

    The argv's exact form is pinned by the last test. The copy must land on copy-tls's writable mount
    of ``volume_name``, and its source must be a file a Secret volume that copy-tls mounts serves."""
    init = _container(pod, "copy-tls")
    argv = init["command"]
    target = _mount_at(init, PurePosixPath(argv[-1]))
    assert target["name"] == volume_name and not target.get("readOnly"), "copy lands elsewhere"
    [source] = [PurePosixPath(a) for a in argv[3:-1] if PurePosixPath(a).name == name]
    secret = _volumes(pod)[_mount_at(init, source.parent)["name"]]
    assert name in {item["path"] for item in secret["secret"]["items"]}, f"Secret serves no {name}"
    return int(argv[argv.index("-m") + 1], 8)


def _engine_tls_paths(pod: dict[str, Any]) -> list[PurePosixPath]:
    """The files the engine's ``MEFOR_API_TLS_*_FILE`` variables name, cert first."""
    env = {e["name"]: e.get("value") for e in _container(pod, "engine").get("env", [])}
    return [PurePosixPath(env[var]) for var in _TLS_VARS]


def _engine_tls_modes(pod: dict[str, Any]) -> dict[str, int]:
    """For each file the engine's TLS variables name, the mode the engine would see it at."""
    engine = _container(pod, "engine")
    modes: dict[str, int] = {}
    for path in _engine_tls_paths(pod):
        volume = _volumes(pod)[_mount_at(engine, path.parent)["name"]]
        if "secret" in volume:
            modes[str(path)] = _secret_mode(volume, path.name)
        elif "emptyDir" in volume:
            modes[str(path)] = _installed_mode(pod, volume["name"], path.name)
        else:
            raise AssertionError(f"{path} is on a volume of a kind this test does not read")
    return modes


def _refused(modes: dict[str, int]) -> dict[str, str]:
    """The files of ``modes`` the key-file gate would refuse, with its reason."""
    return {
        path: problem
        for path, mode in modes.items()
        if (problem := _posix_access_problem(stat.S_IFREG | mode)) is not None
    }


def _engine_secret_mounts(pod: dict[str, Any]) -> list[str]:
    # A mount with no pod volume is a StatefulSet's volumeClaimTemplates PVC, never a Secret.
    volumes = _volumes(pod)
    return [
        m["mountPath"]
        for m in _container(pod, "engine").get("volumeMounts", [])
        if "secret" in volumes.get(m["name"], {})
    ]


def test_the_pre_fix_pod_is_refused_by_the_same_resolver_and_rule() -> None:
    """The positive control: the shape that shipped before is refused, so a pass below means
    something."""
    pod = yaml.safe_load(_PRE_FIX_POD)
    modes = _engine_tls_modes(pod)
    assert modes["/etc/mefor/tls/api.key"] == 0o440
    assert "/etc/mefor/tls/api.key" in _refused(modes)
    assert _engine_secret_mounts(pod) == ["/etc/mefor/tls"]


@pytest.mark.parametrize(("name", "pod"), _PODS, ids=_IDS)
def test_the_engine_reads_its_tls_files_at_a_mode_the_gate_accepts(
    name: str, pod: dict[str, Any]
) -> None:
    modes = _engine_tls_modes(pod)
    assert set(modes) == {"/etc/mefor/tls/api.crt", "/etc/mefor/tls/api.key"}, name
    assert _refused(modes) == {}, name
    assert modes["/etc/mefor/tls/api.key"] == 0o600, name


@pytest.mark.parametrize(("name", "pod"), _PODS, ids=_IDS)
def test_the_engine_mounts_no_secret_volume(name: str, pod: dict[str, Any]) -> None:
    assert _engine_secret_mounts(pod) == [], name


@pytest.mark.parametrize(("name", "pod"), _PODS, ids=_IDS)
def test_the_key_copy_lives_in_memory_and_the_engine_mounts_it_read_only(
    name: str, pod: dict[str, Any]
) -> None:
    key = _engine_tls_paths(pod)[1]
    mount = _mount_at(_container(pod, "engine"), key.parent)
    assert mount.get("readOnly") is True, name
    assert _volumes(pod)[mount["name"]]["emptyDir"].get("medium") == "Memory", name


@pytest.mark.parametrize(("name", "pod"), _PODS, ids=_IDS)
def test_copy_tls_runs_as_the_engine_with_the_engine_s_hardening(
    name: str, pod: dict[str, Any]
) -> None:
    """The copy is owned by whoever ran it, so it must be the engine's uid: neither container may
    override the pod's. And the initContainer is held to the engine's own restrictions."""
    engine, init = _container(pod, "engine"), _container(pod, "copy-tls")
    pod_ctx = pod["securityContext"]
    assert pod_ctx["runAsNonRoot"] is True and pod_ctx["runAsUser"] == 10001, name
    assert pod_ctx["seccompProfile"] == {"type": "RuntimeDefault"}, name
    for container in (engine, init):
        assert not {"runAsUser", "runAsGroup"} & set(container["securityContext"]), name
    assert init["securityContext"] == engine["securityContext"], name
    assert engine["securityContext"]["readOnlyRootFilesystem"] is True, name
    assert engine["securityContext"]["capabilities"] == {"drop": ["ALL"]}, name
    assert init["image"] == engine["image"], name


@pytest.mark.parametrize(("name", "pod"), _PODS, ids=_IDS)
def test_the_install_argv_is_what_the_resolver_reads(name: str, pod: dict[str, Any]) -> None:
    """The resolver splits argv by position, so pin that the shipped command is the plain form it
    reads, written as a list and not a shell string."""
    assert shlex.join(_container(pod, "copy-tls")["command"]) == (
        "install -m 0600 /etc/mefor/tls-secret/api.crt /etc/mefor/tls-secret/api.key "
        "/etc/mefor/tls/"
    ), name
