# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The shipped Kubernetes manifests hand the engine a TLS key its key-file gate accepts (BACKLOG #3402).

Under ``[security].enforcement = "enforce"`` the engine refuses an ``[api].tls_key_file`` on POSIX by
:func:`messagefoundry.restricted_file._posix_key_file_problem`: a group or other bit on the file, an
owner other than the engine's account or root, and a directory holding it that accounts other than its
owner may write with no sticky bit. A Secret volume serves its files root-owned, so the engine could
read one only through ``fsGroup`` and a group-read mode, which that rule refuses. The manifests
therefore mount the Secret on a ``copy-tls`` initContainer, which installs the pair into a
memory-backed ``emptyDir`` at ``0600`` as the engine's uid, and the engine mounts that ``emptyDir``.
The kubelet makes the ``emptyDir``'s root, so a ``tls-dir`` initContainer first makes the pair's own
directory at ``0700`` as the engine's uid (vault BACKLOG #5636). Why is recorded once, in
``docs/PHI.md`` section 2, *Key files*.

:func:`_engine_tls_files` works out, from a pod spec alone, what the engine would see on each file its
``MEFOR_API_TLS_*_FILE`` variables name and on the directory holding it. :data:`_PRE_FIX_POD` is the
pod spec as it shipped before #3402, trimmed to the parts the resolver reads, and
:func:`_key_at_the_volume_root` the layout before #5636. Each is a positive control: the same resolver
and the same rule must refuse it before the shipped manifests are judged.
"""

from __future__ import annotations

import copy
import shlex
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import pytest
import yaml

from messagefoundry.restricted_file import _posix_key_file_problem

_K8S_DIR = Path(__file__).resolve().parent.parent / "docker" / "k8s"
_TLS_VARS = ("MEFOR_API_TLS_CERT_FILE", "MEFOR_API_TLS_KEY_FILE")
_ENGINE_UID = 10001
_KEY = "/etc/mefor/tls/engine/api.key"

#: The root of a volume the kubelet makes: owned by root, at the mode the kubelet's emptyDir code
#: sets (0777, read from its source, ``pkg/volume/emptydir``). NOT MEASURED on a cluster, and a
#: memory-backed volume's tmpfs may answer differently, so the manifests never rely on it: the key's
#: own directory is made by an initContainer.
_KUBELET_VOLUME_ROOT = (stat.S_IFDIR | 0o777, 0)

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


@dataclass(frozen=True)
class _Seen:
    """What the engine would read for one file: its mode and owner, and its directory's."""

    mode: int
    uid: int
    parent_mode: int
    parent_uid: int


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


def _mount_holding(container: dict[str, Any], path: PurePosixPath) -> dict[str, Any]:
    """The mount ``path`` is on: the deepest one whose mount path is above it."""
    found = [
        m
        for m in container.get("volumeMounts", [])
        if PurePosixPath(m["mountPath"]) in path.parents
    ]
    assert found, f"{container['name']} mounts nothing above {path}"
    return max(found, key=lambda m: len(PurePosixPath(m["mountPath"]).parts))


def _secret_mode(pod: dict[str, Any], volume: dict[str, Any], name: str) -> int:
    """The mode the kubelet serves ``name`` at in a Secret volume, or fail if the volume lacks it.

    Under ``fsGroup`` the kubelet's volume-ownership step ORs a group-read mask into each file of a
    read-only volume, so a declared ``0400`` is served as ``0440``."""
    secret = volume["secret"]
    widen = 0o440 if "fsGroup" in pod.get("securityContext", {}) else 0
    for item in secret.get("items", []):
        if item["path"] == name:
            return int(item.get("mode", secret.get("defaultMode", 0o644))) | widen
    raise AssertionError(f"Secret volume {volume['name']} serves no {name}")


def _installed_mode(pod: dict[str, Any], volume_name: str, path: PurePosixPath) -> int:
    """The mode copy-tls's ``install -m MODE SRC... DIR/`` gives ``path`` in ``volume_name``.

    The argv's exact form is pinned by the last test. The copy must land in ``path``'s directory, on
    copy-tls's writable mount of ``volume_name``, and its source must be a file a Secret volume that
    copy-tls mounts serves."""
    init = _container(pod, "copy-tls")
    argv = init["command"]
    assert PurePosixPath(argv[-1]) == path.parent, "copy lands in another directory"
    target = _mount_holding(init, path)
    assert target["name"] == volume_name and not target.get("readOnly"), "copy lands elsewhere"
    [source] = [PurePosixPath(a) for a in argv[3:-1] if PurePosixPath(a).name == path.name]
    secret = _volumes(pod)[_mount_at(init, source.parent)["name"]]
    assert path.name in {item["path"] for item in secret["secret"]["items"]}, "Secret serves none"
    return int(argv[argv.index("-m") + 1], 8)


def _made_directory(pod: dict[str, Any], volume_name: str, directory: PurePosixPath) -> int:
    """The mode of ``directory``, which an initContainer before copy-tls makes with
    ``install -d -m MODE DIR`` on its writable mount of ``volume_name``, or fail if none does."""
    inits = pod.get("initContainers", [])
    before_copy = inits[: [c["name"] for c in inits].index("copy-tls")]
    for init in before_copy:
        argv = init.get("command", [])
        if argv[:2] != ["install", "-d"] or PurePosixPath(argv[-1]) != directory:
            continue
        mount = _mount_holding(init, directory)
        assert mount["name"] == volume_name and not mount.get("readOnly"), "made elsewhere"
        return int(argv[argv.index("-m") + 1], 8)
    raise AssertionError(f"no initContainer before copy-tls makes {directory}")


def _engine_tls_paths(pod: dict[str, Any]) -> list[PurePosixPath]:
    """The files the engine's ``MEFOR_API_TLS_*_FILE`` variables name, cert first."""
    env = {e["name"]: e.get("value") for e in _container(pod, "engine").get("env", [])}
    return [PurePosixPath(env[var]) for var in _TLS_VARS]


def _engine_tls_files(pod: dict[str, Any]) -> dict[str, _Seen]:
    """For each file the engine's TLS variables name, what the engine would see on it and on the
    directory holding it. A file or directory an initContainer makes is owned by the pod's
    ``runAsUser``, which a test below pins as the engine's."""
    engine = _container(pod, "engine")
    owner = pod["securityContext"]["runAsUser"]
    seen: dict[str, _Seen] = {}
    for path in _engine_tls_paths(pod):
        mount = _mount_holding(engine, path)
        volume = _volumes(pod)[mount["name"]]
        root = PurePosixPath(mount["mountPath"])
        if path.parent == root:
            parent_mode, parent_uid = _KUBELET_VOLUME_ROOT
        elif path.parent.parent == root and "emptyDir" in volume:
            parent_mode = stat.S_IFDIR | _made_directory(pod, volume["name"], path.parent)
            parent_uid = owner
        else:
            raise AssertionError(f"{path} is in a directory this test does not read")
        if "secret" in volume:
            # The kubelet serves each Secret entry as a root-owned link into its ..data directory,
            # and the mode it serves the entry at is checked by _secret_mode.
            _secret_mode(pod, volume, path.name)
            kind_mode, uid = stat.S_IFLNK | 0o777, 0
        elif "emptyDir" in volume:
            kind_mode, uid = stat.S_IFREG | _installed_mode(pod, volume["name"], path), owner
        else:
            raise AssertionError(f"{path} is on a volume of a kind this test does not read")
        seen[str(path)] = _Seen(kind_mode, uid, parent_mode, parent_uid)
    return seen


def _refused(files: dict[str, _Seen]) -> dict[str, str]:
    """The files of ``files`` the key-file gate would refuse, with its reason, as the engine's
    account would see them."""
    refused: dict[str, str] = {}
    for path, f in files.items():
        problem = _posix_key_file_problem(f.mode, f.uid, f.parent_mode, f.parent_uid, _ENGINE_UID)
        if problem is not None:
            refused[path] = problem
    return refused


def _key_at_the_volume_root(pod: dict[str, Any]) -> dict[str, Any]:
    """``pod`` with the pair copied into the emptyDir's root, as it shipped before #5636."""
    pod = copy.deepcopy(pod)
    _container(pod, "copy-tls")["command"][-1] = "/etc/mefor/tls/"
    for entry in _container(pod, "engine")["env"]:
        if entry["name"] in _TLS_VARS:
            entry["value"] = entry["value"].replace("/etc/mefor/tls/engine/", "/etc/mefor/tls/")
    return pod


def _serves_a_secret(volume: dict[str, Any]) -> bool:
    """A Secret volume, or a projected volume with a Secret among its sources."""
    sources = volume.get("projected", {}).get("sources", [])
    return "secret" in volume or any("secret" in source for source in sources)


def _engine_secret_mounts(pod: dict[str, Any]) -> list[str]:
    # A mount with no pod volume is a StatefulSet's volumeClaimTemplates PVC, never a Secret.
    volumes = _volumes(pod)
    return [
        m["mountPath"]
        for m in _container(pod, "engine").get("volumeMounts", [])
        if _serves_a_secret(volumes.get(m["name"], {}))
    ]


def test_a_projected_secret_counts_as_a_secret_mount() -> None:
    """The control for the projected branch, which no shipped manifest exercises."""
    assert _serves_a_secret({"projected": {"sources": [{"secret": {"name": "mefor-secrets"}}]}})
    assert not _serves_a_secret({"projected": {"sources": [{"configMap": {"name": "x"}}]}})
    assert not _serves_a_secret({"emptyDir": {"medium": "Memory"}})


def test_the_pre_fix_pod_is_refused_by_the_same_resolver_and_rule() -> None:
    """The positive control: the shape that shipped before is refused, so a pass below means
    something."""
    pod = yaml.safe_load(_PRE_FIX_POD)
    volume = _volumes(pod)["tls"]
    assert _secret_mode(pod, volume, "api.key") == 0o440
    assert "it is a link" in _refused(_engine_tls_files(pod))["/etc/mefor/tls/api.key"]
    assert _engine_secret_mounts(pod) == ["/etc/mefor/tls"]


@pytest.mark.parametrize(("name", "pod"), _PODS, ids=_IDS)
def test_a_key_copied_into_the_volume_root_is_refused_on_its_directory(
    name: str, pod: dict[str, Any]
) -> None:
    """The positive control for #5636: the layout before it, the pair at the emptyDir's root, is
    refused for its directory, not for the file, by the same resolver and rule."""
    files = _engine_tls_files(_key_at_the_volume_root(pod))
    assert stat.S_IMODE(files["/etc/mefor/tls/api.key"].mode) == 0o600, name
    problem = _refused(files)["/etc/mefor/tls/api.key"]
    assert "the directory that holds it has mode 0777" in problem, name


@pytest.mark.parametrize(("name", "pod"), _PODS, ids=_IDS)
def test_the_engine_reads_its_tls_files_at_a_mode_the_gate_accepts(
    name: str, pod: dict[str, Any]
) -> None:
    files = _engine_tls_files(pod)
    assert set(files) == {"/etc/mefor/tls/engine/api.crt", _KEY}, name
    assert _refused(files) == {}, name
    expected = _Seen(stat.S_IFREG | 0o600, _ENGINE_UID, stat.S_IFDIR | 0o700, _ENGINE_UID)
    assert files[_KEY] == expected, name


@pytest.mark.parametrize(("name", "pod"), _PODS, ids=_IDS)
def test_tls_dir_makes_the_key_directory_before_copy_tls(name: str, pod: dict[str, Any]) -> None:
    """The order matters: copy-tls installs into a directory that must already exist."""
    names = [c["name"] for c in pod["initContainers"]]
    assert names.index("tls-dir") < names.index("copy-tls"), name
    assert shlex.join(_container(pod, "tls-dir")["command"]) == (
        "install -d -m 0700 /etc/mefor/tls/engine"
    ), name


@pytest.mark.parametrize(("name", "pod"), _PODS, ids=_IDS)
def test_the_engine_mounts_no_secret_volume(name: str, pod: dict[str, Any]) -> None:
    assert _engine_secret_mounts(pod) == [], name


@pytest.mark.parametrize(("name", "pod"), _PODS, ids=_IDS)
def test_the_key_copy_lives_in_memory_and_the_engine_mounts_it_read_only(
    name: str, pod: dict[str, Any]
) -> None:
    key = _engine_tls_paths(pod)[1]
    mount = _mount_holding(_container(pod, "engine"), key)
    assert mount.get("readOnly") is True, name
    assert _volumes(pod)[mount["name"]]["emptyDir"].get("medium") == "Memory", name


@pytest.mark.parametrize(("name", "pod"), _PODS, ids=_IDS)
def test_copy_tls_runs_as_the_engine_with_the_engine_s_hardening(
    name: str, pod: dict[str, Any]
) -> None:
    """The copy and its directory are owned by whoever made them, so that must be the engine's uid:
    no container may override the pod's. And each initContainer is held to the engine's own
    restrictions."""
    engine = _container(pod, "engine")
    inits = [_container(pod, "tls-dir"), _container(pod, "copy-tls")]
    pod_ctx = pod["securityContext"]
    assert pod_ctx["runAsNonRoot"] is True and pod_ctx["runAsUser"] == 10001, name
    assert pod_ctx["seccompProfile"] == {"type": "RuntimeDefault"}, name
    for container in (engine, *inits):
        assert not {"runAsUser", "runAsGroup"} & set(container["securityContext"]), name
    assert engine["securityContext"]["readOnlyRootFilesystem"] is True, name
    assert engine["securityContext"]["capabilities"] == {"drop": ["ALL"]}, name
    for init in inits:
        assert init["securityContext"] == engine["securityContext"], name
        assert init["image"] == engine["image"], name


@pytest.mark.parametrize(("name", "pod"), _PODS, ids=_IDS)
def test_copy_tls_can_read_the_root_owned_secret(name: str, pod: dict[str, Any]) -> None:
    """The kubelet writes Secret files root-owned, so copy-tls (uid 10001) reads them only through
    fsGroup, which serves them group-readable. Dropping fsGroup would leave the pod stuck in Init.
    And no Secret file is served to other accounts."""
    pod_ctx = pod["securityContext"]
    assert pod_ctx["fsGroup"] == pod_ctx["runAsGroup"] == 10001, name
    volume = _volumes(pod)["tls-secret"]
    for item in volume["secret"]["items"]:
        mode = _secret_mode(pod, volume, item["path"])
        assert mode & 0o040 and not mode & 0o007, (name, item["path"], oct(mode))


def test_fsgroup_widens_a_0400_secret_the_engine_would_mount() -> None:
    """The control for the fsGroup widening: a 0400 Secret on the engine is still refused."""
    pod = yaml.safe_load(_PRE_FIX_POD.replace("defaultMode: 0440", "defaultMode: 0400"))
    assert _secret_mode(pod, _volumes(pod)["tls"], "api.key") == 0o440
    assert "/etc/mefor/tls/api.key" in _refused(_engine_tls_files(pod))


@pytest.mark.parametrize(("name", "pod"), _PODS, ids=_IDS)
def test_the_install_argv_is_what_the_resolver_reads(name: str, pod: dict[str, Any]) -> None:
    """The resolver splits argv by position, so pin that the shipped command is the plain form it
    reads, written as a list and not a shell string."""
    assert shlex.join(_container(pod, "copy-tls")["command"]) == (
        "install -m 0600 /etc/mefor/tls-secret/api.crt /etc/mefor/tls-secret/api.key "
        "/etc/mefor/tls/engine/"
    ), name
