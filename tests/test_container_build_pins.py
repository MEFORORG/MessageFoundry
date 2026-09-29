# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Supply-chain pins in the engine image build (BACKLOG #1193, ASVS 15.2.4).

``docker/Dockerfile`` used to start from a floating tag, and its builder stage ran an unpinned
``pip install build``. Both let a registry or index hand the build something nobody reviewed. The
Dockerfile header says why the fix looks the way it does; this module keeps it from quietly coming
back, since no CI job reads the Dockerfile for pins (``trivy config`` in security.yml ends in
``|| true``).

Three invariants:

* every REGISTRY image the build pulls, by ``FROM`` or ``COPY --from``, is named by tag AND digest,
  written literally, because Dependabot's ``docker`` entry cannot follow an ARG-interpolated tag
  and has nothing to move without a tag;
* every ``pip install`` is either hash-checked or installs only the locally built engine wheel with
  ``--no-deps``;
* the build frontend comes from ``ci/locks/release-tools.lock``, the lock CI and the release use.

:data:`_PRE_FIX` is the positive control. Each predicate is asserted to FIRE on it before the real
file is checked, because a predicate that fires on nothing looks the same as a clean file.
"""

from __future__ import annotations

import contextlib
import json
import re
from pathlib import Path

_DOCKERFILE = Path(__file__).resolve().parent.parent / "docker" / "Dockerfile"

#: The shape this module exists to refuse, kept from the pre-fix Dockerfile.
_PRE_FIX = """\
ARG PYTHON_VERSION=3.14
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder-base
RUN python -m pip install build \\
 && python -m build --wheel --outdir /wheels .
FROM builder-base AS builder
RUN /opt/venv/bin/pip install --require-hashes -r /tmp/req.lock \\
 && /opt/venv/bin/pip install --no-deps /wheels/messagefoundry-*.whl
"""

_FROM = re.compile(r"^FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?\s*$", re.IGNORECASE)
_COPY_FROM = re.compile(r"^COPY\s.*--from=(\S+)", re.IGNORECASE)
#: `<name>:<tag>@sha256:<digest>`. The TAG is required as well as the digest: a digest-only
#: reference gives Dependabot nothing to track, so the pin would freeze the base image.
_PINNED = re.compile(r"^[^@\s$]+:[^@/:\s$]+@sha256:[0-9a-f]{64}$")
_PIP_INSTALL = re.compile(r"\bpip3?(?:\.\d+)?\s+install\b")


def _instructions(text: str) -> list[str]:
    """One string per instruction, as BuildKit reads them.

    Comment lines go FIRST, because BuildKit drops a comment line even in the middle of a
    continued instruction; joining first would cut that instruction in two at the comment. A
    backslash followed by trailing blanks still continues the line, as it does for BuildKit.
    """
    kept = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    joined = re.sub(r"\\[ \t]*\n\s*", " ", kept)
    return [line.strip() for line in joined.splitlines() if line.strip()]


def _registry_bases(text: str) -> list[str]:
    """Every image the build pulls: a FROM or COPY --from that is not an earlier stage.

    A FROM line the parser cannot read is returned whole rather than skipped, so it fails the
    pin check instead of passing unexamined. Stage names match case-insensitively and a stage may
    be named by its index, as BuildKit allows.
    """
    stages: set[str] = set()
    bases: list[str] = []
    index = 0
    for line in _instructions(text):
        if re.match(r"FROM\s", line, re.IGNORECASE):
            match = _FROM.match(line)
            if match is None:
                bases.append(line)
                continue
            image, alias = match.group(1), match.group(2)
            if image.lower() not in stages:
                bases.append(image)
            stages.add(str(index))
            index += 1
            if alias:
                stages.add(alias.lower())
        elif (copied := _COPY_FROM.match(line)) and copied.group(1).lower() not in stages:
            bases.append(copied.group(1))
    return bases


def _unpinned_bases(text: str) -> list[str]:
    return [b for b in _registry_bases(text) if not _PINNED.match(b)]


def _pip_install_commands(text: str) -> list[str]:
    """Every shell command in a RUN that invokes pip install, split at each shell separator."""
    commands: list[str] = []
    for line in _instructions(text):
        if not re.match(r"RUN\s", line, re.IGNORECASE):
            continue
        body = re.sub(r"^(?:--\S+\s+)*", "", line[3:].strip())
        # A body that is not JSON is shell form beginning with the `[` test command.
        if body.startswith("["):
            with contextlib.suppress(json.JSONDecodeError):
                body = " ".join(json.loads(body))
        commands += [c.strip() for c in re.split(r"&&|\|\||[;&|]", body) if _PIP_INSTALL.search(c)]
    return commands


def _unchecked_pip_installs(text: str) -> list[str]:
    """Every pip install that neither checks hashes nor installs only the locally built wheel."""
    found: list[str] = []
    for command in _pip_install_commands(text):
        if "--require-hashes" in command:
            continue
        args = _PIP_INSTALL.split(command, maxsplit=1)[1].split()
        targets = [a for a in args if not a.startswith("-")]
        if "--no-deps" in args and targets and all(t.startswith("/wheels/") for t in targets):
            continue
        found.append(command)
    return found


_DIGEST = "@sha256:" + "0" * 64


def test_the_predicates_fire_on_the_pre_fix_shape() -> None:
    """Positive control, run first, so the checks below cannot pass by matching nothing."""
    assert _registry_bases(_PRE_FIX) == ["python:${PYTHON_VERSION}-slim-bookworm"]
    assert _unpinned_bases(_PRE_FIX) == ["python:${PYTHON_VERSION}-slim-bookworm"]
    assert _unchecked_pip_installs(_PRE_FIX) == ["python -m pip install build"]


def test_the_predicates_fire_on_the_evasions_a_review_named() -> None:
    """Each shape here once passed an earlier cut of these predicates."""
    bases = (
        f"FROM python{_DIGEST} AS a\n"  # a digest with no tag, so nothing for Dependabot to move
        f"FROM --platform=linux/amd64 --foo=bar python:3.14 AS b\n"  # extra flags
        f"COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/\n"  # a registry image outside FROM
        f"FROM python:3.14{_DIGEST} AS c\n"
        f"COPY --from=c /x /y\n"  # an earlier stage, which is fine
    )
    assert _unpinned_bases(bases) == [
        f"python{_DIGEST}",
        "python:3.14",
        "ghcr.io/astral-sh/uv:latest",
    ]
    installs = (
        "RUN pip install --require-hashes -r /tmp/x.lock; pip install build\n"
        "RUN pip3 install build\n"
        'RUN ["pip", "install", "build"]\n'
        "RUN true \\\n    # a comment inside a continued RUN\n && pip install build\n"
        "RUN pip install --no-deps /wheels/a.whl build\n"
        "RUN pip install /wheels/a.whl\n"  # no --no-deps, so pip resolves dependencies
        "RUN pip install --no-deps /wheels/a.whl\n"  # fine
        "RUN true \\ \n && pip install build\n"  # trailing blank after the backslash
        'RUN --network=none ["pip", "install", "build"]\n'  # exec form behind a RUN flag
        "RUN pip install --require-hashes -r x.lock & pip install build\n"
        'RUN [ "$(uname -m)" = "x86_64" ] && pip install --require-hashes -r y.lock\n'  # fine
    )
    assert len(_unchecked_pip_installs(installs)) == 9, _unchecked_pip_installs(installs)
    # Stage references BuildKit accepts are not registry pulls: a case change and an index.
    stages = f"FROM python:3.14{_DIGEST} AS base\nFROM BASE AS b\nCOPY --from=0 /x /y\n"
    assert _unpinned_bases(stages) == []


def test_every_registry_base_is_pinned_by_a_literal_digest() -> None:
    text = _DOCKERFILE.read_text(encoding="utf-8")
    bases = _registry_bases(text)
    assert bases, "no registry FROM found -- the parser is broken, so the check below is vacuous"
    assert not _unpinned_bases(text), (
        f"{_unpinned_bases(text)} is not pinned by a literal digest. Pin it as "
        f"<tag>@sha256:<digest>, written out so Dependabot can see it (BACKLOG #1193)."
    )


def test_every_pip_install_is_hash_checked() -> None:
    text = _DOCKERFILE.read_text(encoding="utf-8")
    # Counted over PARSED commands, not raw text: a comment mentioning pip would satisfy a text
    # search while the parser examined nothing.
    assert _pip_install_commands(text), "no RUN-level pip install parsed -- the check is vacuous"
    assert not _unchecked_pip_installs(text), (
        f"unchecked install(s) {_unchecked_pip_installs(text)}: use --require-hashes -r <lock> "
        f"(BACKLOG #1193)"
    )


def test_the_build_frontend_comes_from_the_release_tools_lock() -> None:
    text = _DOCKERFILE.read_text(encoding="utf-8")
    copied = [
        i.split()[-1]
        for i in _instructions(text)
        if re.match(r"COPY\s", i, re.IGNORECASE)
        and "ci/locks/release-tools.lock" in i.split()[1:-1]
    ]
    assert len(copied) == 1, f"expected one COPY of ci/locks/release-tools.lock, found {copied}"
    target = copied[0]
    assert not target.endswith("/"), f"copy it to a named file, not the directory {target}"
    installed = [
        c
        for c in _pip_install_commands(text)
        if "--require-hashes" in c.split() and re.search(rf"-r\s+{re.escape(target)}(\s|$)", c)
    ]
    assert installed, f"ci/locks/release-tools.lock is copied to {target} but never installed"
