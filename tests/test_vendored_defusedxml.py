# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin the vendored defusedxml copy to upstream's bytes, and the packaging that carries it.

``messagefoundry/_vendor/defusedxml/README.md`` states each vendored file's upstream SHA-256 in a table.
These tests read the table and check it against the tree, so the README cannot claim a provenance the
files no longer have. What each call site's parser REFUSES is held by
``tests/test_xml_refusal_guard.py``, and that nothing imports the upstream package any more is held
by ``tests/test_security_static.py``.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import re
import tomllib
from pathlib import Path

import pytest

import messagefoundry._vendor.defusedxml as vendored

REPO = Path(__file__).resolve().parent.parent
#: Located through the import, so the files checked are the ones the engine loads.
VENDOR = Path(vendored.__file__).parent

#: The upstream release the copy was taken from, as the README and the header both state it.
VENDORED_VERSION = "0.7.1"

#: The upstream files the README's table must record, one digest each.
UPSTREAM_FILES = ("common.py", "ElementTree.py", "LICENSE")

#: The two lines each vendored module carries above upstream's bytes, exactly.
HEADER = (
    b"# SPDX-License-Identifier: PSF-2.0\n"
    b"# Vendored from defusedxml " + VENDORED_VERSION.encode() + b". Every line after these two is "
    b"upstream's, unchanged.\n"
)

#: A README row: the file name in backticks, the change, then a 64-hex digest in backticks.
_ROW = re.compile(r"^\| `([^`]+)` \| [^|]+ \| `([0-9a-f]{64})` \|$", re.MULTILINE)
RECORDED = dict(_ROW.findall((VENDOR / "README.md").read_text(encoding="utf-8")))


def _upstream_bytes(name: str) -> bytes:
    """The file as upstream shipped it: a module loses its header, and the licence is whole."""
    data = (VENDOR / name).read_bytes()
    if name.endswith(".py"):
        assert data.startswith(HEADER), f"{name} does not start with the vendoring header"
        return data[len(HEADER) :]
    return data


def test_the_readme_records_every_upstream_file() -> None:
    # The positive control for the digest test: an empty table would make it pass vacuously.
    assert set(RECORDED) == set(UPSTREAM_FILES)


@pytest.mark.parametrize("name", UPSTREAM_FILES)
def test_each_vendored_file_is_upstreams_bytes(name: str) -> None:
    assert hashlib.sha256(_upstream_bytes(name)).hexdigest() == RECORDED[name]


def _installed_upstream() -> Path | None:
    """The upstream package's directory, where an extra installed it (``pyx12`` pulls it in)."""
    spec = importlib.util.find_spec("defusedxml")
    return Path(spec.origin).parent if spec is not None and spec.origin else None


@pytest.mark.parametrize("name", ["common.py", "ElementTree.py"])
def test_each_vendored_module_is_the_installed_upstream_file(name: str) -> None:
    """The README digests are written beside the files, so an edit that updates both passes the
    test above. This one compares with upstream's own bytes wherever upstream is installed, which
    the CI test legs do through the ``x12`` extra, and only while the lock pins the same version."""
    upstream = _installed_upstream()
    if upstream is None:
        pytest.skip("upstream defusedxml is not installed here (it rides only the x12 extra)")
    assert importlib.metadata.version("defusedxml") == VENDORED_VERSION
    assert _upstream_bytes(name) == (upstream / name).read_bytes()


def test_the_lock_pins_the_version_that_was_vendored() -> None:
    """A lock that moves upstream defusedxml off the vendored version means someone must re-vendor.

    Without this, a bump would turn the dependency audit of the lock green while the engine kept
    parsing through the old copy. The ``x12`` extra is the only thing that still locks it."""
    lock = tomllib.loads((REPO / "uv.lock").read_text(encoding="utf-8"))
    locked = {p["version"] for p in lock["package"] if p["name"] == "defusedxml"}
    assert locked == {VENDORED_VERSION}, (
        f"uv.lock pins defusedxml {sorted(locked)}, but messagefoundry/_vendor/defusedxml is "
        f"{VENDORED_VERSION}: re-vendor it, or record why the two may differ"
    )


def test_the_package_ships_only_what_the_readme_accounts_for() -> None:
    """A module dropped in beside the recorded ones would ride along unrecorded."""
    shipped = {p.name for p in VENDOR.iterdir() if p.name != "__pycache__"}
    assert shipped == {"__init__.py", "README.md", *UPSTREAM_FILES}


def test_the_engine_no_longer_declares_the_package() -> None:
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert not [d for d in project["dependencies"] if d.lower().startswith("defusedxml")]
    # The vendored licence travels with every wheel and sdist, as PSF-2.0 requires.
    assert "messagefoundry/_vendor/defusedxml/LICENSE" in project["license-files"]
    assert "PSF-2.0" in project["license"]
