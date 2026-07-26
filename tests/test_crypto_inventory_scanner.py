# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 11.1.3 (WP-L3-02) scanner-behaviour guard for the widened crypto-discovery gate.

Sibling of ``tests/test_crypto_inventory_doc.py`` (the §4 doc-truth guard) and #283's
``tests/test_security_static.py`` (which runs the gate's own ``discover()`` over every walk root).
Those cover the *inventory truth*; this file freezes the *scanner's widened detection* (BACKLOG #282):

* a module that delegates crypto **through the Transit seam with ZERO of the six stdlib crypto
  modules** must still be discovered and — when absent from the inventory — reported undocumented (the
  regression the un-widened scanner could not catch, and the reason ``store/crypto_transit.py`` was
  invisible before);
* the third-party crypto libraries (hvac / truststore / webauthn / signxml) and every seam import
  form are detected;
* the walk-set is the pinned five roots (no ``samples/``); and
* the ``ide/``-is-TypeScript exclusion is an **enforced** invariant, not a silent drop.

PHI-free: it reads only code *names/paths*, never a secret value. The gate script is not an importable
package (``scripts/`` has no ``__init__``), so load it standalone by file path like the doc guard does.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_CRYPTO_GATE = _ROOT / "scripts" / "security" / "crypto_inventory_check.py"

# A seam import that pulls in NONE of the six stdlib crypto modules — the exact shape the un-widened
# scanner was blind to (store/crypto_transit.py is the real-world instance).
_TRANSIT_SEAM_DELEGATOR = "from messagefoundry.store.crypto_transit import build_transit_cipher\n"


def _gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_crypto_inventory_check_scanner", _CRYPTO_GATE)
    assert spec is not None and spec.loader is not None, f"cannot load {_CRYPTO_GATE}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_transit_seam_delegator_has_zero_of_the_six_stdlib_modules() -> None:
    # Precondition for the regression: the fixture really imports none of the six — otherwise the
    # un-widened scanner would have caught it and the seam trigger would prove nothing.
    gate = _gate()
    found = gate.crypto_imports_in(_TRANSIT_SEAM_DELEGATOR)
    assert found & gate.CRYPTO_MODULES == set(), f"fixture leaked a stdlib crypto import: {found}"
    assert found == {"messagefoundry.store.crypto_transit"}


def test_seam_only_delegator_is_reported_undocumented(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    # The regression fixture: a brand-new module that performs crypto ONLY through the Transit seam,
    # absent from the inventory, must trip the gate (return 1) and be named in the output. This is the
    # coverage the six-module scanner could never provide.
    gate = _gate()
    pkg = tmp_path / "seampkg"
    pkg.mkdir()
    (pkg / "delegator.py").write_text(_TRANSIT_SEAM_DELEGATOR, encoding="utf-8")

    rc = gate.main(["--package", str(pkg)])
    out = capsys.readouterr().out
    assert rc == 1, out
    assert "delegator.py" in out
    assert "messagefoundry.store.crypto_transit" in out


def test_third_party_crypto_libraries_are_detected() -> None:
    gate = _gate()
    for lib in ("hvac", "truststore", "webauthn", "signxml"):
        assert gate.crypto_imports_in(f"import {lib}\n") == {lib}, lib
        assert gate.crypto_imports_in(f"from {lib} import thing\n") == {lib}, lib
    assert set(gate.CRYPTO_LIBRARY_MODULES) == {"hvac", "truststore", "webauthn", "signxml"}


@pytest.mark.parametrize(
    "source",
    [
        "from messagefoundry.store.crypto import Cipher\n",  # from <seam> import X
        "from messagefoundry.store import crypto\n",  # from <parent> import <leaf>
        "import messagefoundry.store.crypto\n",  # import <seam>
        "import messagefoundry.store.crypto as c\n",  # import <seam> as alias
    ],
)
def test_every_seam_import_form_is_detected(source: str) -> None:
    gate = _gate()
    assert "messagefoundry.store.crypto" in gate.crypto_imports_in(source), source


def test_a_plain_non_crypto_store_import_is_not_a_false_positive() -> None:
    # store.base is not a seam — importing it must not be read as a crypto site (guards the leaf-name
    # matcher against over-triggering on any `messagefoundry.store.*`).
    gate = _gate()
    assert gate.crypto_imports_in("from messagefoundry.store import base\n") == set()


def test_walk_roots_are_the_pinned_five_with_no_samples() -> None:
    # Byte-identical to tests/test_security_static.py's _CRYPTO_ROOTS basenames (#283's pin). A later
    # narrowing (or a stray samples/) has to edit this literal rather than pass a tautology.
    gate = _gate()
    assert gate.WALK_ROOTS == (
        "messagefoundry",
        "messagefoundry_webconsole",
        "harness",
        "tee",
        "scripts",
    )
    assert "samples" not in gate.WALK_ROOTS


def test_ide_typescript_invariant_holds_on_the_real_tree() -> None:
    gate = _gate()
    assert gate._assert_ide_is_typescript(_ROOT) == []


def test_ide_invariant_flags_a_planted_python_file(tmp_path: Path) -> None:
    # The exclusion rationale is enforced, not decorative: a .py appearing under ide/ reds the gate so
    # a new crypto site there cannot escape the walk silently.
    gate = _gate()
    (tmp_path / "ide").mkdir()
    (tmp_path / "ide" / "sneaky.py").write_text("import hashlib\n", encoding="utf-8")
    violations = gate._assert_ide_is_typescript(tmp_path)
    assert violations and "ide/sneaky.py" in violations[0]


def test_gate_is_clean_on_the_real_tree() -> None:
    # End-to-end: the widened walk over the five real roots matches the maintained inventory (no drift).
    gate = _gate()
    assert gate.main([]) == 0
