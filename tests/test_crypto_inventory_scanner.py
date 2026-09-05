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

The last group (BACKLOG #1172, ASVS 11.5.1) freezes the **non-Python randomness arm** the Python
scanner structurally could not provide. Three properties, and a scan missing any one of them proves
nothing: it must FIND a planted ``Math.random()`` in a ``.ts`` file, it must NOT flag the legitimate
``randomBytes`` draw in ``ide/src/cspNonce.ts``, and it must REFUSE an empty walk rather than let one
render as clean.

A fourth property joined them in the ASVS 11.5.1 **scope-completeness pass**: the arm must reach
EVERY root that holds non-Python source, not only the root someone remembered. It previously walked
``ide/`` alone, and a sibling test asserted the non-Python roots were DISJOINT from the Python ones —
which quietly asserted that no first-party root is mixed-language. ``messagefoundry_webconsole`` is,
so its shipped ``static/*.js`` was read by neither arm while the root reported green off its ``.py``.
The disjointness assertion is gone and the walk covers both roots; a weak draw planted in the real
console now reds the gate (measured, then reverted).

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


# --- BACKLOG #1172 / ASVS 11.5.1: the cross-language randomness arm -------------------------------
#
# The Python arm is ``import ast`` over ``*.py``, so it cannot see a weak-PRNG draw in another
# language however its walk-set is spelled. These tests pin the arm that can. Each fixture repo is
# built on disk rather than mocked, because the property under test is what the WALK reaches.

#: The real anchor, reproduced in miniature. Fixtures carry it by default so the arm's stale
#: direction (which fires when the inventory's one row is unbacked) does not drown the assertion
#: under test. The tests that want that direction ask for it explicitly.
_ANCHOR_REL = "ide/src/cspNonce.ts"
_ANCHOR_SRC = (
    'import { randomBytes } from "node:crypto";\n'
    'export function nonce(): string {\n  return randomBytes(18).toString("base64url");\n}\n'
)


#: One inert placeholder source per DECLARED non-Python walk root that a fixture does not otherwise
#: populate. Needed because the arm refuses a declared root that is missing from the tree — which is
#: a control worth keeping, not a nuisance to route around, so the fixture satisfies it rather than
#: the gate relaxing it. Derived from the gate's own tuple so a third root added later cannot leave
#: these fixtures silently red.
_PLACEHOLDER_SRC = "// inert fixture placeholder: no randomness draw\nexport const x = 1;\n"


def _ts_repo(tmp_path: Path, files: dict[str, str], *, with_anchor: bool = True) -> Path:
    """Write ``files`` (repo-relative path -> text) into a throwaway repo root and return it.

    Every declared non-Python walk root the caller did not write into gets one inert placeholder, so
    the missing-root and empty-walk refusals stay armed for the root under test without firing on the
    others."""
    written = dict(files)
    if with_anchor:
        written.setdefault(_ANCHOR_REL, _ANCHOR_SRC)
    touched = {rel.split("/", 1)[0] for rel in written}
    for root in _gate().NON_PYTHON_WALK_ROOTS:
        if root not in touched:
            written.setdefault(f"{root}/_placeholder.js", _PLACEHOLDER_SRC)
    for rel, text in written.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


def _placeholders_in(repo: Path) -> int:
    """How many inert placeholders :func:`_ts_repo` seeded, so a ``scanned`` expectation stays
    derivable rather than a transcribed constant that drifts when a root is added."""
    return len(list(repo.rglob("_placeholder.js")))


@pytest.mark.parametrize(
    "call",
    [
        "const n = Math.random();",
        "const n = Math . random ();",  # spacing must not hide it
        "const n = window.Math.random();",  # a qualified reference is the same draw
        "const n = crypto.pseudoRandomBytes(18);",  # node's own non-cryptographic sibling
    ],
)
def test_a_planted_weak_draw_in_a_ts_file_is_flagged(tmp_path: Path, call: str) -> None:
    # THE ARM'S REASON TO EXIST. Without this assertion its green is worth nothing: a scanner that
    # cannot be made to fire is indistinguishable from one reading an empty corpus.
    gate = _gate()
    repo = _ts_repo(
        tmp_path, {"ide/src/planted.ts": f"export function bad(): string {{\n  {call}\n"}
    )
    violations, scanned = gate.check_non_python_randomness(repo)

    assert scanned == 2 + _placeholders_in(repo), (
        f"the fixture walk should have read both files, it read {scanned}"
    )
    weak = [v for v in violations if "WEAK randomness source" in v]
    assert len(weak) == 1, violations
    assert "ide/src/planted.ts" in weak[0], weak[0]


def test_a_weak_draw_in_a_js_webview_asset_is_flagged_too(tmp_path: Path) -> None:
    # The webview scripts shipped as static assets rather than as .ts are the same kind of code and
    # the same blind spot; a nonce minted there is as capability-granting as one minted in src/.
    gate = _gate()
    repo = _ts_repo(tmp_path, {"ide/media/panel.js": "const nonce = Math.random().toString(36);\n"})
    violations, _ = gate.check_non_python_randomness(repo)
    assert any("ide/media/panel.js" in v and "WEAK" in v for v in violations), violations


def test_a_weak_draw_cannot_be_registered_away(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # THE DISQUALIFIED MOVE, pinned. #1172 rules out narrowing the declared scope so a weak-PRNG hit
    # stops being visible. An inventory row is exactly that move in miniature, so the weak check runs
    # BEFORE the inventory diff and no row can silence it. Mutating the inventory here proves the
    # ordering rather than asserting it: the gate must still red with the site fully "documented".
    gate = _gate()
    monkeypatch.setattr(
        gate,
        "NON_PYTHON_INVENTORY",
        {"ide/src/planted.ts": frozenset({"Math.random", "randomBytes"})},
    )
    repo = _ts_repo(
        tmp_path,
        {"ide/src/planted.ts": "const n = Math.random();\n"},
        with_anchor=False,
    )
    violations, _ = gate.check_non_python_randomness(repo)
    assert any("WEAK randomness source" in v and "ide/src/planted.ts" in v for v in violations), (
        violations
    )


def test_no_weak_token_is_documentable_in_the_shipped_inventory() -> None:
    # The structural half of the same property: the shipped inventory may not name a weak source.
    gate = _gate()
    documented = set().union(*gate.NON_PYTHON_INVENTORY.values())
    assert documented & set(gate.WEAK_RANDOMNESS_PATTERNS) == set(), documented


def test_the_real_cspnonce_draw_is_not_a_false_positive() -> None:
    # THE OTHER HALF OF A USEFUL SCANNER. One that flags everything is as useless as one that flags
    # nothing, and cspNonce.ts is the hard case on purpose: its header NAMES Math.random twice in
    # prose to explain why it is unusable. The tokens must be exactly the sound draw it makes.
    gate = _gate()
    tokens = gate.randomness_tokens_in((_ROOT / _ANCHOR_REL).read_text(encoding="utf-8"))
    assert tokens == {"randomBytes"}, tokens


def test_prose_naming_a_weak_source_is_not_a_hit() -> None:
    gate = _gate()
    prose = (
        "// WHY Math.random() cannot be used here: it is xorshift128+.\n"
        " * A doc comment mentioning Math.random() is not a call.\n"
        "/* Math.random() in a block comment is not a call either. */\n"
    )
    assert gate.randomness_tokens_in(prose) == set()


def test_a_trailing_comment_cannot_hide_a_call() -> None:
    # The conservative direction of _is_comment_only, asserted rather than assumed: only a WHOLLY
    # commented line is skipped, so putting a // earlier on a code line does not launder the draw.
    gate = _gate()
    assert gate.randomness_tokens_in("const n = Math.random(); // harmless, honest\n") == {
        "Math.random"
    }


def test_an_undocumented_strong_source_is_flagged(tmp_path: Path) -> None:
    # A sound draw is inventoried, not merely tolerated, so a NEW CSPRNG site is reviewed. This is
    # the same bidirectional discipline the Python arm applies, reusing the same diff function.
    gate = _gate()
    repo = _ts_repo(tmp_path, {"ide/src/other.ts": "const k = randomBytes(32);\n"})
    violations, _ = gate.check_non_python_randomness(repo)
    assert any(
        "ide/src/other.ts" in v and "undocumented randomness use" in v for v in violations
    ), violations
    # ...and the anchor itself, which IS documented, must not be flagged in the same run.
    assert not any(_ANCHOR_REL in v for v in violations), violations


def test_an_empty_walk_is_refused_rather_than_reported_clean(tmp_path: Path) -> None:
    # THE NAMED FAILURE SHAPE. An empty scan and a clean scan must not look alike -- and this whole
    # item exists because a gate could not see half its corpus while reporting green.
    gate = _gate()
    (tmp_path / "ide" / "src").mkdir(parents=True)
    (tmp_path / "ide" / "README.md").write_text("no sources here\n", encoding="utf-8")
    violations, scanned = gate.check_non_python_randomness(tmp_path)
    assert scanned == 0
    assert any("ZERO" in v and "VACUOUS" in v for v in violations), violations


def test_a_missing_walk_root_is_refused(tmp_path: Path) -> None:
    gate = _gate()
    violations, scanned = gate.check_non_python_randomness(tmp_path)
    assert scanned == 0
    assert any("is not a directory" in v for v in violations), violations


def test_a_broken_walk_reds_through_the_stale_anchor(tmp_path: Path) -> None:
    # THE MUST-FIRE CONTROL, and the reason the inventory carries an anchor row at all. If the walk
    # ever stops reaching cspNonce.ts -- a moved file, a wrong suffix list, an over-eager prune --
    # the row is unbacked and the arm reds instead of reporting a clean tree it never read.
    gate = _gate()
    repo = _ts_repo(tmp_path, {"ide/src/plain.ts": "export const x = 1;\n"}, with_anchor=False)
    violations, scanned = gate.check_non_python_randomness(repo)
    assert scanned == 1 + _placeholders_in(repo), (
        "the walk must have run; this is not the empty-scan case"
    )
    assert any(_ANCHOR_REL in v and "no longer draws from" in v for v in violations), violations


def test_vendor_and_build_trees_are_pruned(tmp_path: Path) -> None:
    # node_modules is not first-party source, and walking it would bury a real finding under vendor
    # hits. Pruned here rather than filtered later so the walk stays fast on a developer checkout.
    gate = _gate()
    repo = _ts_repo(
        tmp_path,
        {
            "ide/node_modules/pkg/index.js": "const n = Math.random();\n",
            "ide/out/extension.js": "const n = Math.random();\n",
            "ide/dist/extension.js": "const n = Math.random();\n",
        },
    )
    violations, scanned = gate.check_non_python_randomness(repo)
    assert scanned == 1 + _placeholders_in(repo), (
        f"only the anchor is first-party source; scanned {scanned}"
    )
    assert violations == [], violations


def test_the_real_tree_passes_and_the_scan_is_non_trivial() -> None:
    # END-TO-END on the shipped tree, with the corpus size asserted so a silently-emptied walk can
    # never satisfy this test by returning no violations.
    gate = _gate()
    violations, scanned = gate.check_non_python_randomness(_ROOT)
    assert violations == [], violations
    assert scanned > 40, f"the extension's source corpus looks truncated: {scanned} file(s)"


def test_the_walk_reaches_both_halves_of_the_extension_corpus() -> None:
    # Second positive control, for the half of the corpus that does not live under src/: the webview
    # scripts shipped as static assets. Mirrors the shipped extension-hardening test's own control.
    gate = _gate()
    found = {p.relative_to(_ROOT).as_posix() for p in gate.non_python_sources(_ROOT / "ide")}
    assert _ANCHOR_REL in found
    assert "ide/media/stepsWebview.js" in found, sorted(found)[:20]


def test_the_shipped_anchor_is_both_discovered_and_inventoried() -> None:
    # Both limbs on purpose (the shape #283 uses for the Python arm): the arm can SEE the site, and
    # the site is accounted for. Either alone would pass while the other silently rotted.
    gate = _gate()
    discovered = gate.discover_non_python(_ROOT / "ide", repo=_ROOT)
    assert discovered.get(_ANCHOR_REL) == frozenset({"randomBytes"}), discovered.get(_ANCHOR_REL)
    assert _ANCHOR_REL in gate.NON_PYTHON_INVENTORY


def test_non_python_walk_roots_are_declared_and_each_holds_the_source_it_claims() -> None:
    # THIS ASSERTION REPLACED A DISJOINTNESS ONE, and the replacement is the finding (BACKLOG #1172).
    # The old test asserted ``NON_PYTHON_WALK_ROOTS`` shared no member with ``WALK_ROOTS``, reasoning
    # that "merging the walk-sets would let one arm's green stand in for the other's silence". That
    # reasoning is sound and it justifies keeping the two ARMS separate -- different instruments,
    # separately reported corpus sizes. It does NOT justify requiring the two ROOT SETS to be
    # disjoint, and conflating the two claims is what hid a real gap: disjointness silently asserts
    # that no first-party root is MIXED-language, and ``messagefoundry_webconsole`` is exactly that.
    # Its Python sat in WALK_ROOTS, so the root rendered green and looked covered, while its shipped
    # first-party JavaScript was read by NEITHER arm -- ``discover()`` rglobs ``*.py``, and the
    # randomness arm walked only ``ide/``. The greenness was a fact about the root's ``.py`` alone.
    #
    # The invariant that actually earns its place: a root is declared here only if it really holds
    # non-Python source, so a declared root can never report clean on a corpus it never reached.
    gate = _gate()
    assert gate.NON_PYTHON_WALK_ROOTS == ("ide", "messagefoundry_webconsole")
    for name in gate.NON_PYTHON_WALK_ROOTS:
        assert gate.non_python_sources(_ROOT / name), (
            f"{name}/ is declared a non-Python walk root but holds no "
            f"{'/'.join(gate.NON_PYTHON_SUFFIXES)} source"
        )


def test_the_walk_reaches_the_operator_consoles_shipped_javascript() -> None:
    # The regression this arm could not catch before (BACKLOG #1172, ASVS 11.5.1 scope pass). Both
    # files are first-party, shipped, and served to an authenticated operator's browser at /ui, and
    # ``csp-probe.js`` IS a security control (the ASVS 3.7.5 CSP-enforcement canary) rather than a
    # cosmetic asset. A weak draw added to either would have merged green.
    gate = _gate()
    found = {
        p.relative_to(_ROOT).as_posix()
        for p in gate.non_python_sources(_ROOT / "messagefoundry_webconsole")
    }
    assert "messagefoundry_webconsole/static/app.js" in found, sorted(found)[:20]
    assert "messagefoundry_webconsole/static/csp-probe.js" in found, sorted(found)[:20]


def test_a_weak_draw_in_the_operator_console_is_caught(tmp_path: Path) -> None:
    # The arm must FAIL on a planted weak source in the console, not merely walk past it. Planted in
    # a copy so the shipped tree is never mutated; the console's real JS is clean today (measured),
    # which is why this control is what proves the arm can see it at all.
    gate = _gate()
    console = tmp_path / "messagefoundry_webconsole" / "static"
    console.mkdir(parents=True)
    (console / "app.js").write_text("var nonce = Math.random().toString(36);\n", encoding="utf-8")
    (tmp_path / "ide").mkdir()
    (tmp_path / "ide" / "cspNonce.ts").write_text("// placeholder\n", encoding="utf-8")

    violations, scanned = gate.check_non_python_randomness(tmp_path)

    assert scanned >= 2, scanned
    assert any("WEAK randomness source" in v and "app.js" in v for v in violations), violations
