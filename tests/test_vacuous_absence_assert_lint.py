# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A test may not assert an empty collection it never showed was built from something.

BACKLOG #1746, limb 2. The shape this lint finds is the one behind the dependency-boundary test's
vacuous pass (Fable packet 18, control B; BACKLOG #1747): a test collects offenders with a
comprehension, then ends on ``assert not offenders``. When the collection the comprehension walks
is empty -- a renamed package, a glob that matches nothing, a fixture that moved -- the list is
empty too, and the test reports the property clean while checking nothing. Zero offenders over
zero candidates is not a pass; it is a gate that never ran.

WHAT COUNTS AS A SITE. Inside a ``test*`` function, an ``assert not NAME`` where NAME was bound
IN THAT FUNCTION to a list, set or dict comprehension, or to ``list(...)``, ``sorted(...)`` or
``set(...)`` over a generator expression. That is the "collect, then assert none" shape. An
``assert not`` on anything else (a flag, a return value, a helper's result) is not a site: the
lint cannot see what such a name was built from, and guessing would bury the real shape in noise.

WHAT GUARDS A SITE. An EARLIER ``assert`` in the same function that states a count: one that calls
``len``, one that compares with ``>`` or ``>=``, or one that asserts a bare name, attribute,
subscript or call is truthy (``assert files``). Any of those shows the walk found something before
the absence was trusted. A comprehension whose first loop runs over a non-empty literal list,
tuple or set is also exempt, because it cannot iterate nothing.

WHAT THIS DOES NOT CATCH, stated so nobody reads its zero as more than it is. A floor enforced in a
helper the test calls (``_guarded_scan`` in test_dependency_boundaries.py is one) is invisible to
it, so such a site counts against the baseline even though it is guarded. A count assertion AFTER
the absence assertion does not guard it. A collection built in a fixture or a helper and returned
is not a site. The lint over-reports in the first case and under-reports in the others.

IT IS A RATCHET, NOT A SWEEP. The tree carried 169 unguarded sites in 92 files when this landed;
rewriting them all is not this item's work and would collide with every open test change. The
baseline below holds each file at its measured count. A NEW site fails at once, in any file, and
the baseline is exact: a file that drops below its number must have its row lowered or removed,
so the allowance cannot outlive the sites it was written for.
"""

from __future__ import annotations

import ast
import functools
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]

#: Both ``testpaths`` roots. The console suite is collected by the same ``pytest -q``.
_ROOTS = (_REPO / "tests", _REPO / "packaging" / "messagefoundry-webconsole" / "tests")

#: The walk's own floors, so this lint cannot pass on nothing either. Measured when it landed:
#: 1011 test files and 169 unguarded sites. A floor well under each still fails a walk that went
#: blind (a moved root, a changed glob), which is the failure this file exists to name.
_MIN_TEST_FILES = 500
_MIN_SITES_SEEN = 100

_COLLECTORS = frozenset({"list", "sorted", "set"})

#: Per-file count of unguarded sites, measured at landing. Relative POSIX paths from the repo root.
#: Lower a row when you guard a site; delete it at zero. Never raise one: guard the new site.
_BASELINE: dict[str, int] = {
    "packaging/messagefoundry-webconsole/tests/test_ui_csp_canary.py": 1,
    "tests/test_adaptive_attributes_doc_drift.py": 1,
    "tests/test_ai_provenance_claims.py": 1,
    "tests/test_anon_parity.py": 2,
    "tests/test_asvs_file_surface_inventory.py": 1,
    "tests/test_binary_carriage.py": 1,
    "tests/test_builtin_hl7_hardening.py": 1,
    "tests/test_ci_odbc_installer_pipefail.py": 1,
    "tests/test_ci_step_margin.py": 1,
    "tests/test_ci_tooling_gate.py": 1,
    "tests/test_ci_venv_pinning.py": 1,
    "tests/test_cla_action_provenance.py": 1,
    "tests/test_claude_settings_contract.py": 2,
    "tests/test_connection_factory_redaction_domain.py": 2,
    "tests/test_connections_file.py": 1,
    "tests/test_connections_file_container_settings.py": 1,
    "tests/test_connscale_rate_window_description.py": 3,
    "tests/test_coord_claim_adjudicate.py": 1,
    "tests/test_coord_claim_reconcile.py": 1,
    "tests/test_coord_lock.py": 1,
    "tests/test_coord_usage.py": 1,
    "tests/test_corepoint_import.py": 1,
    "tests/test_crit2_inline_doc_drift.py": 1,
    "tests/test_crypto_inventory_doc.py": 4,
    "tests/test_csv_formula_consistency.py": 1,
    "tests/test_cutover_slug_rot.py": 2,
    "tests/test_dast_auth_sweep.py": 2,
    "tests/test_dast_claims.py": 1,
    "tests/test_dast_ingress_sweep.py": 1,
    "tests/test_dependency_boundaries.py": 2,
    "tests/test_dicom_parse_error_contract.py": 1,
    "tests/test_doc_guards_lane.py": 1,
    "tests/test_docs_db_grants.py": 2,
    "tests/test_docs_no_first_run_account.py": 1,
    "tests/test_docs_security_pathways.py": 2,
    "tests/test_durability_hook_remote_guard.py": 1,
    "tests/test_engine_text_survives_the_name_run.py": 1,
    "tests/test_feature_map_claims.py": 1,
    "tests/test_field_authz_enforcement_sites.py": 1,
    "tests/test_from_none_is_not_redaction.py": 3,
    "tests/test_gate_ci_mirror_parity.py": 2,
    "tests/test_gate_installed_parity.py": 1,
    "tests/test_hook_prose_folding_push_ledger.py": 1,
    "tests/test_installed_coord_hooks.py": 1,
    "tests/test_key_lifecycle_coverage.py": 1,
    "tests/test_key_usage_scope_inventory.py": 2,
    "tests/test_lens_param_modes.py": 1,
    "tests/test_log_redaction_secret_domain.py": 2,
    "tests/test_logging_credential_scrub.py": 2,
    "tests/test_mfa.py": 2,
    "tests/test_mypy_tests_scope.py": 2,
    "tests/test_negative_controls.py": 1,
    "tests/test_nightly_notice.py": 2,
    "tests/test_off_loopback_runbook.py": 1,
    "tests/test_packaged_tree_denylist.py": 2,
    "tests/test_phi_at_rest_inventory.py": 4,
    "tests/test_phi_logging_inventory.py": 8,
    "tests/test_quality_record_scope_claims.py": 2,
    "tests/test_redaction_structured_shapes.py": 6,
    "tests/test_release_member_gate.py": 1,
    "tests/test_release_pipeline.py": 2,
    "tests/test_relocated_key_messages.py": 2,
    "tests/test_reply_hint_thread_affinity.py": 1,
    "tests/test_required_contexts.py": 1,
    "tests/test_required_contexts_drift.py": 1,
    "tests/test_retention_classification_drift.py": 2,
    "tests/test_risky_component_designation.py": 3,
    "tests/test_scan_forbidden.py": 1,
    "tests/test_sds_rule_ids_are_stable.py": 5,
    "tests/test_secret_rotation_inventory.py": 4,
    "tests/test_security_doc_context_words.py": 1,
    "tests/test_security_doc_drift.py": 4,
    "tests/test_security_doc_rate_limits.py": 3,
    "tests/test_security_posture.py": 6,
    "tests/test_security_static.py": 7,
    "tests/test_service_install_manifest.py": 1,
    "tests/test_shardcert_partitioned.py": 1,
    "tests/test_shardcert_partitioned_fanout.py": 1,
    "tests/test_shipped_line_endings_pinned.py": 2,
    "tests/test_store_encryption.py": 1,
    "tests/test_threat_model_doc_drift.py": 5,
    "tests/test_tls_cipher_assertion_sites.py": 1,
    "tests/test_tls_default_suites.py": 2,
    "tests/test_tls_handshake_sigalgs.py": 1,
    "tests/test_tooling_partition.py": 2,
    "tests/test_tray_boundary.py": 1,
    "tests/test_tray_iconset.py": 1,
    "tests/test_uploads_cross_process_quota.py": 1,
    "tests/test_verify_federation.py": 1,
    "tests/test_webconsole_mount.py": 1,
    "tests/test_workflow_pipefail_screen.py": 3,
    "tests/test_xml_signature_anchor.py": 2,
}


def _binds_a_collection(value: ast.expr) -> bool:
    if isinstance(value, (ast.ListComp, ast.SetComp, ast.DictComp)):
        return True
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id in _COLLECTORS
        and bool(value.args)
        and isinstance(value.args[0], ast.GeneratorExp)
    )


def _iterates_a_nonempty_literal(value: ast.expr) -> bool:
    if isinstance(value, ast.Call):
        value = value.args[0]
    generators = getattr(value, "generators", None)
    if not generators:
        return False
    source = generators[0].iter
    return isinstance(source, (ast.List, ast.Tuple, ast.Set)) and bool(source.elts)


def _states_a_count(test: ast.expr) -> bool:
    if any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "len"
        for n in ast.walk(test)
    ):
        return True
    if isinstance(test, ast.Compare) and any(isinstance(o, (ast.Gt, ast.GtE)) for o in test.ops):
        return True
    return isinstance(test, (ast.Name, ast.Attribute, ast.Subscript, ast.Call))


def _unguarded_sites(source: str) -> list[tuple[int, str, str]]:
    """Every unguarded ``assert not <collected>`` in ``source``, as ``(line, test, name)``."""
    tree = ast.parse(source)
    found: list[tuple[int, str, str]] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not fn.name.startswith("test"):
            continue
        collected: dict[str, ast.expr] = {}
        asserts: list[ast.Assert] = []
        for node in ast.walk(fn):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and _binds_a_collection(node.value)
            ):
                collected[node.targets[0].id] = node.value
            elif isinstance(node, ast.Assert):
                asserts.append(node)
        for node in asserts:
            test = node.test
            if not (
                isinstance(test, ast.UnaryOp)
                and isinstance(test.op, ast.Not)
                and isinstance(test.operand, ast.Name)
                and test.operand.id in collected
            ):
                continue
            name = test.operand.id
            if _iterates_a_nonempty_literal(collected[name]):
                continue
            if any(a.lineno < node.lineno and _states_a_count(a.test) for a in asserts):
                continue
            found.append((node.lineno, fn.name, name))
    return found


def _test_files() -> list[Path]:
    return sorted(p for root in _ROOTS for p in root.rglob("test_*.py"))


def _rel(path: Path) -> str:
    return path.relative_to(_REPO).as_posix()


@functools.cache
def _measure() -> dict[str, list[tuple[int, str, str]]]:
    return {
        _rel(p): sites
        for p in _test_files()
        if (sites := _unguarded_sites(p.read_text(encoding="utf-8")))
    }


# --- the lint's own red: planted cases, so its zero means something ------------------------------

_PLANTED_BAD = """
def test_nothing_is_forbidden(tmp_path):
    offenders = [p for p in tmp_path.rglob("*.py") if "bad" in p.read_text()]
    assert not offenders
"""


def test_the_lint_catches_a_planted_unguarded_absence() -> None:
    assert _unguarded_sites(_PLANTED_BAD) == [(4, "test_nothing_is_forbidden", "offenders")]


@pytest.mark.parametrize(
    "guard",
    [
        "assert len(files) > 3",
        "assert files",
        "assert len(files) >= 1, files",
    ],
)
def test_an_earlier_count_assertion_guards_the_site(guard: str) -> None:
    source = (
        "def test_x(tmp_path):\n"
        "    files = list(tmp_path.rglob('*.py'))\n"
        f"    {guard}\n"
        "    offenders = [p for p in files if p.stat().st_size == 0]\n"
        "    assert not offenders\n"
    )
    assert _unguarded_sites(source) == []


def test_a_count_assertion_after_the_absence_does_not_guard_it() -> None:
    source = (
        "def test_x(files):\n"
        "    offenders = [p for p in files if p]\n"
        "    assert not offenders\n"
        "    assert len(files) > 3\n"
    )
    assert _unguarded_sites(source) == [(3, "test_x", "offenders")]


@pytest.mark.parametrize(
    "binding",
    [
        "bad = sorted(p for p in files if p)",
        "bad = set(p for p in files if p)",
        "bad = {p for p in files if p}",
        "bad = {p: 1 for p in files if p}",
    ],
)
def test_every_collector_spelling_is_a_site(binding: str) -> None:
    source = f"def test_x(files):\n    {binding}\n    assert not bad\n"
    assert _unguarded_sites(source) == [(3, "test_x", "bad")]


def test_a_nonempty_literal_source_cannot_iterate_nothing() -> None:
    source = (
        "def test_x():\n"
        "    bad = [n for n in ('a', 'b') if n.isupper()]\n"
        "    assert not bad\n"
        "    empty = [n for n in () if n]\n"
        "    assert not empty\n"
    )
    assert _unguarded_sites(source) == [(5, "test_x", "empty")]


def test_a_non_test_function_and_an_uncollected_name_are_not_sites() -> None:
    source = (
        "def helper(files):\n"
        "    bad = [p for p in files if p]\n"
        "    assert not bad\n"
        "def test_x(files):\n"
        "    bad = check(files)\n"
        "    assert not bad\n"
    )
    assert _unguarded_sites(source) == []


# --- the ratchet over the real tree --------------------------------------------------------------


def test_the_walk_reaches_the_test_trees() -> None:
    files = _test_files()
    assert len(files) >= _MIN_TEST_FILES, f"walked {len(files)} test file(s) under {_ROOTS}"
    seen = sum(len(s) for s in _measure().values())
    assert seen >= _MIN_SITES_SEEN, (
        f"saw {seen} unguarded site(s), floor {_MIN_SITES_SEEN}: either the tree was cleaned "
        f"(lower the floor with the baseline) or the scan went blind"
    )


def test_no_file_gains_an_unguarded_absence_assertion() -> None:
    over: list[str] = []
    for rel, sites in _measure().items():
        allowed = _BASELINE.get(rel, 0)
        if len(sites) > allowed:
            shown = "; ".join(f"line {n} {fn}: assert not {name}" for n, fn, name in sites)
            over.append(f"{rel}: {len(sites)} site(s), baseline {allowed} -- {shown}")
    assert len(over) == 0, (
        "a test asserts an empty collection with no earlier count assertion, so it passes when "
        "the walk finds nothing. Add `assert len(<source>) >= N` (or `assert <source>`) before "
        "the absence assertion:\n  " + "\n  ".join(over)
    )


def test_the_baseline_is_exact_and_self_pruning() -> None:
    measured = {rel: len(sites) for rel, sites in _measure().items()}
    assert len(_BASELINE) >= 1, "the baseline is empty; delete it and this test together"
    stale = sorted(
        f"{rel}: baseline {n}, measured {measured.get(rel, 0)}"
        for rel, n in _BASELINE.items()
        if measured.get(rel, 0) < n
    )
    assert len(stale) == 0, (
        "these rows allow more sites than the file has; lower or delete them:\n  "
        + "\n  ".join(stale)
    )
