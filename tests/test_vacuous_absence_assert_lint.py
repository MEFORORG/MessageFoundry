# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A test may not assert an empty collection it never showed was built from something.

BACKLOG #1746, limb 2. The shape this lint finds is the one behind the dependency-boundary test's
vacuous pass (Fable packet 18, control B; BACKLOG #1747): a test collects offenders with a
comprehension, then ends on ``assert not offenders``. When the collection the comprehension walks
is empty -- a renamed package, a glob that matches nothing, a fixture that moved -- the list is
empty too, and the test reports the property clean while checking nothing. Zero offenders over
zero candidates is not a pass; it is a gate that never ran.

WHAT COUNTS AS A SITE. Inside a ``test*`` function, an absence assertion over a NAME that was bound
IN THAT FUNCTION to a comprehension, or to ``list``, ``sorted``, ``set``, ``tuple`` or
``frozenset`` over one. The absence spellings are ``assert not NAME``, ``assert NAME == []`` and
``assert len(NAME) == 0``. That is the "collect, then assert none" shape. An absence assertion on
anything else (a flag, a return value, a helper's result) is not a site: the lint cannot see what
such a name was built from, and guessing would bury the real shape in noise.

WHAT GUARDS A SITE. An EARLIER ``assert`` in the same function that states a positive count:
``len(x)`` compared with ``>`` or ``>=``, a bare ``assert len(x)``, or a bare truthiness assertion
of a name, attribute or subscript (``assert files``). ``len(x) == 0``, ``all(...)`` and other calls
do not guard: each is true on an empty input. A comprehension all of whose loops run over non-empty
literal lists, tuples or sets is exempt, because it cannot iterate nothing.

WHAT THIS DOES NOT CATCH is at least the following, so read its zero as no more than that. A floor
enforced in a helper the test calls (``_guarded_scan`` in test_dependency_boundaries.py is one) is
invisible to it, so such a site counts against the baseline although it is guarded. A collection
built in a fixture or a helper and returned is not a site, and neither is any absence spelling not
named above. The baseline is a per-file COUNT, so guarding one site in a file frees room for one new
unguarded site in the same file.

IT IS A RATCHET, NOT A SWEEP. Rewriting every existing site is not this item's work and would
collide with every open test change. The baseline below holds each file at its measured count. A
new site in a file past its count fails at once, and the baseline is exact: a file that drops below
its number must have its row lowered or removed, so the allowance cannot outlive its sites.
"""

from __future__ import annotations

import ast
import functools
from dataclasses import dataclass
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]

#: Both ``testpaths`` roots. The console suite is collected by the same ``pytest -q``.
_ROOTS = (_REPO / "tests", _REPO / "packaging" / "messagefoundry-webconsole" / "tests")

#: The walk's own floors, so this lint cannot pass on nothing either. The site floor counts EVERY
#: candidate site, guarded or not, so guarding sites never pushes the walk under it. Both floors sit
#: well under what the tree carried at landing; what they catch is a walk gone blind (a moved root,
#: a changed glob).
_MIN_TEST_FILES = 500
_MIN_CANDIDATE_SITES = 200

_COLLECTORS = frozenset({"list", "sorted", "set", "tuple", "frozenset"})
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)

#: Per-file count of unguarded sites, measured at landing. Relative POSIX paths from the repo root.
#: Lower a row when you guard a site; delete it at zero. Never raise one: guard the new site.
_BASELINE: dict[str, int] = {
    "packaging/messagefoundry-webconsole/tests/test_ui_csp_canary.py": 1,
    "tests/test_adaptive_attributes_doc_drift.py": 1,
    "tests/test_adr0071_fused_callables_sqlserver.py": 1,
    "tests/test_ai_provenance_claims.py": 1,
    "tests/test_anon_parity.py": 2,
    "tests/test_api_input_validation.py": 1,
    "tests/test_api_security_header_floor.py": 2,
    "tests/test_api_tls.py": 1,
    "tests/test_asvs_crypto_agility_seam.py": 1,
    "tests/test_asvs_file_surface_inventory.py": 1,
    "tests/test_auth_hardening.py": 1,
    "tests/test_binary_carriage.py": 1,
    "tests/test_bounded_egress_reads.py": 2,
    "tests/test_builtin_hl7_hardening.py": 1,
    "tests/test_ci_odbc_installer_pipefail.py": 1,
    "tests/test_ci_step_margin.py": 1,
    "tests/test_ci_tooling_gate.py": 1,
    "tests/test_ci_venv_pinning.py": 1,
    "tests/test_cla_action_provenance.py": 1,
    "tests/test_claude_settings_contract.py": 2,
    "tests/test_communications_inventory.py": 1,
    "tests/test_connection_factory_redaction_domain.py": 2,
    "tests/test_connections_file.py": 1,
    "tests/test_connections_file_container_settings.py": 1,
    "tests/test_connscale_empty_claims_per_msg.py": 1,
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
    "tests/test_docs_security_pathways.py": 3,
    "tests/test_durability_hook_remote_guard.py": 2,
    "tests/test_engine_text_survives_the_name_run.py": 1,
    "tests/test_failure_signal.py": 2,
    "tests/test_feature_map_claims.py": 1,
    "tests/test_field_authz_enforcement_sites.py": 1,
    "tests/test_from_none_is_not_redaction.py": 4,
    "tests/test_fuzz_targets.py": 2,
    "tests/test_gate_ci_mirror_parity.py": 3,
    "tests/test_gate_installed_parity.py": 1,
    "tests/test_harness_monitor.py": 1,
    "tests/test_hook_prose_folding.py": 1,
    "tests/test_hook_prose_folding_push_ledger.py": 1,
    "tests/test_install_gate_allowlist_merge.py": 2,
    "tests/test_installed_coord_hooks.py": 1,
    "tests/test_key_lifecycle_coverage.py": 1,
    "tests/test_key_usage_scope_inventory.py": 2,
    "tests/test_ldap_timeouts.py": 2,
    "tests/test_lens_param_modes.py": 1,
    "tests/test_log_redaction_secret_domain.py": 2,
    "tests/test_logging.py": 1,
    "tests/test_logging_credential_scrub.py": 2,
    "tests/test_mfa.py": 2,
    "tests/test_mypy_tests_scope.py": 3,
    "tests/test_negative_controls.py": 1,
    "tests/test_nightly_notice.py": 3,
    "tests/test_no_store_phi_coverage.py": 2,
    "tests/test_off_loopback_runbook.py": 1,
    "tests/test_packaged_tree_denylist.py": 2,
    "tests/test_phi_at_rest_inventory.py": 5,
    "tests/test_phi_logging_inventory.py": 8,
    "tests/test_provision_first_administrator.py": 1,
    "tests/test_quality_record_scope_claims.py": 2,
    "tests/test_redaction_structured_shapes.py": 6,
    "tests/test_release_member_gate.py": 1,
    "tests/test_release_pipeline.py": 3,
    "tests/test_relocated_key_messages.py": 3,
    "tests/test_reply_hint_thread_affinity.py": 1,
    "tests/test_required_contexts.py": 1,
    "tests/test_required_contexts_drift.py": 1,
    "tests/test_retention_classification_drift.py": 2,
    "tests/test_risky_component_designation.py": 3,
    "tests/test_sandbox_import_boundary.py": 1,
    "tests/test_scan_forbidden.py": 1,
    "tests/test_scan_tokens_source.py": 1,
    "tests/test_sds_rule_ids_are_stable.py": 5,
    "tests/test_secret_rotation_inventory.py": 4,
    "tests/test_security_doc_context_words.py": 1,
    "tests/test_security_doc_drift.py": 4,
    "tests/test_security_doc_rate_limits.py": 3,
    "tests/test_security_posture.py": 6,
    "tests/test_security_static.py": 7,
    "tests/test_security_txt_expiry_reminder.py": 1,
    "tests/test_security_txt_rfc9116.py": 2,
    "tests/test_service_install_manifest.py": 2,
    "tests/test_session_mail.py": 3,
    "tests/test_session_mail_held.py": 1,
    "tests/test_shardcert_partitioned.py": 1,
    "tests/test_shardcert_partitioned_fanout.py": 1,
    "tests/test_shipped_line_endings_pinned.py": 2,
    "tests/test_site_context_words.py": 1,
    "tests/test_steer_inject.py": 1,
    "tests/test_store.py": 2,
    "tests/test_store_encryption.py": 1,
    "tests/test_store_key_calendar_expiry.py": 1,
    "tests/test_store_pool_acquire_timeout.py": 1,
    "tests/test_threat_model_doc_drift.py": 5,
    "tests/test_tls_cipher_assertion_sites.py": 2,
    "tests/test_tls_default_suites.py": 2,
    "tests/test_tls_handshake_sigalgs.py": 1,
    "tests/test_tooling_partition.py": 3,
    "tests/test_tray_boundary.py": 1,
    "tests/test_tray_iconset.py": 1,
    "tests/test_uploads_cross_process_quota.py": 1,
    "tests/test_usage_headroom_inject.py": 2,
    "tests/test_verify_federation.py": 1,
    "tests/test_webconsole_mount.py": 1,
    "tests/test_workflow_pipefail_screen.py": 4,
    "tests/test_xml_signature_anchor.py": 2,
}


@dataclass(frozen=True)
class Site:
    line: int
    test: str
    name: str
    guarded: bool


def _comprehension(value: ast.expr) -> ast.expr | None:
    """The comprehension a binding collects, or None when the value is not a collection."""
    if isinstance(value, _COMPREHENSIONS):
        return value
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id in _COLLECTORS
        and value.args
        and isinstance(value.args[0], _COMPREHENSIONS)
    ):
        return value.args[0]
    return None


def _iterates_only_nonempty_literals(comp: ast.expr) -> bool:
    generators: list[ast.comprehension] = getattr(comp, "generators", [])
    return bool(generators) and all(
        isinstance(g.iter, (ast.List, ast.Tuple, ast.Set)) and bool(g.iter.elts) for g in generators
    )


def _len_argument(node: ast.expr) -> ast.expr | None:
    """``x`` when ``node`` is ``len(x)``, else None."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "len"
        and len(node.args) == 1
    ):
        return node.args[0]
    return None


def _states_a_count(test: ast.expr) -> bool:
    if isinstance(test, (ast.Name, ast.Attribute, ast.Subscript)):
        return True
    if _len_argument(test) is not None:
        return True
    return (
        isinstance(test, ast.Compare)
        and _len_argument(test.left) is not None
        and len(test.ops) == 1
        and isinstance(test.ops[0], (ast.Gt, ast.GtE))
    )


def _absence_subject(test: ast.expr) -> str | None:
    """The name an absence assertion is about: ``not X``, ``X == []`` or ``len(X) == 0``."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return test.operand.id if isinstance(test.operand, ast.Name) else None
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1):
        return None
    if not isinstance(test.ops[0], ast.Eq):
        return None
    left, right = test.left, test.comparators[0]
    if isinstance(left, ast.Name) and isinstance(right, ast.List) and not right.elts:
        return left.id
    counted = _len_argument(left)
    if isinstance(counted, ast.Name) and isinstance(right, ast.Constant) and right.value == 0:
        return counted.id
    return None


def _sites(source: str) -> list[Site]:
    """Every candidate site in ``source``, guarded or not."""
    tree = ast.parse(source)
    found: list[Site] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not fn.name.startswith("test"):
            continue
        collected: dict[str, ast.expr] = {}
        asserts: list[ast.Assert] = []
        for node in ast.walk(fn):
            target: ast.expr | None = None
            value: ast.expr | None = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target, value = node.targets[0], node.value
            elif isinstance(node, ast.AnnAssign):
                target, value = node.target, node.value
            elif isinstance(node, ast.Assert):
                asserts.append(node)
            if isinstance(target, ast.Name) and value is not None:
                comp = _comprehension(value)
                if comp is not None:
                    collected[target.id] = comp
        for node in asserts:
            name = _absence_subject(node.test)
            if name is None or name not in collected:
                continue
            if _iterates_only_nonempty_literals(collected[name]):
                continue
            guarded = any(a.lineno < node.lineno and _states_a_count(a.test) for a in asserts)
            found.append(Site(node.lineno, fn.name, name, guarded))
    return found


def _unguarded_sites(source: str) -> list[tuple[int, str, str]]:
    """Every unguarded site in ``source``, as ``(line, test, name)``."""
    return [(s.line, s.test, s.name) for s in _sites(source) if not s.guarded]


def _test_files() -> list[Path]:
    return sorted(p for root in _ROOTS for p in root.rglob("test_*.py"))


def _rel(path: Path) -> str:
    return path.relative_to(_REPO).as_posix()


@functools.cache
def _measure_all() -> dict[str, tuple[Site, ...]]:
    return {_rel(p): tuple(_sites(p.read_text(encoding="utf-8"))) for p in _test_files()}


def _measure() -> dict[str, list[Site]]:
    """Per file, its UNGUARDED sites; files with none are left out."""
    return {
        rel: unguarded
        for rel, sites in _measure_all().items()
        if (unguarded := [s for s in sites if not s.guarded])
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
    "absence",
    ["assert not bad", "assert bad == []", "assert len(bad) == 0"],
)
def test_every_absence_spelling_is_a_site(absence: str) -> None:
    source = f"def test_x(files):\n    bad = [p for p in files if p]\n    {absence}\n"
    assert _unguarded_sites(source) == [(3, "test_x", "bad")]


@pytest.mark.parametrize(
    "guard",
    [
        "assert len(files) > 3",
        "assert files",
        "assert len(files) >= 1, files",
        "assert len(files)",
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


@pytest.mark.parametrize(
    "not_a_guard",
    [
        "assert all(f.suffix == '.py' for f in files)",
        "assert len(files) == 0 or True",
        "assert isinstance(files, list)",
        "assert len(files) < 99",
    ],
)
def test_an_assertion_true_on_an_empty_input_does_not_guard(not_a_guard: str) -> None:
    source = (
        "def test_x(files):\n"
        f"    {not_a_guard}\n"
        "    bad = [p for p in files if p]\n"
        "    assert not bad\n"
    )
    assert _unguarded_sites(source) == [(4, "test_x", "bad")]


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
        "bad = tuple(p for p in files if p)",
        "bad = frozenset(p for p in files if p)",
        "bad = sorted({p for p in files if p})",
        "bad = {p for p in files if p}",
        "bad = {p: 1 for p in files if p}",
        "bad: list[str] = [p for p in files if p]",
    ],
)
def test_every_collector_spelling_is_a_site(binding: str) -> None:
    source = f"def test_x(files):\n    {binding}\n    assert not bad\n"
    assert _unguarded_sites(source) == [(3, "test_x", "bad")]


def test_a_nonempty_literal_source_cannot_iterate_nothing() -> None:
    source = (
        "def test_x(root):\n"
        "    bad = [n for n in ('a', 'b') if n.isupper()]\n"
        "    assert not bad\n"
        "    empty = [n for n in () if n]\n"
        "    assert not empty\n"
        "    walked = [p for pat in ('*.py',) for p in root.glob(pat)]\n"
        "    assert not walked\n"
    )
    assert _unguarded_sites(source) == [(5, "test_x", "empty"), (7, "test_x", "walked")]


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
    seen = sum(len(sites) for sites in _measure_all().values())
    assert seen >= _MIN_CANDIDATE_SITES, (
        f"saw {seen} candidate site(s), guarded or not, floor {_MIN_CANDIDATE_SITES}: the scan "
        f"went blind, or the collect-then-assert-none shape left the tree"
    )


def test_no_file_gains_an_unguarded_absence_assertion() -> None:
    over: list[str] = []
    for rel, sites in _measure().items():
        allowed = _BASELINE.get(rel, 0)
        if len(sites) > allowed:
            shown = "; ".join(f"line {s.line} {s.test}: {s.name}" for s in sites)
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
