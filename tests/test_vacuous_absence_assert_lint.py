# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A test may not assert an empty collection it never showed was built from something.

BACKLOG #1746, limb 2. The shape this lint finds is the one behind the dependency-boundary test's
vacuous pass (Fable packet 18, control B; BACKLOG #1747): a test collects offenders with a
comprehension, then ends on ``assert not offenders``. When the collection the comprehension walks
is empty -- a renamed package, a glob that matches nothing, a fixture that moved -- the list is
empty too, and the test reports the property clean while checking nothing. Zero offenders over
zero candidates is not a pass; it is a gate that never ran.

WHAT COUNTS AS A SITE. Inside a ``test*`` function, an absence assertion over a NAME whose binding
just before it, IN THAT FUNCTION, is to a comprehension, or to ``list``, ``sorted``, ``set``,
``tuple`` or ``frozenset`` over one. A later rebinding does not change how an earlier site is
judged, and a rebinding to anything else ends the site, except ``bad = sorted(bad)`` and the like,
which re-collect the same walk. A function defined inside a test is a scope of its own, judged by
its own bindings and its own guards. The absence spellings are ``assert not NAME``,
``assert NAME == <empty>`` (``[]``, ``{}``, ``()``, ``set()`` and the like) and
``assert len(NAME) == 0``. That is the
"collect, then assert none" shape. An absence assertion on anything else (a flag, a return value, a
helper's result) is not a site: the lint cannot see what such a name was built from, and guessing
would bury the real shape in noise.

WHAT GUARDS A SITE. An EARLIER ``assert`` at the test function's own top level that states a
positive count of something the comprehension iterates over: ``len(x)`` compared with ``>`` or
``>=`` a bound that excludes zero, a bare ``assert len(x)``, or a bare truthiness assertion
(``assert files``), where ``x`` or ``files`` IS an expression the comprehension's loops draw
from (``_walked`` lists what does not count). Sharing a name is not enough:
``assert report['declared']`` does not guard a walk over ``report['commands']``, and neither does
``assert report``, since a non-empty container can hold an empty part. A guard also fails when a name it reads is rebound between the guard and the walk,
because the two then read different values. An assertion about something else does not guard, nor
does one inside a loop, a ``with`` block or a nested def, which may run zero times.
``len(x) == 0``, ``len(x) >= 0``, ``len(x) >= 0.0``, ``all(...)`` and other calls do not guard:
each is true on an empty input. A comprehension all of whose loops run over
non-empty literal lists, tuples or sets, with nothing starred, is exempt: it cannot iterate nothing.

WHAT THIS DOES NOT CATCH is at least the following, so read its zero as no more than that. A floor
enforced in a helper the test calls (``_guarded_scan`` in test_dependency_boundaries.py is one) is
invisible to it, so such a site counts against the baseline although it is guarded. A collection
built in a fixture or a helper and returned is not a site, and neither is a name a nested helper
reads from the test around it, nor any absence spelling not named above. "Before" means earlier
in the source, not in control flow, so a binding in one branch of an ``if`` counts for code in the
other, and a rebinding later in a loop body is not seen to reach the next pass. Assignments in a
class body are not scanned. An argument to any call counts as a population, so ``assert tmp_path``
guards a walk over ``tmp_path.rglob('*.py')`` although a path is always truthy. The baseline is a per-file COUNT, so
guarding one site in a file frees room for one new unguarded site in the same file.

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
    "packaging/messagefoundry-webconsole/tests/test_ui_mfa_gate.py": 1,
    "packaging/messagefoundry-webconsole/tests/test_webui.py": 1,
    "tests/test_adaptive_attributes_doc_drift.py": 1,
    "tests/test_adr0071_fused_callables_sqlserver.py": 1,
    "tests/test_ai_provenance_claims.py": 1,
    "tests/test_anon_parity.py": 2,
    "tests/test_api_input_validation.py": 1,
    "tests/test_api_security_header_floor.py": 2,
    "tests/test_api_tls.py": 1,
    "tests/test_asvs_crypto_agility_seam.py": 1,
    "tests/test_asvs_file_surface_inventory.py": 2,
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
    "tests/test_conftest_restores_process_logging.py": 1,
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
    "tests/test_credential_parameter_mapping.py": 1,
    "tests/test_credential_reply_no_store.py": 1,
    "tests/test_crit2_inline_doc_drift.py": 1,
    "tests/test_crypto_inventory_doc.py": 4,
    "tests/test_csv_formula_consistency.py": 1,
    "tests/test_cutover_slug_rot.py": 2,
    "tests/test_dast_auth_sweep.py": 2,
    "tests/test_dast_claims.py": 1,
    "tests/test_dast_ingress_sweep.py": 1,
    "tests/test_dependency_boundaries.py": 3,
    "tests/test_dicom_parse_error_contract.py": 1,
    "tests/test_doc_guards_lane.py": 1,
    "tests/test_docs_cite_no_refused_config_keys.py": 1,
    "tests/test_docs_db_grants.py": 2,
    "tests/test_docs_no_first_run_account.py": 1,
    "tests/test_docs_security_pathways.py": 3,
    "tests/test_durability_hook_remote_guard.py": 2,
    "tests/test_engine_text_survives_the_name_run.py": 1,
    "tests/test_environments.py": 1,
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
    "tests/test_log_redaction_secret_domain.py": 3,
    "tests/test_logging.py": 1,
    "tests/test_logging_credential_scrub.py": 2,
    "tests/test_mfa.py": 2,
    "tests/test_mypy_tests_scope.py": 3,
    "tests/test_negative_controls.py": 1,
    "tests/test_nightly_notice.py": 3,
    "tests/test_no_store_phi_coverage.py": 3,
    "tests/test_off_loopback_runbook.py": 1,
    "tests/test_packaged_tree_denylist.py": 2,
    "tests/test_phi_at_rest_inventory.py": 7,
    "tests/test_phi_logging_inventory.py": 9,
    "tests/test_provision_first_administrator.py": 1,
    "tests/test_quality_record_scope_claims.py": 2,
    "tests/test_redaction_structured_shapes.py": 6,
    "tests/test_release_member_gate.py": 1,
    "tests/test_release_pipeline.py": 3,
    "tests/test_relocated_key_messages.py": 3,
    "tests/test_replay_erased_body_scope.py": 2,
    "tests/test_reply_hint_thread_affinity.py": 1,
    "tests/test_required_contexts.py": 1,
    "tests/test_required_contexts_drift.py": 1,
    "tests/test_retention_classification_drift.py": 2,
    "tests/test_risky_component_designation.py": 4,
    "tests/test_sandbox_import_boundary.py": 1,
    "tests/test_scan_forbidden.py": 1,
    "tests/test_scan_tokens_source.py": 1,
    "tests/test_sds_rule_ids_are_stable.py": 5,
    "tests/test_secret_rotation_inventory.py": 4,
    "tests/test_security_composite_parity.py": 1,
    "tests/test_security_doc_context_words.py": 1,
    "tests/test_security_doc_drift.py": 4,
    "tests/test_security_doc_rate_limits.py": 3,
    "tests/test_security_posture.py": 6,
    "tests/test_security_static.py": 7,
    "tests/test_security_txt_expiry_reminder.py": 1,
    "tests/test_security_txt_rfc9116.py": 2,
    "tests/test_service_install_manifest.py": 4,
    "tests/test_session_mail.py": 3,
    "tests/test_session_mail_held.py": 1,
    "tests/test_shardcert_partitioned.py": 1,
    "tests/test_shardcert_partitioned_fanout.py": 1,
    "tests/test_shipped_line_endings_pinned.py": 2,
    "tests/test_site_context_words.py": 1,
    "tests/test_steer_inject.py": 1,
    "tests/test_store.py": 3,
    "tests/test_store_encryption.py": 1,
    "tests/test_store_key_calendar_expiry.py": 1,
    "tests/test_store_pool_acquire_timeout.py": 1,
    "tests/test_threat_model_doc_drift.py": 5,
    "tests/test_tls_cipher_assertion_sites.py": 3,
    "tests/test_tls_default_suites.py": 2,
    "tests/test_tls_handshake_sigalgs.py": 1,
    "tests/test_tooling_partition.py": 3,
    "tests/test_tray_boundary.py": 1,
    "tests/test_tray_iconset.py": 1,
    "tests/test_tray_logscrub.py": 1,
    "tests/test_uploads_cross_process_quota.py": 1,
    "tests/test_usage_headroom_inject.py": 2,
    "tests/test_verify_federation.py": 1,
    "tests/test_webconsole_mount.py": 1,
    "tests/test_workflow_pipefail_screen.py": 4,
    "tests/test_worktree_new_cleanup_advice.py": 1,
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
    """Every loop runs over a literal with elements, none of them starred (``[*xs]`` can be empty)."""
    generators: list[ast.comprehension] = getattr(comp, "generators", [])
    return bool(generators) and all(
        isinstance(g.iter, (ast.List, ast.Tuple, ast.Set))
        and bool(g.iter.elts)
        and not any(isinstance(e, ast.Starred) for e in g.iter.elts)
        for g in generators
    )


def _walked(comp: ast.expr) -> set[str]:
    """The expressions the comprehension draws its candidates from, as ``ast.dump`` text.

    Only the FIRST loop counts: a later loop runs once per item of the first, so counting what it
    walks says nothing when the first is empty. Its iterable counts, and so does every expression
    inside it, since a call such as ``_without_hash(requirements)`` may filter a population the test
    counted as ``requirements``. Left out, because counting them says nothing about the population:
    a called function (``sorted`` in ``sorted(files)``), a constant, a container the iterable only
    selects a part of (``report`` in ``report['commands']``, ``self`` in ``self.files``), a
    subscript's index, and the parts of a conditional (``files`` in ``(files if cond else [])`` may
    be the arm not taken). Of ``a or b`` only ``a`` counts, and of ``a and b`` neither does. A
    comprehension inside the iterable counts through its own first loop.
    """
    generators: list[ast.comprehension] = getattr(comp, "generators", [])
    parts: set[str] = set()

    def collect(node: ast.AST, counts: bool) -> None:
        if not isinstance(node, ast.expr) or isinstance(node, ast.Constant):
            return
        if counts:
            parts.add(ast.dump(node))
        if isinstance(node, (ast.Subscript, ast.Attribute)):
            # The container a part is selected from, but never a subscript's index.
            collect(node.value, False)
        elif isinstance(node, _COMPREHENSIONS):
            collect(node.generators[0].iter, True)
        elif isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.Or):
                collect(node.values[0], True)
        elif isinstance(node, ast.Call):
            # A method's receiver counts (``texts`` in ``texts.items()``); the function does not.
            if isinstance(node.func, ast.Attribute):
                collect(node.func.value, True)
            for arg in node.args:
                collect(arg, True)
            for keyword in node.keywords:
                collect(keyword.value, True)
        elif not isinstance(node, (ast.IfExp, ast.Lambda)):
            for child in ast.iter_child_nodes(node):
                collect(child, True)

    if generators:
        collect(generators[0].iter, True)
    return parts


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


def _floor_is_positive(op: ast.cmpop, bound: ast.expr) -> bool:
    """``len(x) >= bound`` or ``len(x) > bound`` excludes zero, as far as the source shows.

    A numeric constant bound is checked (``>= 0``, ``>= 0.0`` and ``> -1`` do not exclude zero), and
    any other constant does not guard. A named bound such as ``_MIN_FILES`` is taken on trust: the
    lint cannot evaluate it, and naming a floor is the habit it wants.
    """
    if isinstance(bound, ast.UnaryOp) and isinstance(bound.op, ast.USub):
        return False  # a negative literal bound excludes nothing
    if isinstance(bound, ast.Constant):
        if not isinstance(bound.value, (int, float)):
            return False
        return bound.value > 0 if isinstance(op, ast.GtE) else bound.value >= 0
    return True


def _counted_expr(test: ast.expr) -> ast.expr | None:
    """What a positive-count assertion is about, or None when ``test`` is not one."""
    if isinstance(test, (ast.Name, ast.Attribute, ast.Subscript)):
        return test
    counted = _len_argument(test)
    if counted is not None:
        return counted
    if (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], (ast.Gt, ast.GtE))
        and _floor_is_positive(test.ops[0], test.comparators[0])
    ):
        return _len_argument(test.left)
    return None


#: Calls that keep a collection non-empty exactly when their argument is.
_SAME_COUNT_CALLS = frozenset({"list", "sorted", "set", "tuple", "frozenset", "reversed"})


def _same_count_argument(node: ast.expr) -> ast.expr | None:
    """``x`` when ``node`` is ``sorted(x)`` or another call that is empty exactly when ``x`` is."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _SAME_COUNT_CALLS
        and len(node.args) == 1
        and not isinstance(node.args[0], ast.Starred)
    ):
        return node.args[0]
    return None


def _guards(test: ast.expr, walked: set[str]) -> ast.expr | None:
    """What ``test`` counts, when that is itself something the comprehension draws from.

    The counted expression must BE what the loop walks (see ``_walked``), not merely share a name
    with it: ``assert report['declared']`` says nothing about a walk over ``report['commands']``.
    ``len(sorted(files))`` counts ``files``.
    """
    counted = _counted_expr(test)
    while counted is not None and (inner := _same_count_argument(counted)) is not None:
        counted = inner
    if counted is None or ast.dump(counted) not in walked:
        return None
    return counted


_EMPTY_CALLS = frozenset({"set", "dict", "list", "tuple", "frozenset"})


def _is_empty_literal(node: ast.expr) -> bool:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return not node.elts
    if isinstance(node, ast.Dict):
        return not node.keys
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _EMPTY_CALLS
        and not node.args
        and not node.keywords
    )


def _absence_subject(test: ast.expr) -> str | None:
    """The name an absence assertion is about: ``not X``, ``X == <empty>`` or ``len(X) == 0``."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return test.operand.id if isinstance(test.operand, ast.Name) else None
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1):
        return None
    if not isinstance(test.ops[0], ast.Eq):
        return None
    left, right = test.left, test.comparators[0]
    if isinstance(left, ast.Name) and _is_empty_literal(right):
        return left.id
    counted = _len_argument(left)
    if isinstance(counted, ast.Name) and isinstance(right, ast.Constant) and right.value == 0:
        return counted.id
    return None


_Scope = ast.FunctionDef | ast.AsyncFunctionDef

#: Nodes whose insides belong to another scope: a nested def or class, a lambda, or a comprehension
#: (whose loop variables are its own).
_OPAQUE = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda, *_COMPREHENSIONS)


#: A source position, ``(line, column)``, so two statements on one line still have an order.
_Pos = tuple[int, int]


def _pos(node: ast.AST) -> _Pos:
    return (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))


@dataclass(frozen=True)
class _Binding:
    """One binding of a name, attribute or item in a scope, keyed by its source text.

    ``comp`` is the comprehension the value collects, if any, and ``walk`` is where that
    comprehension ran. A binding whose value reads the name it binds (``bad = sorted(bad)``,
    ``bad = bad - ALLOWED``, ``bad += more``) works on the value it finds, so it keeps the earlier
    binding's ``comp`` and ``walk``. ``same_count`` marks one that cannot change whether the value
    is empty (``files = sorted(files)``), so it does not make a guard on that name stale.
    """

    pos: _Pos
    comp: ast.expr | None
    walk: _Pos
    same_count: bool = False


def _own_nodes(fn: _Scope) -> list[ast.AST]:
    """Every node in ``fn``'s own scope, leaving out the insides of nested scopes."""
    found: list[ast.AST] = []
    stack: list[ast.AST] = list(fn.body)
    while stack:
        node = stack.pop()
        found.append(node)
        if not isinstance(node, _OPAQUE):
            stack.extend(ast.iter_child_nodes(node))
    return found


def _other_binders(node: ast.AST) -> list[tuple[str, _Pos]]:
    """Names ``node`` binds in the scope without a ``Store`` name of its own.

    That is an import, ``except ... as``, a ``match`` capture, a nested ``def`` or ``class``, and a
    walrus inside a comprehension, which binds in the enclosing scope although the comprehension's
    other names stay inside it.
    """
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return [((a.asname or a.name).split(".")[0], _pos(node)) for a in node.names]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [(node.name, _pos(node))]
    if isinstance(node, ast.ExceptHandler) and node.name:
        return [(node.name, _pos(node))]
    if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
        return [(node.name, _pos(node))]
    if isinstance(node, ast.MatchMapping) and node.rest:
        return [(node.rest, _pos(node))]
    if isinstance(node, _COMPREHENSIONS):
        return [
            (n.target.id, _pos(n.target))
            for n in ast.walk(node)
            if isinstance(n, ast.NamedExpr) and isinstance(n.target, ast.Name)
        ]
    return []


_STORABLE = (ast.Name, ast.Attribute, ast.Subscript)


def _bindings(nodes: list[ast.AST]) -> dict[str, list[_Binding]]:
    """Every binding in a scope, keyed by source text (``bad``, ``self.files``), in source order.

    A name bound to anything but a comprehension gets a binding with no comprehension, so a later
    ``bad = check(files)`` ends the site an earlier ``bad = [...]`` started. A bare annotation
    (``bad: list[str]``) binds nothing.
    """
    comps: dict[int, ast.expr] = {}
    inherits: set[int] = set()
    same_count: set[int] = set()
    skipped: set[int] = set()
    raw: list[tuple[str, _Pos, int]] = []
    for node in nodes:
        if isinstance(node, ast.AnnAssign) and node.value is None:
            skipped.add(id(node.target))
        if isinstance(node, ast.AugAssign):
            inherits.add(id(node.target))
        target: ast.expr | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        if isinstance(target, ast.Name) and value is not None:
            comp = _comprehension(value)
            if comp is not None:
                comps[id(target)] = comp
            elif any(isinstance(n, ast.Name) and n.id == target.id for n in ast.walk(value)):
                inherits.add(id(target))
                argument = _same_count_argument(value)
                if isinstance(argument, ast.Name) and argument.id == target.id:
                    same_count.add(id(target))
        raw.extend((name, pos, 0) for name, pos in _other_binders(node))
    raw.extend(
        (ast.unparse(n), _pos(n), id(n))
        for n in nodes
        if isinstance(n, _STORABLE) and isinstance(n.ctx, ast.Store) and id(n) not in skipped
    )
    found: dict[str, list[_Binding]] = {}
    for key, pos, ident in sorted(raw, key=lambda r: r[1]):
        bound = found.setdefault(key, [])
        if ident in inherits and bound:
            last = bound[-1]
            bound.append(_Binding(pos, last.comp, last.walk, ident in same_count))
        else:
            bound.append(_Binding(pos, comps.get(ident), pos))
    return found


def _reaching(bound: list[_Binding], pos: _Pos) -> _Binding | None:
    """The last binding before ``pos``, which is the value an assertion there reads."""
    earlier = [b for b in bound if b.pos < pos]
    return earlier[-1] if earlier else None


def _rebound_between(bound: list[_Binding], guard: _Pos, walk: _Pos) -> bool:
    """A binding lands between the guard and the walk, so they read two different values.

    A guard before the walk is stale if the name is rebound after the guard and before the walk's
    statement; that statement reads the old value before any binding it makes. A guard after the
    walk is stale if the name is rebound from the walk's statement up to the guard.
    """
    changing = [b for b in bound if not b.same_count]
    if guard < walk:
        return any(guard < b.pos < walk for b in changing)
    return any(walk <= b.pos < guard for b in changing)


def _read_keys(counted: ast.expr) -> list[str]:
    """The source text of every name, attribute and item a counted expression reads."""
    return [ast.unparse(n) for n in ast.walk(counted) if isinstance(n, _STORABLE)]


@dataclass(frozen=True)
class _Enclosing:
    """A scope around a nested helper: its top-level guards and bindings, and where the def sits."""

    guards: tuple[ast.Assert, ...]
    bindings: dict[str, list[_Binding]]
    def_pos: _Pos


def _closure_guarded(walked: set[str], own: set[str], enclosing: tuple[_Enclosing, ...]) -> bool:
    """A guard in an enclosing test counts a value this helper reads from it, and nothing rebinds it.

    The guard must sit at the enclosing scope's top level before the helper's ``def``, every name it
    reads must be one the helper does not bind itself (``own``, parameters included), and the enclosing scope must not rebind any of
    them after the guard, since the helper may run after that.
    """
    for outer in enclosing:
        for guard in outer.guards:
            if _pos(guard) >= outer.def_pos:
                continue
            counted = _guards(guard.test, walked)
            if counted is None:
                continue
            keys = _read_keys(counted)
            if any(isinstance(n, ast.Name) and n.id in own for n in ast.walk(counted)):
                continue
            if any(
                b.pos > _pos(guard) and not b.same_count
                for k in keys
                for b in outer.bindings.get(k, [])
            ):
                continue
            return True
    return False


def _scope_sites(
    fn: _Scope, label: str, enclosing: tuple[_Enclosing, ...]
) -> tuple[list[Site], tuple[ast.Assert, ...], dict[str, list[_Binding]]]:
    """The candidate sites in ``fn``'s own scope, with the scope's guards and bindings.

    Each site is judged by the scope's own top-level guards, and, for a helper nested in a test, by
    a guard in the test around it on a value the helper reads from there.
    """
    nodes = _own_nodes(fn)
    bindings = _bindings(nodes)
    # Only a guard at the function's own top level is sure to have RUN before the site: one in
    # a loop body runs zero times on an empty input, and one in a `with pytest.raises` block or
    # a nested def may never run at all.
    top_level = tuple(s for s in fn.body if isinstance(s, ast.Assert))
    found: list[Site] = []
    for node in sorted((n for n in nodes if isinstance(n, ast.Assert)), key=_pos):
        name = _absence_subject(node.test)
        if name is None:
            continue
        reaching = _reaching(bindings.get(name, []), _pos(node))
        if reaching is None or reaching.comp is None:
            continue
        if _iterates_only_nonempty_literals(reaching.comp):
            continue
        walked = _walked(reaching.comp)
        guarded = False
        for guard in top_level:
            if _pos(guard) >= _pos(node):
                continue
            counted = _guards(guard.test, walked)
            if counted is not None and not any(
                _rebound_between(bindings.get(key, []), _pos(guard), reaching.walk)
                for key in _read_keys(counted)
            ):
                guarded = True
                break
        if not guarded:
            own = set(bindings) | {a.arg for a in ast.walk(fn.args) if isinstance(a, ast.arg)}
            guarded = _closure_guarded(walked, own, enclosing)
        found.append(Site(node.lineno, label, name, guarded))
    return found, top_level, bindings


def _sites(source: str) -> list[Site]:
    """Every candidate site in ``source``, guarded or not.

    Every ``test*`` function is a scope, and so is every function defined inside one (a helper a
    test builds for itself); ``label`` names a nested one ``test_x.helper``. Each scope is judged by
    its own bindings, its own assertions and its own top-level guards, plus, for a nested helper,
    the guards of the test around it (see ``_closure_guarded``).
    """
    found: list[Site] = []

    def visit(
        node: ast.AST,
        inside: str | None,
        enclosing: tuple[_Enclosing, ...],
        scope: tuple[tuple[ast.Assert, ...], dict[str, list[_Binding]]] | None,
    ) -> None:
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, inside, enclosing, scope)
                continue
            if inside is not None:
                label: str | None = f"{inside}.{child.name}"
            elif child.name.startswith("test"):
                label = child.name
            else:
                label = None
            if label is None:
                visit(child, None, (), None)
                continue
            around = enclosing
            if scope is not None:
                around = (_Enclosing(scope[0], scope[1], _pos(child)), *enclosing)
            sites, guards, bindings = _scope_sites(child, label, around)
            found.extend(sites)
            visit(child, label, around, (guards, bindings))

    visit(ast.parse(source), None, (), None)
    return sorted(found, key=lambda s: s.line)


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
    [
        "assert not bad",
        "assert bad == []",
        "assert bad == set()",
        "assert bad == {}",
        "assert bad == ()",
        "assert len(bad) == 0",
    ],
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
        "assert len(files) >= 0.5",
        "assert len(files) > 0.0",
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
        "assert len(files) >= 0",
        "assert len(files) > -1",
        "assert len(files) >= 0.0",
        "assert len(files) > -0.5",
        # Positive, but about something the comprehension does not iterate.
        "assert other",
        "assert len(other) > 3",
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


@pytest.mark.parametrize(
    "wrapped",
    [
        "for f in roots:\n        assert files",
        "with pytest.raises(AssertionError):\n        assert files",
        "def inner():\n        assert files",
    ],
)
def test_a_guard_that_may_never_run_does_not_guard(wrapped: str) -> None:
    source = (
        "def test_x(files, roots):\n"
        f"    {wrapped}\n"
        "    bad = [p for p in files if p]\n"
        "    assert not bad\n"
    )
    assert _unguarded_sites(source) == [(5, "test_x", "bad")]


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
        "    starred = [p for p in [*root] if p]\n"
        "    assert not starred\n"
    )
    assert _unguarded_sites(source) == [
        (5, "test_x", "empty"),
        (7, "test_x", "walked"),
        (9, "test_x", "starred"),
    ]


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


def test_the_binding_that_reaches_the_assertion_is_the_one_judged() -> None:
    """Each site is judged by the binding just before it, not by the name's last binding."""
    source = (
        "def test_x(files):\n"
        "    bad = [n for n in ('a', 'b') if n.isupper()]\n"
        "    assert not bad\n"
        "    bad = [p for p in files if p]\n"
        "    assert not bad\n"
        "    bad = check(files)\n"
        "    assert not bad\n"
        "def test_y(files):\n"
        "    bad = [p for p in files if p]\n"
        "    assert not bad\n"
        "    bad = [n for n in ('a',) if n]\n"
        "    assert not bad\n"
    )
    assert _unguarded_sites(source) == [(5, "test_x", "bad"), (10, "test_y", "bad")]


def test_a_helper_inside_a_test_is_judged_by_its_own_guards() -> None:
    source = (
        "def test_x(roots):\n"
        "    def check(files):\n"
        "        assert files\n"
        "        bad = [p for p in files if p]\n"
        "        assert not bad\n"
        "    def unchecked(files):\n"
        "        bad = [p for p in files if p]\n"
        "        assert not bad\n"
        "    for r in roots:\n"
        "        check(r)\n"
        "        unchecked(r)\n"
    )
    assert _unguarded_sites(source) == [(8, "test_x.unchecked", "bad")]


@pytest.mark.parametrize(
    ("walk", "guard"),
    [
        ("report['commands']", "assert report['declared']"),
        ("sorted(files)", "assert len(sorted(other)) > 0"),
        ("self.files", "assert self.other"),
        ("self.files", "assert self"),
        ("report['commands']", "assert report"),
        ("report[key]", "assert key"),
        ("(files if cond else [])", "assert cond"),
    ],
)
def test_a_guard_must_count_what_the_comprehension_walks(walk: str, guard: str) -> None:
    """Sharing a name (a builtin, ``self``, a dict) with the walk is not counting the walk."""
    source = (
        "def test_x(self, report, files, other, key, cond):\n"
        f"    {guard}\n"
        f"    bad = [p for p in {walk} if p]\n"
        "    assert not bad\n"
    )
    assert _unguarded_sites(source) == [(4, "test_x", "bad")]


@pytest.mark.parametrize(
    ("walk", "guard"),
    [
        ("report['commands']", "assert report['commands']"),
        ("sorted(files)", "assert len(files) >= 2"),
        ("self.files", "assert self.files"),
        ("texts.items()", "assert texts"),
        ("report['jobs'].items()", "assert len(report['jobs']) > 1"),
    ],
)
def test_a_guard_on_the_walked_expression_still_guards(walk: str, guard: str) -> None:
    source = (
        "def test_x(self, report, files, texts):\n"
        f"    {guard}\n"
        f"    bad = [p for p in {walk} if p]\n"
        "    assert not bad\n"
    )
    assert _unguarded_sites(source) == []


@pytest.mark.parametrize(
    ("before", "after"),
    [
        # The guard counted `files` before a filter narrowed it, possibly to nothing.
        ("    assert files\n    files = [f for f in files if f.suffix == '.py']\n", ""),
        ("    assert files\n    files = load(root)\n", ""),
        # The guard counts a `files` rebound after the comprehension walked the old one.
        ("", "    files = load(root)\n    assert files\n"),
    ],
)
def test_a_guard_on_a_rebound_source_does_not_guard(before: str, after: str) -> None:
    source = (
        "def test_x(root):\n"
        "    files = list(root.rglob('*'))\n"
        f"{before}"
        "    bad = [p for p in files if p]\n"
        f"{after}"
        "    assert not bad\n"
    )
    line = source.count("\n")
    assert _unguarded_sites(source) == [(line, "test_x", "bad")]


def test_an_outer_name_spelled_like_a_loop_variable_does_not_guard() -> None:
    source = (
        "def test_x(dirs, d):\n"
        "    assert d\n"
        "    bad = [x for d in dirs for x in d.iterdir() if x]\n"
        "    assert not bad\n"
    )
    assert _unguarded_sites(source) == [(4, "test_x", "bad")]


@pytest.mark.parametrize(
    "rebind",
    [
        "    _ = [(files := []) for _ in (1,)]\n",
        "    from somewhere import files\n",
        "    try:\n        pass\n    except OSError as files:\n        pass\n",
        "    match root:\n        case [*files]:\n            pass\n",
        "    class files:\n        pass\n",
        "    def files():\n        pass\n",
    ],
)
def test_each_of_these_rebindings_makes_a_guard_stale(rebind: str) -> None:
    source = (
        "def test_x(root):\n"
        "    files = list(root.rglob('*'))\n"
        "    assert files\n"
        f"{rebind}"
        "    bad = [p for p in files if p]\n"
        "    assert not bad\n"
    )
    assert _unguarded_sites(source) == [(source.count("\n"), "test_x", "bad")]


def test_a_guard_after_the_walk_with_no_rebinding_still_guards() -> None:
    source = (
        "def test_x(files):\n"
        "    bad = [p for p in files if p]\n"
        "    assert files\n"
        "    assert not bad\n"
    )
    assert _unguarded_sites(source) == []


def test_a_guard_after_a_walk_that_rebinds_its_own_source_does_not_guard() -> None:
    """The walk read the old ``files``; the guard reads the new one the same statement bound."""
    source = (
        "def test_x(files):\n"
        "    files = [p for p in files if p]\n"
        "    assert files\n"
        "    assert not files\n"
    )
    assert _unguarded_sites(source) == [(4, "test_x", "files")]


@pytest.mark.parametrize(
    "between",
    [
        "    bad = sorted(bad)\n",
        "    bad = set(bad)\n",
        "    bad = sorted(set(bad))\n",
        "    bad = bad - ALLOWED\n",
        "    bad = '\\n'.join(bad)\n",
        "    bad: list[str]\n",
        "    bad += [1]\n",
    ],
)
def test_a_statement_that_works_on_the_collected_value_keeps_the_site(between: str) -> None:
    """Re-collecting, filtering, annotating or extending the name does not end its site."""
    source = f"def test_x(files):\n    bad = [p for p in files if p]\n{between}    assert not bad\n"
    assert _unguarded_sites(source) == [(4, "test_x", "bad")]


@pytest.mark.parametrize(
    ("between", "guarded"),
    [
        ("    files = sorted(files)\n", True),
        ("    files -= IGNORED\n", False),
        ("    files = files - IGNORED\n", False),
    ],
)
def test_only_a_count_keeping_rebinding_leaves_a_guard_standing(
    between: str, guarded: bool
) -> None:
    source = (
        "def test_x(root):\n"
        "    files = set(root.rglob('*'))\n"
        "    assert files\n"
        f"{between}"
        "    bad = [p for p in files if p]\n"
        "    assert not bad\n"
    )
    assert [s.guarded for s in _sites(source)] == [guarded]


@pytest.mark.parametrize(
    ("walk", "guard", "guarded"),
    [
        # The conditional may take the other arm, so neither arm is counted.
        ("(files if cond else [])", "assert files", False),
        ("(files or [])", "assert files", True),
        ("(other and files)", "assert files", False),
        # Only the first loop's population says the comprehension runs at all.
        ("roots for pat in patterns", "assert patterns", False),
        ("roots for pat in patterns", "assert roots", True),
        # A generator inside the iterable counts through its own first loop.
        ("sorted(f for f in files)", "assert files", True),
        ("[root for f in files]", "assert root", False),
        # A guard that wraps the population in a count-keeping call still counts it.
        ("files", "assert len(sorted(files)) > 0", True),
        ("files", "assert len(set(files)) >= 1", True),
    ],
)
def test_what_a_guard_counts_is_what_the_first_loop_draws_from(
    walk: str, guard: str, guarded: bool
) -> None:
    source = (
        "def test_x(files, other, cond, roots, patterns, root):\n"
        f"    {guard}\n"
        f"    bad = [p for p in {walk} if p]\n"
        "    assert not bad\n"
    )
    assert [s.guarded for s in _sites(source)] == [guarded]


@pytest.mark.parametrize(
    ("between", "guarded"),
    [
        ("", True),
        ("    self.files = []\n", False),
        ("    self.files.sort()\n", True),
    ],
)
def test_an_attribute_store_makes_a_guard_on_it_stale(between: str, guarded: bool) -> None:
    source = (
        "def test_x(self):\n"
        "    assert self.files\n"
        f"{between}"
        "    bad = [p for p in self.files if p]\n"
        "    assert not bad\n"
    )
    assert [s.guarded for s in _sites(source)] == [guarded]


@pytest.mark.parametrize(
    ("helper_args", "after", "guarded"),
    [
        # The helper reads `files` from the test, which counted it first.
        ("", "", True),
        # The helper walks its own `files`, which the test's guard says nothing about.
        ("files", "", False),
        # The test rebinds `files` after the guard, and the helper may run after that.
        ("", "    files = []\n", False),
    ],
)
def test_a_nested_helper_counts_the_tests_guard_on_a_value_it_reads(
    helper_args: str, after: str, guarded: bool
) -> None:
    source = (
        "def test_x(files):\n"
        "    assert files\n"
        f"    def check({helper_args}):\n"
        "        bad = [p for p in files if p]\n"
        "        assert not bad\n"
        f"{after}"
        "    check()\n"
    )
    assert [(s.test, s.guarded) for s in _sites(source)] == [("test_x.check", guarded)]


def test_a_recollected_site_keeps_the_guard_of_its_walk() -> None:
    source = (
        "def test_x(files):\n"
        "    assert files\n"
        "    bad = [p for p in files if p]\n"
        "    bad = sorted(bad)\n"
        "    assert not bad\n"
    )
    assert _unguarded_sites(source) == []


def test_two_statements_on_one_line_keep_their_order() -> None:
    source = "def test_x(files):\n    bad = [p for p in files if p]; assert not bad\n"
    assert _unguarded_sites(source) == [(2, "test_x", "bad")]


def test_a_guard_on_the_rebound_source_itself_guards() -> None:
    source = (
        "def test_x(root):\n"
        "    files = list(root.rglob('*'))\n"
        "    files = [f for f in files if f.suffix == '.py']\n"
        "    assert files\n"
        "    bad = [p for p in files if p]\n"
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
