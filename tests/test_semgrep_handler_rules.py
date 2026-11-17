# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Semgrep handler-security rules resolve through the package and are well-formed (ADR 0144 Inc 3).

Semgrep is NOT a project dependency, so authoritative rule-syntax/behaviour validation is the
``security.yml`` semgrep job (``--validate``/``--test``). This is the dep-free local guard: the rules
file resolves at its packaged path, and its structure is well-formed. PyYAML is in
``requirements.lock`` so the deep parse runs where the full lock is installed; a bare env skips it
(``importorskip``) and keeps the substring smoke.

WHAT THIS FILE DOES NOT CHECK (BACKLOG #1716): whether a BUILT WHEEL carries the rules. Nothing here
builds one, and a source tree resolves the path regardless of what the packaging config would
include, so reading the resolution as a wheel guard would be a control resting on a false premise.

WHAT STANDS IN ITS PLACE IS WEAKER THAN A TEST, AND THAT IS THE POINT OF SAYING SO.
``messagefoundry/integrity.py`` names ``security/semgrep/handler-security.yml`` in
``_ATTESTED_ASSETS`` (BACKLOG #1432), so an install missing the file, or carrying an edited copy,
records attestation drift at engine startup. Three limits travel with that: it is **alert-only by
default** (``[integrity].fail_closed_on_drift`` is opt-in), it runs on an INSTALLED engine rather
than in CI, and it is a no-op on an editable checkout. So a packaging regression here would red no
test and no CI leg -- it would surface as a startup log line on a site that had opted in. Calling it
a guarantee would overstate it.

``pyproject.toml`` grades the same mechanism the other way for the sibling common-password corpus,
saying an ``importlib.resources`` test IS the guard against a build-config change that dropped it.
Both cannot be right, and the disagreement is recorded here rather than settled here. THE NARROWER
CASE IS NOT HYPOTHETICAL: ``[tool.hatch.build]`` carries ``exclude = ["CLAUDE.md"]`` (BACKLOG #1702),
which hatchling matches with gitignore semantics, so one slashless pattern drops a file from every
build target at any depth under ``messagefoundry/``. Resolution here is therefore good evidence
against the whole directory going missing and no evidence at all against a pattern that reaches this
one file.

WHAT COVERS THAT LIST IS A CONFIG READ, NOT A BUILD, and it lives in another file. In
``tests/test_packaging.py``, the test named
``test_the_engine_excludes_its_nested_instructions_from_every_build_target``
reads the table and grades the pattern; its own docstring carries why, and the hatchling semantics
are recorded beside the key in ``pyproject.toml``. The limit worth knowing HERE is that it is
pinned to the ``CLAUDE.md`` value, so a SECOND pattern added beside that one -- the pattern that
could reach this rules file -- passes it. Whether a built wheel carries this file is BACKLOG
#1701's question, and answering it here would mean building a wheel in this suite -- slow, and
network-dependent.
"""

from __future__ import annotations

import collections
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from messagefoundry.security import handler_semgrep_rules

_EXPECTED = {
    "mf-handler-phi-to-log",
    "mf-handler-sqli-db-lookup",
    "mf-handler-phi-to-file",
    "mf-handler-ambient-subprocess",
    "mf-handler-ambient-os-exec",
    "mf-handler-ambient-eval-exec",
    "mf-handler-ambient-deserialization",
}
_TAINT = {"mf-handler-phi-to-log", "mf-handler-sqli-db-lookup", "mf-handler-phi-to-file"}


def test_rules_file_resolves_through_the_package() -> None:
    # BACKLOG #1716: what this assertion proves is that the rules file RESOLVES THROUGH THE PACKAGE
    # -- `handler_semgrep_rules()` finds it under `messagefoundry/security/`, so an import path that
    # has gone stale or a file that has been moved out from under it reds here. It is NOT evidence
    # about a built wheel; the module docstring carries that reasoning and what stands in its place.
    #
    # The NAME carries the claim, which is why it moved with the comment: a CI failure line, a
    # coverage row and `pytest -k` all surface the identifier and none of them surface this block, so
    # `test_rules_file_ships_in_the_package` would have gone on asserting the retracted reading to
    # every reader who never opened the file.
    assert handler_semgrep_rules().is_file()
    text = handler_semgrep_rules().read_text(encoding="utf-8")
    assert "rules:" in text and "mode: taint" in text
    for rid in _EXPECTED:
        assert rid in text  # stdlib-only substring smoke (no yaml needed)


def test_rules_are_wellformed_yaml() -> None:
    yaml = pytest.importorskip("yaml")  # in requirements.lock; NO new dep
    doc = yaml.safe_load(handler_semgrep_rules().read_text(encoding="utf-8"))
    rules = {r["id"]: r for r in doc["rules"]}
    assert set(rules) >= _EXPECTED
    for r in doc["rules"]:
        assert r["languages"] == ["python"] and r["message"].strip()
        assert r["severity"] in {"WARNING", "ERROR", "INFO"}
    for tid in _TAINT:
        assert rules[tid]["mode"] == "taint"
        assert rules[tid]["pattern-sources"] and rules[tid]["pattern-sinks"]


def _load_gate() -> ModuleType:
    path = (
        Path(__file__).resolve().parents[1] / "scripts" / "ci" / "assert_semgrep_handler_taint.py"
    )
    spec = importlib.util.spec_from_file_location("_assert_semgrep_handler_taint", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fixture_annotations_match_the_pinned_counts() -> None:
    # The CI gate needs semgrep; this half does not. It keeps the fixture's `# ruleid:` annotations and
    # the gate's pinned per-rule counts in step, so a case added or deleted on one side only reds here
    # before it reds in the security.yml semgrep job (BACKLOG #5380, #5381, #5382).
    gate = _load_gate()
    want, ok = gate.annotated_findings(gate._FIXTURE.read_text(encoding="utf-8"))
    assert collections.Counter(rule for rule, _ in want) == gate._EXPECTED
    assert not want & ok
    assert set(gate._EXPECTED) <= _EXPECTED


@pytest.mark.parametrize(
    ("rule", "needle"),
    [
        # BACKLOG #5380: module-qualified decorators and underscore helpers are taint sources.
        ("mf-handler-phi-to-log", "def h_qualified("),
        ("mf-handler-phi-to-log", "def r_qualified("),
        ("mf-handler-phi-to-log", "def _helper_log("),
        ("mf-handler-sqli-db-lookup", "def _helper_sql("),
        ("mf-handler-phi-to-file", "def _helper_file("),
        # BACKLOG #5381: connection= keyword, module alias, import alias, FhirRaw, FhirToken system.
        ("mf-handler-sqli-db-lookup", 'db_lookup(connection="MPI", statement="select * from'),
        ("mf-handler-sqli-db-lookup", 'mf.db_lookup("MPI", "select * from'),
        ("mf-handler-sqli-db-lookup", 'dl("MPI"'),
        ("mf-handler-sqli-db-lookup", "FhirRaw(mrn)"),
        ("mf-handler-sqli-db-lookup", 'FhirToken(code="x", system=mrn)'),
        # BACKLOG #5382: file egress the ambient-authority lint misses.
        ("mf-handler-phi-to-file", 'with open("/tmp/a.hl7", mode)'),
        ("mf-handler-phi-to-file", 'codecs.open("/tmp/b.hl7"'),
        ("mf-handler-phi-to-file", 'bopen("/tmp/c.hl7"'),
        ("mf-handler-phi-to-file", 'opener("/tmp/d.hl7"'),
        ("mf-handler-phi-to-file", "os.write(3, body)"),
        ("mf-handler-phi-to-file", "tempfile.NamedTemporaryFile("),
        ("mf-handler-phi-to-file", "shutil.copyfileobj("),
    ],
)
def test_fixture_carries_a_positive_case_per_gap(rule: str, needle: str) -> None:
    # The semgrep job proves the rules fire on the fixture; this pins that the fixture still HOLDS a
    # positive case for each closed gap, within the next five lines of the needle (the function or the
    # opening statement), so deleting one case cannot pass by shrinking both the fixture and the count.
    gate = _load_gate()
    text = gate._FIXTURE.read_text(encoding="utf-8")
    want, _ok = gate.annotated_findings(text)
    starts = [n for n, line in enumerate(text.splitlines(), start=1) if needle in line]
    assert starts, needle
    assert any((rule, n + k) in want for n in starts for k in range(6)), (rule, needle)
