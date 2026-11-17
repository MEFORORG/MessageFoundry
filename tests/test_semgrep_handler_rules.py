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
import functools
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


@functools.cache
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
    # the gate's pinned per-rule counts in step, so a case added or deleted on one side reds here
    # before it reds in the security.yml semgrep job (BACKLOG #5380, #5381, #5382).
    gate = _load_gate()
    want, ok = gate.annotated_findings(gate.read_fixture())
    assert collections.Counter(rule for rule, _ in want) == gate._EXPECTED
    assert not want & ok
    assert set(gate._EXPECTED) <= _EXPECTED


# Every `# ruleid:` case in the fixture, by the start of its code line. Pinning each case by name, not
# by count, means changing one case's annotation to `# ok:`, or deleting it, reds here even when the
# per-rule totals are edited to match.
_POSITIVE_CASES: tuple[tuple[str, str], ...] = (
    ("mf-handler-phi-to-log", "log.info(body)"),
    ("mf-handler-phi-to-log", "log.log(logging.INFO, msg.raw)"),
    # BACKLOG #5380: a module-qualified decorator, an aliased decorator on an async def, an
    # undecorated `_` helper, a public helper, the parameter after self or _self on a method, and an
    # attribute-form logger.
    ("mf-handler-phi-to-log", "log.error(body)"),
    ("mf-handler-phi-to-log", "print(msg.raw)"),
    ("mf-handler-phi-to-log", "log.critical(msg.raw)"),
    ("mf-handler-phi-to-log", "log.warning(m.raw)"),
    ("mf-handler-phi-to-log", "sys.stderr.write(msg.raw)"),
    ("mf-handler-phi-to-log", "log.exception(msg.raw)"),
    ("mf-handler-phi-to-log", "_self.logger.info(msg.raw)"),
    ("mf-handler-ambient-subprocess", 'r(["/bin/echo", msg.raw])'),
    ("mf-handler-ambient-deserialization", "pk(msg.raw)"),
    ("mf-handler-ambient-eval-exec", "eval(msg.text)"),
    ("mf-handler-sqli-db-lookup", 'db_lookup("MPI", "select * from p where mrn = \'" + mrn'),
    ("mf-handler-sqli-db-lookup", 'db_lookup("MPI", f"select * from p'),
    # BACKLOG #5381: connection= keyword, module alias, import alias, FhirRaw, FhirToken system.
    ("mf-handler-sqli-db-lookup", 'db_lookup(connection="MPI", statement="select * from'),
    ("mf-handler-sqli-db-lookup", 'mf.db_lookup("MPI", "select * from'),
    ("mf-handler-sqli-db-lookup", 'mf.fhir_lookup(connection="epic", query="Patient/" + mrn)'),
    ("mf-handler-sqli-db-lookup", 'dl("MPI", "select * from'),
    ("mf-handler-sqli-db-lookup", 'fhir_lookup("epic", "Patient", {"code": FhirRaw(mrn)})'),
    (
        "mf-handler-sqli-db-lookup",
        'fhir_lookup("epic", "Patient", {"code": mf.FhirRaw(value=mrn)})',
    ),
    (
        "mf-handler-sqli-db-lookup",
        'fhir_lookup("epic", "Patient", {"identifier": FhirToken(mrn, "x")})',
    ),
    (
        "mf-handler-sqli-db-lookup",
        'fhir_lookup("epic", "Patient", {"identifier": FhirToken(code="x", system=mrn)})',
    ),
    ("mf-handler-phi-to-file", 'Path("/tmp/x.hl7").write_text('),
    ("mf-handler-phi-to-file", 'Path("/tmp/h.hl7").write_bytes(body)'),
    # BACKLOG #5382: a non-literal mode, codecs.open, an import-aliased and a name-aliased open,
    # os.write, tempfile and shutil.
    ("mf-handler-phi-to-file", "fh.write(body)"),
    ("mf-handler-phi-to-file", "out.write(body)"),
    ("mf-handler-phi-to-file", 'bopen("/tmp/c.hl7", "w").write(body)'),
    ("mf-handler-phi-to-file", 'opener("/tmp/d.hl7", "w").writelines([body])'),
    ("mf-handler-phi-to-file", "os.write(3, body)"),
    ("mf-handler-phi-to-file", "tmpf.writelines([body])"),
    ("mf-handler-phi-to-file", "shutil.copyfileobj(io.BytesIO(body), sink)"),
)


# Every `# ok:` case, the same way: an over-match is usually "fixed" by deleting the ok case it
# fires on, which the counts and the gate's line match cannot see.
_NEGATIVE_CASES: tuple[tuple[str, str], ...] = (
    ("mf-handler-phi-to-log", "log.debug(msg.raw)"),
    ("mf-handler-phi-to-log", 'log.info("processed %s", msg.control_id)'),
    ("mf-handler-sqli-db-lookup", 'db_lookup("MPI", "select npi from p where mrn = :mrn"'),
    ("mf-handler-phi-to-log", "log.info(note)"),
    ("mf-handler-phi-to-log", "log.info(self.banner)"),
    ("mf-handler-sqli-db-lookup", 'db_lookup(connection="MPI", statement="select npi from p'),
    ("mf-handler-sqli-db-lookup", 'mf.db_lookup("MPI", "select npi from p'),
    (
        "mf-handler-sqli-db-lookup",
        'fhir_lookup("epic", "Patient", {"identifier": FhirToken("MRN", mrn)})',
    ),
    (
        "mf-handler-sqli-db-lookup",
        'fhir_lookup("epic", "Patient", {"_sort": FhirRaw("status,-date")})',
    ),
    ("mf-handler-phi-to-file", "buf.write(body)"),
    ("mf-handler-phi-to-file", 'fh2.write("processed")'),
    ("mf-handler-phi-to-file", 'os.write(len(body), b"ok")'),
    ("mf-handler-phi-to-file", "shutil.which(body)"),
    ("mf-handler-phi-to-file", 'shutil.move("/tmp/staged.hl7", body)'),
)


def _pin(cases: tuple[tuple[str, str], ...], lines: list[str]) -> set[tuple[str, int]]:
    pinned: set[tuple[str, int]] = set()
    for rule, start in cases:
        found = [n for n, line in enumerate(lines, start=1) if line.strip().startswith(start)]
        assert len(found) == 1, (start, found)
        pinned.add((rule, found[0]))
    return pinned


def test_every_annotated_case_is_pinned_by_name() -> None:
    gate = _load_gate()
    text = gate.read_fixture()
    want, ok = gate.annotated_findings(text)
    lines = text.split("\n")
    assert _pin(_POSITIVE_CASES, lines) == want
    assert _pin(_NEGATIVE_CASES, lines) == ok
    # A misspelt rule id in an annotation would pin a case no rule can ever fire on.
    assert {rule for rule, _ in want | ok} <= _EXPECTED


def test_annotations_count_lines_as_semgrep_does() -> None:
    # A U+2028 inside a string literal is not a line break to semgrep, and stacked annotations both
    # name the next code line.
    gate = _load_gate()
    text = 'x = "a\u2028b"\n# ruleid: r1\n# ok: r2\ncall()\n'
    assert gate.annotated_findings(text) == ({("r1", 4)}, {("r2", 4)})
