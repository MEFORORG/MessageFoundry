# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""AST scanner (BACKLOG #1327): a settings model drops an unknown keyword, so a test that still
passes one goes green and proves nothing.

Every section model in :mod:`messagefoundry.config.settings` inherits ``_Section``, which keeps
``model_config = ConfigDict(extra="ignore")`` on purpose (see the comment at ``settings.py`` near
line 233, which the pre-commit gate refuses to let this file restate -- SDS-3.5 -- and which this
scanner exists **because** of, not despite: the model stays permissive, so something else has to
catch the mistake it can no longer catch itself). Deleting a setting leaves every call site that
still passes it as a keyword green and silent -- ``hasattr`` is ``False`` and ``model_extra`` is
``None``, nothing raises, nothing logs. The test most likely to still pass it is the one *named*
after the deleted setting, so that test keeps passing while establishing nothing.

**Why an AST scan and not a type check.** Two independent reasons, both required:

1. Making the models ``extra="forbid"`` (so pydantic itself would refuse) is ruled out in shipped
   code: ``_Section``'s own comment records four reasons, including that a forbidding model would
   echo a mistyped secret's value back into a log a CLI writes to disk. This scanner is what fills
   the gap the model deliberately leaves open.
2. mypy would not catch this even if the model were strict, because CI never runs mypy over
   ``tests/`` at all -- see ``.github/workflows/ci.yml``, the "Type-check (mypy, strict --
   ...)" steps, both of which type-check ``messagefoundry`` (and ``messagefoundry_webconsole``)
   only. An undeclared keyword in test code is invisible to every gate this repository runs today
   except this one.

**Scope: models that do NOT already self-protect.** Pydantic v2's default -- an *unset* ``extra``
-- behaves identically to an explicit ``extra="ignore"`` (verified below against
:class:`~messagefoundry.config.settings.RetryPolicy`, which sets no ``extra`` at all and still
drops an unknown keyword silently). So the hazard set is "every model visible on
``messagefoundry.config.settings`` that is not ``extra="forbid"``", not the narrower set spelled
``extra="ignore"`` in source. The three that opt out on purpose --``AlertRule``, ``EscalationTier``,
``Schedule`` -- are excluded deliberately: they already fail loudly at construction, and
``tests/test_alert_rules.py`` relies on exactly that, constructing
``AlertRule(extra_field="x")`` inside a ``pytest.raises(ValidationError)`` block as a negative
control proving the forbid works. Scanning them too would fail this scanner on that legitimate
test.

**Which call sites this recognizes -- a name-based match, not a type-checker.** A construction is
recognized only when the class name reaches the call site through one of the import shapes this
codebase actually uses: ``from <trusted module> import XSettings[, ...]`` (the overwhelming
majority -- 181 files import this way today), ``from messagefoundry.config import settings as
<alias>`` followed by ``<alias>.XSettings(...)``, or ``import messagefoundry.config.settings
[as <alias>]`` followed by attribute access. The trusted modules are ``messagefoundry``,
``messagefoundry.config``, ``messagefoundry.config.models`` and ``messagefoundry.config.settings``
themselves -- covering both a model's true home and the handful re-exported through the top-level
package (``RetryPolicy``, ``BuildupThreshold``, ``SaturationThreshold``, ``StallThreshold``, all of
which ``messagefoundry/config/settings.py`` imports and therefore also carries on its own
namespace). A name a test never legally imports from one of those places cannot appear as a false
positive -- the import itself would fail first.

**The false-negative boundary -- stated, not hidden.** This is a name-based scan, not a type
checker, and it misses:

- ``Model(**some_dict)`` -- a dict-splat construction. The offending key is a runtime string, not
  an AST keyword, and is invisible to a static walk.
- A class re-exported through any path other than the four trusted modules above (a deeper
  re-export, or a local alias created by plain assignment such as ``M = DeliverySettings``).
- Indirection through a helper: a fixture or factory function that accepts ``**kwargs`` and
  forwards them into a model constructor hides the keyword from this file entirely.
- A subclass of a target model defined for test purposes; only the exact class names visible on
  ``messagefoundry.config.settings`` today are matched.
- ``packaging/messagefoundry-webconsole/tests/`` -- a second tree pytest also collects
  (``testpaths`` in ``pyproject.toml``) and which does construct these same models with keyword
  arguments (at least 18 files reference ``messagefoundry.config.settings`` there today, e.g.
  ``AuthSettings(require_mfa=False)`` in ``test_ui_cluster.py``). This scanner walks only
  ``tests/``, per its filed scope; that second tree is a known, named gap, not a silent one.

A scanner that recognizes a call shape and silently skips it when it fails to match is the same
class of defect as the bug it exists to catch, so the self-test below proves this one actually
*fails* on a known-bad construction -- a clean run over the real tree cannot tell a working
scanner from one that matches nothing.

**One exemption, found by running this scanner and reading what it flagged, not guessed in
advance.** ``LoggingSettings`` carries a ``model_validator(mode="before")`` (``_refuse_renamed_
file_keys``, ``settings.py`` near line 1622) that inspects the raw input dict for exactly two
legacy spellings -- ``max_bytes`` and ``backups`` -- and raises ``ValidationError`` naming the
real field, *before* ``extra="ignore"`` would otherwise drop them. ``tests/test_log_write_guard.py``
deliberately constructs ``LoggingSettings(max_bytes=1000)`` and ``LoggingSettings(backups=2)``
inside ``pytest.raises(...)`` blocks as negative controls proving that guard works -- verified live:
both raise ``ValidationError`` today, with or without any other keyword present. A pure
``model_fields`` membership check cannot see a ``mode="before"`` validator, so without this
exemption the scanner would fail a legitimate, already-loudly-failing construction -- the opposite
mistake from the one this row is filed for. ``_GUARDED_LEGACY_KEYS`` below is that one, narrow,
reasoned exemption; grep found no second ``model_validator(mode="before")`` anywhere else in
``messagefoundry/config/settings.py``, so it is not standing in for a wider pattern today.
"""

from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

import messagefoundry.config.settings as _settings_module

# The modules a test file legitimately imports a settings model (or the settings module itself)
# from, today. See the docstring's "false-negative boundary" for what falling outside this list
# means.
_TRUSTED_MODULES = (
    "messagefoundry",
    "messagefoundry.config",
    "messagefoundry.config.models",
    "messagefoundry.config.settings",
)
_SETTINGS_MODULE_DOTTED = "messagefoundry.config.settings"

# Keys a model's OWN `model_validator(mode="before")` intercepts and refuses outright, so passing
# one does NOT silently drop it -- it raises before extra="ignore" ever sees it. See this module's
# docstring, "One exemption", for the one entry here and how it was verified rather than assumed.
_GUARDED_LEGACY_KEYS: dict[str, frozenset[str]] = {
    "LoggingSettings": frozenset({"max_bytes", "backups"}),
}


def _target_models() -> dict[str, frozenset[str]]:
    """Every ``BaseModel`` subclass visible on :mod:`messagefoundry.config.settings` that does not
    self-protect with ``extra="forbid"``, mapped to its allowed keyword names.

    ``.get("extra")`` returning ``None`` (unset) is treated the same as ``"ignore"`` -- both drop an
    unrecognized keyword silently; only an explicit ``"forbid"`` raises. Verified live rather than
    assumed: ``RetryPolicy(bogus_kwarg_xyz=123)`` succeeds, ``hasattr`` is ``False`` and
    ``model_extra`` is ``None``, and it sets no ``extra`` at all.
    """
    out: dict[str, frozenset[str]] = {}
    for name, value in vars(_settings_module).items():
        if not (
            isinstance(value, type) and value is not BaseModel and issubclass(value, BaseModel)
        ):
            continue
        if value.model_config.get("extra") == "forbid":
            continue
        out[name] = frozenset(value.model_fields) | _GUARDED_LEGACY_KEYS.get(name, frozenset())
    return out


@dataclass(frozen=True, slots=True)
class _Violation:
    path: Path
    lineno: int
    model: str
    keyword: str

    def __str__(self) -> str:
        return (
            f"{self.path}:{self.lineno}: {self.model}(..., {self.keyword}=...) -- "
            f"{self.keyword!r} is not a field of messagefoundry.config.settings.{self.model} "
            "(extra keywords are silently dropped, not rejected -- see this file's docstring)"
        )


def _flatten_attribute(node: ast.expr) -> str | None:
    """``a.b.c`` -> ``"a.b.c"``; a call, subscript, or anything but a dotted name chain -> ``None``."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _import_map(
    tree: ast.Module, classes: dict[str, frozenset[str]]
) -> tuple[dict[str, str], dict[str, str]]:
    """(local name -> target model class name, local name -> canonical dotted module) for every
    binding this file creates that plausibly names a settings model or the settings module."""
    class_alias: dict[str, str] = {}
    module_alias: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            if node.module in _TRUSTED_MODULES:
                for alias in node.names:
                    if alias.name in classes:
                        class_alias[alias.asname or alias.name] = alias.name
            if node.module == "messagefoundry.config":
                for alias in node.names:
                    if alias.name == "settings":
                        module_alias[alias.asname or alias.name] = _SETTINGS_MODULE_DOTTED
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == _SETTINGS_MODULE_DOTTED and alias.asname:
                    module_alias[alias.asname] = _SETTINGS_MODULE_DOTTED
    return class_alias, module_alias


def _violations_in_file(path: Path) -> list[_Violation]:
    classes = _target_models()
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    class_alias, module_alias = _import_map(tree, classes)
    violations: list[_Violation] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        model_name: str | None = None
        if isinstance(node.func, ast.Name):
            model_name = class_alias.get(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            chain = _flatten_attribute(node.func)
            if chain is not None:
                prefix, _, cls_name = chain.rpartition(".")
                if cls_name in classes and (
                    prefix == _SETTINGS_MODULE_DOTTED
                    or module_alias.get(prefix) == _SETTINGS_MODULE_DOTTED
                ):
                    model_name = cls_name
        if model_name is None:
            continue
        allowed = classes[model_name]
        for kw in node.keywords:
            if kw.arg is None:  # **mapping -- the keys are a runtime value, invisible statically
                continue
            if kw.arg not in allowed:
                violations.append(_Violation(path, node.lineno, model_name, kw.arg))
    return violations


def test_no_unknown_kwargs_passed_to_settings_models() -> None:
    """Fails naming the file, line, model and offending keyword for every keyword this scan finds
    that is not a real field of the settings model it is passed to. See this module's docstring for
    which models are in scope and the scan's stated false-negative boundary."""
    tests_root = Path(__file__).resolve().parent
    violations: list[_Violation] = []
    for path in sorted(tests_root.rglob("*.py")):
        violations.extend(_violations_in_file(path))
    assert not violations, "unknown keyword(s) passed to a settings model:\n" + "\n".join(
        str(v) for v in violations
    )


def test_scanner_actually_fails_on_a_known_bad_construction(tmp_path: Path) -> None:
    """The self-test the docstring promises: a clean result on the real tree cannot tell a working
    scanner from one whose call-shape match never fires. Feed it a fixture file that imports a real
    settings model exactly the way 181 files in this repository do, then passes it a keyword that
    does not exist, and require the scan to name the file, the line, the model and the keyword."""
    bad_file = tmp_path / "test_fixture_bad_settings_kwarg.py"
    bad_file.write_text(
        textwrap.dedent(
            """\
            from messagefoundry.config.settings import StoreSettings

            def test_uses_a_deleted_setting() -> None:
                StoreSettings(this_setting_was_deleted_long_ago=True)
            """
        ),
        encoding="utf-8",
    )

    violations = _violations_in_file(bad_file)

    assert len(violations) == 1, violations
    (violation,) = violations
    assert violation.path == bad_file
    assert violation.lineno == 4
    assert violation.model == "StoreSettings"
    assert violation.keyword == "this_setting_was_deleted_long_ago"


def test_scanner_does_not_flag_a_real_field() -> None:
    """Guards the guard the other way: a legitimate call with only real field names must not trip
    the scan, on a fixture built the same way as the failing one above."""
    tree = ast.parse("StoreSettings(backend='sqlite', path='x.db')")
    classes = _target_models()
    class_alias = {"StoreSettings": "StoreSettings"}
    violations: list[_Violation] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            model_name = class_alias.get(node.func.id)
            if model_name is None:
                continue
            allowed = classes[model_name]
            violations.extend(
                _Violation(Path("<test>"), node.lineno, model_name, kw.arg)
                for kw in node.keywords
                if kw.arg is not None and kw.arg not in allowed
            )
    assert not violations, violations


def test_forbid_models_are_excluded_from_scope() -> None:
    """Documents and locks the scope decision: AlertRule/EscalationTier/Schedule already self-
    protect with extra="forbid", so they are deliberately absent from the target set -- otherwise
    tests/test_alert_rules.py's own negative control (AlertRule(extra_field="x")) would trip this
    scanner on a construction that is supposed to raise."""
    classes = _target_models()
    assert "AlertRule" not in classes
    assert "EscalationTier" not in classes
    assert "Schedule" not in classes
    # And the exclusion is FOR a real reason, not an accident: each is genuinely extra="forbid".
    assert _settings_module.AlertRule.model_config.get("extra") == "forbid"
    assert _settings_module.EscalationTier.model_config.get("extra") == "forbid"
    assert _settings_module.Schedule.model_config.get("extra") == "forbid"


def test_guarded_legacy_keys_actually_raise_rather_than_silently_drop() -> None:
    """Pins the fact ``_GUARDED_LEGACY_KEYS`` rests on, so the exemption cannot silently go stale:
    LoggingSettings(max_bytes=...) / (backups=...) must keep raising. If a future edit ever turns
    ``_refuse_renamed_file_keys`` into a no-op, THIS test fails loudly, rather than the exemption
    quietly starting to hide a real silent-drop the way the row this scanner is filed for warns
    about."""
    with pytest.raises(ValidationError, match="file_max_bytes"):
        _settings_module.LoggingSettings(max_bytes=1000)  # type: ignore[call-arg]
    with pytest.raises(ValidationError, match="file_backup_count"):
        _settings_module.LoggingSettings(backups=2)  # type: ignore[call-arg]


def test_default_extra_behaves_like_ignore_not_like_forbid() -> None:
    """Pins the mechanism the whole scanner's scope decision rests on: pydantic v2 with no
    explicit ``extra`` set drops an unknown keyword exactly as ``extra="ignore"`` would, so a
    model that never mentions ``extra`` is still in-scope for this scanner. If a future pydantic
    changes this default, this test (not a silent scope drift) is what will catch it.

    Constructed via a dict-splat, deliberately -- the documented dict-splat false-negative gap
    (this module's docstring) means this literal keyword is invisible to the scanner's own AST
    walk, so this pin does not trip the tree-wide scan below on itself.
    """
    bogus_kwargs = {"bogus_kwarg_xyz": 123}
    rp = _settings_module.RetryPolicy(**bogus_kwargs)  # type: ignore[arg-type]
    assert not hasattr(rp, "bogus_kwarg_xyz")
    assert rp.model_extra is None
    assert _settings_module.RetryPolicy.model_config.get("extra") is None
