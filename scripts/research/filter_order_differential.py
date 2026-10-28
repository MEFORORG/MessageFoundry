# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3005 research: the log filter order, measured as a differential. NOT A TEST.

Feeds one corpus of synthetic log records through the handler filter chain in two orders and
counts what each prints:

* ``main``: the order ``_install_phi_filters`` installs on ``main`` -- the PHI redaction filter
  (which renders ``exc_info`` first), then the credential query scrub, the credential scrub and the
  control-character scrub.
* ``new``: the exception text is rendered by its own first filter, then the two credential
  filters, then the PHI redaction filter, then the control-character scrub.

Two informational arms ride along and are not part of the preregistered rule: ``new-no-switch``,
the new order with ``redaction._CREDENTIAL_AHEAD`` matching nothing (the claim that a reorder would
let #2171's off-switch go), and three controls that each make one counter fire.

Each record goes through these paths, at least: the message straight to a handler (``once``), the
same record through a second handler's chain (``twice``), ``safe_text`` or ``safe_exc`` first as an
error log call does (each once and twice), and an ``exc_info`` record whose chained exception
carries the text (once and twice). A planted value is LEAKED on a path when it is in the input and
in the formatted output there. Credential and PHI values are planted values harvested from the
redaction suites, so the counters only see values a test already plants.

The corpus is the string inputs of the redaction suites (parametrize values and module constants),
the #2171 grammar, the #2968 product of runs, glues, labels and separators, and the #2312 fixtures.
Synthetic values only. Run from the repository root::

    python scripts/research/filter_order_differential.py

It exits non-zero when a positive control does not fire."""

from __future__ import annotations

import dataclasses
import importlib
import logging
import re
import sys
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(_ROOT), str(_ROOT / "tests")]

from messagefoundry import logging_setup, redaction  # noqa: E402
from messagefoundry.logging_setup import (  # noqa: E402
    ControlCharScrubFilter,
    CredentialQueryScrubFilter,
    CredentialScrubFilter,
    RedactionFilter,
)
from messagefoundry.redaction import prepare_log_record, safe_exc, safe_text  # noqa: E402

#: Modules whose string inputs are the corpus. The redaction suites, and the credential-scrub suites
#: whose families are the credential side of the chain.
_SUITES = (
    "test_redaction",
    "test_redaction_glued_credential_label",
    "test_redaction_glued_phi_label",
    "test_redaction_structured_shapes",
    "test_redaction_dtm_ssn_comma_names",
    "test_logging_credential_scrub",
    "test_log_redaction_secret_domain",
)
#: A harvested string longer than this is a cost probe, not a log line; it is skipped and counted.
_MAX_LEN = 100_000


class _RenderException(logging.Filter):
    """The new order's first filter: render ``exc_info`` into ``exc_text`` before any scrub, as
    ``RedactionFilter`` does on ``main``. ``prepare_log_record`` never raises."""

    def filter(self, record: logging.LogRecord) -> bool:
        prepare_log_record(record)
        return True


class _AppendX(logging.Filter):
    """The idempotence control: a filter whose second pass always changes the first's output."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = record.getMessage() + " x"
        record.args = ()
        return True


Chain = Callable[[], list[logging.Filter]]

_MAIN: Chain = lambda: [  # noqa: E731
    RedactionFilter(),
    CredentialQueryScrubFilter(),
    CredentialScrubFilter(),
    ControlCharScrubFilter(),
]
_NEW: Chain = lambda: [  # noqa: E731
    _RenderException(),
    CredentialQueryScrubFilter(),
    CredentialScrubFilter(),
    RedactionFilter(),
    ControlCharScrubFilter(),
]
#: Controls: each drops or adds one thing so one counter must fire.
_NO_CREDENTIAL: Chain = lambda: [RedactionFilter(), ControlCharScrubFilter()]  # noqa: E731
_NO_PHI: Chain = lambda: [  # noqa: E731
    _RenderException(),
    CredentialQueryScrubFilter(),
    CredentialScrubFilter(),
    ControlCharScrubFilter(),
]
_NOT_IDEMPOTENT: Chain = lambda: [*_MAIN(), _AppendX()]  # noqa: E731

_NEVER = re.compile(r"(?!)")


def _strings(obj: Any, depth: int = 0) -> Iterator[str]:
    """Every string reachable from ``obj`` through builtin containers, dataclasses and
    ``pytest.param`` sets, a few levels deep."""
    if depth > 4:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield from _strings(key, depth + 1)
            yield from _strings(value, depth + 1)
    elif isinstance(obj, (tuple, list, set, frozenset)):
        for item in obj:
            yield from _strings(item, depth + 1)
    elif dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        for field in dataclasses.fields(obj):
            yield from _strings(getattr(obj, field.name), depth + 1)
    elif type(obj).__name__ == "ParameterSet":
        yield from _strings(obj.values, depth + 1)


def _harvest(module: Any) -> Iterator[str]:
    """Module-level constants and every ``parametrize`` argvalue in ``module``."""
    for name, value in vars(module).items():
        if name.startswith("__"):
            continue
        if callable(value) and not isinstance(value, (str, tuple, list, dict)):
            for mark in getattr(value, "pytestmark", []):
                if getattr(mark, "name", "") == "parametrize" and len(mark.args) > 1:
                    yield from _strings(mark.args[1])
            continue
        yield from _strings(value)


def _planted(suites: dict[str, Any]) -> tuple[set[str], set[str]]:
    """The planted credential and PHI values, read from the suites' own constants."""
    red = suites["test_redaction"]
    glued = suites["test_redaction_glued_credential_label"]
    phi_glued = suites["test_redaction_glued_phi_label"]
    shapes = suites["test_redaction_structured_shapes"]
    credentials = {
        red._CREDENTIAL_VALUE,
        red._PW_ONE,
        red._PW_TWO,
        red._PW_REAL,
        red._PASSWORD_HEAD,
        glued._VALUE,
    }
    for name in ("test_logging_credential_scrub", "test_log_redaction_secret_domain"):
        module = suites[name]
        credentials.update(family.secret for family in module.FAMILIES)
        for case in module.QUOTED_VALUES:
            credentials.update(case.fragments)
        credentials.add(module._REGISTRY_SENTINEL)
    secret_domain = suites["test_log_redaction_secret_domain"]
    credentials.add(secret_domain._FOLD_VALUE)
    credentials.update(secret_domain._SWALLOW_VALUES)
    phi = {
        *red._FHIR_PLANTED,
        *red._GRAMMAR_PHI,
        *red._CUSTOM_IDENTIFIERS,
        *glued._PHI,
        *phi_glued._PLANTED,
        shapes.FAMILY,
        shapes.GIVEN,
        shapes.MRN,
        shapes.PHONE,
        shapes.STREET,
        shapes.CITY,
        shapes.DICOM_NAME,
        shapes.DICOM_ID,
        shapes.OTHER_ID,
        shapes.OTHER_NAME,
        shapes.BIRTH_NAME,
        shapes.MOTHER_NAME,
        "19800505",
        "1980-05-05",
        "05/05/1980",
    }
    # A value shorter than four characters is a substring of too much ordinary text to count.
    return {c for c in credentials if len(c) >= 4}, {p for p in phi if len(p) >= 4}


def _generated(suites: dict[str, Any]) -> Iterator[str]:
    """The generated cases: #2171's grammar and glues, #2968's product, #2312's fixtures."""
    red = suites["test_redaction"]
    glued = suites["test_redaction_glued_credential_label"]
    yield from red._grammar_texts()
    for glue in red._LABEL_GLUE:
        yield f"{red._ENCODED_TOKEN}{glue}password: {red._CREDENTIAL_VALUE}"
    for run in glued._RUNS.values():
        for separator in glued._SEPARATORS:
            for glue in glued._GLUE:
                for label in glued._LABELS:
                    yield f"x {run}{glue}{label}{separator}{glued._VALUE}"
    words = (
        *red.secretscrub._CREDENTIAL_WORDS,
        *red.secretscrub._TOKEN_WORDS,
        *red.secretscrub._KEY_MATERIAL_WORDS,
    )
    for label in (*words, "db_password", "a_b_c_d_e_f_password", "PWD", "Password"):
        yield f"x {glued._RUNS['pipe']};{label}: {glued._VALUE}"
        yield f"{red._ENCODED_TOKEN},{label}: {red._CREDENTIAL_VALUE}"
    yield red._two_credential_spans()
    yield red._opener_then_scrubbed_span()


def _corpus() -> tuple[list[str], set[str], set[str], dict[str, int]]:
    suites = {name: importlib.import_module(name) for name in _SUITES}
    seen: dict[str, None] = {}
    sizes: dict[str, int] = {}
    skipped = 0
    for name, module in suites.items():
        before = len(seen)
        for text in _harvest(module):
            if len(text) > _MAX_LEN:
                skipped += 1
            elif len(text) >= 3:
                seen.setdefault(text)
        sizes[name] = len(seen) - before
    before = len(seen)
    for text in _generated(suites):
        seen.setdefault(text)
    sizes["generated"] = len(seen) - before
    sizes["skipped over length"] = skipped
    credentials, phi = _planted(suites)
    return list(seen), credentials, phi, sizes


_FORMATTER = logging.Formatter("%(message)s")


def _filter(record: logging.LogRecord, chain: Chain) -> str:
    """Run one handler's chain over ``record`` and return what that handler would write."""
    for handler_filter in chain():
        handler_filter.filter(record)
    return _FORMATTER.format(record)


def _message_record(text: str) -> logging.LogRecord:
    return logging.LogRecord("t", logging.ERROR, __file__, 1, "%s", (text,), None)


def _exc_record(text: str) -> logging.LogRecord:
    try:
        try:
            raise ValueError(text)
        except ValueError as inner:
            raise RuntimeError("delivery failed") from inner
    except RuntimeError:
        exc_info = sys.exc_info()
    return logging.LogRecord(
        "t", logging.ERROR, __file__, 1, "transform failed on %s", ("conn",), exc_info
    )


def _paths(text: str, chain: Chain) -> dict[str, str]:
    """``text`` by each log path, once and twice through (a second handler on the same record)."""
    out: dict[str, str] = {}
    makers: tuple[tuple[str, Callable[[], logging.LogRecord]], ...] = (
        ("msg", lambda: _message_record(text)),
        ("safe_text", lambda: _message_record(safe_text(text, limit=100_000))),
        ("safe_exc", lambda: _message_record(safe_exc(ValueError(text), limit=100_000))),
        ("exc_info", lambda: _exc_record(text)),
    )
    for name, make in makers:
        record = make()
        out[f"{name} once"] = _filter(record, chain)
        out[f"{name} twice"] = _filter(record, chain)
    return out


@dataclasses.dataclass
class _Arm:
    name: str
    outputs: list[dict[str, str]]


def _run(texts: list[str], chain: Chain, *, no_switch: bool = False) -> list[dict[str, str]]:
    saved = redaction._CREDENTIAL_AHEAD
    if no_switch:
        redaction._CREDENTIAL_AHEAD = _NEVER
    try:
        return [_paths(text, chain) for text in texts]
    finally:
        redaction._CREDENTIAL_AHEAD = saved


def _leaks(text: str, out: str, values: Iterable[str]) -> set[str]:
    return {value for value in values if value in text and value in out}


def _report(
    texts: list[str], base: _Arm, arm: _Arm, credentials: set[str], phi: set[str]
) -> dict[str, dict[str, int]]:
    """Per path: leaks under the arm, new and fixed leaks against ``base``, outputs that differ from
    ``base``, and outputs a second pass changes. Leaks are (text, value) pairs."""
    table: dict[str, dict[str, int]] = {}
    for path in base.outputs[0]:
        row = dict.fromkeys(
            (
                "cred leaks",
                "cred new",
                "cred fixed",
                "phi leaks",
                "phi new",
                "phi fixed",
                "differ",
                "texts with a new leak",
            ),
            0,
        )
        for text, b_out, a_out in zip(texts, base.outputs, arm.outputs, strict=True):
            for kind, values in (("cred", credentials), ("phi", phi)):
                b = _leaks(text, b_out[path], values)
                a = _leaks(text, a_out[path], values)
                row[f"{kind} leaks"] += len(a)
                row[f"{kind} new"] += len(a - b)
                row[f"{kind} fixed"] += len(b - a)
            row["differ"] += a_out[path] != b_out[path]
            row["texts with a new leak"] += bool(
                _leaks(text, a_out[path], credentials | phi)
                - _leaks(text, b_out[path], credentials | phi)
            )
        table[path] = row
    for path in [p for p in table if p.endswith(" once")]:
        twice = path.replace(" once", " twice")
        table[path]["second pass changes"] = sum(out[path] != out[twice] for out in arm.outputs)
    return table


def _print_table(title: str, table: dict[str, dict[str, int]]) -> None:
    print(f"\n## {title}")
    columns = list(next(iter(table.values())).keys())
    columns += [c for c in ("second pass changes",) if c not in columns]
    print("| path | " + " | ".join(columns) + " |")
    print("|" + "---|" * (len(columns) + 1))
    for path, row in table.items():
        print(f"| {path} | " + " | ".join(str(row.get(c, "")) for c in columns) + " |")


def _examples(
    texts: list[str], base: _Arm, arm: _Arm, values: set[str], limit: int = 5
) -> list[str]:
    found = []
    for text, b_out, a_out in zip(texts, base.outputs, arm.outputs, strict=True):
        for path in b_out:
            new = _leaks(text, a_out[path], values) - _leaks(text, b_out[path], values)
            if new:
                found.append(f"{path}: {text!r} -> {sorted(new)}")
                break
        if len(found) >= limit:
            break
    return found


def _timing() -> None:
    """The bound the PHI filter gives the filters after it on ``main`` (its docstring). One record of
    each size, a dotted payload with no whitespace, through each order once. Informational only:
    one sample per cell, and on ``main`` the clamp cuts a whitespace-free payload short."""
    print("\n## timing: one dotted record through one chain, seconds")
    print("| size | main | new |")
    print("|---|---|---|")
    for size in (64 * 1024, 256 * 1024, 1024 * 1024):
        text = ("a." * (size // 2))[:size]
        row = []
        for chain in (_MAIN, _NEW):
            start = time.perf_counter()
            _filter(_message_record(text), chain)
            row.append(f"{time.perf_counter() - start:.3f}")
        print(f"| {size} | " + " | ".join(row) + " |")


def main() -> int:
    texts, credentials, phi, sizes = _corpus()
    installed = [type(f).__name__ for f in _installed()]
    print("# BACKLOG #3005 filter-order differential")
    print(f"installed order (_install_phi_filters at this head): {installed}")
    print(f"corpus: {len(texts)} distinct texts; by source {sizes}")
    print(f"planted credential values: {len(credentials)}; planted PHI values: {len(phi)}")
    print(
        "texts holding a planted credential:",
        sum(any(c in t for c in credentials) for t in texts),
        "; a planted PHI value:",
        sum(any(p in t for p in phi) for t in texts),
    )

    start = time.perf_counter()
    main_arm = _Arm("main", _run(texts, _MAIN))
    new_arm = _Arm("new", _run(texts, _NEW))
    switch_arm = _Arm("new-no-switch", _run(texts, _NEW, no_switch=True))
    controls = {
        "control: no credential filters": _Arm("nocred", _run(texts, _NO_CREDENTIAL)),
        "control: no PHI filter": _Arm("nophi", _run(texts, _NO_PHI)),
        "control: a filter that appends": _Arm("append", _run(texts, _NOT_IDEMPOTENT)),
    }
    print(f"elapsed: {time.perf_counter() - start:.1f} s")

    _print_table(
        "main order, against itself (leak totals and idempotence)",
        _report(texts, main_arm, main_arm, credentials, phi),
    )
    new_table = _report(texts, main_arm, new_arm, credentials, phi)
    _print_table("new order, against main", new_table)
    _print_table(
        "INFORMATIONAL new order with _CREDENTIAL_AHEAD off, against main",
        _report(texts, main_arm, switch_arm, credentials, phi),
    )
    failed = []
    fired = {
        "control: no credential filters": "cred new",
        "control: no PHI filter": "phi new",
        "control: a filter that appends": "second pass changes",
    }
    for title, arm in controls.items():
        table = _report(texts, main_arm, arm, credentials, phi)
        _print_table(title, table)
        counter = fired[title]
        total = sum(row.get(counter, 0) for row in table.values())
        differ = sum(row["differ"] for row in table.values())
        print(f"{title}: '{counter}' summed over paths = {total}; differ summed = {differ}")
        if total == 0 or differ == 0:
            failed.append(title)

    for kind, values in (("credential", credentials), ("PHI", phi)):
        print(f"\nnew {kind} leaks under the new order, first path per text (up to 50):")
        for line in _examples(texts, main_arm, new_arm, values, limit=50):
            print("  " + line)
        print(f"first new {kind} leaks with the switch off (up to 5):")
        for line in _examples(texts, main_arm, switch_arm, values):
            print("  " + line)
        print(f"first {kind} leaks the new order fixes (up to 5):")
        for line in _examples(texts, new_arm, main_arm, values):
            print("  " + line)

    _timing()
    if failed:
        print(f"\nCONTROL DID NOT FIRE: {failed}")
        return 1
    print("\nevery positive control fired")
    return 0


def _installed() -> list[logging.Filter]:
    handler = logging.NullHandler()
    logging_setup._install_phi_filters(handler)
    return [f for f in handler.filters if isinstance(f, logging.Filter)]


if __name__ == "__main__":
    raise SystemExit(main())
