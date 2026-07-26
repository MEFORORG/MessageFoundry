# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Security hardening for the built-ins HL7 unescape (DELTA-01 / DELTA-02 / ASVS 1.3.3).

The built-in tolerant parser is the **default** hot-path backend (ADR 0054). Its rich-text
repetition escape (``\\.inN\\`` etc.) must not expand an attacker-controlled count without bound — a
~15-byte ``\\.in2000000000\\`` would otherwise allocate gigabytes synchronously on the pre-ACK path
(memory-exhaustion DoS, DELTA-01) — and a malformed count must not raise out of a field read
(DELTA-02, which severed the connection and dropped a parseable message with no disposition, breaking
the count-and-log invariant).

``MAX_ESCAPE_REPEAT`` clamps ONE escape; **composition** was still unbounded (ASVS 1.3.3): 8-byte
``\\.in512\\`` escapes expand ~256x each, so a body sitting just under the 16 MiB raw cap grew toward
~4 GiB as its leaves were unescaped — pre-ACK and unauthenticated. The aggregate budget
(``peek.enforce_expansion_budget``) closes that by measuring worst-case growth **before** either
backend parses, so a breach is a *contract* error on the listener's existing NAK + ``ERROR`` path.

**Measuring is itself attacker-paid work**, so this file bounds the guard in two dimensions, not one:
the *growth* a body can cause (the residual's memory clause) **and** the *cost of deciding* — an
opener whose count is zero-width or non-numeric adds nothing to the running total, so a total-only
short-circuit is unreachable for exactly the bodies an attacker sends. A bounded-growth suite alone
passes green over a multi-second pre-ACK event-loop stall; see "the budget's own COST must be bounded
too" below.

These tests assert the clamp/budget and **intentionally diverge** from python-hl7's unbounded
behavior, so they live outside the byte-parity suite.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

import hl7
import hl7.parser
import pytest

import messagefoundry.parsing._backend as _backend
import messagefoundry.parsing._builtin_hl7 as _builtin_hl7
from messagefoundry.config.models import ConnectorType, ContentType
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.parsing._builtin_hl7 import (
    MAX_ESCAPE_REPEAT,
    escape_expansion_estimate,
    message_escape_char,
    unescape,
)
from messagefoundry.parsing.message import Message
from messagefoundry.parsing.peek import (
    DEFAULT_MAX_MESSAGE_BYTES,
    HL7PeekError,
    Peek,
    enforce_expansion_budget,
)
from messagefoundry.parsing.summary import summarize
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore

SEPS = ("|", "^", "~", "&", "\\")

_MSG = (
    "MSH|^~\\&|SEND|FAC|RECV|FAC|20260101000000||ADT^A01|MSG00001|P|2.5\rPID|1||{pid3}||DOE^JOHN\r"
)

#: One ``\.in512\`` expands to 512 * 4 = 2,048 characters — the ~256x ratio the ASVS 1.3.3 residual
#: names. Each is individually **under** MAX_ESCAPE_REPEAT, so only the aggregate budget sees them.
_ESCAPE = "\\.in512\\"
_ESCAPE_GROWTH = MAX_ESCAPE_REPEAT * 4
#: Exactly at the budget (not over) — the largest composition that must still parse untouched.
_AT_BUDGET_REPEATS = DEFAULT_MAX_MESSAGE_BYTES // _ESCAPE_GROWTH


def _peek(raw: str) -> Peek:
    with _backend.backend(builtin=True):
        return Peek.parse(raw)


# --- unit: unescape repeat-count guard --------------------------------------


def test_unescape_drops_oversized_repeat_count() -> None:
    # ~15 bytes that would expand to ~8 GB without the clamp: dropped, no allocation.
    assert unescape("\\.in2000000000\\", SEPS) == ""


def test_unescape_allows_count_at_cap_and_drops_above() -> None:
    indent = "    "  # ".in" -> 4 spaces
    assert unescape(f"\\.in{MAX_ESCAPE_REPEAT}\\", SEPS) == indent * MAX_ESCAPE_REPEAT
    assert unescape(f"\\.in{MAX_ESCAPE_REPEAT + 1}\\", SEPS) == ""


@pytest.mark.parametrize("seq", ["\\.inX\\", "\\.in \\", "\\.br9z\\", "\\.in-5\\"])
def test_unescape_drops_malformed_or_negative_count_without_raising(seq: str) -> None:
    # DELTA-02: a non-numeric/negative count must not raise; unmappable -> dropped.
    assert unescape(seq, SEPS) == ""


def test_unescape_preserves_small_legitimate_repeat() -> None:
    assert unescape("\\.in3\\", SEPS) == "    " * 3


def test_unescape_preserves_ordinary_delimiter_and_hex_escapes() -> None:
    # The count guard must not disturb byte-parity for the common escape cases.
    assert unescape("A\\F\\B", SEPS) == "A|B"
    assert unescape("A\\X0a\\B", SEPS) == "A\nB"


# --- reachability: pre-ACK field reads must stay safe -----------------------


def test_peek_field_over_cap_but_under_budget_count_returns_none_not_oom() -> None:
    # DELTA-01's in-unescape clamp is still the second line of defence for a count that passes the
    # aggregate budget: 513 > MAX_ESCAPE_REPEAT, but its worst case (513 * 4) is far under the budget,
    # so the message parses and the clamp drops the escape at the field read.
    peek = _peek(_MSG.format(pid3=f"\\.in{MAX_ESCAPE_REPEAT + 1}\\^^^MRN"))
    assert peek.field("PID-3.1") is None  # dropped -> "" -> None; completes without OOM


def test_peek_field_malformed_count_does_not_raise() -> None:
    peek = _peek(_MSG.format(pid3="\\.inX\\^^^MRN"))
    assert peek.field("PID-3.1") is None


def test_summarize_is_safe_on_hostile_repeat_escape() -> None:
    # summary.summarize() runs on the pre-ACK path (wiring_runner); it must neither OOM nor raise
    # (DELTA-01/02). A well-formed message carrying a hostile PID-3.1 summarizes cleanly.
    for pid3 in (f"\\.in{MAX_ESCAPE_REPEAT + 1}\\^^^MRN", "\\.inX\\^^^MRN"):
        with _backend.backend(builtin=True):
            peek = Peek.parse(_MSG.format(pid3=pid3))
            result = summarize(peek)
        assert isinstance(result, str)


# --- ASVS 1.3.3: the AGGREGATE expansion budget ------------------------------
#
# The unit tests above bound ONE escape. These bound the whole message: the budget is measured before
# either backend parses, so it is a pre-ACK contract error (HL7PeekError), never a fallback into
# python-hl7's unbounded unescape and never an accept-and-drop.

_BACKENDS = pytest.mark.parametrize("builtin", [True, False], ids=["builtin", "python-hl7"])


def test_repeat_widths_track_unescape_output() -> None:
    # Drift guard, BOTH directions. Iterating _REPEAT_WIDTHS alone could only ever catch a changed
    # WIDTH — never an ADDITION to what unescape expands, which is the silent hole (a new counted
    # escape would expand at parse time and contribute zero to the pre-parse budget). So: the table is
    # derived from _RICH_TEXT_MAP (set equality below is structural), and unescape splices that same
    # constant in, which the AST guard on the next test is what actually pins.
    assert set(_builtin_hl7._REPEAT_WIDTHS) == set(_builtin_hl7._RICH_TEXT_MAP)
    for prefix, width in _builtin_hl7._REPEAT_WIDTHS.items():
        assert len(unescape(f"\\{prefix}1\\", SEPS)) == width, prefix


def test_the_prefixes_the_scanner_skips_provably_expand_nothing() -> None:
    # The scanner deliberately does NOT look for zero-width prefixes (.fi/.nf): matching them buys an
    # attacker Python-level iterations that can never move the estimate (`count * 0`). That exclusion
    # is only safe while those prefixes really are width 0, so pin BOTH halves — the excluded set is
    # exactly the zero-width set, and each excluded prefix genuinely emits nothing per repeat. A
    # future _RICH_TEXT_MAP edit that gave `.fi` a body would otherwise leave it silently unscanned
    # (an under-estimate: the one direction the budget must never fail in).
    excluded = set(_builtin_hl7._REPEAT_WIDTHS) - set(_builtin_hl7._EXPANDING_PREFIXES)
    assert excluded, "the exclusion is meant to be non-empty; .fi/.nf are the zero-width prefixes"
    for prefix in excluded:
        assert _builtin_hl7._REPEAT_WIDTHS[prefix] == 0, prefix
        assert unescape(f"\\{prefix}999\\", SEPS) == "", prefix
    for prefix in _builtin_hl7._EXPANDING_PREFIXES:
        assert _builtin_hl7._REPEAT_WIDTHS[prefix] > 0, prefix
    # ...and the compiled scanner really is built from that set, not from a stale literal.
    scanner = _builtin_hl7._repeat_escape_scanner("\\")
    for prefix in _builtin_hl7._REPEAT_WIDTHS:
        hit = scanner.search(f"\\{prefix}5\\")
        assert (hit is not None) is (prefix in _builtin_hl7._EXPANDING_PREFIXES), prefix


def test_unescape_declares_no_counted_escape_of_its_own() -> None:
    # THE direction the old iterate-the-table guard could not see. `default_map` is a local dict, so
    # nothing structurally stopped a future change adding `".xx": "…"` straight into it: that escape
    # would expand while the estimator stayed blind to it, silently reopening the composition gap.
    # Adding one is now only possible via _RICH_TEXT_MAP (which _REPEAT_WIDTHS is derived from) — and
    # this fails if anyone puts a dotted key back inside the function.
    source = Path(_builtin_hl7.__file__).read_text(encoding="utf-8")
    func = next(
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.FunctionDef) and node.name == "unescape"
    )
    inline_dotted = [
        key.value
        for node in ast.walk(func)
        if isinstance(node, ast.Dict)
        for key in node.keys
        if isinstance(key, ast.Constant)
        and isinstance(key.value, str)
        and key.value.startswith(".")
    ]
    assert not inline_dotted, (
        "unescape declares counted rich-text escape(s) inline; add them to _RICH_TEXT_MAP so the "
        f"ASVS 1.3.3 expansion estimator measures them: {inline_dotted}"
    )
    # Anti-vacuity: the matcher really does see a dotted key where one exists.
    planted = ast.parse('def unescape():\n    m = {"H": "_", ".xx": "yy"}\n    return m\n')
    assert [
        key.value
        for node in ast.walk(planted)
        if isinstance(node, ast.Dict)
        for key in node.keys
        if isinstance(key, ast.Constant)
        and isinstance(key.value, str)
        and key.value.startswith(".")
    ] == [".xx"]


def test_estimate_ignores_contracting_and_uncounted_escapes() -> None:
    # Only the counted rich-text escapes expand. Delimiter/highlight escapes, hex runs and a bare
    # (count-less) rich-text escape all contract or stay fixed-width, so they contribute nothing.
    assert escape_expansion_estimate(_MSG.format(pid3="\\F\\\\S\\\\H\\\\X4142\\\\.br\\")) == 0
    assert escape_expansion_estimate(_MSG.format(pid3="MRN001")) == 0


def test_estimate_counts_the_composition_the_per_escape_clamp_misses() -> None:
    body = _MSG.format(pid3=_ESCAPE * 3)
    assert escape_expansion_estimate(body) == 3 * _ESCAPE_GROWTH


def test_estimate_models_the_unclamped_worst_case_for_backend_uniformity() -> None:
    # MAX_ESCAPE_REPEAT is deliberately NOT applied here: python-hl7's unescape has no clamp, so a
    # count the built-in would drop is exactly the count the fallback backend would expand.
    assert escape_expansion_estimate(_MSG.format(pid3="\\.in2000000000\\")) == 2_000_000_000 * 4


def test_estimate_is_not_defeated_by_unbalanced_escapes() -> None:
    # A lone escape character shifts escape *pairing* for everything after it. An estimator that
    # paired escapes itself would score the payload below as 0 and let ~2 KB (scaled: ~4 GiB) through;
    # matching openers wherever they appear cannot be shifted out of alignment.
    assert escape_expansion_estimate(_MSG.format(pid3=f"\\X\\{_ESCAPE}")) == _ESCAPE_GROWTH


def test_estimate_reads_the_escape_character_from_the_message() -> None:
    # CLAUDE.md §8: never hardcode `|^~\&`. With `!` as the escape char, `\.in512\` is inert text and
    # `!.in512!` is the live escape — the estimate must follow the message's own MSH-2.
    custom = "MSH|^~!&|S|F|R|F|20260101000000||ADT^A01|M1|P|2.5\rPID|1||{pid3}\r"
    assert message_escape_char(custom) == "!"
    assert escape_expansion_estimate(custom.format(pid3="!.in512!")) == _ESCAPE_GROWTH
    assert escape_expansion_estimate(custom.format(pid3="\\.in512\\")) == 0


def test_escape_char_read_agrees_with_the_parser_on_every_header_shape() -> None:
    # The budget and the parser must never disagree about which character escapes a message — a
    # divergence is exactly how a payload would hide its escapes from the pre-parse scan. This reads
    # defensively (Message.parse has no MSH pre-guard, so the budget sees arbitrary bytes) but the
    # answer is identical to the parser's own _extract_separators wherever that one can run.
    for header in ("MSH|^~\\&|S", "MSH|^~!&|S", "MSH|^~\\", "MSH|^~!", "MSH|^~", "FHS|^~\\&"):
        expected = _builtin_hl7._extract_separators(header)[4]
        assert message_escape_char(header + "\rPID|1\r") == expected, header
    # Shapes the parser itself cannot index (it runs only after the MSH check): HL7's default escape
    # character, never an IndexError out of the pre-parse budget.
    for short in ("", "M", "MSH", "MSH|"):
        assert message_escape_char(short) == "\\"
    assert escape_expansion_estimate("not hl7 at all") == 0


def test_escape_char_read_agrees_with_python_hl7_or_is_unreachable() -> None:
    # The budget exists to bound python-hl7's UNBOUNDED unescape, so the FALLBACK backend's notion of
    # the escape character matters too — and it is derived differently: create_parse_plan searches
    # `strmsg.find(sep0, 4)` over the whole message, while message_escape_char (like the built-in's
    # _extract_separators) searches only the MSH line. On a header with no second field separator the
    # two really do differ (`MSH|^~X` -> `\` here, `X` there). Every such shape is unreachable today —
    # python-hl7 refuses the message, or lands on `\r`, which no leaf can contain (it is the segment
    # separator) so its unescape expands nothing. If an upstream change ever makes a divergent shape
    # parse cleanly with a usable escape char, this goes red instead of the bypass opening silently.
    for header in ("MSH|", "MSH|^", "MSH|^~", "MSH|^~X", "MSH|^~\\", "MSH|^~\\&|", "MSH|^~\\&|S|F"):
        body = header + "\rPID|1||X\r"
        mine = message_escape_char(body)
        try:
            parsed = hl7.parse(body)
        except Exception:  # noqa: BLE001 — refused outright (_ParsePlan assert): unreachable shape
            continue
        theirs = hl7.parser.create_parse_plan(body.strip()).esc
        if mine == theirs:
            continue
        assert theirs == "\r", f"{header!r}: divergent escape char {theirs!r} (mine {mine!r})"
        # ...and a `\r` escape char is inert, because python-hl7 splits segments on `\r` first, so no
        # leaf it hands to unescape can contain one.
        assert all("\r" not in str(field) for seg in parsed for field in seg)


@_BACKENDS
def test_composed_escapes_over_budget_are_a_contract_error(builtin: bool) -> None:
    # THE cell: every escape is individually under MAX_ESCAPE_REPEAT, so only the aggregate sees the
    # breach. Both read surfaces raise the contract error on BOTH backends — the fallback backend is
    # never handed the message (its unescape is unbounded).
    body = _MSG.format(pid3=_ESCAPE * (_AT_BUDGET_REPEATS + 1))
    with _backend.backend(builtin=builtin):
        with pytest.raises(HL7PeekError, match="escape expansion exceeds budget"):
            Peek.parse(body)
        with pytest.raises(HL7PeekError, match="escape expansion exceeds budget"):
            Message.parse(body)


@_BACKENDS
def test_just_under_budget_parses_byte_identically(builtin: bool) -> None:
    # Anti-over-rejection: the largest composition that fits the budget is untouched — same parse,
    # byte-identical raw and re-encode, ordinary fields still readable.
    body = _MSG.format(pid3=_ESCAPE * _AT_BUDGET_REPEATS)
    with _backend.backend(builtin=builtin):
        peek = Peek.parse(body)
        message = Message.parse(body)
    assert peek.raw == body
    assert message.encode() == body
    assert peek.field("MSH-9.1") == "ADT"
    assert message.field("PID-5.1") == "DOE"


@_BACKENDS
def test_single_huge_count_is_a_contract_error_on_both_backends(builtin: bool) -> None:
    # DELTA-01's ~15-byte payload: previously accepted (the clamp dropped it to a blank field, so the
    # sender got an AA for a message the engine could not read). Now it is rejected explicitly, and
    # the python-hl7 backend — which would really have allocated ~8 GB — is never reached.
    body = _MSG.format(pid3="\\.in2000000000\\^^^MRN")
    with _backend.backend(builtin=builtin):
        with pytest.raises(HL7PeekError):
            Peek.parse(body)
        with pytest.raises(HL7PeekError):
            Message.parse(body)


def test_budget_message_is_numeric_only_never_the_offending_value() -> None:
    # The breach text lands in MSA-3 (wiring_runner build_ack `text=str(exc)`), so it must quote only
    # counts — never a field value or a body fragment (PHI back to the sender).
    marker = "ZZSECRETNAME9137X"
    body = _MSG.format(pid3=f"{marker}{_ESCAPE * (_AT_BUDGET_REPEATS + 1)}")
    with pytest.raises(HL7PeekError) as excinfo:
        enforce_expansion_budget(body)
    text = str(excinfo.value)
    assert marker not in text and "DOE" not in text and _ESCAPE not in text
    assert str(DEFAULT_MAX_MESSAGE_BYTES) in text


def test_a_large_body_cannot_buy_itself_a_larger_expansion_allowance() -> None:
    # The budget is the FIXED 16 MiB, not one scaled to the body. It has to be: the off-loopback
    # deployment runbook raises max_message_bytes to 256 MiB on an UNAUTHENTICATED MLLP inbound, and
    # a scaled allowance would hand that connection 256 MiB of pre-ACK escape expansion — 16x weaker
    # on exactly the connection that matters most. This body is >16 MiB and its escapes estimate just
    # over 16 MiB of growth, so a `max(len(norm), 16 MiB)` budget admits it; the fixed one refuses it.
    filler = "F" * (DEFAULT_MAX_MESSAGE_BYTES + 1)
    body = _MSG.format(pid3=f"{filler}|{_ESCAPE * (_AT_BUDGET_REPEATS + 1)}")
    assert len(body) > DEFAULT_MAX_MESSAGE_BYTES  # a scaled budget would have been len(body)
    with pytest.raises(HL7PeekError, match="escape expansion exceeds budget"):
        enforce_expansion_budget(body)


def test_fixed_budget_does_not_over_reject_a_large_streaming_body() -> None:
    # The anti-over-rejection half: the runbook's streaming feed is a base64 document in OBX-5.5, and
    # the base64 alphabet contains no backslash — so a >16 MiB attachment estimates ZERO growth and the
    # fixed constant cannot reject it. The budget bounds GROWTH, never total size (enforce_size_limits
    # owns that, and it is the knob a streaming inbound legitimately raises).
    blob = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5Ky8=" * 340_000
    assert len(blob) > DEFAULT_MAX_MESSAGE_BYTES
    mdm = (
        "MSH|^~\\&|SEND|FAC|RECV|FAC|20260101000000||MDM^T02|MSG00002|P|2.5\r"
        "OBX|1|ED|DOC^document||^application^pdf^Base64^" + blob + "\r"
    )
    enforce_expansion_budget(mdm)  # no growth to measure: admitted whatever its size
    assert _builtin_hl7.escape_expansion_estimate(mdm) == 0


# --- ASVS 1.3.3: the budget's own COST must be bounded too -------------------
#
# The tests above bound the memory the residual names. They are all satisfied by a scan that takes
# arbitrarily long, which is how a 1-2 s pre-ACK event-loop stall shipped green beside them: measuring
# growth means reading every counted escape's count, and the cheapest hostile openers (a zero-width
# prefix, or a non-numeric count) add NOTHING to the running total — so the `limit` short-circuit is
# structurally unreachable for exactly the bodies an attacker sends, and the message is then ACCEPTED
# with an estimate of 0. Un-fixed, `\.fia` filling a 16 MiB body cost ~3.3M iterations / ~1.6 s and
# `\.sk1\` ~2.8M / ~1.1 s, on an unauthenticated pre-ACK path that blocks EVERY listener, worker and
# the API. These tests assert the guard's work, not its verdict.
#
# The assertion is on an ITERATION COUNT, never wall-clock: a timing threshold flakes on a loaded
# Windows CI runner (this repo already carries that failure mode), and would also pass for the wrong
# reason on a fast box.


class _CountingScanner:
    """Wraps the compiled scanner so a test can count Python-level loop iterations exactly."""

    def __init__(self, pattern: object) -> None:
        self._pattern = pattern
        self.iterations = 0

    def finditer(self, text: str):  # type: ignore[no-untyped-def]
        for match in self._pattern.finditer(text):  # type: ignore[attr-defined]
            self.iterations += 1
            yield match


def _count_iterations(monkeypatch: pytest.MonkeyPatch, body: str) -> tuple[int, bool]:
    """Run the real budget over ``body``; return (Python-level iterations, refused?)."""
    real = _builtin_hl7._repeat_escape_scanner
    spy = _CountingScanner(real("\\"))
    monkeypatch.setattr(_builtin_hl7, "_repeat_escape_scanner", lambda esc: spy)
    try:
        enforce_expansion_budget(body)
    except HL7PeekError:
        return spy.iterations, True
    return spy.iterations, False


def _fill_to_cap(unit: str) -> str:
    """A well-formed message saturated with ``unit``, sized just inside the DEFAULT ingress caps."""
    head = "MSH|^~\\&|SEND|FAC|RECV|FAC|20260101000000||ADT^A01|MSG00003|P|2.5\rPID|1||"
    body = head + unit * ((DEFAULT_MAX_MESSAGE_BYTES - len(head) - 8) // len(unit))
    assert len(body) <= DEFAULT_MAX_MESSAGE_BYTES  # inside the caps: enforce_size_limits admits it
    return body


@pytest.mark.parametrize(
    "unit",
    ["\\.fia", "\\.fi1\\", "\\.sk1\\", "\\.ska", "\\.in1\\", "\\.in0\\"],
    ids=[
        "zero-width-nonnumeric",
        "zero-width",
        "counted-w1",
        "nonnumeric-w1",
        "counted-w4",
        "zero",
    ],
)
def test_a_cap_sized_body_of_cheap_escape_openers_cannot_buy_an_unbounded_scan(
    monkeypatch: pytest.MonkeyPatch, unit: str
) -> None:
    # Each `unit` contributes ZERO to the estimate, so none of them can ever trip the `limit`
    # short-circuit — that is precisely why they are the attack. The scan must be bounded anyway.
    iterations, _refused = _count_iterations(monkeypatch, _fill_to_cap(unit))
    # +1: the cap is enforced *inside* the loop, so the iteration that raises is itself counted.
    assert iterations <= _builtin_hl7.MAX_COUNTED_ESCAPE_OPENERS + 1, (
        f"{unit!r} bought {iterations} pre-ACK Python iterations on the event loop"
    )


@pytest.mark.parametrize("unit", ["\\.sk1\\", "\\.ska", "\\.in1\\"], ids=["w1", "nonnumeric", "w4"])
def test_an_unmeasurable_body_is_refused_and_logged_never_accepted_un_measured(
    unit: str,
) -> None:
    # Bounding the scan means some bodies stop being measurable. Fail CLOSED: a body carrying more
    # counted openers than the estimator will walk is refused as a contract error on the same pre-ACK
    # NAK + ERROR path as a budget breach — never accepted with a half-finished estimate (which would
    # be an under-estimate, the one direction that reopens the residual) and never accept-and-dropped.
    with pytest.raises(HL7PeekError, match="exceeds max counted escapes"):
        enforce_expansion_budget(_fill_to_cap(unit))


def test_the_scan_cap_message_is_numeric_only() -> None:
    marker = "ZZSECRETNAME9137X"
    head = f"MSH|^~\\&|S|F|R|F|20260101||ADT^A01|M|P|2.5\rPID|1||{marker}^"
    with pytest.raises(HL7PeekError) as excinfo:
        enforce_expansion_budget(head + "\\.sk1\\" * (_builtin_hl7.MAX_COUNTED_ESCAPE_OPENERS + 1))
    assert marker not in str(excinfo.value)
    assert str(_builtin_hl7.MAX_COUNTED_ESCAPE_OPENERS) in str(excinfo.value)


def test_a_legitimate_rich_text_report_still_costs_zero_python_iterations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Anti-vacuity twin, and the anti-over-rejection half: the bound must not have been "achieved" by
    # refusing legitimate rich text. A cap-sized report densely formatted with real HL7 line breaks
    # (`\.br\`, the overwhelmingly common form) and structural escapes is ACCEPTED and costs the
    # estimator no Python-level work at all — so a future "optimization" that starts rejecting or
    # walking benign reports reds here rather than passing as a tightened guard.
    for unit in ("\\.br\\", "\\F\\", "\\.in\\", "\\X4142\\"):
        iterations, refused = _count_iterations(monkeypatch, _fill_to_cap(unit))
        assert not refused, unit
        assert iterations == 0, (unit, iterations)


def test_a_body_that_actually_breaches_still_short_circuits_on_the_total(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The `limit` short-circuit is not dead code — it is just not a general cost bound. A body whose
    # escapes DO expand breaches the budget within a handful of openers, long before the opener cap.
    iterations, refused = _count_iterations(monkeypatch, _fill_to_cap(_ESCAPE))
    assert refused
    assert iterations <= DEFAULT_MAX_MESSAGE_BYTES // _ESCAPE_GROWTH + 1
    assert iterations < _builtin_hl7.MAX_COUNTED_ESCAPE_OPENERS


def test_peek_and_message_budgets_agree_on_every_body() -> None:
    # Count-and-log guard for the pre-ACK streaming detach: it runs Message.parse on a body Peek.parse
    # already accepted, inside a try/finally whose caller does NOT catch HL7PeekError. If the two
    # budgets could disagree the connection would drop with no row and no NAK.
    for pid3 in (
        "MRN001",
        _ESCAPE * _AT_BUDGET_REPEATS,
        _ESCAPE * (_AT_BUDGET_REPEATS + 1),
        "\\.in2000000000\\",
    ):
        body = _MSG.format(pid3=pid3)
        peek_rejected = message_rejected = False
        try:
            Peek.parse(body)
        except HL7PeekError:
            peek_rejected = True
        try:
            Message.parse(body)
        except HL7PeekError:
            message_rejected = True
        assert peek_rejected == message_rejected, pid3


# --- ASVS 1.3.3: the pre-ACK listener disposition ----------------------------


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _hl7_registry() -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            name="IB_HL7",
            spec=ConnectionSpec(ConnectorType.MLLP, {}),
            router="r",
            content_type=ContentType.HL7V2,
        )
    )
    reg.add_router("r", lambda m: [])
    return reg


async def test_over_budget_message_records_error_and_naks_before_any_ingress_row(
    store: MessageStore,
) -> None:
    # The whole point of the EAGER placement: the breach surfaces from Peek.parse, inside the
    # listener's existing HL7PeekError catch, so the message is dead-lettered ERROR + NAK'd AR before
    # the ingress stage — counted and logged, never accepted-and-dropped and never silently blanked.
    reg = _hl7_registry()
    runner = RegistryRunner(reg, store)
    body = _MSG.format(pid3=_ESCAPE * (_AT_BUDGET_REPEATS + 1)).encode("utf-8")

    ack = await runner._handle_inbound(reg.inbound["IB_HL7"], body)

    assert ack is not None and "MSA|AR" in ack
    cur = await store._db.execute("SELECT status, error FROM messages")
    rows = [dict(r) for r in await cur.fetchall()]
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.ERROR.value
    assert "escape expansion exceeds budget" in rows[0]["error"]
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM queue")
    assert (await cur.fetchone())["n"] == 0  # nothing reached the ingress stage


async def test_under_budget_message_still_reaches_the_ingress_stage(store: MessageStore) -> None:
    # Anti-vacuity twin: the same listener path with an at-budget composition still ACKs and commits.
    reg = _hl7_registry()
    runner = RegistryRunner(reg, store)
    body = _MSG.format(pid3=_ESCAPE * _AT_BUDGET_REPEATS).encode("utf-8")

    ack = await runner._handle_inbound(reg.inbound["IB_HL7"], body)

    assert ack is not None and "MSA|AA" in ack
    cur = await store._db.execute("SELECT status FROM messages")
    rows = [dict(r) for r in await cur.fetchall()]
    assert len(rows) == 1 and rows[0]["status"] == MessageStatus.RECEIVED.value


# --- ADR 0054 Phase-1 fallback guard ----------------------------------------
#
# Each built-ins parse is wrapped so an *unexpected* internal fault falls back to python-hl7 (never
# crashing a connection) and is logged; the contract errors still re-raise without falling back
# (Message.parse re-raises hl7.ParseException; Peek.parse raises HL7PeekError from its no-MSH
# pre-guard, before the try). None of these branches are exercised by the parity or unescape-DoS
# suites. The forced-fault log also sits on the pre-ACK ingress path (Peek.parse runs inside
# summarize()), so it must stay PHI-free.

_FALLBACK_MSG = "falling back to python-hl7"

# A unique PID-5 marker that must never leak into the fallback log (PHI-safety regression guard).
_PHI_MARKER = "ZZSECRETNAME9137X"
_PHI_MSG = (
    "MSH|^~\\&|SEND|FAC|RECV|FAC|20260101000000||ADT^A01|MSG00001|P|2.5\r"
    f"PID|1||MRN001||{_PHI_MARKER}^JOHN\r"
)


def _raise_builtin_fault(*_args: object, **_kwargs: object) -> None:
    # Stand-in for an unexpected internal built-ins bug (anything other than the contract's
    # ParseException / HL7PeekError). Carries no body text of its own.
    raise RuntimeError("forced built-ins fault")


def _fallback_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if _FALLBACK_MSG in r.getMessage()]


def test_peek_falls_back_to_python_hl7_on_builtin_fault(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(_builtin_hl7, "parse", _raise_builtin_fault)
    with caplog.at_level(logging.WARNING), _backend.backend(builtin=True):
        peek = Peek.parse(_MSG.format(pid3="MRN001"))
    # Landed on the proven python-hl7 backend, and the routing read still works.
    assert isinstance(peek.message, hl7.Message)
    assert peek.field("MSH-9.1") == "ADT"
    records = _fallback_records(caplog)
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    # exc_info=True is attached, but the PHI-redaction log filter (when installed) redacts it into
    # exc_text and clears exc_info — so a diagnostic traceback is present in one form or the other.
    assert records[0].exc_info is not None or records[0].exc_text is not None


def test_message_falls_back_to_python_hl7_on_builtin_fault(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(_builtin_hl7, "parse", _raise_builtin_fault)
    with caplog.at_level(logging.WARNING), _backend.backend(builtin=True):
        msg = Message.parse(_MSG.format(pid3="MRN001"))
    assert msg._builtin is False
    assert isinstance(msg._m, hl7.Message)
    assert msg.field("MSH-9.1") == "ADT"
    records = _fallback_records(caplog)
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    # exc_info=True is attached, but the PHI-redaction log filter (when installed) redacts it into
    # exc_text and clears exc_info — so a diagnostic traceback is present in one form or the other.
    assert records[0].exc_info is not None or records[0].exc_text is not None


def test_message_parse_reraises_parseexception_without_fallback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # A non-MSH-leading body is the built-ins parser matching python-hl7's contract, not an internal
    # fault: Message.parse re-raises hl7.ParseException as-is, with no fallback and no warning.
    with caplog.at_level(logging.WARNING), _backend.backend(builtin=True):  # noqa: SIM117
        with pytest.raises(hl7.ParseException):
            Message.parse("PID|1||X\r")
    assert _fallback_records(caplog) == []


def test_peek_parse_raises_hl7peekerror_without_fallback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Peek's no-MSH pre-guard raises HL7PeekError *before* the try, so the fallback never runs and
    # nothing is logged.
    with caplog.at_level(logging.WARNING), _backend.backend(builtin=True):  # noqa: SIM117
        with pytest.raises(HL7PeekError):
            Peek.parse("PID|1||X\r")
    assert _fallback_records(caplog) == []


@pytest.mark.parametrize("parse", [Peek.parse, Message.parse], ids=["peek", "message"])
def test_expansion_budget_never_falls_back_to_python_hl7(
    parse: object, caplog: pytest.LogCaptureFixture
) -> None:
    # ASVS 1.3.3's load-bearing routing property: the budget breach is a CONTRACT error, so neither
    # entry point logs a fallback or hands the body to python-hl7's UNBOUNDED unescape. (A budget
    # raised from inside the wrapped call would be swallowed by the bare `except Exception` guards and
    # turn the clamp into a bypass — the eager placement is what prevents that.)
    body = _MSG.format(pid3=_ESCAPE * (_AT_BUDGET_REPEATS + 1))
    with caplog.at_level(logging.WARNING), _backend.backend(builtin=True):  # noqa: SIM117
        with pytest.raises(HL7PeekError):
            parse(body)  # type: ignore[operator]
    assert _fallback_records(caplog) == []


@pytest.mark.parametrize("parse", [Peek.parse, Message.parse], ids=["peek", "message"])
def test_contract_error_from_the_builtins_call_is_re_raised_not_fallen_back(
    parse: object, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Defence in depth for the same property (_backend.py's documented contract): even if a contract
    # error were ever raised from INSIDE the wrapped built-ins call, the guard re-raises it rather than
    # retrying on the unbounded backend.
    def _raise_contract(*_a: object, **_k: object) -> None:
        raise HL7PeekError("forced contract error")

    monkeypatch.setattr(_builtin_hl7, "parse", _raise_contract)
    with caplog.at_level(logging.WARNING), _backend.backend(builtin=True):  # noqa: SIM117
        with pytest.raises(HL7PeekError):
            parse(_MSG.format(pid3="MRN001"))  # type: ignore[operator]
    assert _fallback_records(caplog) == []


def test_fallback_log_is_phi_free_for_both_entry_points(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Regression guard: the fallback warning is a constant string and exc_info=True renders a
    # traceback *without* local variables, so the message body (held only in the ``norm`` local)
    # never reaches the log. Fails if the warning ever interpolates the raw, or an exception starts
    # carrying body text.
    monkeypatch.setattr(_builtin_hl7, "parse", _raise_builtin_fault)
    with caplog.at_level(logging.WARNING), _backend.backend(builtin=True):
        peek = Peek.parse(_PHI_MSG)
        msg = Message.parse(_PHI_MSG)
    # The body really was carried through the fallback (the marker survives the parse)...
    assert peek.field("PID-5.1") == _PHI_MARKER
    assert msg.field("PID-5.1") == _PHI_MARKER
    # ...both fallbacks logged, yet the marker never appears anywhere in the emitted log text.
    assert len(_fallback_records(caplog)) == 2
    assert _PHI_MARKER not in caplog.text
