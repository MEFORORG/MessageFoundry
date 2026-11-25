# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A PRIVATE KEY block whose lines are separate log lines, in the support bundle (BACKLOG #5550).

``redact_log_text`` split the text at its line breaks before any pass ran, so the key-block mask,
which needs the BEGIN marker and the body in one text, never matched such a block, and a body line
too short for the long-base64 sweep printed. The differential below feeds HL7-prefixed bundle text
and compares every line with the per-line reading the code before this change printed. Every value
here is synthetic; the key material is generated (``tests/_pem_fixture.py`` says why).
"""

from __future__ import annotations

import itertools
import re
from collections import Counter
from pathlib import Path

import pytest

from messagefoundry import secretscrub as scrub_mod
from messagefoundry.secretscrub import scrub_credentials
from messagefoundry.support import bundle as bundle_mod
from messagefoundry.support import redact as redact_mod
from messagefoundry.support.redact import (
    mask_key_body_lines,
    redact_log_record,
    redact_log_text,
    split_log_lines,
)
from tests._pem_fixture import b64_run, pem_block, pem_marker

_KEY_LINE = b64_run(11, 64)
#: Short enough that no long-base64 sweep reaches it.
_KEY_LAST = b64_run(12, 10) + "=="


def _per_line(text: str) -> str:
    """The reading before this change: each line redacted on its own."""
    return "\n".join(redact_log_record(line) for line in split_log_lines(text))


def test_a_short_last_body_line_no_longer_prints() -> None:
    text = "\n".join(
        [
            "2026-11-25 12:00:00,001 ERROR mefor.tls key load failed:",
            pem_block("RSA PRIVATE KEY", "\n", _KEY_LINE, _KEY_LAST),
            "PID|1||MRN7712345^^^HOSP^MR||ZQDOE^ZQJANE||19700101|F",
        ]
    )
    # The control: the reading before this change prints the short line.
    assert _KEY_LAST[:-2] in _per_line(text)
    out = redact_log_text(text)
    assert _KEY_LAST[:-2] not in out, out
    assert out.count("\n") == text.count("\n")
    # The BEGIN line and the lines after the block read as the per-line reading printed them.
    old, new = _per_line(text).split("\n"), out.split("\n")
    assert (new[0], new[1], new[4:]) == (old[0], old[1], old[4:])


def test_a_body_ending_at_an_escaped_break_leaves_its_line_whole() -> None:
    # The last body line is followed on the same line by an escaped break and the END marker, so
    # the body covers that line only in part. It is left as it was, a stated residual: a masked
    # prefix would change what the line passes read in the rest of the line.
    end = "\\n" + pem_marker("END", "RSA PRIVATE KEY") + " PID|2||ZQROE^ZQRICH"
    lines = [pem_marker("BEGIN", "RSA PRIVATE KEY"), _KEY_LINE, _KEY_LAST + end]
    assert mask_key_body_lines(lines) == [lines[0], "x" * len(_KEY_LINE), lines[2]]


def test_a_one_line_escaped_block_is_left_to_the_line_pass() -> None:
    lines = ["before", pem_block("EC PRIVATE KEY", "\\n", _KEY_LINE, _KEY_LAST), "after"]
    assert mask_key_body_lines(lines) is lines


def test_lines_holding_a_line_break_are_returned_unchanged() -> None:
    lines = ["a\nb", *pem_block("RSA PRIVATE KEY", "\n", _KEY_LINE, _KEY_LAST).split("\n")]
    assert mask_key_body_lines(lines) is lines


def test_the_log_viewer_masks_a_block_whose_begin_line_is_on_an_earlier_page(
    tmp_path: Path,
) -> None:
    from messagefoundry.api.app import _read_log_tail

    lines = [
        "2026-11-25 12:00:00,001 ERROR mefor.tls key load failed:",
        *pem_block("RSA PRIVATE KEY", "\n", _KEY_LINE, _KEY_LINE[::-1], _KEY_LAST).split("\n"),
        "PID|1||MRN7712345^^^HOSP^MR||ZQDOE^ZQJANE||19700101|F",
    ]
    (tmp_path / "engine.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    whole, total, available = _read_log_tail(str(tmp_path), limit=len(lines), offset=0)
    page, _, _ = _read_log_tail(str(tmp_path), limit=4, offset=0)
    assert available and total == len(lines)
    assert not any(_KEY_LAST[:-2] in line for line in whole + page), (whole, page)
    assert page == whole[-4:]


def test_two_blocks_are_each_masked_at_their_own_lines() -> None:
    first = pem_block("RSA PRIVATE KEY", "\n", _KEY_LINE, _KEY_LAST)
    second = pem_block("EC PRIVATE KEY", "\n", _KEY_LAST, _KEY_LINE[:9])
    lines = ["a", *first.split("\n"), "b", "c", *second.split("\n"), "d"]
    out = mask_key_body_lines(lines)
    changed = [i for i, (old, new) in enumerate(zip(lines, out, strict=True)) if old != new]
    assert changed == [2, 3, 8, 9]
    assert all(set(out[i]) <= {"x"} for i in changed)


def test_the_bundle_masks_a_block_whose_begin_line_is_cut_off_by_the_tail(tmp_path: Path) -> None:
    lines = [
        "2026-11-25 12:00:00,001 ERROR mefor.tls key load failed:",
        *pem_block("RSA PRIVATE KEY", "\n", _KEY_LINE, _KEY_LINE[::-1], _KEY_LAST).split("\n"),
        "PID|1||MRN7712345^^^HOSP^MR||ZQDOE^ZQJANE||19700101|F",
    ]
    (tmp_path / "engine.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    # The control: the tail alone, redacted as text, still prints the short body line.
    assert _KEY_LAST[:-2] in redact_log_text("\n".join(lines[-4:]))
    out = bundle_mod._log_tail(str(tmp_path), lines=4)
    assert out is not None
    assert _KEY_LAST[:-2] not in out, out
    assert out.count("\n") == 3


#: Text before a BEGIN marker, after an END marker, and around a block, HL7-shaped.
_HL7 = (
    "MSH|^~\\&|SNDAPP|SNDFAC|RCVAPP|RCVFAC|20261125120000||ADT^A01|MSG0001|P|2.5.1",
    "PID|1||MRN7712345^^^HOSP^MR||ZQDOE^ZQJANE^Q||19700101|F|||12 ZQ ST^^ZQTOWN^ZZ^00000",
    "2026-11-25 12:00:00,001 ERROR mefor.pipeline transform failed PID|1||MRN7712346||ZQROE^ZQRICH",
    "NK1|1|ZQDOE^ZQJOHN|SPO|||555-0100",
)
_BEFORE = ("", "2026-11-25 12:00:00 ERROR key load: ", "PID|1||MRN77||ZQDOE^ZQJANE|| ", "password=")
_AFTER = ("", " PID|2||ZQROE^ZQRICH", " while loading MSH|^~\\&|A|B")
_KINDS = ("RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY")
_BODIES = (
    (_KEY_LINE, _KEY_LAST),
    (_KEY_LINE[:23],),
    (_KEY_LINE + "  ", _KEY_LINE[::-1], "", _KEY_LAST),
    ("Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC,0A1B2C3D4E5F", "", _KEY_LINE, _KEY_LAST),
    (_KEY_LINE[:20] + "\\n" + _KEY_LAST,),
    (_KEY_LINE, _KEY_LAST + "\\n" + pem_marker("END", "RSA PRIVATE KEY") + " PID|3||ZQDOE^ZQAMY"),
)

#: A run of letters and digits a line prints, after an escaped line break, which a masked body
#: keeps, is read as a blank.
_RUN = re.compile(r"[A-Za-z0-9]{3,}")


def _printed(line: str) -> Counter[str]:
    """Each letter or digit run of three or more ``line`` prints, counted, but "x" runs and the
    placeholder word. Counted, so a run printed once more than the reading before is caught."""
    runs = _RUN.findall(line.replace("\\n", "  "))
    return Counter(run for run in runs if run.strip("x") and run != "REDACTED")


def _corpus() -> list[str]:
    texts = []
    for hl7, before, after, kind, body, ended, blank in itertools.product(
        _HL7, _BEFORE, _AFTER, _KINDS, _BODIES, (True, False), ("", " \t")
    ):
        begin = before + pem_marker("BEGIN", kind) + blank
        end = [pem_marker("END", kind) + after] if ended else [after.strip() or "next record"]
        texts.append("\n".join([hl7, begin, *body, *end, hl7]))
    return texts


@pytest.mark.parametrize("crlf", [False, True], ids=["lf", "crlf"])
def test_no_line_prints_a_value_the_per_line_reading_hid(crlf: bool) -> None:
    """The differential: over HL7-prefixed bundle text, no line prints a letter or digit run the
    per-line reading did not print on that line. The control arm: at least one run the per-line
    reading printed is hidden now, so the comparison can fail."""
    hidden = 0
    for text in _corpus():
        if crlf:
            text = text.replace("\n", "\r\n")
        old_lines = _per_line(text).split("\n")
        new_lines = redact_log_text(text).split("\n")
        assert len(old_lines) == len(new_lines), text
        for old, new in zip(old_lines, new_lines, strict=True):
            assert not _printed(new) - _printed(old), (text, old, new)
            hidden += bool(_printed(old) - _printed(new))
    assert hidden > 0


# Added items 14 and 26: where the camelCase union returns its reading before for a whole text, no
# key-block pass ran in it, and ``scrub_credentials`` printed a key body on any line of that text.

#: A member key the camelCase reading hides the ";" of, which sends the whole text to the fallback.
_FALLBACK = "userPwd='a;PWD=b' password=b'v w'"


@pytest.mark.parametrize("sep", ["\n", "\\n"], ids=["real", "escaped"])
@pytest.mark.parametrize("trigger_first", [True, False], ids=["trigger-first", "trigger-last"])
def test_scrub_credentials_masks_a_key_body_on_the_fallback_reading(
    sep: str, trigger_first: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    block = pem_block("RSA PRIVATE KEY", sep, _KEY_LINE, _KEY_LAST)
    text = sep.join([_FALLBACK, block] if trigger_first else [block, _FALLBACK])
    atoms = (_KEY_LINE, _KEY_LAST[:-2])
    out = scrub_credentials(text)
    assert not [atom for atom in atoms if atom in out], out
    # The control: this text takes the fallback, so without the last mask the body prints.
    with monkeypatch.context() as patch:
        patch.setattr(scrub_mod, "mask_private_key_blocks", lambda text: text)
        unmasked = scrub_credentials(text)
    assert all(atom in unmasked for atom in atoms), unmasked


def test_a_label_value_that_takes_the_begin_marker_still_prints_the_body_on_the_fallback() -> None:
    """A known residual, pinned so a change to it is seen: the label pass took ``-----BEGIN``, so
    the last mask finds no block (the comment above ``secretscrub._NO_LABEL_BEFORE`` states it)."""
    text = _FALLBACK + " secret=" + pem_block("RSA PRIVATE KEY", "\n", _KEY_LINE, _KEY_LAST)
    assert _KEY_LINE in scrub_credentials(text)


def _fallback_corpus() -> list[str]:
    texts = []
    for hl7, kind, sep, trigger in itertools.product(
        _HL7, _KINDS, ("\n", "\\n"), (_FALLBACK, "Server=x;PWD=zqpw1", "userPwd='a;PWD=b'")
    ):
        block = pem_block(kind, sep, _KEY_LINE, _KEY_LINE[:23], _KEY_LAST)
        texts.append(sep.join([hl7, trigger, block, hl7]))
        texts.append(hl7 + " " + trigger + " " + block + " " + hl7)
    return texts


def test_the_fallback_mask_prints_nothing_the_reading_before_it_hid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The differential for items 14 and 26, over HL7-prefixed bundle text and through
    ``scrub_credentials`` alone: with both #5550 changes on, against the reading with both off,
    which is the code before them. A changed line may print no letter or digit run the reading
    before did not; the control arm needs at least one run that reading printed to be hidden."""
    corpus = _fallback_corpus()
    surfaces = (("bundle", redact_log_text), ("scrub_credentials", scrub_credentials))
    new = {name: [apply(text) for text in corpus] for name, apply in surfaces}
    with monkeypatch.context() as patch:
        patch.setattr(scrub_mod, "mask_private_key_blocks", lambda text: text)
        patch.setattr(redact_mod, "mask_key_body_lines", lambda lines: lines)
        old = {name: [apply(text) for text in corpus] for name, apply in surfaces}
    hidden = 0
    for name, _apply in surfaces:
        for text, before, after in zip(corpus, old[name], new[name], strict=True):
            before_lines, after_lines = before.split("\n"), after.split("\n")
            assert len(before_lines) == len(after_lines), (name, text)
            for old_line, new_line in zip(before_lines, after_lines, strict=True):
                newly = _printed(new_line) - _printed(old_line)
                assert not newly, (name, text, old_line, new_line)
                hidden += bool(_printed(old_line) - _printed(new_line))
    assert hidden > 0
