# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Surrogate **production** — the code half of the rule model (ADR 0030 §2/§3).

One pure function per :class:`~messagefoundry_toolkit.anon.rules.SurrogateKind`, each turning a real field
value into a **structurally-faithful, fabricated** replacement of the same HL7 datatype — so the
anonymized corpus still exercises field widths, repetitions, and routing-key shapes (ADR 0030 §3:
*replace, don't blank*). Every choice is drawn from ``keyer.rng(kind, value)``, so the same real
value always yields the same surrogate **within a dataset** and a different (secret) salt yields a
disjoint mapping (ADR 0030 §4). ``FREETEXT`` and ``DROP`` write a constant instead, and ``DATE``
keeps the year and takes no salt on purpose, so those three are the same in every dataset
(BACKLOG #2248). Adding a *new kind* of surrogate is writing a function here — never
an overlay/data edit.

Each function operates on **one field repetition** (the adapter splits/joins ``~`` repetitions) and
is separator-aware via :class:`Seps` (read from the message's own MSH), so it never hardcodes
``|^~\\&`` and composes a whole **field** value, not a bare component.

Pure stdlib + the ``_pools`` seam — byte-identical with ``tee/anon/surrogates.py`` (parity test).
"""

from __future__ import annotations

import os
import random
import re
import unicodedata
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from . import _pools
from .keying import Keyer
from .rules import HEADER_SEGMENTS, AnonError, FieldRule, SurrogateKind

#: A never-matching pattern — the site-code detector when no prefix is configured (a token-less
#: public build). ``re`` has no built-in "match nothing", so encode one explicitly.
_NEVER: re.Pattern[str] = re.compile(r"(?!x)x")
#: A UTF-8 byte-order mark, which an editor can save ahead of a token file's first line.
_BOM = chr(0xFEFF)


def _resolve_token_text() -> str | None:
    """The active token content, or ``None`` if no source is configured — the SAME source
    ``scripts/security/scan_forbidden.py`` reads, so the site-code authority is externalized in one
    place (never committed). ``MEFOR_FORBIDDEN_TOKENS`` wins: an existing file path is read; any other
    non-empty value is inline content; an explicitly-empty value means "no source". Otherwise ONE
    path is built, never searched for (BACKLOG #2995): the git-ignored ``scan-tokens.local.txt`` in
    ``scripts/security/`` under the folder that holds this package. No file there means no source.
    """
    env = os.environ.get("MEFOR_FORBIDDEN_TOKENS")
    if env is not None:
        env = env.strip()
        if not env:
            return None
        try:
            p = Path(env)
            if p.is_file():
                return p.read_text(encoding="utf-8")
        except OSError:
            pass
        return env
    try:  # parents[2]: the repository root in a checkout. A shorter path has none (IndexError).
        root = Path(__file__).resolve().parents[2]
        candidate = root / "scripts" / "security" / "scan-tokens.local.txt"
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    except (OSError, IndexError):
        pass
    return None


def _load_site_prefixes() -> tuple[str, ...]:
    """The estate's site-code numeric prefixes, EXTERNALIZED out of source (they identify a real
    customer estate; ADR 0030 §5, owner decision 2026-06-20). Only the ``[site_prefix]`` section of
    the shared token file is read here, two-digit prefixes only (the site-code model is a two-digit
    prefix + four digits). An absent source yields ``()`` — the site-code safety pass then no-ops,
    correct for a token-less public build where the rule map is the primary control.
    """
    text = _resolve_token_text()
    if text is None:
        return ()
    prefixes: list[str] = []
    section: str | None = None
    for raw in text.splitlines():
        # A byte-order mark is dropped first, as the publish guard's own parser does. Kept, it hid
        # a first-line ``[site_prefix]`` header while the guard still called the token tables live,
        # and inline content in the variable never passes through a file read (BACKLOG #3609).
        line = raw.lstrip(_BOM).strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        # ASCII only, as the guard reads it: ``isdigit`` alone takes a fullwidth or superscript
        # digit, which no site code holds, and the prefix would load and match nothing.
        if section == "site_prefix" and line.isascii() and line.isdigit() and len(line) == 2:
            prefixes.append(line)
    return tuple(dict.fromkeys(prefixes))


#: Field-anchored site-code detector (``fullmatch`` on a whole component, so a coincidental site-code
#: run inside a longer timestamp/order number is left alone, unlike the publish gate's broad catch-all).
#: Built from the externalized prefixes; ``_NEVER`` when none are configured. Recomputed by
#: :func:`reload_site_prefixes`; read as a stable public contract by the leak-check bridge.
_SITE_PREFIXES: tuple[str, ...] = ()
SITE_CODE_RE: re.Pattern[str] = _NEVER
#: Two-digit prefixes that are NOT site-code prefixes — a fabricated replacement code draws its lead
#: from here so it can never itself be a site code.
_NON_SITE_PREFIXES: tuple[str, ...] = ()


def reload_site_prefixes() -> None:
    """Recompute the externalized site-code globals from the current environment / local token file.
    Called once at import and by tests after adjusting the source. Never raises."""
    global _SITE_PREFIXES, SITE_CODE_RE, _NON_SITE_PREFIXES
    _SITE_PREFIXES = _load_site_prefixes()
    if _SITE_PREFIXES:
        alt = "|".join(re.escape(p) for p in _SITE_PREFIXES)
        SITE_CODE_RE = re.compile(rf"(?:{alt})\d{{4}}")
    else:
        SITE_CODE_RE = _NEVER
    _NON_SITE_PREFIXES = tuple(
        f"{n:02d}" for n in range(10, 100) if f"{n:02d}" not in _SITE_PREFIXES
    )


reload_site_prefixes()


def site_prefixes_loaded() -> bool:
    """True when at least one site-code prefix loaded, so the site-code scrub can match anything.

    False whatever the cause: no token source, a file that could not be read, or a source with no
    two-digit entry under ``[site_prefix]``. A caller with a console of its own says so there,
    because nothing here logs it (BACKLOG #3516)."""
    return bool(_SITE_PREFIXES)


#: What :class:`SurrogateKind.FREETEXT` collapses a narrative field to. Free text routinely embeds
#: identifiers (a name/MRN/DOB in prose) that field-level surrogation cannot reach and the leak-check
#: only catches as known tokens — so the default is a blunt full-redact (ADR 0030 §3).
REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class Seps:
    """The component/repetition/subcomponent separators and the escape character of the message
    being anonymized, read from its own MSH-1/MSH-2 (never hardcoded). The field separator is the
    adapter's concern. The surrogate kinds never read ``escape``; the leak-check decodes an escaped
    value with it before its detectors look (BACKLOG #5532), and so does the site-code scrub
    (BACKLOG #5632)."""

    component: str = "^"
    repetition: str = "~"
    subcomponent: str = "&"
    escape: str = "\\"


def _fake_digits(rng: random.Random, length: int) -> str:
    """A fabricated all-digit string of the given length (>= 1)."""
    return "".join(str(rng.randrange(10)) for _ in range(max(1, length)))


def _fake_like(rng: random.Random, sample: str) -> str:
    """A fabricated value with the **same shape** as ``sample``: each digit becomes an ASCII digit,
    each letter and each other non-ASCII character becomes an upper-case ASCII letter, and ASCII
    punctuation and spaces are kept verbatim. Preserves the original width AND the alphanumeric
    shape (so ``A0049`` becomes ``X7321``, not a shrunk digit-only string). A non-ASCII letter used to be kept as it was, so
    an accented letter of a real id reached the output (BACKLOG #5534)."""
    if not sample:
        return _fake_digits(rng, 6)
    out: list[str] = []
    for ch in sample:
        if ch.isdigit():
            out.append(str(rng.randrange(10)))
        elif ch.isalpha() or not ch.isascii():
            out.append(chr(rng.randrange(ord("A"), ord("Z") + 1)))
        else:
            out.append(ch)
    return "".join(out)


def _components(rep: str, seps: Seps) -> list[str]:
    return rep.split(seps.component) if rep else [""]


def surrogate_name(rep: str, keyer: Keyer, seps: Seps) -> str:
    """XPN ``Family^Given^Middle`` from the fabricated name pools (trailing components dropped)."""
    rng = keyer.rng("name", rep)
    family = rng.choice(_pools.FAMILY_NAMES)
    given = rng.choice(_pools.GIVEN_NAMES)
    middle = rng.choice(_pools.MIDDLE_INITIALS)
    parts = [family, given, middle] if middle else [family, given]
    return seps.component.join(parts)


def surrogate_address(rep: str, keyer: Keyer, seps: Seps) -> str:
    """XAD ``Street^^City^State^Zip^USA`` from the fabricated street/city pools."""
    rng = keyer.rng("address", rep)
    street = rng.choice(_pools.STREETS)
    city, state, zip_code = rng.choice(_pools.CITIES)
    return seps.component.join([street, "", city, state, zip_code, "USA"])


#: The 1-based CX components an identifier surrogate keeps as captured: CX.3 check-digit scheme,
#: CX.4 assigning authority, CX.5 identifier type, CX.6 assigning facility, CX.9 assigning
#: jurisdiction and CX.10 assigning agency. They describe the id, its scheme, type and issuer,
#: rather than hold it, and routing and correlation read them. They are kept as the sender wrote
#: them, so the leak-check scans them for the shapes it knows (``leak.kept_component_hits``). Every other component past the first is blanked: CX.2, the
#: check digit, is computed from the real id and is wrong for the fabricated one; CX.7 and CX.8
#: are the effective and expiration dates; and a component past CX.10, such as a security check,
#: is blanked until someone decides it is safe to keep (BACKLOG #5534).
_CX_KEPT_COMPONENTS = frozenset({3, 4, 5, 6, 9, 10})


def _kept_tail(comps: list[str], kept: frozenset[int]) -> list[str]:
    """Components 2 onward of ``comps``, each one whose 1-based position is not in ``kept``
    blanked, and the empty components that leaves at the end dropped, so a blanked date is not
    left behind as a run of separators."""
    tail = [comp if index in kept else "" for index, comp in enumerate(comps[1:], start=2)]
    while tail and not tail[-1]:
        tail.pop()
    return tail


def _surrogate_identifier(
    kind: str,
    rep: str,
    keyer: Keyer,
    seps: Seps,
    kept: frozenset[int] = _CX_KEPT_COMPONENTS,
) -> str:
    """Replace the **id** component (component 1) with a fabricated value of the same length and
    alphanumeric shape, keep the components ``kept`` names (by default the CX authority
    components, :data:`_CX_KEPT_COMPONENTS`: non-PHI, routing-relevant) and blank the rest — so an alphanumeric MRN keeps its width and shape, not
    just its digit count, and its check digit and dates do not survive (BACKLOG #5534)."""
    rng = keyer.rng(kind, rep)
    comps = _components(rep, seps)
    fabricated = _fake_like(rng, comps[0])
    return seps.component.join([fabricated, *_kept_tail(comps, kept)])


def surrogate_mrn(rep: str, keyer: Keyer, seps: Seps) -> str:
    """CX medical-record number — fabricated id, assigning authority/type preserved."""
    return _surrogate_identifier("mrn", rep, keyer, seps)


def surrogate_id(rep: str, keyer: Keyer, seps: Seps) -> str:
    """A generic identifier — fabricated id, authority components kept, the rest blanked."""
    return _surrogate_identifier("id", rep, keyer, seps)


#: The 1-based DLN components a driver's licence surrogate keeps: DLN.2, the issuing state,
#: province or country. DLN.3, the expiration date, is blanked (BACKLOG #5534).
_DLN_KEPT_COMPONENTS = frozenset({2})


def surrogate_dln(rep: str, keyer: Keyer, seps: Seps) -> str:
    """A DLN driver's licence number (PID-20): a fabricated number of the same shape, the issuing
    state kept and the expiration date blanked. The generic identifier reads a field as a CX, so
    it would blank the state as a check digit and could not tell the expiry was a date."""
    return _surrogate_identifier("dln", rep, keyer, seps, _DLN_KEPT_COMPONENTS)


#: The identifier kinds, whose surrogate keeps sender components past the first as captured:
#: the three that call :func:`_surrogate_identifier`, and ``ssn``. The leak-check scans what they
#: keep (``leak.kept_component_hits``), so an identifier kind that starts keeping a component
#: belongs here. They are not every kind that keeps captured text in a field it maps: at least
#: ``date`` keeps a TS.2 precision code, and ``freetext`` on ``OBX-5`` keeps some values whole,
#: and neither is scanned there.
COMPONENT_KEEPING_KINDS: frozenset[SurrogateKind] = frozenset(
    {SurrogateKind.ID, SurrogateKind.MRN, SurrogateKind.SSN, SurrogateKind.DLN}
)


def surrogate_ssn(rep: str, keyer: Keyer, seps: Seps) -> str:
    """A fabricated SSN/national id — preserves a dashed ``NNN-NN-NNNN`` shape if present, and keeps
    the CX authority components a CX-shaped national id carries, blanking the rest as
    :func:`_surrogate_identifier` does (BACKLOG #5534)."""
    rng = keyer.rng("ssn", rep)
    comps = _components(rep, seps)
    id_part = comps[0]
    if re.fullmatch(r"\d{3}-\d{2}-\d{4}", id_part):
        fabricated = f"{_fake_digits(rng, 3)}-{_fake_digits(rng, 2)}-{_fake_digits(rng, 4)}"
    else:
        fabricated = _fake_digits(rng, sum(c.isdigit() for c in id_part) or 9)
    return seps.component.join([fabricated, *_kept_tail(comps, _CX_KEPT_COMPONENTS)])


def surrogate_phone(rep: str, keyer: Keyer, seps: Seps) -> str:
    """A fabricated NANP number in the reserved-fictional ``NXX-555-01XX`` range (replaces the whole
    repetition, so any embedded email/contact component is scrubbed too)."""
    rng = keyer.rng("phone", rep)
    area = rng.randrange(200, 1000)
    line = 100 + rng.randrange(100)  # 0100–0199, reserved for fictional use
    digits = f"{area:03d}555{line:04d}"
    return f"{digits[:3]}-{digits[3:6]}-{digits[6:]}" if "-" in rep else digits


#: What may follow the eight date digits of a date of birth: hours, minutes and seconds, a
#: fraction, then an offset. All optional, and nothing else.
_DOB_TIME: re.Pattern[str] = re.compile(r"((?:[0-9]{2}){0,3}(?:\.[0-9]{1,4})?)([+-][0-9]{4})?")
#: One ASCII digit of a kept time, which :func:`surrogate_dob` writes as ``0``.
_DIGIT: re.Pattern[str] = re.compile(r"[0-9]")
#: What any real UTC offset becomes, in a date of birth and in a date alike: a placeholder, not a
#: conversion.
_OFFSET_FILL = "+0000"


def surrogate_dob(rep: str, keyer: Keyer, seps: Seps) -> str:
    """A fabricated date of birth that **preserves the original's precision/width** (HL7 DT/TS allows
    ``YYYY`` / ``YYYYMM`` / ``YYYYMMDD`` and a TS time tail): ``1980`` → ``YYYY``, ``198001`` →
    ``YYYYMM``, ``YYYYMMDD`` → a full fabricated date, ``YYYYMMDDHHMMSS`` → fabricated date + a
    zero time of the same width, ``YYYYMMDDHHMM-0500`` becomes a fabricated date + ``0000+0000``.

    **The real time of birth and the real offset are not kept (vault BACKLOG #2767).** A time of
    birth is a date detail below the day, and an offset shows whether daylight saving time was in
    effect and can name a region, which is why :func:`surrogate_date` never keeps one either. So the
    time digits are zero-filled at their width and an offset becomes ``+0000``, the same placeholder
    :func:`surrogate_date` writes. The shape, and so the precision, survives; none of the value does."""
    rng = keyer.rng("dob", rep)
    date8 = f"{rng.randrange(1920, 2022):04d}{rng.randrange(1, 13):02d}{rng.randrange(1, 29):02d}"
    if len(rep) < 8:
        return date8[: len(rep)]  # match the original's precision/width
    # Only a time after eight digits is kept, and only as its shape. Anything else there (a name, a
    # second identifier, the year of a ``MM/DD/YYYY``) is dropped: a mapped field is not scanned by
    # the leak-check, so text kept here would leave unseen (BACKLOG #2330).
    head, tail = rep[:8], rep[8:]
    if head.isascii() and head.isdigit() and (time := _DOB_TIME.fullmatch(tail)) is not None:
        clock, offset = time.groups()
        return date8 + _DIGIT.sub("0", clock) + (_OFFSET_FILL if offset else "")
    return date8


#: An HL7 DTM, which is also a TS's first component, in ASCII digits with every group in range. The
#: ranges are what make the kept "year" a year: a US ``MMDDYYYY`` such as ``03152026`` would read as
#: year ``0315`` and month ``20``, and it must be scrubbed, not kept with its real month and day.
#: The year window is narrow for the same reason: an ``MMDD`` with a real month (01-12) never falls
#: in 1850-2199, so ``1231`` or ``101012`` cannot pass as a year.
_DTM: re.Pattern[str] = re.compile(
    r"""
    (18[5-9][0-9]|19[0-9]{2}|2[01][0-9]{2}) # year, 1850-2199
    (                                       # everything the fill replaces
      (?:0[1-9]|1[0-2])                     # month
      (?:(?:0[1-9]|[12][0-9]|3[01])         # day
        (?:(?:[01][0-9]|2[0-3])             # hour
          (?:[0-5][0-9]                     # minute
            (?:[0-5][0-9]                   # second
              (?:\.[0-9]{1,4})?             # fraction, only after the seconds
            )?)?)?)?
    )?
    ([+-][0-9]{4})?                         # offset, replaced by +0000
    """,
    re.VERBOSE,
)
#: A two-digit year, a month and a day. A six-digit value that fits BOTH this and ``YYYYMM`` has no
#: certain reading: ``201107`` is July 2011, or 7 November 2020. Kept as a year and a month it
#: would show the real month of the second reading, so it is scrubbed to empty (BACKLOG #2330).
#: The cost is a true ``YYYYMM`` whose year ends in 01 to 12, such as ``200803``: it is emptied too.
_YYMMDD: re.Pattern[str] = re.compile(r"[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])")
#: What everything between the year and the offset becomes, cut to the original's width: month and
#: day ``01`` so the value stays a valid date (hl7apy refuses a ``00`` month), then zeros.
_DATE_FILL = "0101000000.0000"
#: What may follow a TS's first component: nothing, or a TS.2 degree-of-precision code (HL7 table
#: 0529). Anything else there, a third component included, is malformed.
_TS_PRECISION = frozenset({"", "Y", "L", "D", "H", "M", "S"})


def surrogate_date(rep: str, keyer: Keyer, seps: Seps) -> str:
    """Keep the year of a DTM/TS and fill the rest at the same width, so ``20260315142233.12-0500``
    becomes ``20260101000000.00+0000``. There is **no salt**, so two sides anonymized apart still
    agree. The ``+0000`` is a placeholder, not a conversion: the kept year is the sender's local
    year. A real offset is never kept, because it shows whether daylight saving time was in effect
    (a date detail below the year), can name a region smaller than a state, and can hide a month
    and day (``2026-0315``).

    A TS precision component (TS.2) survives when it is a known code. A value that is not a valid
    DTM (a group out of range, a non-ASCII digit, prose or a stray component) is **scrubbed to
    empty**, never passed through: no faithful surrogate exists for it. So is a year and a month
    that also reads as a two-digit year, a month and a day (``_YYMMDD``). The HL7 explicit null
    ``""`` carries nothing and is kept.
    """
    return _filled_date(rep, seps)


def _filled_date(rep: str, seps: Seps) -> str:
    """What :func:`surrogate_date` returns. It takes no keyer, so the site-code pass can call it."""
    if rep == '""':
        return rep
    ts1, sep, ts2 = rep.partition(seps.component)
    match = _DTM.fullmatch(ts1)
    if match is None or ts2 not in _TS_PRECISION:
        return ""
    year, rest, offset = match.groups()
    if _YYMMDD.fullmatch(year + (rest or "")):
        return ""
    return year + _DATE_FILL[: len(rest or "")] + (_OFFSET_FILL if offset else "") + sep + ts2


def surrogate_provider(rep: str, keyer: Keyer, seps: Seps) -> str:
    """XCN ``Id^Family^Given`` drawn from the fabricated clinician pool."""
    rng = keyer.rng("provider", rep)
    cid, family, given = rng.choice(_pools.CLINICIANS)
    return seps.component.join([cid, family, given])


def surrogate_freetext(rep: str, keyer: Keyer, seps: Seps) -> str:
    """Blunt full-redaction — narrative may embed identifiers field-surrogation can't reach."""
    return REDACTED


_Surrogate = Callable[[str, Keyer, Seps], str]

_SURROGATES: dict[SurrogateKind, _Surrogate] = {
    SurrogateKind.NAME: surrogate_name,
    SurrogateKind.ADDRESS: surrogate_address,
    SurrogateKind.MRN: surrogate_mrn,
    SurrogateKind.ID: surrogate_id,
    SurrogateKind.DLN: surrogate_dln,
    SurrogateKind.SSN: surrogate_ssn,
    SurrogateKind.PHONE: surrogate_phone,
    SurrogateKind.DOB: surrogate_dob,
    SurrogateKind.DATE: surrogate_date,
    SurrogateKind.PROVIDER: surrogate_provider,
    SurrogateKind.FREETEXT: surrogate_freetext,
}


def surrogate_field(kind: SurrogateKind, value: str, keyer: Keyer, seps: Seps) -> str:
    """Apply ``kind`` to a whole field value, mapping each ``~`` repetition independently.

    ``DROP`` blanks the field; ``KEEP`` is filtered out before here and leaves it intact. An empty
    field is left empty (nothing to fabricate). Repetitions are keyed on their own text, so the same
    identifier yields the same surrogate wherever it appears.

    ``kind`` is compared by VALUE, so a plain ``"drop"`` string behaves like the enum member. Any
    other kind with no surrogate raises :class:`AnonError` rather than leaving the value in place.
    """
    if kind == SurrogateKind.DROP:
        return ""
    if not value or kind == SurrogateKind.KEEP:
        return value
    fn = _SURROGATES.get(kind)
    if fn is None:
        raise AnonError(f"no surrogate for kind {str(kind)!r} — refusing to emit the field")
    reps = value.split(seps.repetition)
    return seps.repetition.join(fn(rep, keyer, seps) for rep in reps)


def surrogate_field_recorded(
    path: str,
    kind: SurrogateKind,
    value: str,
    keyer: Keyer,
    seps: Seps,
    blanked: list[str] | None,
) -> str:
    """:func:`surrogate_field`, and a record of the one case where a rule destroys a value without
    anyone having decided that: the ``DATE`` kind scrubbing a repetition that is not a valid
    timestamp to empty (BACKLOG #2330). ``path`` is appended to ``blanked`` once per field it
    happens in. The address only, never the value, so the list is safe to log.

    A ``DROP`` is not recorded: the rule map already says that field is blanked. Both adapters call
    this, each with the value it read, so they agree wherever they read the same value.
    """
    # Asked of each INPUT repetition. The output is not split again: a filled ``+0000`` holds a
    # ``+``, which a message may declare as its repetition separator.
    if (
        blanked is not None
        and kind == SurrogateKind.DATE
        and any(rep and not _filled_date(rep, seps) for rep in value.split(seps.repetition))
    ):
        blanked.append(path)
    return surrogate_field(kind, value, keyer, seps)


def _reads_as_site_code(part: str, seps: Seps, field_sep: str) -> bool:
    """True if ``part``, one component or one subcomponent, is a site code on any reading a
    consumer can take (BACKLOG #5632): as written, trimmed, with its invisible characters dropped
    (:func:`dropped`), split at each invisible character, or any of :func:`decoded_readings`.
    Each reading must be a site code whole, by ``fullmatch``. A part with no escape character is
    not split on whitespace, so a site-code run inside a longer value, such as ``Call 971234
    today``, reads as no site code. A part that holds one is also read split on
    whitespace and on escaped delimiters, so ``Call 971234 today\\.br\\`` reads as a site code,
    and :func:`scrub_site_codes` then replaces the whole part. Each escape body is also read as
    written, split at every character that is not a digit: a raw viewer, or a receiver that
    defines the escape, shows the body's text, and a site code is digits only. docs/PHI.md
    section 9, *Field-anchored site-code scrub*, states the rule and its consequences."""
    forms = [trim(part), trim(dropped(part)), *map(trim, _split_at_invisible(part))]
    forms += decoded_readings(part, seps, field_sep, resplit=True)
    if seps.escape and seps.escape in part:
        # Every piece after an opening escape character is a body: the odd pieces of the split,
        # an unclosed tail among them. The text around them is already read decoded.
        for body in part.split(seps.escape)[1::2]:
            forms += _NON_DIGITS.split(body)
    return any(SITE_CODE_RE.fullmatch(form) for form in forms)


#: What splits an escape body read as written: any run of characters that are not ASCII digits.
_NON_DIGITS: re.Pattern[str] = re.compile(r"[^0-9]+")


def scrub_site_codes(value: str, keyer: Keyer, seps: Seps, field_sep: str = "|") -> str:
    """Field-anchored site-code safety pass (ADR 0030 §5): replace any **whole component or
    subcomponent** that is a site code with a fabricated non-site code of the same width, leaving a
    coincidental site-code run inside a longer value with no escape character (timestamps, order
    numbers) untouched. In a part that holds an escape character, a site-code run that whitespace
    or an escaped delimiter sets apart counts, and the whole part, free text included, becomes
    digits (:func:`_reads_as_site_code`). Applied
    to every field as a net under the rule map, since a site code can lurk in an unexpected field.
    A no-op when no site-code prefix is configured (a token-less build; the rule map remains the
    primary control).

    A part is a site code on any reading :func:`_reads_as_site_code` takes, so one joined to an
    escaped delimiter or written with a hex escape is replaced too, and the whole part as written,
    escape sequences included, gives way to digits of its own width (BACKLOG #5632). A subcomponent
    is replaced on its own; a component that still reads as a site code decoded whole, because an
    escape pairs across its subcomponent separator, is replaced whole. The surrogate is keyed on
    the part as written, so one site code written two ways gets two unrelated surrogates.
    ``field_sep`` is the message's field separator, which ``\\F\\`` decodes to."""
    if not value or not _SITE_PREFIXES:
        return value
    # The check also reads the value with its invisible characters dropped, so the fast exit does.
    visible = dropped(value)
    if not any(p in visible for p in _SITE_PREFIXES) and not (seps.escape and seps.escape in value):
        return value

    def _fake(part: str) -> str:
        rng = keyer.rng("sitecode", part)
        prefix = rng.choice(_NON_SITE_PREFIXES)
        return f"{prefix}{_fake_digits(rng, len(part) - len(prefix))}"

    def _one(part: str) -> str:
        return _fake(part) if _reads_as_site_code(part, seps, field_sep) else part

    def _component(comp: str) -> str:
        comp = seps.subcomponent.join(_one(sub) for sub in comp.split(seps.subcomponent))
        return _one(comp) if seps.subcomponent in comp else comp

    return seps.repetition.join(
        seps.component.join(_component(comp) for comp in rep.split(seps.component))
        for rep in value.split(seps.repetition)
    )


def normalized_message(raw: str, mapped_paths: tuple[str, ...] = ()) -> str:
    """Canonicalize a message for anonymization (ADR 0030 §3) so BOTH adapters see the same structure:
    strip MLLP framing (VT ``\\x0b`` / FS ``\\x1c``), normalize line endings to the HL7 segment
    separator ``\\r``, and drop every line that carries nothing: an empty one, and one holding only
    whitespace or control characters (NUL padding, a trailing SUB). Dropping them keeps the engine's
    parser from choking on a blank segment and keeps it byte-aligned with the tee's pure splitter.
    The engine's parser trims a leading or trailing whitespace-only line and the tee's splitter kept
    it, so the two disagreed until both dropped it here (BACKLOG #2247). Whitespace after the last
    field of the last line is NOT trimmed here: on a latin-1 capture that would cut a UTF-8
    character ending in 0xA0 or 0x85 in half. The engine's parser still trims it, so the two
    still differ on that input.

    Then REFUSE a message holding a line no rule can reach (BACKLOG #2246): one whose first field
    is not a segment id, or bare text that is not a segment id the message's HL7 version defines
    or a rule names. Under a header whose MSH-12 holds no readable version, bare text passes
    only as an id a rule names (BACKLOG #3001). Such a line would pass through untouched, and a
    wrapped name or note is what it tends to carry. Raises a body-free :class:`AnonError`, so plain ``anonymize`` and
    ``anonymize_checked`` agree.

    ``mapped_paths`` is the paths of the rules the caller will apply. The adapters pass them, so
    the anonymizer and the leak-check judge a bare rule-named id (``ZPD``) the same way. A caller
    with no rules passes nothing, and then only a version-defined id may stand bare."""
    # Imported here because ``leak`` imports this module; the one definition of such a line is there.
    from .leak import MALFORMED_LINE_ADVICE, MALFORMED_LINE_HIT, has_unreachable_line

    text = raw.replace("\x0b", "").replace("\x1c", "")
    text = text.replace("\r\n", "\r").replace("\n", "\r")
    text = "\r".join(
        seg for seg in text.split("\r") if not all(c.isspace() or not c.isprintable() for c in seg)
    )
    if has_unreachable_line(text, mapped_paths):
        raise AnonError(
            f"message has a {MALFORMED_LINE_HIT} — refusing to emit. {MALFORMED_LINE_ADVICE} "
            "Then retry."
        )
    return text


def read_message_seps(text: str) -> tuple[Seps, str] | None:
    """The ``(component/repetition/escape/subcomponent, field)`` separators of an HL7 message, read
    from its own MSH-1/MSH-2 (never hardcoded). Returns ``None`` when there is no MSH carrying the
    **full four** encoding characters — a degenerate/absent MSH-2 — so BOTH adapters fail closed
    identically (the engine's ``Message`` itself raises when MSH-2 has fewer than four chars).
    Shared (parity)."""
    for seg in text.replace("\r\n", "\r").replace("\n", "\r").split("\r"):
        if seg[:3].upper() == "MSH" and len(seg) >= 5:
            field = seg[3]
            enc = seg[4:].split(field, 1)[0]
            if len(enc) >= 4:
                seps = Seps(component=enc[0], repetition=enc[1], escape=enc[2], subcomponent=enc[3])
                return seps, field
    return None


#: The dotted formatting commands that write a break or spaces: ``.br``, ``.sp``, ``.ce``, ``.in``,
#: ``.ti`` and ``.sk``. Any other dotted body, ``.fi`` and ``.nf`` among them, decodes to nothing.
_SPACING_FORMAT_COMMANDS = frozenset({".br", ".sp", ".ce", ".in", ".ti", ".sk"})
#: The largest repeat count the engine's parser expands in a dotted command
#: (``_builtin_hl7.MAX_ESCAPE_REPEAT``). A count past it, or below 1, writes nothing there.
_MAX_ESCAPE_REPEAT = 512


def _decode_hex(digits: str) -> str:
    """A ``\\Xhh...\\`` body after its ``X``, decoded one pair at a time to the character with
    that code, as the engine's parser decodes it. A last single digit is read alone, and the
    decode stops at the first pair that is not hex, keeping what it already decoded."""
    out: list[str] = []
    for at in range(0, len(digits), 2):
        try:
            out.append(chr(int(digits[at : at + 2], 16)))
        except ValueError:
            break
    return "".join(out)


def _spacing_command(body: str) -> bool:
    """True if a dotted ``body`` writes a break or spaces on the engine's parser: a spacing command
    alone, or one whose repeat count ``int()`` reads as 1 to :data:`_MAX_ESCAPE_REPEAT`."""
    if body[:3] not in _SPACING_FORMAT_COMMANDS:
        return False
    if len(body) == 3:
        return True
    try:
        return 0 < int(body[3:]) <= _MAX_ESCAPE_REPEAT
    except ValueError:
        return False


def _decode_escape(body: str, letters: dict[str, str]) -> str:
    """What one escape sequence decodes to, given the text between its two escape characters and
    the message's single-letter escapes. It follows ``messagefoundry/parsing/_builtin_hl7.unescape``,
    the engine's own reading, so a value reads here as an HL7 receiver reads it (BACKLOG #5532): a
    delimiter escape becomes the message's own delimiter, ``\\H\\`` and ``\\N\\`` become
    ``_``, a hex escape becomes its characters, and a sequence the receiver cannot map, an empty
    one included, decodes to nothing. One deliberate difference: a dotted command that writes a
    break or spaces decodes to one space, not the break or the run of spaces. Either keeps two
    runs of digits apart. ``tests/test_anon_b214_5532.py`` compares the two decoders."""
    if (letter := letters.get(body)) is not None:
        return letter
    if body.startswith("X"):
        return _decode_hex(body[1:])
    return " " if _spacing_command(body) else ""


def unescape(value: str, seps: Seps, field_sep: str) -> str:
    """``value`` with every HL7 escape sequence decoded, by the message's own escape character and
    separators (BACKLOG #5532), as :func:`_decode_escape` reads each one. The tee cannot import the
    engine's parser, so the leak-check of both copies decodes here, in this byte-identical file.
    Of the anonymizer's own passes, only the site-code scrub calls it, through
    :func:`decoded_readings` (BACKLOG #5632). Pass one component or one subcomponent, the two parts the
    engine's ``Message`` decodes on a component read and a subcomponent read: an escape character
    no second one closes is kept, with the text after it, and across a separator it would pair
    with the next sequence's opener. Never raises."""
    escape = seps.escape
    if not escape or escape not in value:
        return value
    # The single-letter escapes: F field, S component, T subcomponent, R repetition, E the escape
    # character itself, and H and N, highlighting on and off, which the engine writes as ``_``.
    letters = {
        "F": field_sep,
        "S": seps.component,
        "T": seps.subcomponent,
        "R": seps.repetition,
        "E": escape,
        "H": "_",
        "N": "_",
    }
    out: list[str] = []
    at = 0
    while (start := value.find(escape, at)) != -1:
        end = value.find(escape, start + 1)
        if end == -1:
            break
        out.append(value[at:start])
        out.append(_decode_escape(value[start + 1 : end], letters))
        at = end + 1
    out.append(value[at:])
    return "".join(out)


def decoded_readings(part: str, seps: Seps, field_sep: str, *, resplit: bool) -> list[str]:
    """The decoded readings a consumer can take of ``part``, one component or one subcomponent,
    for the detectors that must fail closed on any of them (BACKLOG #5632, #5654): the part
    decoded (:func:`unescape`), and decoded with ``\\H\\`` and ``\\N\\`` dropped, as a display
    that shows highlighting rather than a character reads it; each of those with its invisible
    characters dropped (:func:`dropped`); and each trimmed (:func:`trim`). Empty when ``part``
    holds no escape character: :func:`_reads_as_site_code` and the MRN-typed check read the part
    as written themselves.

    With ``resplit`` each reading is also split again on the message's delimiters, its field
    separator, its escape character, whitespace and every invisible character, and each piece is
    a reading too: a consumer that unescapes the part sees an escaped delimiter as a real one,
    stops at a control character such as ``\\X00\\``, and :func:`unescape` writes a break
    command such as ``\\.br\\`` as a space where the engine writes a line break. The site-code
    check takes it, since a site code is digits only, so a word split out of free text is no
    false hit. The MRN-typed check does not: a split-out word ``MR`` or ``Mr`` in ordinary text,
    such as ``PET\\T\\MR`` or ``MR BRAIN W\\T\\WO``, would refuse the message."""
    escape = seps.escape
    if not escape or escape not in part:
        return []
    shown = part.replace(f"{escape}H{escape}", "").replace(f"{escape}N{escape}", "")
    breaks = re.escape(field_sep + seps.component + seps.repetition + seps.subcomponent + escape)
    forms: list[str] = []
    for decoded in dict.fromkeys(
        (unescape(part, seps, field_sep), unescape(shown, seps, field_sep))
    ):
        candidates = [decoded, dropped(decoded)]
        if resplit:
            # An invisible character becomes a space first, so the one class splits on it too.
            spaced = "".join(" " if _is_invisible(c) else c for c in decoded)
            candidates += re.split(f"[{breaks}{_TRIM_CLASS}]", spaced)
        forms.extend(trim(form) for form in candidates)
    return list(dict.fromkeys(forms))


#: The Unicode categories of a character that takes up no place in what a consumer shows: Cc, every
#: C0 and C1 control character and DEL, and Cf, the format characters, among them the soft hyphen
#: U+00AD, the zero-width space U+200B and the byte-order mark U+FEFF. A consumer drops, trims or
#: stops at them, and a one-byte hex escape reaches the controls, so a value padded, split or
#: interleaved with one, such as ``971234\\X00\\``, ``97\\XAD\\1234`` or ``MR`` with a U+200B, reads
#: as the value without it (BACKLOG #5632, #5654).
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf"})
#: The split class besides the delimiters: whitespace, which :func:`decoded_readings` maps every
#: invisible character to before it splits.
_TRIM_CLASS = "\\s"


def _is_invisible(char: str) -> bool:
    """True if ``char`` is in :data:`_INVISIBLE_CATEGORIES`."""
    return unicodedata.category(char) in _INVISIBLE_CATEGORIES


def _is_blank(char: str) -> bool:
    """True if ``char`` is whitespace or invisible: what :func:`trim` takes off."""
    return char.isspace() or _is_invisible(char)


def dropped(text: str) -> str:
    """``text`` with every invisible character (:data:`_INVISIBLE_CATEGORIES`) removed, as a
    consumer that drops them reads it."""
    return "".join(c for c in text if not _is_invisible(c))


def trim(text: str) -> str:
    """``text`` without the whitespace and invisible characters at either end. It walks in from
    each end once, so a long run of them inside the text costs nothing extra."""
    start, end = 0, len(text)
    while start < end and _is_blank(text[start]):
        start += 1
    while end > start and _is_blank(text[end - 1]):
        end -= 1
    return text[start:end]


def _split_at_invisible(text: str) -> list[str]:
    """``text`` split at each invisible character, as a consumer that stops at one reads each
    piece. Whitespace does not split it, a tab, a form feed or NEL included, though they are
    category Cc: free text such as ``Call<TAB>971234<TAB>today`` keeps the code, as it does with
    spaces."""
    pieces: list[str] = []
    start = 0
    for at, char in enumerate(text):
        if _is_invisible(char) and not char.isspace():
            pieces.append(text[start:at])
            start = at + 1
    pieces.append(text[start:])
    return pieces


def _unescape_field(field: str, seps: Seps, field_sep: str, *, by_component: bool) -> str:
    """``field`` with each subcomponent decoded on its own, or with ``by_component`` each component
    decoded whole, and the separators kept as written."""
    if not seps.escape or seps.escape not in field:
        return field

    def decoded(comp: str) -> str:
        if by_component:
            return unescape(comp, seps, field_sep)
        leaves = comp.split(seps.subcomponent)
        return seps.subcomponent.join(unescape(leaf, seps, field_sep) for leaf in leaves)

    return seps.repetition.join(
        seps.component.join(decoded(comp) for comp in rep.split(seps.component))
        for rep in field.split(seps.repetition)
    )


def unescaped_message(text: str, *, by_component: bool = False) -> str:
    """``text`` with the escape sequences in every field decoded, a subcomponent at a time, or with
    ``by_component`` a component at a time, the two readings :func:`unescape` names, for the token
    scan (BACKLOG #5532). The segment id and encoding characters of a header line are left as
    written, since they hold the escape character itself. Every other line is decoded from its
    first field, so a line with no field separator, which is all one field, is decoded too.
    ``text`` is returned as it is when it has no parseable MSH or no field holds an escape
    sequence."""
    parsed = read_message_seps(text)
    if parsed is None:
        return text
    seps, field_sep = parsed
    changed = False
    lines: list[str] = []
    for line in text.replace("\r\n", "\r").replace("\n", "\r").split("\r"):
        fields = line.split(field_sep)
        decoded = unescaped_fields(fields, seps, field_sep, by_component=by_component)
        changed = changed or decoded != fields
        lines.append(field_sep.join(decoded))
    return "\r".join(lines) if changed else text


def unescaped_fields(
    fields: list[str], seps: Seps, field_sep: str, *, by_component: bool
) -> list[str]:
    """The split ``fields`` of one line, each decoded as :func:`unescaped_message` decodes it. The
    segment id and encoding characters of a header line are left as written."""
    kept = 2 if fields[0].upper() in HEADER_SEGMENTS else 0
    return fields[:kept] + [
        _unescape_field(field, seps, field_sep, by_component=by_component)
        for field in fields[kept:]
    ]


def _date_output_test(rules: tuple[FieldRule, ...], seps: Seps) -> Callable[[list[str], int], bool]:
    """A test for "field ``index`` of this segment holds ``DATE``-kind output", for the site-code pass
    and its leak-check twin to skip (BACKLOG #2330).

    A ``YYYYMM`` date such as ``202601`` has the shape of a site code whenever the estate's prefix is
    ``19`` or ``20``. Scrubbing it replaced a date with a salted number that was no longer a date and
    no longer matched across datasets. A field passes this test only when BOTH hold:

    * the rules put the ``DATE`` kind there: every rule for its path is ``DATE``, or it is the OBX-5
      of a date-typed OBX under the OBX-5 free-text rule (:func:`obx5_kind`); and
    * its value is already what the ``DATE`` kind writes, repetition by repetition. So text that
      never went through the kind, or a real site code that is not a filled date, is not skipped.

    The OBX-5 case reads OBX-2 from the text it is given. A rule that rewrites OBX-2 hides the date
    type, and that OBX-5 is then scrubbed as before the exemption existed.

    A header line (``MSH``, ``BHS``, ``FHS``) is never skipped. Both adapters apply a rule there
    (BACKLOG #2265, #2998), but this test does not number a header's fields the header way, so a
    ``DATE`` rule there earns no exemption: its output is checked and scrubbed like any other
    header field. Before, a ``BHS-7`` date rule exempted the field one to the right of the one
    the rule wrote. What this lets through: a site code that reads as a year and a month,
    sitting in a date field, leaves as its first four digits and ``01``.
    """
    if not _SITE_PREFIXES:
        return lambda fields, index: False  # no site code can match, so there is nothing to skip
    kinds: dict[str, set[str]] = {}
    for rule in rules:
        if rule.kind != SurrogateKind.KEEP:  # a KEEP rewrites nothing, so it decides no output
            kinds.setdefault(rule.path, set()).add(str(rule.kind))
    date_paths = {path for path, found in kinds.items() if found == {SurrogateKind.DATE.value}}
    obx5_dates = kinds.get("OBX-5") == {SurrogateKind.FREETEXT.value}

    def is_date_output(fields: list[str], index: int) -> bool:
        seg_id = fields[0]
        if index == 0 or seg_id.upper() in HEADER_SEGMENTS:
            return False
        if f"{seg_id}-{index}" not in date_paths and not (
            obx5_dates
            and seg_id == "OBX"
            and index == 5
            and obx5_kind(fields[2]) == SurrogateKind.DATE
        ):
            return False
        return all(_filled_date(rep, seps) == rep for rep in fields[index].split(seps.repetition))

    return is_date_output


def message_has_site_code(text: str, rules: tuple[FieldRule, ...] = ()) -> bool:
    """True if any whole field/component/subcomponent **is** a site code, on any reading
    :func:`_reads_as_site_code` takes — the field-anchored leak-check that matches the scrub (ADR
    0030 §5). Using ``fullmatch`` per component (not a broad
    substring search) means a value that merely *contains* a site-code run — a timestamp, a fabricated
    date, a long order number — is not falsely flagged, while a genuine scrub *miss* still is. Falls
    back to a broad search only for unstructured (no-MSH) text. Always False when no site-code prefix
    is configured.

    ``rules`` are the rules the text was anonymized with. A field they filled with the ``DATE`` kind
    is not checked, for the reason :func:`_date_output_test` gives.

    Each component and subcomponent is read as :func:`scrub_site_codes` reads it
    (:func:`_reads_as_site_code`), so a site code joined to an escaped delimiter or written with a
    hex escape is found, and the scrub's output reads as clean (BACKLOG #5632)."""
    if not _SITE_PREFIXES:
        return False  # no site code can match, so skip decoding every escaped part
    parsed = read_message_seps(text)
    if parsed is None:
        return SITE_CODE_RE.search(text) is not None
    seps, field_sep = parsed
    is_date_output = _date_output_test(rules, seps)
    for seg in text.replace("\r\n", "\r").replace("\n", "\r").split("\r"):
        fields = seg.split(field_sep)
        for index, field in enumerate(fields):
            if is_date_output(fields, index):
                continue
            for rep in field.split(seps.repetition):
                for comp in rep.split(seps.component):
                    parts = comp.split(seps.subcomponent)
                    if len(parts) > 1:
                        parts.append(comp)
                    if any(_reads_as_site_code(part, seps, field_sep) for part in parts):
                        return True
    return False


def scrub_message_site_codes(text: str, keyer: Keyer, rules: tuple[FieldRule, ...] = ()) -> str:
    """Field-anchored site-code safety pass over a whole ``\\r``-delimited message (ADR 0030 §5).

    Splits on the message's own separators and replaces any whole component or subcomponent that is
    a site code on any reading :func:`scrub_site_codes` names, anywhere in the message — the net under the rule map for a site code lurking in an
    unexpected field. MSH-1 (field separator) and MSH-2 (encoding characters) are left untouched so
    the header stays parseable. The broad, unanchored catch-all stays in the publish leak-gate as
    defense-in-depth; here we never over-redact a coincidental site-code run inside a longer value.

    ``rules`` are the rules the adapter just applied. A field they filled with the ``DATE`` kind is
    left as it is; :func:`_date_output_test` says why, and what that lets through.
    """
    parsed = read_message_seps(text)
    if parsed is None:
        return text
    seps, field_sep = parsed
    is_date_output = _date_output_test(rules, seps)
    out_segments: list[str] = []
    for seg in text.replace("\r\n", "\r").replace("\n", "\r").split("\r"):
        if not seg:
            out_segments.append(seg)
            continue
        fields = seg.split(field_sep)
        if fields[0].upper() == "MSH":
            # fields[0]="MSH", fields[1]=encoding chars (^~\&) — never scrub the header machinery.
            head = fields[:2]
            tail = [scrub_site_codes(f, keyer, seps, field_sep) for f in fields[2:]]
            out_segments.append(field_sep.join(head + tail))
        else:
            head = fields[:1]
            tail = [
                f if is_date_output(fields, i) else scrub_site_codes(f, keyer, seps, field_sep)
                for i, f in enumerate(fields[1:], start=1)
            ]
            out_segments.append(field_sep.join(head + tail))
    # Drop trailing empty segments so the engine's re-encode (which appends a trailing
    # segment separator) and the tee's pure splitter converge to the same bytes — golden-corpus
    # parity (ADR 0030 §1). A mid-message empty segment is preserved; only the trailing one(s) go.
    while out_segments and out_segments[-1] == "":
        out_segments.pop()
    return "\r".join(out_segments)


# --- the OBX-5 preserve allowlist (shared by both adapters) ---------------------------------------

#: OBX-5 carries a value of the type named in OBX-2, and the ``FREETEXT`` rule redacts it wholesale
#: (ADR 0030 §3). These are the ONLY value types whose OBX-5 may be left intact — an **allowlist**,
#: because the inverse (a blocklist of the types known to be narrative) silently preserves every type
#: nobody thought of: an embedded document (``ED``, an OBX-5 base64 payload — ADR 0028 §7), a
#: reference pointer (``RP``), a vendor Z-type, or an OBX with no OBX-2 at all. Under a blocklist an
#: ED document would reach a fixture un-redacted on first use; under the allowlist it is redacted.
#: The numeric types are the keys of ``_NUMERIC_OBX_GRAMMAR`` below: ``NM``, ``SN`` and ``TM``.
#: A date-typed OBX-5 (a last menstrual period, a collection time) is a date like any other, so it
#: is NOT preserved: it takes the ``DATE`` kind, which keeps the year only (BACKLOG #2330). ``DTM``
#: is not listed, so a value declared ``DTM`` stays redacted whole.
_DATE_OBX_TYPES = frozenset({"DT", "TS"})
_CODED_OBX_TYPES = frozenset({"ID", "IS"})
_CODED_ELEMENT_OBX_TYPES = frozenset({"CE", "CWE"})

#: The 1-based TEXT components of a ``CE``/``CWE`` value: 2 *text*, 5 *alternate text*, 9 *original
#: text*. A coded element carrying free text in any of them is free text, so it is redacted. Component
#: 9 belongs to CWE only; requiring it empty costs a conformant CE nothing (it has no 9th component)
#: and fails closed on one that is not conformant.
_CODED_ELEMENT_TEXT_COMPONENTS = (2, 5, 9)

#: One grammar per numeric value type (BACKLOG #2961). One character class used to serve all three,
#: and any run of digits and marks fitted it, so ``123-45-6789`` under ``NM`` was kept whole. A
#: grammar says what the type IS, so a shape nobody listed is refused too. ASCII ``[0-9]``, never
#: ``\d``, which also matches the digits of other scripts.
_COMPARATOR = r"(?:<=|>=|<>|[<>=])"
#: An HL7 NM: an optional sign, digits, and at most one decimal point.
_NUMBER = r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)"
#: An HL7 TM, ``HH[MM[SS[.S[S[S[S]]]]]]``, with every group in range. The ranges matter: an
#: eight-digit date is not a time of day, and it does not fit. A time with an offset is not kept,
#: as the ``DATE`` and ``DOB`` kinds never keep one (vault BACKLOG #2767): an offset can name a
#: small region, and a date written ``YYYY-MMDD`` or a phone number written ``NNNNNN-NNNN`` reads as
#: a time and an offset.
_TIME_OF_DAY = r"""
    (?:[01][0-9]|2[0-3])                    # hour
    (?:[0-5][0-9]                           # minute
      (?:[0-5][0-9]                         # second
        (?:\.[0-9]{1,4})?                   # fraction, only after the seconds
      )?)?
"""
#: Every character the three grammars are written in. No numeric value is kept when one of them is
#: the component, repetition or subcomponent separator: under a repetition separator of ``-``,
#: ``000-12-3456`` splits into three valid numbers. The field separator is not read.
_NUMERIC_GRAMMAR_CHARS = frozenset("0123456789+-.:/<>=")


#: What each COMPONENT of a preserved numeric value must match, by position. A value with more
#: components than its type has is refused. ``NM`` takes a leading comparator because ``<5`` under
#: ``NM`` is a common sender habit and carries no identifier. ``SN`` is comparator, number,
#: separator or suffix, number, so ``>^100`` and ``^1^:^128`` fit and a bare ``123-45-6789`` in the
#: comparator's place does not.
_NUMERIC_OBX_GRAMMAR: dict[str, tuple[re.Pattern[str], ...]] = {
    "NM": (re.compile(_COMPARATOR + "?" + _NUMBER),),
    "SN": (
        re.compile(_COMPARATOR),
        re.compile(_NUMBER),
        re.compile(r"[-+/.:]"),
        re.compile(_NUMBER),
    ),
    "TM": (re.compile(_TIME_OF_DAY, re.VERBOSE),),
}


def _obx5_parts(value: str, seps: Seps) -> Iterator[str]:
    """Every subcomponent of every component of every repetition of an OBX-5 value, split on the
    message's own separators (never a hardcoded ``|^~\\&``). Lazy, so a caller's ``all()`` stops at
    the first part that fails — a narrative or base64 value is rejected without decomposing it."""
    return (
        sub
        for rep in value.split(seps.repetition)
        for comp in _components(rep, seps)
        for sub in comp.split(seps.subcomponent)
    )


def _fits_numeric_grammar(grammar: tuple[re.Pattern[str], ...], value: str, seps: Seps) -> bool:
    """True if every repetition of ``value`` fits ``grammar``, component by component. An empty
    component is legal, because an ``SN`` leaves out the parts it does not use. No numeric type has
    subcomponents, and the patterns refuse that separator. Nothing is kept when a grammar uses the
    component, repetition or subcomponent separator. The field separator is not read."""
    if not _NUMERIC_GRAMMAR_CHARS.isdisjoint((seps.component, seps.repetition, seps.subcomponent)):
        return False
    for rep in value.split(seps.repetition):
        comps = _components(rep, seps)
        if len(comps) > len(grammar):
            return False
        # Not strict: a value may stop short of its type's last component (``>^100`` has two).
        for comp, pattern in zip(comps, grammar, strict=False):
            part = comp.strip()
            if part and pattern.fullmatch(part) is None:
                return False
    return True


def _is_bare_token(part: str) -> bool:
    """True if ``part`` is at most one whitespace-free token — a table code, never a sentence."""
    return len(part.split(None, 1)) <= 1


def _coded_element_is_bare(value: str, seps: Seps) -> bool:
    """True if a CE/CWE value carries no narrative: every TEXT component empty, and every other part
    a bare token. One pass over the value's structure."""
    for rep in value.split(seps.repetition):
        for index, comp in enumerate(_components(rep, seps), start=1):
            if index in _CODED_ELEMENT_TEXT_COMPONENTS:
                if comp.strip():
                    return False
            elif not all(_is_bare_token(sub) for sub in comp.split(seps.subcomponent)):
                return False
    return True


def preserve_obx5_value(value_type: str | None, value: str | None, seps: Seps) -> bool:
    """True if an OBX-5 carrying ``value`` under declared type ``value_type`` may be left INTACT.

    The fail-closed half of the OBX-5 free-text rule, shared byte-for-byte by the engine and tee
    adapters (ADR 0030 §1 parity) so the two can never disagree about a value type. A message whose
    component, repetition or subcomponent separator is whitespace keeps nothing here. Past that, two
    gates, and anything that clears neither is redacted:

    * the declared type must be on the preserve allowlist above — an absent, empty or unknown OBX-2
      falls straight through to ``False``; and
    * the value must LOOK like the type it claims. A declared type is never taken on trust, because
      an OBX labelled ``NM`` whose OBX-5 carries a sentence is exactly the narrative the ``FREETEXT``
      rule exists to redact. A numeric or time-of-day value must fit the grammar of its own type,
      so an identifier written with dashes or dots is refused (BACKLOG #2961); a coded value must be
      a bare token; a coded ELEMENT must additionally carry no text component.

    A grammar cannot tell a number from an identifier written as a number: an undashed nine or ten
    digit run is a valid ``NM`` and is kept. ``docs/PHI.md`` section 9 names that gap.

    A date type (``DT``, ``TS``) is never preserved. :func:`obx5_kind` says what it gets instead.
    """
    declared = (value_type or "").strip().upper()
    text = value or ""
    # A space is how words and digit groups are written apart. Under a whitespace component,
    # repetition or subcomponent separator, ``000 12 3456`` splits into three valid numbers and a
    # sentence into bare tokens, so no numeric or coded value is kept. A date type never reaches
    # this function. The field separator is not read.
    if any(mark.isspace() for mark in (seps.component, seps.repetition, seps.subcomponent)):
        return False
    if (grammar := _NUMERIC_OBX_GRAMMAR.get(declared)) is not None:
        return _fits_numeric_grammar(grammar, text, seps)
    if declared in _CODED_OBX_TYPES:
        return all(_is_bare_token(part) for part in _obx5_parts(text, seps))
    if declared in _CODED_ELEMENT_OBX_TYPES:
        return _coded_element_is_bare(text, seps)
    return False


def obx5_kind(value_type: str | None) -> SurrogateKind:
    """The kind the OBX-5 free-text rule applies to a value :func:`preserve_obx5_value` did not
    preserve: ``DATE`` when OBX-2 declares a date type, so the year survives and nothing else does,
    and the blunt ``FREETEXT`` redact for everything else. A value under a date label that is not a
    valid timestamp is scrubbed to empty by the ``DATE`` kind, so prose cannot pass as a date."""
    declared = (value_type or "").strip().upper()
    return SurrogateKind.DATE if declared in _DATE_OBX_TYPES else SurrogateKind.FREETEXT
