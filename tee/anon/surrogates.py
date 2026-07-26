# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Surrogate **production** — the code half of the rule model (ADR 0030 §2/§3).

One pure function per :class:`~messagefoundry.anon.rules.SurrogateKind`, each turning a real field
value into a **structurally-faithful, fabricated** replacement of the same HL7 datatype — so the
anonymized corpus still exercises field widths, repetitions, and routing-key shapes (ADR 0030 §3:
*replace, don't blank*). Every choice is drawn from ``keyer.rng(kind, value)``, so the same real
value always yields the same surrogate **within a dataset** and a different (secret) salt yields a
disjoint mapping (ADR 0030 §4). Adding a *new kind* of surrogate is writing a function here — never
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
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from . import _pools
from .keying import Keyer
from .rules import SurrogateKind

#: A never-matching pattern — the site-code detector when no prefix is configured (a token-less
#: public build). ``re`` has no built-in "match nothing", so encode one explicitly.
_NEVER: re.Pattern[str] = re.compile(r"(?!x)x")


def _resolve_token_text() -> str | None:
    """The active token content, or ``None`` if no source is configured — the SAME source
    ``scripts/security/scan_forbidden.py`` reads, so the site-code authority is externalized in one
    place (never committed). ``MEFOR_FORBIDDEN_TOKENS`` wins: an existing file path is read; any other
    non-empty value is inline content; an explicitly-empty value means "no source". Otherwise the
    git-ignored ``scripts/security/scan-tokens.local.txt`` is located by walking up from this file
    (a dev checkout); an installed wheel without it degrades to no-op.
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
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "scripts" / "security" / "scan-tokens.local.txt"
        try:
            if candidate.is_file():
                return candidate.read_text(encoding="utf-8")
        except OSError:
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
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section == "site_prefix" and line.isdigit() and len(line) == 2:
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

#: What :class:`SurrogateKind.FREETEXT` collapses a narrative field to. Free text routinely embeds
#: identifiers (a name/MRN/DOB in prose) that field-level surrogation cannot reach and the leak-check
#: only catches as known tokens — so the default is a blunt full-redact (ADR 0030 §3).
REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class Seps:
    """The component/repetition/subcomponent separators of the message being anonymized, read from
    its own MSH-1/MSH-2 (never hardcoded). The field separator is the adapter's concern."""

    component: str = "^"
    repetition: str = "~"
    subcomponent: str = "&"


def _fake_digits(rng: random.Random, length: int) -> str:
    """A fabricated all-digit string of the given length (>= 1)."""
    return "".join(str(rng.randrange(10)) for _ in range(max(1, length)))


def _fake_like(rng: random.Random, sample: str) -> str:
    """A fabricated value with the **same shape** as ``sample``: each digit → a digit, each ASCII
    letter → an upper-case letter, anything else kept verbatim. Preserves the original width AND the
    alphanumeric shape (so ``A0049`` → ``X7321``, not a shrunk digit-only string)."""
    if not sample:
        return _fake_digits(rng, 6)
    out: list[str] = []
    for ch in sample:
        if ch.isdigit():
            out.append(str(rng.randrange(10)))
        elif ch.isascii() and ch.isalpha():
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


def _surrogate_identifier(kind: str, rep: str, keyer: Keyer, seps: Seps) -> str:
    """Replace the **id** component (component 1) with a fabricated value of the same length and
    alphanumeric shape, keeping the assigning authority / id-type components (non-PHI, routing-
    relevant) intact — so an alphanumeric MRN keeps its width and shape, not just its digit count."""
    rng = keyer.rng(kind, rep)
    comps = _components(rep, seps)
    comps[0] = _fake_like(rng, comps[0])
    return seps.component.join(comps)


def surrogate_mrn(rep: str, keyer: Keyer, seps: Seps) -> str:
    """CX medical-record number — fabricated id, assigning authority/type preserved."""
    return _surrogate_identifier("mrn", rep, keyer, seps)


def surrogate_id(rep: str, keyer: Keyer, seps: Seps) -> str:
    """A generic identifier — fabricated id, trailing components preserved."""
    return _surrogate_identifier("id", rep, keyer, seps)


def surrogate_ssn(rep: str, keyer: Keyer, seps: Seps) -> str:
    """A fabricated SSN/national id — preserves a dashed ``NNN-NN-NNNN`` shape if present, and keeps
    any trailing CX components (an assigning authority) so a CX-shaped national id is not collapsed."""
    rng = keyer.rng("ssn", rep)
    comps = _components(rep, seps)
    id_part = comps[0]
    if re.fullmatch(r"\d{3}-\d{2}-\d{4}", id_part):
        comps[0] = f"{_fake_digits(rng, 3)}-{_fake_digits(rng, 2)}-{_fake_digits(rng, 4)}"
    else:
        comps[0] = _fake_digits(rng, sum(c.isdigit() for c in id_part) or 9)
    return seps.component.join(comps)


def surrogate_phone(rep: str, keyer: Keyer, seps: Seps) -> str:
    """A fabricated NANP number in the reserved-fictional ``NXX-555-01XX`` range (replaces the whole
    repetition, so any embedded email/contact component is scrubbed too)."""
    rng = keyer.rng("phone", rep)
    area = rng.randrange(200, 1000)
    line = 100 + rng.randrange(100)  # 0100–0199, reserved for fictional use
    digits = f"{area:03d}555{line:04d}"
    return f"{digits[:3]}-{digits[3:6]}-{digits[6:]}" if "-" in rep else digits


def surrogate_dob(rep: str, keyer: Keyer, seps: Seps) -> str:
    """A fabricated date of birth that **preserves the original's precision/width** (HL7 DT/TS allows
    ``YYYY`` / ``YYYYMM`` / ``YYYYMMDD`` and a TS time tail): ``1980`` → ``YYYY``, ``198001`` →
    ``YYYYMM``, ``YYYYMMDD`` → a full fabricated date, ``YYYYMMDDHHMMSS`` → fabricated date + the
    original trailing time digits."""
    rng = keyer.rng("dob", rep)
    date8 = f"{rng.randrange(1920, 2022):04d}{rng.randrange(1, 13):02d}{rng.randrange(1, 29):02d}"
    if len(rep) < 8:
        return date8[: len(rep)]  # match the original's precision/width
    return date8 + rep[8:]  # full date + preserved trailing time (TS), if any


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
    SurrogateKind.SSN: surrogate_ssn,
    SurrogateKind.PHONE: surrogate_phone,
    SurrogateKind.DOB: surrogate_dob,
    SurrogateKind.PROVIDER: surrogate_provider,
    SurrogateKind.FREETEXT: surrogate_freetext,
}


def surrogate_field(kind: SurrogateKind, value: str, keyer: Keyer, seps: Seps) -> str:
    """Apply ``kind`` to a whole field value, mapping each ``~`` repetition independently.

    ``DROP`` blanks the field; ``KEEP`` is filtered out before here. An empty field is left empty
    (nothing to fabricate). Repetitions are keyed on their own text, so the same identifier yields
    the same surrogate wherever it appears.
    """
    if kind is SurrogateKind.DROP:
        return ""
    if not value:
        return value
    fn = _SURROGATES.get(kind)
    if fn is None:  # KEEP or an unmapped kind — leave intact (defensive)
        return value
    reps = value.split(seps.repetition)
    return seps.repetition.join(fn(rep, keyer, seps) for rep in reps)


def scrub_site_codes(value: str, keyer: Keyer, seps: Seps) -> str:
    """Field-anchored site-code safety pass (ADR 0030 §5): replace any **whole component** that is
    exactly a site code with a fabricated non-site code of the same width, leaving a coincidental
    site-code run inside a longer value (timestamps, order numbers) untouched. Applied to every field
    as a net under the rule map, since a site code can lurk in an unexpected field. A no-op when no
    site-code prefix is configured (a token-less build; the rule map remains the primary control).
    """
    if not value or not _SITE_PREFIXES:
        return value
    if not any(p in value for p in _SITE_PREFIXES):
        return value

    def _one(component: str) -> str:
        if not SITE_CODE_RE.fullmatch(component):
            return component
        rng = keyer.rng("sitecode", component)
        prefix = rng.choice(_NON_SITE_PREFIXES)
        return f"{prefix}{_fake_digits(rng, len(component) - len(prefix))}"

    reps = value.split(seps.repetition)
    out_reps = []
    for rep in reps:
        comps = rep.split(seps.component)
        comps = [
            seps.subcomponent.join(_one(sub) for sub in comp.split(seps.subcomponent))
            for comp in comps
        ]
        out_reps.append(seps.component.join(comps))
    return seps.repetition.join(out_reps)


def normalized_message(raw: str) -> str:
    """Canonicalize a message for anonymization (ADR 0030 §3) so BOTH adapters see the same structure:
    strip MLLP framing (VT ``\\x0b`` / FS ``\\x1c``), normalize line endings to the HL7 segment
    separator ``\\r``, and drop empty segments (blank lines). Dropping empties is what keeps python-hl7
    (engine) from choking on a blank segment and keeps it byte-aligned with the tee's pure splitter."""
    text = raw.replace("\x0b", "").replace("\x1c", "")
    text = text.replace("\r\n", "\r").replace("\n", "\r")
    return "\r".join(seg for seg in text.split("\r") if seg)


def read_message_seps(text: str) -> tuple[Seps, str] | None:
    """The ``(component/repetition/subcomponent, field)`` separators of an HL7 message, read from its
    own MSH-1/MSH-2 (never hardcoded). Returns ``None`` when there is no MSH carrying the **full four**
    encoding characters — a degenerate/absent MSH-2 — so BOTH adapters fail closed identically (the
    engine's python-hl7 model itself raises when MSH-2 has fewer than four chars). Shared (parity)."""
    for seg in text.replace("\r\n", "\r").replace("\n", "\r").split("\r"):
        if seg[:3].upper() == "MSH" and len(seg) >= 5:
            field = seg[3]
            enc = seg[4:].split(field, 1)[0]
            if len(enc) >= 4:
                return Seps(component=enc[0], repetition=enc[1], subcomponent=enc[3]), field
    return None


def message_has_site_code(text: str) -> bool:
    """True if any whole field/component/subcomponent **is exactly** a site code — the field-anchored
    leak-check that matches the scrub (ADR 0030 §5). Using ``fullmatch`` per component (not a broad
    substring search) means a value that merely *contains* a site-code run — a timestamp, a fabricated
    date, a long order number — is not falsely flagged, while a genuine scrub *miss* still is. Falls
    back to a broad search only for unstructured (no-MSH) text. Always False when no site-code prefix
    is configured."""
    parsed = read_message_seps(text)
    if parsed is None:
        return SITE_CODE_RE.search(text) is not None
    seps, field_sep = parsed
    for seg in text.replace("\r\n", "\r").replace("\n", "\r").split("\r"):
        for field in seg.split(field_sep):
            for rep in field.split(seps.repetition):
                for comp in rep.split(seps.component):
                    if any(SITE_CODE_RE.fullmatch(sub) for sub in comp.split(seps.subcomponent)):
                        return True
    return False


def scrub_message_site_codes(text: str, keyer: Keyer) -> str:
    """Field-anchored site-code safety pass over a whole ``\\r``-delimited message (ADR 0030 §5).

    Splits on the message's own separators and replaces any whole **component** that is exactly a
    site code, anywhere in the message — the net under the rule map for a site code lurking in an
    unexpected field. MSH-1 (field separator) and MSH-2 (encoding characters) are left untouched so
    the header stays parseable. The broad, unanchored catch-all stays in the publish leak-gate as
    defense-in-depth; here we never over-redact a coincidental site-code run inside a longer value.
    """
    parsed = read_message_seps(text)
    if parsed is None:
        return text
    seps, field_sep = parsed
    out_segments: list[str] = []
    for seg in text.replace("\r\n", "\r").replace("\n", "\r").split("\r"):
        if not seg:
            out_segments.append(seg)
            continue
        fields = seg.split(field_sep)
        if fields[0].upper() == "MSH":
            # fields[0]="MSH", fields[1]=encoding chars (^~\&) — never scrub the header machinery.
            head = fields[:2]
            tail = [scrub_site_codes(f, keyer, seps) for f in fields[2:]]
            out_segments.append(field_sep.join(head + tail))
        else:
            head = fields[:1]
            tail = [scrub_site_codes(f, keyer, seps) for f in fields[1:]]
            out_segments.append(field_sep.join(head + tail))
    # Drop trailing empty segments so the engine's python-hl7 re-encode (which appends a trailing
    # segment separator) and the tee's pure splitter converge to the same bytes — golden-corpus
    # parity (ADR 0030 §1). A mid-message empty segment is preserved; only the trailing one(s) go.
    while out_segments and out_segments[-1] == "":
        out_segments.pop()
    return "\r".join(out_segments)
