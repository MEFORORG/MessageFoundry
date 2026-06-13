"""A mutable HL7 v2 message — read and set fields by path, then re-encode.

Wraps a ``python-hl7`` parse. Field paths use the same ``SEG-F[.C[.S]]`` syntax as
:class:`~messagefoundry.parsing.peek.Peek` and the declarative transforms. Components and
subcomponents are rebuilt at the *string* level (split on the message's own separators, modify,
re-join, assign the whole field) — which avoids a python-hl7 quirk where assigning to a component
of a not-yet-componentized field raises.

This is the read/mutate primitive that code-first **Routers** and **Handlers** work against (and
that the declarative transforms now reuse). Never string-slice raw HL7 — go through here and
re-encode.
"""

from __future__ import annotations

import json
from typing import Any

import hl7

from messagefoundry.parsing.peek import normalize, parse_path


class Message:
    """A parsed HL7 message you can read (``msg["MSH-9.2"]``), mutate (``msg["MSH-3"] = …``),
    and re-encode (``msg.encode()``)."""

    #: Symmetry with :class:`RawMessage` — a Router/Handler can branch on ``msg.content_type``.
    content_type = "hl7v2"

    def __init__(self, message: hl7.Message) -> None:
        self._m = message

    @classmethod
    def parse(cls, raw: str | bytes) -> Message:
        """Parse ``raw`` (line endings normalized to ``\\r``) into a mutable message."""
        return cls(hl7.parse(normalize(raw)))

    # --- read ----------------------------------------------------------------

    def field(self, path: str) -> str | None:
        """Value at ``path`` (``"MSH-9"``, ``"MSH-9.1"``, ``"PID-3.1.1"``), or None if absent/empty.

        A whole-field read returns the raw (structural) text, including any repetitions. A
        component/subcomponent read is taken from the **first repetition** (matching
        :class:`~messagefoundry.parsing.peek.Peek`) and is **unescaped** so HL7 escape sequences
        (e.g. ``\\S\\``) round-trip back to their literal value (the inverse of :meth:`set`'s
        escaping)."""
        seg, fld, comp, sub = parse_path(path)
        text = self._raw_field(seg, fld)
        if comp is None:
            return text or None
        _field_sep, comp_sep, rep_sep, _esc, sub_sep = self._encoding_chars()
        # First repetition only, so a component read of a repeating field (e.g. PID-3
        # "111^^^A~222^^^B") returns rep 1's component, not cross-repetition text (review H-9).
        comps = text.split(rep_sep)[0].split(comp_sep)
        if comp > len(comps):
            return None
        value = comps[comp - 1]
        if sub is None:
            return self._m.unescape(value) or None
        subs = value.split(sub_sep)
        return (self._m.unescape(subs[sub - 1]) or None) if sub <= len(subs) else None

    def __getitem__(self, path: str) -> str | None:
        return self.field(path)

    @property
    def message_code(self) -> str | None:
        return self.field("MSH-9.1")

    @property
    def trigger_event(self) -> str | None:
        return self.field("MSH-9.2")

    @property
    def message_type(self) -> str | None:
        return self.field("MSH-9")

    @property
    def control_id(self) -> str | None:
        return self.field("MSH-10")

    def segments(self) -> list[str]:
        """Ordered segment ids, e.g. ``["MSH", "EVN", "PID"]``."""
        return [str(seg[0]) for seg in self._m]

    # --- mutate --------------------------------------------------------------

    def set(self, path: str, value: str) -> None:
        """Write ``value`` at ``path``, extending the field/components as needed.

        ``value`` may never contain a **segment separator** (CR/LF) — that would inject a new segment
        downstream — and a **whole-field** write may not contain the **field separator** (it would
        split into extra fields); both raise ``ValueError`` (XFORM-1, review M-12). A component/
        subcomponent write **escapes** the value's structural delimiters (``| ^ ~ & \\``) so they are
        carried as data, not new structure (e.g. ``PID-5.1 = "O^Brien"`` stays one component), while
        non-delimiter characters — incl. CJK/accented names — pass through intact (review M-13). A
        write to a repeating field edits only the **first repetition**, preserving the rest (review
        H-9). A whole-field write assigns the caller's text verbatim (their structure). Raises
        ``KeyError`` if the target segment isn't present."""
        if "\r" in value or "\n" in value:
            raise ValueError("HL7 field value may not contain a segment separator (CR/LF)")
        seg, fld, comp, sub = parse_path(path)
        try:
            self._m.segment(seg)
        except KeyError:
            raise KeyError(f"cannot set absent segment {seg!r}") from None

        field_sep, comp_sep, rep_sep, esc, sub_sep = self._encoding_chars()

        if comp is None:
            # Whole-field write assigns the caller's structure verbatim — but the field separator
            # would split it into extra fields downstream, so reject it (review M-12). Components and
            # repetitions are the caller's intended structure and remain allowed.
            if field_sep in value:
                raise ValueError(
                    f"HL7 field value may not contain the field separator {field_sep!r}; "
                    "write structured values via a component/subcomponent path"
                )
            self._m[f"{seg}.F{fld}"] = value
            return

        escaped = self._escape_leaf(value, field_sep, comp_sep, rep_sep, esc, sub_sep)
        current = self._raw_field(seg, fld)
        # Edit the FIRST repetition only (matching the read side); preserve any further reps (H-9).
        reps = current.split(rep_sep) if current else [""]
        comps = reps[0].split(comp_sep) if reps[0] else []
        while len(comps) < comp:
            comps.append("")
        if sub is None:
            comps[comp - 1] = escaped
        else:
            subs = comps[comp - 1].split(sub_sep) if comps[comp - 1] else []
            while len(subs) < sub:
                subs.append("")
            subs[sub - 1] = escaped
            comps[comp - 1] = sub_sep.join(subs)
        reps[0] = comp_sep.join(comps)
        self._m[f"{seg}.F{fld}"] = rep_sep.join(reps)

    def __setitem__(self, path: str, value: str) -> None:
        self.set(path, value)

    # --- encode --------------------------------------------------------------

    def encode(self) -> str:
        """Serialize back to a ``\\r``-delimited HL7 string."""
        return str(self._m)

    def __str__(self) -> str:
        return self.encode()

    # --- internals -----------------------------------------------------------

    def _raw_field(self, seg: str, fld: int) -> str:
        """Raw field text (``""`` if the segment/field is absent) — for component rebuilds."""
        try:
            return str(self._m.segment(seg)[fld])
        except (KeyError, IndexError):
            return ""

    def _encoding_chars(self) -> tuple[str, str, str, str, str]:
        """The message's ``(field, component, repetition, escape, subcomponent)`` delimiters, read
        from its **own** MSH-1 (field separator) + MSH-2 (the other four).

        Derived from the actual encoding characters, not hardcoded defaults — so a custom-delimiter
        message isn't split on the wrong characters. Raises ``ValueError`` if they can't be determined
        rather than guess (XFORM-2/3). ``self._m.unescape`` uses the same MSH-2-derived characters, so
        write-escaping and read-unescaping stay consistent."""
        field_sep = self._raw_field("MSH", 1)  # MSH-1 is the field separator itself
        enc = self._raw_field("MSH", 2)  # e.g. "^~\&": component, repetition, escape, subcomponent
        if len(field_sep) != 1 or len(enc) < 4:
            raise ValueError(f"cannot determine HL7 separators: MSH-1={field_sep!r}, MSH-2={enc!r}")
        return field_sep, enc[0], enc[1], enc[2], enc[3]

    @staticmethod
    def _escape_leaf(
        value: str, field_sep: str, comp_sep: str, rep_sep: str, esc: str, sub_sep: str
    ) -> str:
        """Escape ONLY the structural delimiters (and the escape char) so a leaf value carries them
        as data, not new structure. Every other character — including code points above U+00FF
        (CJK/Cyrillic/Greek names) — passes through untouched and round-trips via ``unescape``;
        python-hl7's own ``escape()`` instead hex-encodes those as byte pairs that ``unescape()``
        then mis-decodes, silently corrupting them (review M-13)."""
        out = value.replace(esc, f"{esc}E{esc}")  # the escape char first, so we don't double-escape
        out = out.replace(field_sep, f"{esc}F{esc}")
        out = out.replace(comp_sep, f"{esc}S{esc}")
        out = out.replace(rep_sep, f"{esc}R{esc}")
        out = out.replace(sub_sep, f"{esc}T{esc}")
        return out


class RawMessage:
    """A **non-HL7** inbound payload (ADR 0004) — what a code-first Router/Handler receives when the
    inbound connection's ``content_type`` is not ``hl7v2`` (a database row, a JSON/SOAP body, …).

    The body is committed and routed **verbatim** (no HL7 parse). Read it via :attr:`raw` / :attr:`text`,
    branch on :attr:`content_type`, or :meth:`json` it; a Handler then builds an output **string** and
    returns ``Send(to, that_string)`` (the built destinations accept a ``str`` payload). It deliberately
    has **no** HL7 ``msg["MSH-9.1"]`` API — that surface is HL7-only."""

    def __init__(self, raw: str, content_type: str) -> None:
        self.raw = raw
        self.content_type = content_type

    @property
    def text(self) -> str:
        """The body as text (alias for :attr:`raw`)."""
        return self.raw

    def json(self) -> Any:
        """Parse the body as JSON. Raises ``json.JSONDecodeError`` on malformed input — a Handler can
        return ``None`` (FILTERED) or let it raise (ERROR / dead-letter)."""
        return json.loads(self.raw)

    def encode(self) -> str:
        """The body verbatim — symmetry with :meth:`Message.encode` so a pass-through ``Send`` works."""
        return self.raw

    def __str__(self) -> str:
        return self.raw
