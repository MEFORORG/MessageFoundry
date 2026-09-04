# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The FHIR search-value vocabulary: what a ``fhir_lookup`` ``params`` value MEANS (BACKLOG #1243).

A leaf module by design (it imports nothing from the engine), so ``config/`` and ``transports/`` can
both use it without either importing the other -- which the one-way dependency rule requires, since
``transports/fhir.py`` must not import ``config/`` at module load. Defining it here also keeps
``import messagefoundry`` from dragging in the whole FHIR transport and response codec, which is what
a re-export through ``transports/fhir.py`` would cost. It is not in ``parsing/fhir/`` because that is a
codec for **reading** a resource, not a vocabulary for **constructing** an outbound query. This module
decides **what a value is**; ``transports/fhir.py`` decides how that value goes onto the URL.

WHAT PROBLEM THIS SOLVES. Percent-encoding is a **URL-layer** control: it stops one value becoming
two search *parameters* (CWE-88). It cannot help at the **FHIR value layer**, where ``,`` ``|`` and
``$`` are FHIR's own separators. The FHIR specification says so normatively, and says it in the
course of defining a *different* escape -- R4 section 3.1.1.4.19 and R5 section 3.2.1.5.7 carry the
same two sentences:

    "This specification defines this additional form of escape because the escape syntax using \\
    applies to all parameter values after they have been 'unescaped' on the server while being read
    from the HTTP headers."

    "This escaping is at a different level to the percent encoding that applies to all URL
    parameters (as defined in RFC 3986). Standard percent escaping still applies, such that these
    URLs have the same meaning:"

The second is followed in R5 by a character-exact example pair in which a **percent-encoded comma is
still the OR separator** across three values. So the server percent-decodes first and reads FHIR's
syntax second: ``%7C`` becomes ``|`` and is then a token separator. Read R5 for the examples --
R4's second pair percent-encodes with decimal character codes (``%58`` for ``:``, ``%44`` for
``,``) and is garbled, which invites a reader to dismiss the whole section.

These citations are **evidence, not a test**. Nothing in this repository's suite can arbitrate what
a FHIR server does with a byte on the wire, and a test that pretended to is the defect #1243 exists
to record.

THREE KINDS OF VALUE, BECAUSE ONE STRING CANNOT CARRY TWO PROVENANCES. The idiom this replaces --
``{"identifier": "MRN|" + msg["PID-3.1"]}`` -- is one string whose head is the author's syntax and
whose tail is message data. No encoder can tell those halves apart, so the author states which is
which:

===================================  ==========================================================
``"literal"`` (a plain ``str``)      Data. **Refused** if it carries ``,`` ``|`` or ``$``.
``FhirToken(system, code)``          A ``system|code`` token. The system half is an author
                                     literal and passes through; the code half is data and is
                                     refused on a separator.
``FhirRaw("...")``                   FHIR search syntax the **author** wrote. Percent-encoded
                                     only, never screened. An author has to name it to get it.
===================================  ==========================================================

WHY REFUSAL AND NOT ESCAPING, and this is the load-bearing reason. FHIR defines a backslash escape
for these characters, but the escape is only correct if the server implements the unescape, and
server behaviour is demonstrably variable (HAPI FHIR issue #192 reports an escaped comma coming
back with the backslash still in it). **A value that never leaves the process cannot be misread by
any server.** Refusal's correctness does not depend on the far end; escaping's does. Backslash
escaping is deliberately NOT built here: it is an additive **fourth** kind for a site that has a
real FHIR server and can verify it, which defers the one genuinely unknowable fact to the only
party who can know it.

WHY ``FhirRaw`` IS REQUIRED RATHER THAN A CONVENIENCE. FHIR's own value grammar defeats a two-shape
design, because a composite value is **one value**::

    code-value-quantity=code$loinc|12907-2,value$ge150|http://unitsofmeasure.org|mmol/L

That carries ``$``, three ``|`` and a ``,``, every one of them structural. A quantity is
``[prefix][number]|[system]|[code]``; ``_sort=status,-date,category`` and
``_elements=identifier,active,link`` are comma-separated lists.

AND THE AND/OR TRAP, which is easy to miss. Repeated parameters are ANDed by FHIR, and a ``list``
value expands to repeated parameters -- so a list is an **AND**, not an OR. A comma **inside one
value** is the only way to express OR. Refusing commas with no ``FhirRaw`` would therefore remove
OR from the surface entirely.

``FhirRaw`` carries **author-authored** syntax, not message data: it is the same line
``conditional_query`` already draws on the write side. Operator-authored strings reaching a sink is
its own question, filed as BACKLOG #1241, and is not what this vocabulary is about.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import final

__all__ = [
    "FHIR_VALUE_SEPARATORS",
    "FhirRaw",
    "FhirSearchParams",
    "FhirSearchValue",
    "FhirToken",
    "resolve_search_pairs",
]

#: The FHIR search-value separators this module screens: ``|`` separates a ``system`` from a ``code``
#: in a token, ``,`` ORs several values inside one parameter, and ``$`` introduces an operation or a
#: composite component. Percent-encoding does not neutralise any of them.
#:
#: **This is AT LEAST the set that matters, not a proof that no other character does** (SDS-3.6). The
#: known omission is the **backslash**, which FHIR names in the same breath as these three because it
#: introduces the escape: a server that implements the unescape reads a bare ``\`` in a value as an
#: introducer rather than as data. It is left out here because the ruling that authorised this screen
#: named these three, and widening a refusal is a behaviour change that should be ruled rather than
#: assumed. Filed by subject, unallocated: *the backslash in a FHIR search value*.
FHIR_VALUE_SEPARATORS = ("|", ",", "$")


@final
@dataclass(frozen=True, slots=True)
class FhirToken:
    """A ``system|code`` search token, with the two provenances held apart.

    ``system`` is an author literal and rides through untouched. ``code`` is where message data
    goes, and it is refused if it carries a separator::

        fhir_lookup("epic", "Patient", {"identifier": FhirToken("MRN", msg["PID-3.1"] or "")})

    This is the only way to solve "one string, two provenances" -- by not having one string."""

    system: str
    code: str


@final
@dataclass(frozen=True, slots=True)
class FhirRaw:
    """A search value that is FHIR **syntax the author wrote**, passed through unscreened.

    Percent-encoded like every other value, so the URL layer still holds; the value layer is the
    author's own. Use it for the shapes FHIR expresses inside a single value -- an OR list, a
    quantity, a composite, a sort order::

        {"code": FhirRaw("http://loinc.org|1234-5,http://loinc.org|6789-0")}   # an OR
        {"_sort": FhirRaw("status,-date,category")}

    Never build one out of message data. A ``str`` is the kind that screens; this kind does not."""

    value: str


#: One search value: data (``str``), a token whose halves are declared (``FhirToken``), or author
#: syntax (``FhirRaw``).
FhirSearchValue = str | FhirToken | FhirRaw
#: The ``params`` mapping ``fhir_lookup`` takes. A ``list`` value expands to repeated parameters,
#: which FHIR reads as an **AND** -- see the module docstring's AND/OR note.
FhirSearchParams = Mapping[str, FhirSearchValue | list[FhirSearchValue]]


def _screen(key: str, value: str, *, half: str) -> str:
    """Return ``value`` unchanged, or raise if it carries a FHIR value-layer separator.

    PHI-safe by construction: the message names the parameter key and the offending separator
    character, and **never** the value -- a search value is the most message-derived string the
    engine builds, so it can carry PHI."""
    found = next((sep for sep in FHIR_VALUE_SEPARATORS if sep in value), None)
    if found is None:
        return value
    raise ValueError(
        f"FHIR search parameter {key!r}: the {half} carries {found!r}, which FHIR reads as a "
        f"value-layer separator rather than as data, so the search would not mean what it says. "
        f"Percent-encoding cannot help -- the server decodes first and reads FHIR's syntax second. "
        f"Use FhirToken(system, code) for a system|code token, or FhirRaw(...) if the whole value "
        f"is search syntax you wrote yourself. (The value is withheld: it may carry PHI.)"
    )


def _resolve_one(key: str, value: FhirSearchValue) -> str:
    """One ``params`` value to the string that goes on the URL, before percent-encoding."""
    if isinstance(value, str):
        return _screen(key, value, half="value")
    if isinstance(value, FhirToken):
        # The system half is the author's literal and passes through; the code half is where
        # message data goes, so it is the half that screens.
        return f"{value.system}|{_screen(key, value.code, half='code half of the FhirToken')}"
    if isinstance(value, FhirRaw):
        return value.value
    raise ValueError(
        f"FHIR search parameter {key!r}: a search value must be a str (data), a "
        f"FhirToken(system, code), or a FhirRaw(...) author-syntax value -- got "
        f"{type(value).__name__}. A number is not a kind here: wrap it, str(value). "
        f"(The value is withheld: it may carry PHI.)"
    )


def resolve_search_pairs(params: FhirSearchParams) -> list[tuple[str, str]]:
    """Flatten ``params`` to the ``(key, value)`` pairs a URL encoder takes, screening as it goes.

    A ``list`` value becomes one pair per element (repeated parameters, which FHIR ANDs). Raises a
    PHI-safe :class:`ValueError` on a refused value; the caller turns that into its own error type
    (``FhirLookupError`` on the lookup path)."""
    pairs: list[tuple[str, str]] = []
    for key, value in params.items():
        for one in value if isinstance(value, list) else [value]:
            pairs.append((key, _resolve_one(key, one)))
    return pairs
