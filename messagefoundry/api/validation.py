# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Input-validation rules for the operator API's control-plane data items (BACKLOG #1108).

**This module is the single authority for the rules; the prose lives in
[`docs/API-INPUT-VALIDATION.md`](../../docs/API-INPUT-VALIDATION.md).** The document explains each
rule and why it is drawn where it is; every pattern and ceiling it quotes is defined here and
pinned by ``tests/test_api_input_validation.py``, so the two cannot drift.

Scope is the **control plane** -- the ids, connection names, time bounds and search terms an
operator sends to the engine's own API. The **data plane** (the HL7, X12, DICOM and other payloads
the engine carries) is a separate surface with its own rules; see ``docs/HL7-VALIDATION.md`` and
``docs/CODESETS.md``. Nothing here applies to a message body.

**Why a rule and not just a length.** Before this module the API's request bodies carried length and
numeric bounds only -- an AST walk over ``api/models.py`` and ``api/auth_models.py`` found zero
``pattern=`` constraints between them. A length bound says how much of something may arrive; it does
not say what the something is. ASVS 2.1.1 asks for the second.

**Anchoring, and the trap in it.** Pydantic 2.13 compiles ``pattern=`` with the Rust ``regex`` crate,
not Python's ``re``. Two consequences, both measured, both load-bearing:

* ``$`` there means end-of-input. It does **not** admit a trailing newline the way Python's ``re``
  does, so ``^...$`` is a true full match and no ``\\Z`` is needed.
* ``\\Z`` is **not** a recognized escape in that engine. A pattern carrying one raises
  ``SchemaError`` at class-construction time -- an import-time crash, not a validation failure.

So do not copy a pattern from here into a :mod:`re` call without re-anchoring it (Python's ``$``
would then let a trailing newline through), and do not copy the ``\\Z`` from
:data:`messagefoundry.uploads._FILE_ID_RE` into a pydantic ``pattern=``.

Import weight is a constraint, not an accident: ``api/models.py`` is imported by the engine-free
``apiclient`` (ADR 0088) and through it by the PySide6 harness, so this module depends on nothing
but pydantic and the standard library.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field, StringConstraints

# --- Engine-minted resource ids ------------------------------------------------------------------
#
# Every id the operator API accepts on a path is minted by the engine and handed to the client in an
# earlier response. No person types one. Two shapes cover all of them:
#
#   * 32 lowercase hex -- ``uuid4().hex`` (message, outbox, approval, user, preset) and
#     ``secrets.token_hex(16)`` (upload file id).
#   * 64 lowercase hex -- a SHA-256 digest (session id, which is the opaque token's hash; attachment
#     id, which is the content digest).
#
# The rule earns its place twice over. It refuses a structurally impossible id **before** the value
# reaches a store query or a filesystem join, and it is what makes the by-id upload routes
# non-enumerable claim hold: no ``.``, ``/``, ``\\`` or NUL can survive it.
# ``messagefoundry.uploads._FILE_ID_RE`` already shipped exactly this rule for one id; this
# generalizes it rather than adding a second, differently-spelled copy.

#: 32 lowercase hex characters -- what ``uuid4().hex`` and ``secrets.token_hex(16)`` mint.
RESOURCE_ID_PATTERN = r"^[0-9a-f]{32}$"

#: 64 lowercase hex characters -- a SHA-256 hex digest.
DIGEST_ID_PATTERN = r"^[0-9a-f]{64}$"

#: A custom role id: the ``custom:`` prefix ``messagefoundry.auth.permissions`` defines, then 32 hex.
#: Built-in role ids are words and are never accepted by the ``/roles/custom`` routes.
CUSTOM_ROLE_ID_PATTERN = r"^custom:[0-9a-f]{32}$"

ResourceId = Annotated[str, StringConstraints(pattern=RESOURCE_ID_PATTERN)]
DigestId = Annotated[str, StringConstraints(pattern=DIGEST_ID_PATTERN)]
CustomRoleId = Annotated[str, StringConstraints(pattern=CUSTOM_ROLE_ID_PATTERN)]


# --- Connection names ----------------------------------------------------------------------------
#
# A connection name is operator-chosen, authored code-first or in ``connections.toml``, and reaches
# the API both as a path segment (``/connections/{name}/...``) and as a filter value (``channel_id``,
# ``destination_name``, ``to``, ``source``).
#
# The rule admits a leading letter, then letters, digits, underscore and hyphen, to 256 characters.
# It is deliberately WIDER than the grammar the VS Code extension already enforces at
# ``ide/src/connectionWizardModel.ts`` (``^[A-Za-z][A-Za-z0-9_]*$``, no hyphen). Measured over the
# 108 distinct connection names in ``samples/``, ``harness/``, ``tests/`` and ``messagefoundry/``,
# four fail the IDE's rule and all four fail it on a hyphen (``FILE-OUT_ACME_ADT``,
# ``FILE-OUT_Coverage``, ``FILE-OUT_EXAMPLE_ADT``, ``FILE-OUT_Test_ADT``). Adopting the narrower
# grammar here would make four shipped connections unreachable through the API. All 108 pass the
# rule below.
#
# What it excludes is what earns it: ``.``, ``/`` and ``\\`` (so a name can never read as a path or a
# traversal), whitespace and control characters (so a name cannot forge a log line or a CSV field),
# and the quoting and metacharacters ``%``, ``|``, ``&``, ``'``, ``"`` (so a name carries nothing
# into a URL or a downstream query). The 256 ceiling is the bound ``channel_id`` and
# ``destination_name`` already shipped, reused rather than replaced.

#: A connection name: a leading letter, then letters, digits, ``_`` and ``-``, at most 256 characters.
CONNECTION_NAME_PATTERN = r"^[A-Za-z][A-Za-z0-9_-]{0,255}$"

ConnectionName = Annotated[str, StringConstraints(pattern=CONNECTION_NAME_PATTERN)]


# --- Time ranges ---------------------------------------------------------------------------------
#
# The API's time bounds (``received_from``/``received_to``, ``since``/``until``) are epoch seconds as
# a float, and they reach a store bind.
#
# Two things were missing and both are demonstrable against the shipped code. ``ge=0`` alone does not
# exclude infinity: ``?received_from=inf`` parses to ``float('inf')`` and is accepted. The audit
# routes declare no bound at all, so ``?since=nan`` and ``?since=-inf`` are accepted there too. A
# NaN bound is the worse of the two, because every comparison against it is false, so the filter
# silently returns nothing rather than failing.
#
# The rule is: a finite float, at or after the epoch, at or before 2100-01-01T00:00:00Z. The upper
# ceiling is a sanity bound, not a business one -- it exists so an absurd or overflowed value is
# refused at the edge instead of reaching a query.

#: 2100-01-01T00:00:00Z. The far end of any timestamp this engine will legitimately be asked about.
EPOCH_SECONDS_MAX = 4_102_444_800.0

EpochSeconds = Annotated[float, Field(ge=0.0, le=EPOCH_SECONDS_MAX, allow_inf_nan=False)]


# --- Free-text search terms and metadata filters --------------------------------------------------
#
# ``content`` and ``field_value`` are whatever an operator typed to find a patient, so they are
# PHI-shaped and no alphabet rule can be written for them -- a patient name is any text. What CAN be
# ruled out is a control character. These values reach the search audit record, the application log
# and, through ``/audit/export``, a CSV file; a NUL, CR or LF in one of them forges a second record
# in whichever of those reads a line at a time.
#
# So the rule for free text is: printable, no C0 controls, no DEL, no C1 controls. It is as narrow as
# the data allows and no narrower. It does cost one capability, stated rather than hidden: a needle
# can no longer span an HL7 segment separator, because that separator is CR. The console's search box
# is a single-line input, so nothing today could send one.
#
# The metadata filters divide by what their values actually are. ``status`` is drawn from a closed
# vocabulary the store defines (``MessageStatus``/``OutboxStatus``), all of whose members are letters
# and underscores. ``message_type`` is an HL7 message type such as ``ADT^A01``, so it keeps ``^`` and
# takes the printable rule. ``control_id`` is MSH-10, which a sending system chooses, so it takes the
# printable rule too.
#
# ``field_path`` is NOT here on purpose. Its grammar already ships, in
# ``messagefoundry.parsing.peek.parse_path``, and ``messagefoundry.store.content_search.make_spec``
# already applies it eagerly at all six of its acceptance points in ``api/app.py``, so a malformed
# path is already a 4xx. A copy here would be a second definition of a rule that has one.

#: Printable text: no C0 control, no DEL, no C1 control. One or more characters.
PRINTABLE_TEXT_PATTERN = r"^[^\x00-\x1f\x7f-\x9f]+$"

#: A member of one of the engine's own closed vocabularies -- ``MessageStatus``, ``OutboxStatus``,
#: the connection-event kinds. Every member of all three is letters and underscores only. The
#: vocabulary itself stays the store's to define; this is the shape a member can have.
#:
#: Named "member" and not "token" because bandit's B105 heuristic reads a constant whose name carries
#: "token" and whose value is a string literal as a hardcoded credential. A suppression here would be
#: one more thing a reviewer has to re-derive; the clearer name costs nothing.
VOCABULARY_MEMBER_PATTERN = r"^[A-Za-z_]{1,64}$"

#: The most event kinds one ``/events`` request may filter on. The vocabulary is smaller than this.
MAX_EVENT_KINDS = 32

#: Ceiling for a PHI-shaped free-text needle. The bound ``content``/``field_value`` already shipped.
SEARCH_TEXT_MAX = 512

SearchText = Annotated[
    str, StringConstraints(pattern=PRINTABLE_TEXT_PATTERN, max_length=SEARCH_TEXT_MAX)
]
VocabularyMember = Annotated[str, StringConstraints(pattern=VOCABULARY_MEMBER_PATTERN)]

#: A message/outbox status filter, and a connection-event kind. Both are vocabulary members; they are
#: named separately so a reader looking for the field finds the rule that governs it.
StatusFilter = VocabularyMember
EventKindFilter = VocabularyMember
MessageTypeFilter = Annotated[str, StringConstraints(pattern=PRINTABLE_TEXT_PATTERN, max_length=64)]
ControlIdFilter = Annotated[str, StringConstraints(pattern=PRINTABLE_TEXT_PATTERN, max_length=256)]

#: An audit ``actor`` (a username) or ``action`` (an event name). Printable, bounded as they ship.
ActorFilter = Annotated[str, StringConstraints(pattern=PRINTABLE_TEXT_PATTERN, max_length=256)]
ActionFilter = Annotated[str, StringConstraints(pattern=PRINTABLE_TEXT_PATTERN, max_length=128)]

#: An operator-chosen display label, such as a saved preset's name. Printable, bounded as it ships.
DisplayLabel = Annotated[str, StringConstraints(pattern=PRINTABLE_TEXT_PATTERN, max_length=128)]

#: A client-minted idempotency token. The client chooses the alphabet, so the rule is the printable
#: one: the value reaches a store uniqueness check and an audit record, and nothing else reads it.
IdempotencyKey = Annotated[str, StringConstraints(pattern=PRINTABLE_TEXT_PATTERN, max_length=256)]


# --- Values whose real control is elsewhere -------------------------------------------------------
#
# Two items on this surface already have an enforced rule that is not, and should not be, a pattern.
# The rule below is a shape gate in front of it, not a replacement for it, and saying which is which
# is the point: a compensating control that quietly stood in for the real one would be worse than no
# control at all.
#
#   * A reload ``config_dir`` (and a DR ``archive``) is a filesystem path. The real control is the
#     allow-list confinement -- the loader executes Python from that directory, and only an allowed
#     reload root is accepted. What the shape gate adds is the NUL, which a path check can be
#     truncated by, and the other control characters.
#   * A log ``level`` is checked against ``messagefoundry.logging_setup.LOG_LEVELS``, which raises so
#     the route can 4xx. The shape gate keeps an arbitrary-length string out of that error message.

#: A filesystem path supplied by an operator. Printable, and bounded where its field already bounds it.
FilesystemPath = Annotated[str, StringConstraints(pattern=PRINTABLE_TEXT_PATTERN, max_length=4096)]

#: A log level name. The authority is ``logging_setup.LOG_LEVELS``; this only fixes the shape.
LogLevelName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z]{1,16}$")]

#: An email address, for the one field that accepts one (the alert test-send override).
#:
#: This is a DELIVERABILITY-shaped rule, not a proof of validity: one ``@``, a non-empty local part
#: with no whitespace or control characters, and a dotted domain of letters, digits and hyphens. It
#: is intentionally not RFC 5322 -- that grammar admits quoted local parts and comments that no mail
#: path here would benefit from, and a regex claiming to implement it would be the false-premise
#: control this module is trying to avoid. 254 is the RFC 5321 maximum forward-path length.
EMAIL_ADDRESS_PATTERN = r"^[^\s@\x00-\x1f\x7f-\x9f]+@[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$"

EmailAddress = Annotated[str, StringConstraints(pattern=EMAIL_ADDRESS_PATTERN, max_length=254)]


# --- Bounded id collections ----------------------------------------------------------------------
#
# ``/messages/export`` takes an explicit ``ids`` selection beside its search criteria. The route caps
# how many rows it will return, so the list of ids it will consider is capped to match: an unbounded
# list is a request the engine sizes from the client's side of the wire.

#: The most explicitly-selected message ids one export may name -- the route's own ``limit`` ceiling.
MAX_EXPORT_IDS = 100_000

#: ``GET /search/layered`` takes preset ids as one comma-separated value. The route caps the layers
#: it will compose; the pattern makes a non-id impossible before the split.
LAYERED_PRESET_IDS_PATTERN = r"^[0-9a-f]{32}(,[0-9a-f]{32})*$"

LayeredPresetIds = Annotated[str, StringConstraints(pattern=LAYERED_PRESET_IDS_PATTERN)]
