# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""HL7 v2 parsing & validation.

Two-tier strategy (see docs/ARCHITECTURE.md):

* **Tolerant tier** — :class:`~messagefoundry.parsing.peek.Peek` (``python-hl7``) parses
  any reasonably-formed message and lets us *peek* at fields (e.g. MSH-9 trigger) for
  routing without choking on conformance issues. This is the hot path; every message
  goes through it.
* **Strict tier** — :func:`~messagefoundry.parsing.validate.validate` (``hl7apy``) runs
  version-aware, structure-based validation only when a channel asks for it
  (``validation.strict = true``). Slower and stricter, so it is opt-in and off the hot
  path.
"""

from __future__ import annotations

from messagefoundry.parsing.binary import (
    BinaryCarriageError,
    embed_obx_document,
    extract_obx_document,
)
from messagefoundry.parsing.groups import SegmentGroup
from messagefoundry.parsing.message import Message, RawMessage
from messagefoundry.parsing.peek import HL7PeekError, Peek, normalize, parse_path
from messagefoundry.parsing.split import split_batch, split_by_obr
from messagefoundry.parsing.summary import summarize
from messagefoundry.parsing.tree import TreeNode, parse_tree
from messagefoundry.parsing.validate import ValidationResult, validate
from messagefoundry.parsing.dicom import DicomDataset, DicomPeek, DicomPeekError
from messagefoundry.parsing.fhir import FhirPeek, FhirPeekError, FhirResource
from messagefoundry.parsing.x12 import (
    X12FrameReader,
    X12Group,
    X12Message,
    X12Peek,
    X12PeekError,
)

__all__ = [
    "Peek",
    "Message",
    "RawMessage",
    "SegmentGroup",
    "HL7PeekError",
    "normalize",
    "parse_path",
    "parse_tree",
    "TreeNode",
    "validate",
    "ValidationResult",
    "summarize",
    "split_batch",
    "split_by_obr",
    # X12 EDI codec (ADR 0012) — full surface under messagefoundry.parsing.x12.
    "X12Peek",
    "X12Group",
    "X12Message",
    "X12FrameReader",
    "X12PeekError",
    # FHIR codec (ADR 0022) — headline types; full surface under messagefoundry.parsing.fhir.
    "FhirPeek",
    "FhirResource",
    "FhirPeekError",
    # DICOM codec (ADR 0025) — headline types; full surface (SrMeasurement, hl7_map helpers,
    # DicomError) under messagefoundry.parsing.dicom.
    "DicomPeek",
    "DicomDataset",
    "DicomPeekError",
    # Binary carriage codec (ADR 0028) — the mfb64:v1: substrate marker (use it via
    # RawMessage.from_bytes/.raw_bytes) + OBX-5 ED embed/extract; full surface under
    # messagefoundry.parsing.binary.
    "BinaryCarriageError",
    "embed_obx_document",
    "extract_obx_document",
]

# Defense-in-depth for review finding C-1: python-hl7 logs raw field values at ERROR on
# benign-but-unmapped escape sequences (hl7/util.py unescape), a PHI leak hit on every message via
# summarize(). Silence its loggers the moment the parsing layer — the only thing that triggers
# unescape — is imported, so CLI/embedded paths that never call configure_logging() are covered too.
# Idempotent; configure_logging() also calls it for the serve path.
from messagefoundry.logging_setup import silence_phi_prone_dependency_loggers as _silence_hl7

_silence_hl7()
