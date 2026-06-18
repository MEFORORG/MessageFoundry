# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Parallel-run reconciliation harness — compare MessageFoundry's output against Corepoint's.

During the migration's shadow phase, the same inbound message is processed by both engines; this package
compares the two outputs per connection so real discrepancies surface while engine-non-deterministic
differences (stamped timestamps, regenerated control ids, live db_lookup results, non-semantic ordering)
are normalized away. See ``docs``/``migration-local`` TEST-ENVIRONMENT-PLAN.md §5.

The comparison core (:mod:`harness.reconcile.normalize`) is pure + offline (stdlib + the read-only
``messagefoundry.parsing`` library). The capture/correlate plumbing (MLLP sinks, per-connection matching)
builds on top of it.
"""

from __future__ import annotations

from harness.reconcile.compare import (
    DEFAULT_KEY,
    MessagePair,
    ReconcileResult,
    field_value,
    load_messages,
    reconcile,
)
from harness.reconcile.normalize import (
    DEFAULT_BLANK_FIELDS,
    Difference,
    NormalizeRules,
    Separators,
    diff,
    normalize,
)

__all__ = [
    # normalize core
    "Separators",
    "NormalizeRules",
    "Difference",
    "DEFAULT_BLANK_FIELDS",
    "normalize",
    "diff",
    # per-connection compare orchestration
    "DEFAULT_KEY",
    "MessagePair",
    "ReconcileResult",
    "field_value",
    "load_messages",
    "reconcile",
]
