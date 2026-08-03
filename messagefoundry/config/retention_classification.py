# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The PHI retention classification the startup gate is generated from (ASVS 14.2.7).

**Why a constant rather than a hand-typed tuple in `__main__.py`.** This cell broke once because a new
PHI tier landed and nobody widened a literal in the serve gate. A wider literal with no binding to the
classification is the same defect with more characters. So the gate's tier list is built from
:data:`PHI_RETENTION_WINDOWS`, and `tests/test_retention_classification_drift.py` asserts — in BOTH
directions — that this tuple and `docs/PHI.md` §2's Retention column describe the same set. Add a PHI
tier to the doc without adding it here, or here without the doc, and the suite reds.

**Why the doc is the co-authority and not just prose.** `docs/PHI.md` is git-TRACKED, so a
PHI.md-anchored test actually runs in CI. (`docs/security/` is git-ignored and its doc-anchored tests
take module-level skips — a distinction that has already produced one guard which red locally and
passed in CI.) That single fact is what makes the two-way equality real rather than decorative.

**What is deliberately NOT here.** `[retention].audit_days` is reserved and unenforced by design —
there is no `purge_audit*` on the Store protocol, and the keep-forever rationale rests on the
audit-retention requirement itself (see `docs/PHI.md` §8), not on chain-breakage. Tiers classified
`UNBOUNDED — honest gap` in §2 are absent for the same reason: this tuple describes windows that
EXIST, and inventing an entry for a tier nothing purges would be the false-coverage claim the whole
column was built to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class RetentionWindow:
    """One classified PHI tier and the window that bounds it."""

    #: The operator-facing setting, spelled exactly as it appears in config and in PHI.md §2.
    setting: str
    #: The attribute the serve gate reads.
    field: str
    #: The `[section]` whose settings model actually HOLDS :attr:`field`. Usually the same section as
    #: :attr:`setting` — but not always, and the exception is load-bearing: ADR 0118 moved the
    #: message-body window to the operator-facing `[security].delete_message_bodies_after_days` while
    #: the gate still reads `retention.messages_days` after desugaring. Modelling the two separately is
    #: what lets a test resolve every field against its real model instead of exempting the ones that
    #: do not fit — and an exemption is how a field name silently stops being checked.
    reads_from: str
    #: Protection level from PHI.md §2 — PL-1 (body) or PL-2 (identifier/fragment).
    level: str
    #: Auto-bound to this many days when UNSET on a PHI instance, or ``None`` to leave it alone.
    #:
    #: ``None`` is a deliberate per-window judgement, NOT an oversight. Auto-bounding a window whose
    #: timestamp only moves on a WRITE silently deletes live operational data: `state.set_at` is never
    #: refreshed by `state_get`, so a Handler's MRN→surrogate crosswalk would vanish mid-stream and the
    #: next message would transform WRONGLY, post-ACK, with no ERROR disposition. `search_presets` is
    #: the same shape and `retention.py` forbids exactly that inheritance in prose. These are
    #: classified and WARNED, never silently bounded (owner ruling, 2026-07-30).
    auto_bound_days: int | None
    #: Another setting whose presence this window depends on; the gate skips it when unset.
    requires_setting: tuple[str, str] | None = None
    #: Whether ``0`` on this window actually means UNBOUNDED. Not universal, and the exceptions are
    #: exactly the ones a `days <= 0` predicate would get wrong:
    #:
    #: * ``[retention].connection_event_retention_hours`` — ``0`` means **INHERIT** the message-body
    #:   window, so an unset value is already bounded transitively. Flagging it would refuse or warn
    #:   over a window that is doing its job.
    #: * ``[store].uploads_retention_days`` — carries a ``ge=1`` floor, so ``0`` is unrepresentable and
    #:   the clause would be unfireable by construction. Kept classified, never tested.
    zero_is_unbounded: bool = True


#: Every PL-1/PL-2 tier that HAS a window, keyed to the classification in `docs/PHI.md` §2.
#:
#: Ordered as §2 orders them, so a reviewer can read the two side by side.
PHI_RETENTION_WINDOWS: Final[tuple[RetentionWindow, ...]] = (
    # PL-1 message bodies — the packet's core intent, and the two the gate already refused on.
    RetentionWindow(
        setting="[security].delete_message_bodies_after_days",
        field="messages_days",
        reads_from="[retention]",
        level="PL-1",
        auto_bound_days=30,
    ),
    RetentionWindow(
        setting="[retention].dead_letter_days",
        field="dead_letter_days",
        reads_from="[retention]",
        level="PL-1",
        auto_bound_days=30,
    ),
    # PL-2 orphaned reference snapshots (ADR 0006). ORPHAN-ONLY: a still-declared set is never purged
    # whatever its age, so this window does NOT bound `reference.value` in general — §2 says so, and a
    # plain "rides"/window claim there would be false.
    RetentionWindow(
        setting="[retention].reference_snapshot_days",
        field="reference_snapshot_days",
        reads_from="[retention]",
        level="PL-2",
        auto_bound_days=30,
    ),
    # --- classified and WARNED, never auto-bounded (see auto_bound_days above) ---------------------
    RetentionWindow(
        setting="[retention].state_max_age_days",
        field="state_max_age_days",
        reads_from="[retention]",
        level="PL-2",
        auto_bound_days=None,
    ),
    RetentionWindow(
        setting="[retention].search_preset_days",
        field="search_preset_days",
        reads_from="[retention]",
        level="PL-2",
        auto_bound_days=None,
    ),
    # PL-1 only because redaction is best-effort — a lone identifier can survive it. Gated on a
    # log_dir: with none configured the sweep has nothing to sweep, so refusing over it would refuse
    # over a knob that cannot do anything.
    RetentionWindow(
        setting="[retention].app_log_days",
        field="app_log_days",
        reads_from="[retention]",
        level="PL-1",
        auto_bound_days=None,
        requires_setting=("logging", "log_dir"),
    ),
    # PL-1 operator-uploaded diagnostic files. Already defaults to 30 with a `ge=1` floor, so it can
    # never appear unbounded — kept here so the generated list matches §2 rather than quietly omitting
    # a classified tier because it happens to be safe today.
    RetentionWindow(
        setting="[store].uploads_retention_days",
        field="uploads_retention_days",
        reads_from="[store]",
        level="PL-1",
        auto_bound_days=None,
        zero_is_unbounded=False,
    ),
    # PL-2 `connection_event.reason`. NOT a refuse/auto-bound candidate, and the reason is a genuine
    # trap: here `0` means INHERIT the message-body window, not keep-forever (settings.py, and
    # retention.py resolves it that way). So an unset value is already bounded transitively, and a
    # `days <= 0` predicate would refuse a start over a window that is doing its job.
    RetentionWindow(
        setting="[retention].connection_event_retention_hours",
        field="connection_event_retention_hours",
        reads_from="[retention]",
        level="PL-2",
        auto_bound_days=None,
        zero_is_unbounded=False,
    ),
    # PL-1 `.mfbak` archives, which on SQLite carry FULL inbound+outbound bodies. The odd one out: it
    # is bounded by a COUNT (keep-N), not an age window, and its default of 7 already bounds it — the
    # only way to reach unbounded is an operator explicitly typing 0, which is a deliberate choice
    # (plausibly a DR requirement). So: classified and warned, never auto-bounded and never refused,
    # and it only applies when `[backup].destination` is configured — with no destination there are no
    # archives to bound. Owner ruling, 2026-07-30.
    RetentionWindow(
        setting="[backup].retention_keep",
        field="retention_keep",
        reads_from="[backup]",
        level="PL-1",
        auto_bound_days=None,
        requires_setting=("backup", "destination"),
    ),
)

#: Floor for the derived list. `if not PHI_RETENTION_WINDOWS` is NOT sufficient: a bad merge dropping
#: most of the entries leaves a non-empty tuple, and a startup gate would then check two windows while
#: reporting success.
#:
#: NINE, and the number was corrected by its own drift test rather than by counting. It was first
#: written as 7 — the count I derived by hand from the classification. The two-way equality against
#: docs/PHI.md §2 immediately reported `[backup].retention_keep` and
#: `[retention].connection_event_retention_hours` as documented-but-absent. That is precisely the
#: failure this floor exists to catch, caught in the constant it protects, before either had ever run.
MIN_PHI_RETENTION_WINDOWS: Final[int] = 9


def auto_bounded_windows() -> tuple[RetentionWindow, ...]:
    """The windows a PHI instance silently defaults to 30 days when they are UNSET."""
    return tuple(w for w in PHI_RETENTION_WINDOWS if w.auto_bound_days is not None)


def warn_only_windows() -> tuple[RetentionWindow, ...]:
    """The windows that are classified and WARNED but never silently bounded."""
    return tuple(w for w in PHI_RETENTION_WINDOWS if w.auto_bound_days is None)


def unbounded_windows(read: object) -> tuple[RetentionWindow, ...]:
    """Windows whose configured value is genuinely unbounded on ``read`` (a loaded ``Settings``).

    Skips windows where ``0`` does not mean unbounded, and windows whose ``requires_setting``
    dependency is unmet — with no ``[logging].log_dir`` there is nothing for the app-log sweep to
    sweep, so refusing or warning over it would fire on a knob that cannot act.
    """
    out: list[RetentionWindow] = []
    for window in PHI_RETENTION_WINDOWS:
        if not window.zero_is_unbounded:
            continue
        if window.requires_setting is not None:
            section, dep = window.requires_setting
            if not getattr(getattr(read, section, None), dep, None):
                continue
        section_obj = getattr(read, window.reads_from.strip("[]"), None)
        value = getattr(section_obj, window.field, None)
        if isinstance(value, int) and value <= 0:
            out.append(window)
    return tuple(out)
