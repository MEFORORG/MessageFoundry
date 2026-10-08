# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
audit-retention requirement itself, not on chain-breakage. Tiers classified
`UNBOUNDED — honest gap` in §2 are absent for the same reason: this tuple describes windows that
EXIST, and inventing an entry for a tier nothing purges would be the false-coverage claim the whole
column was built to prevent.

**"Not on chain-breakage" is narrower than it used to read, and the narrowing is the point.** It
rules chain-breakage out as the REASON `audit_days` is reserved; it does not rule the effect out.
Measured 2026-09-03 (BACKLOG #1421): whether a delete breaks `verify_audit_chain` depends on WHICH
rows go, and an oldest-first window — the shape an age bound would use — does break it. So an
in-place age window is closed on its own terms, even though that is not why this key is reserved.
The reasoning is stated in ONE place, the `audit_days` row in `docs/CONFIGURATION.md`; read it there
rather than restating it here, because four copies of it are how the records drifted apart.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from messagefoundry.config.settings import ServiceSettings
    from messagefoundry.config.wiring import Registry


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
    #: The ``[security]`` field that ACKNOWLEDGES this tier as unbounded, or ``None``.
    #:
    #: Owner ruling R4 (b), 2026-09-24 (ASVS 14.2.7, BACKLOG #1967): each warn-only tier needs either
    #: a window or its own audited acknowledgement, and an enforcing instance with neither refuses to
    #: start. Per tier on purpose: one blanket switch would let an operator who meant to keep app logs
    #: also keep transform state without ever naming it. ``None`` on an auto-bounded tier (the body
    #: gate and ``allow_keeping_phi_indefinitely`` own those) and on a tier that can never read as
    #: unbounded (``zero_is_unbounded=False``), where a switch would be a knob that does nothing.
    acknowledged_by: str | None = None
    #: Why setting a WINDOW on this tier is not yet safe, printed with the refusal, or ``None``.
    #:
    #: Only transform state carries one. ``purge_state`` keys on ``set_at``, which no read refreshes,
    #: so a window deletes a correlation entry a Handler still reads. #1188 records that the tier
    #: needs a non-write-time eviction key before any bound is safe. An acknowledgement does not
    #: remove that need; it is the safe answer until the key exists, and the refusal says so.
    window_caveat: str | None = None

    @property
    def acknowledgement_setting(self) -> str | None:
        """:attr:`acknowledged_by` spelled as the operator writes it, or ``None``."""
        return f"[security].{self.acknowledged_by}" if self.acknowledged_by else None

    def is_acknowledged(self, security: object) -> bool:
        """Whether ``security`` (a loaded ``SecuritySettings``) sets this tier's switch. The ONE
        predicate the serve gate and ``security_loosenings()`` share, so the two read the switch the
        same way. They differ in scope on purpose: the posture report names a set switch whatever
        the window says, as it does for ``allow_keeping_phi_indefinitely``; the serve gate honours
        and audits it only for a tier that is actually unbounded."""
        return bool(self.acknowledged_by and getattr(security, self.acknowledged_by, False))


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
        acknowledged_by="allow_keeping_transform_state_indefinitely",
        window_caveat=(
            "a window on it deletes transform state by write time, so a Handler's correlation "
            "entry could vanish while still in use; until state has a non-write-time eviction key, "
            "the acknowledgement is the safe answer here, not a window"
        ),
    ),
    RetentionWindow(
        setting="[retention].search_preset_days",
        field="search_preset_days",
        reads_from="[retention]",
        level="PL-2",
        auto_bound_days=None,
        acknowledged_by="allow_keeping_search_presets_indefinitely",
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
        acknowledged_by="allow_keeping_app_logs_indefinitely",
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
    # (plausibly a DR requirement). So: classified, never auto-bounded (owner ruling, 2026-07-30), and
    # it only applies when `[backup].destination` is configured — with no destination there are no
    # archives to bound. The 2026-07-30 ruling also left it "never refused"; owner ruling R4 (b) of
    # 2026-09-24 covers EACH warn-only tier, so since BACKLOG #1967 that deliberate 0 needs its own
    # acknowledgement on an enforcing instance, like the three tiers above.
    # PL-1 the forwarder's on-disk spool (BACKLOG #1966, ADR 0200): redacted log text, best-effort
    # like the app log. Bounded by SIZE, not age, and `0` turns the spool OFF rather than unbounding
    # it, so it can never read as unbounded and carries no acknowledgement switch.
    RetentionWindow(
        setting="[logging].forward_spool_max_bytes",
        field="forward_spool_max_bytes",
        reads_from="[logging]",
        level="PL-1",
        auto_bound_days=None,
        zero_is_unbounded=False,
    ),
    RetentionWindow(
        setting="[backup].retention_keep",
        field="retention_keep",
        reads_from="[backup]",
        level="PL-1",
        auto_bound_days=None,
        requires_setting=("backup", "destination"),
        acknowledged_by="allow_keeping_backup_archives_indefinitely",
    ),
)

#: Floor for the derived list. `if not PHI_RETENTION_WINDOWS` is NOT sufficient: a bad merge dropping
#: most of the entries leaves a non-empty tuple, and a startup gate would then check two windows while
#: reporting success.
#:
#: TEN since BACKLOG #1966 added the forwarder spool. It was NINE, and that number was corrected by its own drift test rather than by counting. It was first
#: written as 7 — the count I derived by hand from the classification. The two-way equality against
#: docs/PHI.md §2 immediately reported `[backup].retention_keep` and
#: `[retention].connection_event_retention_hours` as documented-but-absent. That is precisely the
#: failure this floor exists to catch, caught in the constant it protects, before either had ever run.
MIN_PHI_RETENTION_WINDOWS: Final[int] = 10


def auto_bounded_windows() -> tuple[RetentionWindow, ...]:
    """The windows a PHI instance silently defaults to 30 days when they are UNSET."""
    return tuple(w for w in PHI_RETENTION_WINDOWS if w.auto_bound_days is not None)


def warn_only_windows() -> tuple[RetentionWindow, ...]:
    """The windows that are never silently bounded.

    Since BACKLOG #1967 "warn-only" names the auto-bound split, not the gate's whole behaviour: an
    enforcing instance refuses one that is unbounded unless its :attr:`RetentionWindow.acknowledged_by`
    switch is set, and warns only under ``enforcement = warn``.
    """
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


@dataclass(frozen=True, slots=True)
class RetentionGateLine:
    """One line the retention start gate writes before its verdict."""

    #: ``True`` for a WARNING-level ``AUDIT:`` log record. ``False`` for a stderr line, which
    #: already carries its ``info:`` or ``warning:`` prefix.
    audit: bool
    text: str


@dataclass(frozen=True, slots=True)
class RetentionGateOutcome:
    """What :func:`evaluate_retention_gate` decided, for its caller to emit."""

    #: The refusal, without the ``error:`` prefix, or ``None`` when the instance may start.
    refusal: str | None
    #: The lines the gate writes, in order. A refusal comes after all of them.
    lines: tuple[RetentionGateLine, ...]
    #: The windows that were unset and are now set to their default bound on the settings.
    defaulted: tuple[RetentionWindow, ...]


def _auto_bound_notice(defaulted: list[RetentionWindow], env_name: str) -> str:
    """The notice for the windows the gate just defaulted, naming the bound each one took.

    The bound is read from each window (vault BACKLOG #2369). While the windows share one bound
    the notice names it once, as it always has; if they come to differ, each window carries its
    own."""
    bounds = {w.auto_bound_days for w in defaulted}
    if len(bounds) == 1:
        named = f"{', '.join(w.setting for w in defaulted)} defaulted ON ({bounds.pop()} days)"
    else:
        named = (
            ", ".join(f"{w.setting} ({w.auto_bound_days} days)" for w in defaulted)
            + " defaulted ON"
        )
    return (
        f"info: {named} for a PHI instance ({env_name!r}) — these PHI tiers are now bounded at "
        "rest (secure-by-default, ASVS 14.2.7). Set an explicit window to override, or "
        f"{BODY_ACKNOWLEDGEMENT_SETTING}=true to retain indefinitely."
    )


def _outcome(
    refusal: str | None, lines: list[RetentionGateLine], defaulted: list[RetentionWindow]
) -> RetentionGateOutcome:
    """The gate's result so far. A ``refusal`` that is not ``None`` stops the start."""
    return RetentionGateOutcome(refusal=refusal, lines=tuple(lines), defaulted=tuple(defaulted))


def evaluate_retention_gate(
    settings: ServiceSettings, *, enforcing: bool, production: bool, env_name: str
) -> RetentionGateOutcome:
    """Decide the secure-by-default retention start gate (#186(a), ASVS 14.2.4/14.2.7).

    ``serve`` and ``messagefoundry check`` both call this, so on the same settings they reach the
    same verdict in the same words (vault BACKLOG #2280). It prints and logs nothing: the caller
    emits :attr:`RetentionGateOutcome.lines` and then the refusal.

    **It changes ``settings``.** Each auto-bounded window that is UNSET is set to its
    ``auto_bound_days``, unless ``[security].allow_keeping_phi_indefinitely`` is set. ``serve``
    relies on that: the same settings object later reaches the retention runner. A caller that
    must keep its settings as loaded passes a copy.

    ``RetentionSettings`` defaults every window to 0 (keep-forever) and the retention runner then
    purges nothing, so an instance would accumulate PHI bodies indefinitely. The refuse/warn
    split is ``[security].enforcement`` (``enforcing``), not the production tier, and no instance
    is exempt as synthetic or dev. ``production`` only words the lines.

    In order:

    1. A classification shorter than :data:`MIN_PHI_RETENTION_WINDOWS` refuses, on either dial.
    2. Each unset auto-bounded window takes its bound, with one ``info:`` notice. Only an UNSET
       window is defaulted (``model_fields_set``), so an explicit value, an explicit 0 included,
       is respected.
    3. An auto-bounded window that is still unbounded, which now means an explicit 0 or the
       acknowledgement: without the acknowledgement it refuses under ``enforce`` and warns under
       ``warn``; with it, under ``enforce``, it warns and writes an ``AUDIT:`` line.
    4. A warn-only tier that is unbounded with no acknowledgement of its own refuses under
       ``enforce`` and warns under ``warn`` (BACKLOG #1967, owner ruling R4 (b) of 2026-09-24).
       The body acknowledgement does not reach these tiers.
    5. Each acknowledged warn-only tier writes an ``AUDIT:`` line.

    A connection's own override is not read here. It is in the graph, and
    :func:`make_retention_override_guard` judges it."""
    # A FLOOR, not an emptiness check. `if not PHI_RETENTION_WINDOWS` passes for a one-element
    # tuple, so a bad merge dropping most entries would leave this gate checking one window while
    # reporting success.
    if len(PHI_RETENTION_WINDOWS) < MIN_PHI_RETENTION_WINDOWS:
        return RetentionGateOutcome(
            refusal=(
                f"the PHI retention classification has shrunk to "
                f"{len(PHI_RETENTION_WINDOWS)} windows (floor {MIN_PHI_RETENTION_WINDOWS}); refusing "
                "to start rather than gate on a partial classification. This is a build defect, not a "
                "configuration one — see messagefoundry/config/retention_classification.py."
            ),
            lines=(),
            defaulted=(),
        )

    lines: list[RetentionGateLine] = []
    prod = "production " if production else ""

    # AUTO-BOUND. Owner ruling 2026-07-30: the three PHI-BODY windows default to 30 days when
    # UNSET, on BOTH dials — previously this ran only when `not enforcing`, so on the shipped
    # `enforce` posture an unset window took the refusal below instead of a default.
    #
    # THE SAFETY TRADE IS DELIBERATE AND WORTH STATING: a production PHI instance with an unset
    # window used to REFUSE TO START, which forced an operator to choose a number. It now starts
    # with 30. What survives is the fail-closed path for an EXPLICIT 0 — choosing keep-forever is
    # still refused unless the audited opt-out is set. So "unbounded by accident" is still
    # prevented; "unbounded by inattention" becomes "30 days by inattention".
    #
    # The warn-only windows are NOT auto-bounded, and that is also a ruling rather than an
    # omission: `purge_state` keys on a timestamp that only moves on a WRITE, so silently bounding
    # it deletes live operational data a Handler is still reading. (`purge_search_presets` keys on
    # last use since #306; the 2026-07-30 ruling still covers it.) Since BACKLOG #1967 they are not
    # merely warned either: each needs a window or its own acknowledgement, below.
    defaulted: list[RetentionWindow] = []
    if not settings.retention.allow_unbounded_phi:
        defaulted = [
            w
            for w in auto_bounded_windows()
            if w.field not in getattr(settings, w.reads_from.strip("[]")).model_fields_set
        ]
        for window in defaulted:
            setattr(
                getattr(settings, window.reads_from.strip("[]")),
                window.field,
                window.auto_bound_days,
            )
        if defaulted:
            lines.append(RetentionGateLine(False, _auto_bound_notice(defaulted, env_name)))

    # REFUSE / WARN. `unbounded_windows` skips the tiers where 0 does not mean unbounded
    # (`connection_event_retention_hours` INHERITS the body window; `uploads_retention_days` has a
    # ge=1 floor so 0 is unrepresentable) and those whose `requires_setting` is unmet — with no
    # [logging].log_dir there is nothing for the app-log sweep to sweep.
    still_unbounded = unbounded_windows(settings)
    refusable = [w for w in still_unbounded if w.auto_bound_days is not None]
    warn_only = [w for w in still_unbounded if w.auto_bound_days is None]

    if refusable:
        windows_desc = ", ".join(w.setting for w in refusable)
        if not settings.retention.allow_unbounded_phi:
            if enforcing:
                return _outcome(
                    f"a data-retention window is explicitly disabled for {windows_desc} on "
                    f"a {prod}PHI instance ({env_name!r}); refusing "
                    "to start — PHI message bodies would be retained indefinitely (unbounded PHI "
                    "at rest, ASVS 14.2.4/14.2.7). Set the window(s) to a positive number of days "
                    "(e.g. 30); or, to deliberately retain forever, set "
                    f"{BODY_ACKNOWLEDGEMENT_SETTING}=true (audited).",
                    lines,
                    defaulted,
                )
            lines.append(
                RetentionGateLine(
                    False,
                    f"warning: no data-retention window is configured for {windows_desc} in a "
                    f"PHI-carrying environment ({env_name!r}) — PHI message bodies accumulate "
                    "without bound. Set the window(s) to bound PHI at rest (ASVS 14.2.4).",
                )
            )
        elif enforcing:
            # Explicit, audited override: unbounded PHI retention under strict enforcement.
            lines.append(
                RetentionGateLine(
                    True,
                    f"AUDIT: starting a {prod}PHI instance (environment {env_name!r}) with "
                    f"unbounded data retention ({BODY_ACKNOWLEDGEMENT_SETTING}=true; "
                    f"{windows_desc} = 0) — PHI message bodies are retained INDEFINITELY "
                    "(retention opt-out override).",
                )
            )
            lines.append(
                RetentionGateLine(
                    False,
                    f"warning: {BODY_ACKNOWLEDGEMENT_SETTING}=true — a "
                    f"{prod}PHI instance "
                    f"({env_name!r}) retains PHI message bodies indefinitely ({windows_desc} "
                    "unset). Configure a window to bound PHI at rest.",
                )
            )

    # BACKLOG #1967, owner ruling R4 (b) of 2026-09-24 (ASVS 14.2.7): each warn-only tier needs a
    # window OR its own acknowledgement. Under `enforce` a tier with neither REFUSES, naming the tier
    # and its switch; under `warn` it warns, the refuse/warn split every posture gate here shares.
    # An acknowledged tier starts and writes a WARNING-level AUDIT line naming it, in the shape of the
    # keyless-PHI second ack. `allow_unbounded_phi` does not reach these: it covers the auto-bounded
    # body tiers above, and one switch for every tier is what the ruling's "per-window" rules out.
    # Placed AFTER the body-window gate so an explicit body 0, the PL-1 core, is reported first.
    acknowledged = [w for w in warn_only if w.is_acknowledged(settings.security)]
    unacknowledged = [w for w in warn_only if w not in acknowledged]
    if unacknowledged:
        # Naming the tier AND its protection level is the point: an operator who sees "PL-1" knows a
        # full body is involved. Every warn-only tier that can read as unbounded has a switch, pinned
        # by a test; one without would still refuse, offering only the window.
        # A tier with a window caveat leads with its acknowledgement, because the window is the
        # remedy the caveat advises against (#1188); every other tier leads with the window.
        tiers = "; ".join(
            (
                f"{w.setting} ({w.level}): set {w.acknowledgement_setting}=true "
                f"rather than a window -- {w.window_caveat}"
            )
            if w.window_caveat and w.acknowledgement_setting
            else (
                f"{w.setting} ({w.level}): set a window"
                + (
                    f", or set {w.acknowledgement_setting}=true"
                    if w.acknowledgement_setting
                    else ""
                )
            )
            for w in unacknowledged
        )
        if enforcing:
            return _outcome(
                f"these classified PHI tiers have no retention window on a PHI instance "
                f"({env_name!r}) and would accumulate without bound; refusing to start, because each "
                f"needs a window or its own audited acknowledgement (ASVS 14.2.7): {tiers}.",
                lines,
                defaulted,
            )
        lines.append(
            RetentionGateLine(
                False,
                "warning: these classified PHI tiers have no retention window on a PHI instance "
                f"({env_name!r}) and will accumulate without bound. They are deliberately NOT "
                "defaulted (owner ruling 2026-07-30); under enforcement=enforce this refuses to "
                f"start: {tiers}.",
            )
        )
    lines.extend(
        RetentionGateLine(
            True,
            f"AUDIT: starting a {prod}PHI instance (environment {env_name!r}) with "
            f"{window.setting} ({window.level}) unbounded, permitted because "
            f"{window.acknowledgement_setting}=true -- that tier accumulates without bound "
            "(retention acknowledgement, ASVS 14.2.7).",
        )
        for window in acknowledged
    )
    return _outcome(None, lines, defaulted)


#: The switch that acknowledges a connection's own keep-forever override. The same switch covers the
#: global body windows; the ``serve`` gate for those spells it out in its own messages.
BODY_ACKNOWLEDGEMENT_SETTING: Final[str] = "[security].allow_keeping_phi_indefinitely"


def keep_forever_overrides(registry: Registry) -> tuple[str, ...]:
    """Each connection in ``registry`` whose own retention override keeps its PHI bodies forever.

    A connection may override either PL-1 body window (ADR 0027): an inbound sets ``messages_days``,
    an outbound sets ``dead_letter_days``. ``None`` inherits the global window and a positive number
    bounds it. ``0`` keeps that connection's bodies forever, whatever the global window says, so it
    is the same choice as a global ``0`` made for one connection. The global windows live in the
    service settings, where :func:`unbounded_windows` reads them; these live in the graph, so the
    start gate cannot see them and a registry guard must (vault BACKLOG #2368).

    The test is ``<= 0``, as the purge reads it: the factories refuse a negative override, but a
    registry built without them would keep those bodies forever too.

    Each entry reads ``inbound 'NAME' (messages_days = 0)``, sorted, inbounds first."""
    inbound = sorted(
        (c.name, c.messages_days)
        for c in registry.inbound.values()
        if c.messages_days is not None and c.messages_days <= 0
    )
    outbound = sorted(
        (c.name, c.dead_letter_days)
        for c in registry.outbound.values()
        if c.dead_letter_days is not None and c.dead_letter_days <= 0
    )
    return tuple(
        [f"inbound {name!r} (messages_days = {days})" for name, days in inbound]
        + [f"outbound {name!r} (dead_letter_days = {days})" for name, days in outbound]
    )


def keep_forever_override_refusal(kept: tuple[str, ...], *, env_name: str | None) -> str:
    """The refusal text for ``kept``, the non-empty result of :func:`keep_forever_overrides`.

    Shared by the registry guard and ``connection upsert``, so an edit is refused in the words a
    reload would use. ``env_name`` is ``None`` where no environment is active."""
    where = f" ({env_name!r})" if env_name is not None else ""
    # Only the auto-bounded windows lose a default. Naming them keeps an operator from setting a
    # window on a tier where a window is the wrong answer, such as transform state.
    auto_bounded = ", ".join(w.setting for w in auto_bounded_windows())
    return (
        "a per-connection retention override keeps PHI message bodies indefinitely on a PHI "
        f"instance{where}: {'; '.join(kept)} (unbounded PHI at rest, ASVS 14.2.4/14.2.7). Set "
        "each override to a positive number of days, or remove it to inherit the global "
        f"window; or, to deliberately retain forever, set {BODY_ACKNOWLEDGEMENT_SETTING}=true "
        "(audited). That switch covers the whole instance: it also turns off the default bound "
        f"on each of these windows that is unset: {auto_bounded}. Set each of them to an "
        "explicit number of days first"
    )


@dataclass(frozen=True, slots=True)
class OverrideVerdict:
    """What :func:`judge_keep_forever_overrides` decided about one graph."""

    #: :func:`keep_forever_overrides` for the graph. Empty when no override keeps bodies forever.
    kept: tuple[str, ...]
    #: Why an enforcing instance refuses the graph, or ``None`` when it does not.
    refusal: str | None
    #: The line a graph load reports and still passes the graph: the ``AUDIT:`` line once
    #: acknowledged, or the same reason as a warning under ``enforcement = warn``. Else ``None``.
    report: str | None


def judge_keep_forever_overrides(
    registry: Registry, *, acknowledged: bool, enforcing: bool, env_name: str | None
) -> OverrideVerdict:
    """Decide a graph's keep-forever overrides: refuse, report, or neither.

    The one decision behind :func:`make_retention_override_guard`, ``messagefoundry check`` and
    the ``supervise`` pre-check (vault BACKLOG #2368), so those three reach the same verdict in
    the same words for the same registry and switches. It prints and logs nothing.

    ``acknowledged`` is the loaded ``[security].allow_keeping_phi_indefinitely``. With it the
    graph passes and :attr:`OverrideVerdict.report` is the ``AUDIT:`` line, on either dial.
    Without it an enforcing instance refuses, and under ``enforcement = warn`` the reason is
    reported instead."""
    kept = keep_forever_overrides(registry)
    if not kept:
        return OverrideVerdict(kept=kept, refusal=None, report=None)
    if acknowledged:
        return OverrideVerdict(
            kept=kept,
            refusal=None,
            report=(
                f"AUDIT: the retention gate on a PHI instance (environment {env_name!r}) passed a "
                "graph with per-connection unbounded data retention "
                f"({BODY_ACKNOWLEDGEMENT_SETTING}=true; {'; '.join(kept)}) -- once that graph is "
                "live, these connections' PHI message bodies are retained INDEFINITELY (retention "
                "opt-out override)."
            ),
        )
    reason = keep_forever_override_refusal(kept, env_name=env_name)
    if enforcing:
        return OverrideVerdict(kept=kept, refusal=reason, report=None)
    return OverrideVerdict(kept=kept, refusal=None, report=reason)


def make_retention_override_guard(
    *, acknowledged: bool, enforcing: bool, env_name: str, log: logging.Logger
) -> Callable[[Registry], None]:
    """The engine registry guard for a connection's own keep-forever retention override.

    The graph half of the body-window gate in ``serve``, with the same refuse-or-warn split.
    Without the acknowledgement (``acknowledged``, the loaded
    ``[security].allow_keeping_phi_indefinitely``) an enforcing instance refuses the graph by
    raising ``WiringError``: a first load fails the start, and a ``/config/reload`` is refused with
    the running graph kept. Without it under ``enforcement = warn``, the guard warns. With the
    acknowledgement the guard passes the graph and a WARNING-level ``AUDIT:`` line names each
    connection, on either dial.

    It is not a copy of the body-window gate. At least this differs: that gate writes its AUDIT
    line only under ``enforce``, and this guard writes one on either dial.

    It runs only where the engine calls its registry guard. At least these do not call it:
    ``Engine.add_registry`` called by an embedder, and the DR re-apply path.
    ``messagefoundry check`` and ``supervise`` do not call it either. Each reads the decision it
    makes, :func:`judge_keep_forever_overrides`, and reports a refusal in its own way; neither
    writes the AUDIT line.

    The AUDIT line is written each time the guard passes such a graph. That includes a dry-run
    reload, and a reload a later check then refuses, so the line says the gate passed the graph and
    never that the graph went live.

    The AUDIT line and the warning go to the logger AND to stderr. A
    ``[logging].level`` above WARNING would otherwise drop the only record of an acknowledged
    override. Under NSSM both streams are captured, so a line can appear in both.

    Like the static-credential guard, it judges every graph against the settings the process started
    with: a reload re-reads the graph and never ``[security]``."""

    def guard(registry: Registry) -> None:
        verdict = judge_keep_forever_overrides(
            registry, acknowledged=acknowledged, enforcing=enforcing, env_name=env_name
        )
        if verdict.report is not None:
            log.warning("%s", verdict.report)
            print(f"warning: {verdict.report}", file=sys.stderr)
        if verdict.refusal is not None:
            # Imported here: wiring is the heavy end of the config package, and this module is
            # otherwise a leaf the settings model can read.
            from messagefoundry.config.wiring import WiringError

            raise WiringError(verdict.refusal)

    return guard
