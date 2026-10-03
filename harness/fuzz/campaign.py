# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Run a fuzz campaign in batches, check the invariants after each, and keep what failed.

A campaign sends ``iterations`` cases, ``batch`` at a time, and stops early at the ``seconds``
budget (checked before every case) or at the first batch that breaks an invariant. A failing case's
exact bytes are written to ``out_dir`` (a fresh private temp directory by default) as ``fuzz-seed<S>-iter<I>.<kind>.bin``; a batch-level failure
(health, the store count, an API fault) writes every case of the batch that was SENT, since any of
them may be the cause. Printed lines name the seed, iteration, layer, mutation, sizes and the replay
path, and never a message body.
"""

from __future__ import annotations

import math
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from harness.fuzz.invariants import (
    ApiFault,
    check_health,
    check_stored,
    judge,
    queryable,
    rows_for,
    shown,
    store_total,
)
from harness.fuzz.mutate import Case, first_frame, frames, make_case
from harness.fuzz.transport import Transport
from harness.scenarios._core import control_id_of
from messagefoundry.apiclient import EngineClient
from messagefoundry.terminal_text import escape_for_terminal

Emit = Callable[[str], None]

#: The prefix of the private directory failing cases go to when no ``out_dir`` is named: made fresh
#: under the system temp directory (``mkdtemp``, owner-only), outside any checkout so a kept case
#: cannot be committed, and never a fixed path another local user could plant links in.
DEFAULT_OUT_PREFIX = "messagefoundry-harness-fuzz-"


class SetupError(RuntimeError):
    """The campaign could not start, or the API refused it for a reason that says nothing about
    the engine's invariants (a 4xx): the engine or the inbound is not there to fuzz."""


@dataclass(frozen=True)
class FuzzConfig:
    seed: int = 0
    iterations: int = 200
    seconds: float | None = None
    batch: int = 10
    #: Where failing cases are kept; None means a fresh private temp directory, made on first use.
    out_dir: Path | None = None
    #: How long a positively ACKed control id may take to appear in the store.
    settle: float = 2.0

    def __post_init__(self) -> None:
        if self.seed < 0:
            raise ValueError("the seed is a non-negative integer")
        if self.iterations < 1 or self.batch < 1:
            raise ValueError("iterations and batch are at least 1")
        if self.seconds is not None and not (math.isfinite(self.seconds) and self.seconds > 0):
            raise ValueError("the time budget is a positive number of seconds")


@dataclass(frozen=True)
class Failure:
    """One broken invariant. ``case`` is None for a batch-level failure."""

    reason: str
    case: Case | None
    replay: tuple[Path, ...]


@dataclass
class CampaignResult:
    seed: int
    cases: int = 0
    #: Reply frames by MSA-1 code, plus ``closed`` (no reply) and ``bad-reply`` exchanges.
    replies: Counter[str] = field(default_factory=Counter)
    layers: Counter[str] = field(default_factory=Counter)
    #: Positive acknowledgements whose stored row was found by control id. Zero means the
    #: per-message store invariant never ran, which proves nothing.
    stored_checked: int = 0
    failures: list[Failure] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures


def run(
    client: EngineClient, transport: Transport, config: FuzzConfig, *, emit: Emit = print
) -> CampaignResult:
    """Run the seeded campaign ``config`` describes. Raises :class:`SetupError` before the first
    send when the engine API or the inbound does not answer, or later on an API 4xx."""
    session = _Session(client, transport, config, emit)
    deadline = None if config.seconds is None else time.monotonic() + config.seconds
    next_iteration = 0
    while next_iteration < config.iterations:
        if deadline is not None and time.monotonic() >= deadline:
            emit(f"time budget of {config.seconds:g}s reached after {next_iteration} case(s)")
            break
        stop = min(next_iteration + config.batch, config.iterations)
        cases = [
            make_case(config.seed, i, wire=transport.wire) for i in range(next_iteration, stop)
        ]
        sent, held = session.batch(cases, deadline)
        next_iteration += sent
        if not held:
            break
        if sent < len(cases):
            emit(f"time budget of {config.seconds:g}s reached after {next_iteration} case(s)")
            break
    return session.finish()


def replay(
    client: EngineClient,
    transport: Transport,
    paths: Sequence[Path],
    config: FuzzConfig,
    *,
    emit: Emit = print,
) -> CampaignResult:
    """Send each file's bytes exactly as written and check the same invariants."""
    cases: list[Case] = []
    for index, path in enumerate(paths):
        if path.suffixes[-2:] != [f".{transport.kind}", ".bin"]:
            raise SetupError(
                f"{path.name} is not a {transport.kind} replay file "
                f"(expected a name ending .{transport.kind}.bin)"
            )
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise SetupError(f"cannot read {path}: {exc}") from exc
        payload = first_frame(data) if transport.wire else data
        cases.append(
            Case(
                seed=config.seed,
                iteration=index,
                message="replay",
                layer="replay",
                mutation=path.name,
                data=data,
                control_id=None if payload is None else control_id_of(payload),
            )
        )
    session = _Session(client, transport, config, emit, keep_replays=False)
    session.batch(cases, None)
    return session.finish()


class _Session:
    def __init__(
        self,
        client: EngineClient,
        transport: Transport,
        config: FuzzConfig,
        emit: Emit,
        *,
        keep_replays: bool = True,
    ) -> None:
        self.client = client
        self.transport = transport
        self.config = config
        self.emit = emit
        self.keep_replays = keep_replays
        self.result = CampaignResult(seed=config.seed)
        self.out_dir: Path | None = None
        self.started = time.monotonic()
        try:
            problem = check_health(client)
            self.total = store_total(client)
        except ApiFault as exc:
            raise SetupError(f"engine API: {exc}") from exc
        if problem:
            raise SetupError(problem)
        unreachable = transport.probe()
        if unreachable:
            raise SetupError(unreachable)

    def batch(self, cases: Sequence[Case], deadline: float | None) -> tuple[int, bool]:
        """Send ``cases`` (stopping at ``deadline``), check every invariant, and return how many
        were sent and whether every invariant held."""
        failures: list[tuple[str, Case | None]] = []
        sent: list[Case] = []
        acknowledgements = 0
        try:
            predicted = {c.control_id for c in cases if c.control_id is not None}
            before = {cid: rows_for(self.client, cid) for cid in predicted if queryable(cid)}
            for case in cases:
                if deadline is not None and time.monotonic() >= deadline:
                    break
                sent.append(case)
                count, problems = self._one(case, before)
                acknowledgements += count
                failures.extend((reason, case) for reason in problems)
            total = store_total(self.client)
            # Per batch, so a surplus row earlier in the campaign cannot hide a missing one now.
            if total - self.total < acknowledgements:
                failures.append(
                    (
                        f"the store grew by {total - self.total} row(s) across the batch but the "
                        f"engine sent {acknowledgements} acknowledgement(s)",
                        None,
                    )
                )
            self.total = total
            problem = check_health(self.client)
            if problem:
                failures.append((problem, None))
        except ApiFault as exc:
            if not exc.invariant and not failures:
                raise SetupError(f"engine API refused the campaign: {exc}") from exc
            # A 4xx after an invariant already broke must not bury that failure under a setup
            # error: the broken invariants stand, and this is reported beside them.
            failures.append((str(exc), None))
        for reason, culprit in failures:
            self._fail(reason, culprit, sent)
        return len(sent), not failures

    def _one(self, case: Case, before: dict[str, int]) -> tuple[int, list[str]]:
        """Send one case; return its acknowledgement count and its broken invariants."""
        self.result.cases += 1
        self.result.layers[case.layer] += 1
        expected = len(frames(case.data)) if self.transport.wire else None
        verdict = judge(self.transport.send(case.data), expected=expected)
        for ack in verdict.acks:
            self.result.replies[ack.code] += 1
        if verdict.problem:
            self.result.replies["bad-reply"] += 1
            return len(verdict.acks), [verdict.problem]
        if not verdict.acks:
            self.result.replies["closed"] += 1
        problems: list[str] = []
        for ack in verdict.acks:
            if not ack.positive:
                continue
            stored = self._stored_as(ack.control_id, case.control_id, before)
            if stored is None:
                continue  # an empty or unqueryable control id: the batch's store count covers it
            problem = check_stored(self.client, *stored, self.config.settle)
            if problem:
                problems.append(problem)
            else:
                self.result.stored_checked += 1
        return len(verdict.acks), problems

    @staticmethod
    def _stored_as(
        echoed: str | None, predicted: str | None, before: dict[str, int]
    ) -> tuple[str, int] | None:
        """The control id a positive ACK is stored under, with its pre-send row count, or none
        when the API cannot ask for it.

        MSA-2, and the predicted id never on its own: the engine echoes what it stored. The one
        exception is a prediction that differs from MSA-2 only by TRAILING whitespace. The
        tolerant parser strips the ends of the reply it reads MSA-2 from, and MSA-2 is the reply's
        last field, so an id ending in a space, tab or VT comes back without it; the prediction,
        read from the frame the engine decoded, still carries it. Leading whitespace is not lost
        that way, so a difference there is the engine's and is not papered over."""
        if echoed is None:
            return None
        stored = echoed
        if predicted is not None and predicted != echoed and predicted.rstrip() == echoed:
            stored = predicted
        if not queryable(stored):
            return None
        return stored, before.get(stored, 0)

    def _fail(self, reason: str, case: Case | None, sent: Sequence[Case]) -> None:
        involved = [case] if case is not None else list(sent)
        written = (self._write(c) for c in involved) if self.keep_replays else ()
        paths = tuple(p for p in written if p is not None)
        self.result.failures.append(Failure(reason, case, paths))
        if case is not None and case.layer == "replay":
            where = f"replay_file={case.mutation} sent_bytes={len(case.data)}"
        elif case is not None:
            where = (
                f"iteration={case.iteration} message={case.message} layer={case.layer} "
                f"mutation={case.mutation} sent_bytes={len(case.data)} "
                f"control_id={shown(case.control_id)}"
            )
        elif sent:
            where = f"iterations={sent[0].iteration}-{sent[-1].iteration} (batch-level)"
        else:
            where = "before any case of the batch was sent (batch-level)"
        replay_note = " ".join(str(p) for p in paths) or "(none written)"
        # The reason can quote a peer: an API reply body, a transport's error text. It stays as it
        # was in the Failure above and is escaped only on this one line (ASVS 1.1.2).
        shown_reason = escape_for_terminal(reason, single_line=True)
        self.emit(
            f"FAIL seed={self.config.seed} {where} reason={shown_reason} replay={replay_note}"
        )

    def _write(self, case: Case) -> Path | None:
        name = f"fuzz-seed{case.seed}-iter{case.iteration}.{self.transport.kind}.bin"
        try:
            if self.out_dir is None:
                self.out_dir = self.config.out_dir or Path(
                    tempfile.mkdtemp(prefix=DEFAULT_OUT_PREFIX)
                )
            path = self.out_dir / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(case.data)
        except OSError as exc:
            # The invariant failure still stands and still exits 1; the seed and iteration
            # regenerate the bytes, so say so rather than turning it into a setup error.
            self.emit(f"could not keep {name} ({exc}); make_case(seed, iteration) rebuilds it")
            return None
        return path

    def finish(self) -> CampaignResult:
        r = self.result
        replies = " ".join(f"{k}={v}" for k, v in sorted(r.replies.items())) or "none"
        layers = " ".join(f"{k}={v}" for k, v in sorted(r.layers.items())) or "none"
        verdict = "PASS" if r.ok else "FAIL"
        elapsed = time.monotonic() - self.started
        self.emit(
            f"{verdict} seed={r.seed} cases={r.cases} replies[{replies}] layers[{layers}] "
            f"stored_checked={r.stored_checked} elapsed={elapsed:.1f}s"
        )
        if r.ok and r.stored_checked == 0:
            self.emit(
                "WARNING: no positive acknowledgement was matched to a stored row, so the "
                "per-message store invariant never ran; this pass proves little"
            )
        return r
