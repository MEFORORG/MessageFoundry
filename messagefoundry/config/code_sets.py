# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Managed, hot-reloadable **code sets** (reference lookup tables) for the message graph.

A code-first Router/Handler often needs a reference table — an Epic diet code → a food-service
system value, a facility code → a downstream mnemonic. Hand-maintained Python dicts in the config dir work, but they
aren't operated like config: they don't reload with the graph, they aren't surfaced as data, and an
edit means a code change. A **code set** is the managed alternative: drop a ``codesets/<name>.csv``
or ``codesets/<name>.toml`` next to the config bundle, then look it up with ``code_set("name")``.

A code set is **read-only reference data** — one frozen :class:`CodeSet` instance is shared by every
transform, so a Router/Handler must never mutate it. The lookup itself is pure (key in → value out),
which keeps it compatible with the staged-pipeline **pure-re-run** invariant (ADR 0001 / CLAUDE.md
§2). **One caveat:** a hot-reload that *changes* a code set between a run and a crash-re-run can make
the re-run derive a different output than the original. That is acceptable for reference data (a code
set is intentionally operator-editable, and a reload is an explicit, audited act) — but it is the one
way a transform's output can legitimately differ across a re-run, so document it where you document
the transform.

**Location.** ``codesets/`` is resolved **relative to the ``--config`` dir** (a config bundle carries
its own reference tables and reloads with it) — distinct from ``environments/`` (cwd-level endpoint
values for :func:`~messagefoundry.config.wiring.env`). A missing ``codesets/`` dir is fine (no code
sets); a referenced-but-missing *name* fails **loud** (:class:`~messagefoundry.config.wiring.WiringError`),
exactly like a missing ``env()`` key — surfaced by ``validate`` / ``check`` / reload.

**Formats** (auto-detected by extension; the code-set NAME is the filename stem):

* **CSV** — a header row; the **first column is the lookup key**. If exactly one other column remains,
  the value is that scalar (``str``); if several remain, the value is a ``dict`` ``{header: cell}``.
  Read via :class:`csv.DictReader`. A duplicate key is a load error (fail loud).
* **TOML** — a flat table ``key = value`` → ``{key: scalar}`` (mirroring
  :mod:`messagefoundry.config.environments`); a nested table value → ``{key: {…}}``. Read via
  :mod:`tomllib`.

**Resolution.** :func:`~messagefoundry.config.wiring.load_config` loads every code set into a registry
and makes it the **active** set *before* importing config modules (so a module-top-level
``DIET = code_set("epic_diets")`` resolves), and the :class:`RegistryRunner` re-publishes the live
registry's set while a Router/Handler runs (so a call-time ``code_set("epic_diets").get(x)`` inside a
handler resolves too). A reload swaps the active set atomically. Use :func:`activated` to scope an
active set; :func:`set_active` to publish one outside a ``with`` block.
"""

from __future__ import annotations

import csv
import logging
import tomllib
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

__all__ = [
    "CODESETS_DIR_NAME",
    "POLICY_SIDECAR_SUFFIX",
    "is_policy_sidecar",
    "CodeSet",
    "load_code_set",
    "load_code_sets",
    "code_set",
    "set_active",
    "activated",
    "CodeSetError",
    # --- #162: declared unmapped-value policy + re-run-safe capture ---
    "UnmappedKind",
    "UnmappedPolicy",
    "Flagged",
    "UnmappedMiss",
    "UnmappedCapture",
    "UnmappedSink",
    "load_policy",
    "capturing",
    "active_capture",
    "set_unmapped_sink",
]

#: Sidecar filename suffix carrying a code set's declared unmapped-value policy (``#162``). A code set
#: ``epic_diets`` (``epic_diets.csv``/``.toml``) may declare its miss policy in
#: ``epic_diets.policy.toml`` next to it. The sidecar is metadata — the loader never treats it as a
#: code set (see :func:`load_code_sets`). Absent ⇒ no declared policy ⇒ today's behavior (miss returns
#: the caller's ``.get()`` default / ``[key]`` raises); backward-compatible for every shipped bundle.
POLICY_SIDECAR_SUFFIX = ".policy.toml"

#: The code-set directory name, resolved relative to the ``--config`` dir.
CODESETS_DIR_NAME = "codesets"

_log = logging.getLogger(__name__)


class CodeSetError(ValueError):
    """A code set is malformed, has a duplicate key, or was referenced but doesn't exist.

    A subclass of :class:`ValueError`; :func:`messagefoundry.config.wiring.code_set` re-raises these
    as :class:`~messagefoundry.config.wiring.WiringError` so a bad/missing code set is surfaced by
    ``validate`` / ``check`` / reload exactly like a missing ``env()`` key (fail loud)."""


# --- #162: declared unmapped-value policy -------------------------------------
#
# THE PURITY CRUX (CLAUDE.md §2/§8). Two distinct things, kept apart on purpose:
#
#   1. APPLYING the policy in the lookup (:meth:`CodeSet.translate`) is a **pure** function of
#      ``(key, table, policy)`` — return the configured default, return the key unchanged, or return a
#      :class:`Flagged` sentinel. No I/O, no mutation of the code set, a deterministic return value.
#      Safe under the at-least-once **pure-re-run** invariant (a re-run derives the identical output).
#
#   2. CAPTURING the unmapped inputs is a SIDE EFFECT. A bare capture write inside a transform would
#      make the transform impure and re-capture on every crash-re-run (duplicating / diverging) —
#      FORBIDDEN. So capture is **decoupled** from the pure return value: on a miss the lookup records
#      into a **run-scoped, in-memory, deduplicated** accumulator (:class:`UnmappedCapture`) that (a)
#      never changes ``translate``'s return value, (b) performs **no external I/O** during the
#      transform, and (c) is a deterministic function of the message, so it is byte-identical on a
#      re-run. The accumulator is published/torn-down by the runner around each run (:func:`capturing`,
#      wired as a run-scoped provider), and the single **external** effect — a non-PHI count on the
#      observability path, and optionally the values to a keyed sink — happens ONCE at scope exit,
#      idempotently. When no capture scope is active (the default), :meth:`CodeSet.translate` is a
#      strictly pure function with zero side effects.


class UnmappedKind(str, Enum):
    """How a code-set lookup resolves a **miss** (a key not in the table), declared per code set.

    ``NONE`` is the backward-compatible default (no policy declared): :meth:`CodeSet.translate` raises,
    and the mapping accessors (``cs.get(key, default)`` / ``cs[key]``) behave exactly as before."""

    NONE = "none"
    DEFAULT = "default"  # return a configured default value
    PASSTHROUGH = "passthrough"  # return the original key unchanged
    FLAG = "flag"  # return a Flagged sentinel the handler/operator can see


@dataclass(frozen=True)
class UnmappedPolicy:
    """A code set's declared unmapped-value policy: a ``kind`` + an optional ``default_value``.

    Validated on construction: ``DEFAULT`` requires a string ``default_value``; every other kind must
    not carry one. The default instance (``kind=NONE``) means *no policy declared* — the shipped,
    backward-compatible behavior."""

    kind: UnmappedKind = UnmappedKind.NONE
    default_value: str | None = None

    def __post_init__(self) -> None:
        if self.kind is UnmappedKind.DEFAULT and self.default_value is None:
            raise CodeSetError("unmapped_policy kind='default' requires a 'default_value'")
        if self.kind is not UnmappedKind.DEFAULT and self.default_value is not None:
            raise CodeSetError(
                f"unmapped_policy kind={self.kind.value!r} must not carry a 'default_value'"
            )

    @property
    def declared(self) -> bool:
        """True unless the policy is the backward-compatible ``NONE`` (nothing declared)."""
        return self.kind is not UnmappedKind.NONE

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> UnmappedPolicy:
        """Build from a parsed sidecar table (``{"kind": ..., "default_value": ...}``); ``None``/empty
        ⇒ the default ``NONE`` policy. Raises :class:`CodeSetError` on an unknown kind or a
        non-string ``default_value`` (fail loud, the loader's contract)."""
        if not raw:
            return cls()
        kind_raw = raw.get("kind", "none")
        try:
            kind = UnmappedKind(str(kind_raw))
        except ValueError:
            valid = ", ".join(k.value for k in UnmappedKind)
            raise CodeSetError(
                f"unmapped_policy: unknown kind {kind_raw!r} (expected one of: {valid})"
            ) from None
        default_value = raw.get("default_value")
        if default_value is not None and not isinstance(default_value, str):
            raise CodeSetError("unmapped_policy: 'default_value' must be a string")
        return cls(kind=kind, default_value=default_value)


@dataclass(frozen=True)
class Flagged:
    """The ``FLAG`` outcome: a sentinel a Handler can test (``isinstance(x, Flagged)``) to route an
    unmapped input to review. Stringifies to the original ``key`` so it degrades gracefully if a
    Handler passes it straight through."""

    code_set: str
    key: str

    def __str__(self) -> str:
        return self.key


# --- #162: re-run-safe capture of unmapped inputs -----------------------------


@dataclass(frozen=True)
class UnmappedMiss:
    """One distinct unmapped input observed during a run: the ``code_set`` and the missing ``key``.

    ``key`` may derive from a PHI field, so it is treated as PHI: never logged at INFO+; when persisted
    it must be encrypted at rest, keyed by ``(message_id, code_set, key)``, and its access audited (see
    :func:`capturing` and ADR 0033 §"Unmapped-value policy")."""

    code_set: str
    key: str


class UnmappedCapture:
    """A **run-scoped, deduplicated** accumulator of unmapped inputs — the re-run-safe capture buffer.

    Deduplication is keyed by ``(code_set, key)``, so recording the same miss twice within a run (or on
    a crash-re-run of the same message) yields exactly one entry — the property that makes capture
    idempotent. Holds values **in memory only** for the duration of one router/transform run; the
    runner drains it once at scope exit (:func:`capturing`)."""

    __slots__ = ("_seen",)

    def __init__(self) -> None:
        self._seen: dict[tuple[str, str], UnmappedMiss] = {}

    def record(self, code_set: str, key: str) -> None:
        """Record a miss (idempotent: a repeat ``(code_set, key)`` is a no-op)."""
        dedup_key = (code_set, key)
        if dedup_key not in self._seen:
            self._seen[dedup_key] = UnmappedMiss(code_set, key)

    def misses(self) -> list[UnmappedMiss]:
        """The distinct misses recorded this run (insertion order)."""
        return list(self._seen.values())

    def counts(self) -> dict[str, int]:
        """Per-code-set count of **distinct** unmapped inputs — the non-PHI health signal."""
        out: dict[str, int] = {}
        for code_set, _ in self._seen:
            out[code_set] = out.get(code_set, 0) + 1
        return out

    def __len__(self) -> int:
        return len(self._seen)


#: A sink drains the run's distinct misses at scope exit: ``(misses, message_id) -> None``. Default is
#: ``None`` (no persistence — this PR introduces no PHI at rest). A store-backed sink MUST key by
#: ``(message_id, code_set, key)`` so a re-run upserts the same rows (a no-op), encrypt the ``key`` at
#: rest, never log it at INFO+, and audit access — the ADR 0033 capture contract.
#:
#: **Must not block the event loop.** :func:`_drain_capture` invokes the sink **synchronously** where the
#: :func:`capturing` scope exits, which on the non-fused async router/transform path is the **asyncio loop
#: thread** (only the router/transform body hops off-loop via ``asyncio.to_thread``; the ``with`` unwinds
#: back on the loop — the fused executor path unwinds off-loop). So a store-backed sink MUST offload its
#: own persistence (enqueue to a writer / run its DB write off the loop) and return promptly — a blocking
#: DB write here would stall every listener, worker, and the API (CLAUDE.md §6). See ADR 0033 amendment.
UnmappedSink = Callable[[list[UnmappedMiss], "str | None"], None]

_sink: UnmappedSink | None = None

# The active capture buffer as a ContextVar (mirrors _active below): the runner publishes a fresh
# buffer around each router/transform run via capturing(); asyncio.to_thread copies the context into
# the transform worker thread, so a miss recorded off-loop mutates the *same* buffer object the loop
# drains on scope exit. Default None = "no capture scope active" ⇒ translate() records nothing and is
# strictly pure (the dry-run / import / bare-call cases).
_capture: ContextVar[UnmappedCapture | None] = ContextVar("mefor_unmapped_capture", default=None)


def set_unmapped_sink(sink: UnmappedSink | None) -> None:
    """Install (or clear with ``None``) the process-wide sink drained at each capture scope's exit."""
    global _sink
    _sink = sink


def active_capture() -> UnmappedCapture | None:
    """The capture buffer for the current run, or ``None`` when no capture scope is active."""
    return _capture.get()


def _record_unmapped(code_set: str, key: str) -> None:
    """Record a miss into the active capture buffer, if any. A no-op (and side-effect-free) when no
    capture scope is active — which is why :meth:`CodeSet.translate` stays pure by default."""
    buffer = _capture.get()
    if buffer is not None:
        buffer.record(code_set, key)


@contextmanager
def capturing(message_id: str | None = None) -> Iterator[UnmappedCapture]:
    """Publish a fresh :class:`UnmappedCapture` for the duration of one run, then drain it **once**.

    This is the **controlled, re-run-idempotent point** the purity crux requires: the transform runs
    inside the ``with`` body performing no capture I/O; on exit the buffer's distinct misses are drained
    to the observability path (non-PHI counts, DEBUG) and to the installed :data:`UnmappedSink` (values,
    keyed by ``message_id`` for idempotency). A crash-re-run re-derives the identical buffer, so a keyed
    sink re-upserts the same rows — a no-op. The runner brackets each router/transform run with this
    (registered as a run-scoped provider); dry-run mirrors it. Draining never raises into the caller."""
    buffer = UnmappedCapture()
    token = _capture.set(buffer)
    try:
        yield buffer
    finally:
        _capture.reset(token)
        _drain_capture(buffer, message_id)


def _drain_capture(buffer: UnmappedCapture, message_id: str | None) -> None:
    """Emit the run's capture ONCE (best-effort): non-PHI counts on the log path + the optional sink.

    Runs synchronously where the :func:`capturing` scope exits — the asyncio loop thread on the non-fused
    path — so the installed sink MUST NOT block the loop (see :data:`UnmappedSink`)."""
    if len(buffer) == 0:
        return
    # Non-PHI health signal (option (a)): per-code-set COUNTS only, at DEBUG. Never the values — a
    # missing key may derive from PHI, so it never reaches the general log (CLAUDE.md §9).
    if _log.isEnabledFor(logging.DEBUG):
        _log.debug("unmapped code-set inputs (distinct per set): %s", buffer.counts())
    sink = _sink
    if sink is not None:
        try:
            sink(buffer.misses(), message_id)
        except Exception as exc:  # noqa: BLE001 — a post-run capture sink must never break a transform
            # Log the failure TYPE only (never the exception message — it could echo a PHI-derived key).
            _log.warning("unmapped-capture sink failed: %s", type(exc).__name__)


# --- code set ----------------------------------------------------------------


class CodeSet(Mapping[str, Any]):
    """A frozen, read-only reference table: ``name`` + an immutable ``key → value`` mapping.

    Behaves like a read-only ``dict`` (``cs[key]``, ``cs.get(key, default)``, ``key in cs``,
    ``len(cs)``, iteration) but rejects mutation — one instance is shared across every transform, so
    reference data can't be edited from a handler. ``cs[missing]`` raises a :class:`KeyError` naming
    the code set; ``cs.get(missing, default)`` returns the default.

    A code set may also declare an **unmapped-value policy** (``#162``, see :class:`UnmappedPolicy`),
    applied by :meth:`translate` on a miss so a Handler no longer hand-codes ``cs.get(key, default)``
    per crosswalk. The mapping accessors are unchanged; only the new :meth:`translate` consults it."""

    __slots__ = ("_name", "_data", "_policy")

    def __init__(
        self, name: str, data: Mapping[str, Any], policy: UnmappedPolicy | None = None
    ) -> None:
        self._name = name
        self._data: dict[str, Any] = dict(data)
        self._policy: UnmappedPolicy = policy if policy is not None else UnmappedPolicy()

    @property
    def name(self) -> str:
        return self._name

    @property
    def policy(self) -> UnmappedPolicy:
        """The declared unmapped-value policy (default: the backward-compatible ``NONE``)."""
        return self._policy

    def translate(self, key: str) -> Any:
        """Look up ``key``, applying the declared **unmapped-value policy** on a miss (``#162``).

        A hit returns the mapped value (identical to ``cs[key]``). A miss applies the policy — a
        **pure** function of ``(key, table, policy)``: ``DEFAULT`` returns the configured value,
        ``PASSTHROUGH`` returns ``key`` unchanged, ``FLAG`` returns a :class:`Flagged` sentinel. With
        no policy declared (``NONE``) a miss raises :class:`CodeSetError` (fail loud — declare a policy,
        or use ``.get()``/``[]`` for the old None/KeyError behavior).

        The **only** effect beyond the return value is a record into the active run-scoped capture
        buffer (if a :func:`capturing` scope is active) — deterministic, in-memory, deduplicated, and
        drained idempotently by the runner. When no scope is active this method is strictly pure. See
        the purity crux at the top of this section."""
        try:
            return self._data[key]
        except KeyError:
            pass
        # A miss. Record it for operator reconciliation (a no-op when no capture scope is active), then
        # apply the pure policy. Recording never changes the value returned below.
        _record_unmapped(self._name, key)
        kind = self._policy.kind
        if kind is UnmappedKind.DEFAULT:
            return self._policy.default_value
        if kind is UnmappedKind.PASSTHROUGH:
            return key
        if kind is UnmappedKind.FLAG:
            return Flagged(self._name, key)
        raise CodeSetError(
            f"key {key!r} not in code set {self._name!r} and no unmapped_policy is declared — "
            f"declare one (default/passthrough/flag) in codesets/{self._name}{POLICY_SIDECAR_SUFFIX}, "
            "or use .get()/[] for the None/KeyError behavior"
        )

    def __getitem__(self, key: str) -> Any:
        try:
            return self._data[key]
        except KeyError:
            # Name the code set so a miss is self-explanatory in a transform traceback.
            raise KeyError(f"key {key!r} not in code set {self._name!r}") from None

    def __contains__(self, key: object) -> bool:
        return key in self._data

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"CodeSet(name={self._name!r}, entries={len(self._data)})"


# --- loading -----------------------------------------------------------------


def load_code_set(path: str | Path) -> CodeSet:
    """Load one ``.csv``/``.toml`` file into a :class:`CodeSet` (the NAME is the file stem).

    Auto-detects the format by extension. Raises :class:`CodeSetError` (naming the file) for an
    unknown extension, a malformed file, or a duplicate key — never silently drops data."""
    path = Path(path)
    name = path.stem
    suffix = path.suffix.lower()
    if suffix == ".csv":
        data = _load_csv(path)
    elif suffix == ".toml":
        data = _load_toml(path)
    else:
        raise CodeSetError(
            f"code set {path.name!r}: unsupported extension {suffix!r} (use .csv or .toml)"
        )
    return CodeSet(name, data, load_policy(path))


def _policy_sidecar_path(codeset_path: Path) -> Path:
    """The ``<name>.policy.toml`` sibling for a code-set file (``epic_diets.csv`` → ``epic_diets.policy.toml``)."""
    return codeset_path.with_name(codeset_path.stem + POLICY_SIDECAR_SUFFIX)


def is_policy_sidecar(path: Path) -> bool:
    """True when ``path`` is a ``#162`` policy sidecar for an actual code set beside it — i.e. it ends in
    ``.policy.toml`` **and** a companion ``<base>.csv``/``<base>.toml`` exists in the same directory.

    A standalone ``region.policy.toml`` with **no** companion is a legacy/hand-authored code set in its
    own right (name ``region.policy``), so it is *not* a sidecar and must still load — never silently
    dropped (CLAUDE.md §1 "never accept-and-drop"). Enumerators skip only true sidecars (this predicate),
    not any ``.policy.toml``-named file."""
    name = path.name
    if not name.endswith(POLICY_SIDECAR_SUFFIX):
        return False
    base = name[: -len(POLICY_SIDECAR_SUFFIX)]
    parent = path.parent
    return (parent / f"{base}.csv").is_file() or (parent / f"{base}.toml").is_file()


def load_policy(codeset_path: str | Path) -> UnmappedPolicy:
    """Load the unmapped-value policy (``#162``) declared beside the code set at ``codeset_path``.

    Reads ``<name>.policy.toml`` next to the code-set file. Absent ⇒ the default ``NONE`` policy (so
    every shipped bundle keeps today's behavior). Raises :class:`CodeSetError` (naming the sidecar) on
    invalid TOML or an invalid policy — fail loud, exactly like the code-set file itself."""
    sidecar = _policy_sidecar_path(Path(codeset_path))
    if not sidecar.is_file():
        return UnmappedPolicy()
    try:
        with sidecar.open("rb") as fh:
            raw = tomllib.load(fh)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        raise CodeSetError(f"policy sidecar {sidecar.name!r}: invalid TOML — {exc}") from exc
    try:
        return UnmappedPolicy.from_mapping(raw)
    except CodeSetError as exc:
        # Re-raise with the sidecar filename so a bad policy is self-explanatory at load.
        raise CodeSetError(f"policy sidecar {sidecar.name!r}: {exc}") from None


def load_code_sets(codesets_dir: str | Path) -> dict[str, CodeSet]:
    """Load every ``*.csv``/``*.toml`` in ``codesets_dir`` into a ``{name: CodeSet}`` registry.

    A missing directory is **not** an error (returns ``{}`` — a config bundle need not ship any code
    sets). Two files producing the same name (e.g. ``diets.csv`` and ``diets.toml``) is a
    :class:`CodeSetError` (ambiguous), as is any malformed file."""
    codesets_dir = Path(codesets_dir)
    if not codesets_dir.is_dir():
        return {}
    out: dict[str, CodeSet] = {}
    # Sorted for a deterministic load order, so a clash error names a stable "first" file.
    for path in sorted(codesets_dir.iterdir()):
        if not path.is_file() or path.suffix.lower() not in (".csv", ".toml"):
            continue
        # A ``<name>.policy.toml`` sidecar (#162) is policy METADATA for its code set, not a code set
        # of its own — skip it here (it is read by load_policy() alongside the code-set file). Skip
        # ONLY a true sidecar (a companion code set exists); a standalone ``x.policy.toml`` with no
        # companion is a legacy code set named ``x.policy`` and still loads (no silent drop).
        if is_policy_sidecar(path):
            continue
        cs = load_code_set(path)
        if cs.name in out:
            raise CodeSetError(
                f"duplicate code set name {cs.name!r} in {codesets_dir} — two files (different "
                "extensions) resolve to the same name; rename one"
            )
        out[cs.name] = cs
    return out


def _load_csv(path: Path) -> dict[str, Any]:
    """CSV with a header row: first column = key; one other column → scalar, several → ``{header: cell}``."""
    data: dict[str, Any] = {}
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        fields = reader.fieldnames
        if not fields:
            raise CodeSetError(f"code set {path.name!r}: empty CSV (no header row)")
        key_field, *value_fields = fields
        if not value_fields:
            raise CodeSetError(
                f"code set {path.name!r}: CSV needs a key column plus at least one value column"
            )
        single = len(value_fields) == 1
        for row in reader:
            key = row.get(key_field)
            if key is None:
                continue  # short/blank row — DictReader fills missing cells with None
            if key in data:
                raise CodeSetError(f"code set {path.name!r}: duplicate key {key!r}")
            if single:
                data[key] = row.get(value_fields[0])
            else:
                data[key] = {vf: row.get(vf) for vf in value_fields}
    return data


def _load_toml(path: Path) -> dict[str, Any]:
    """Flat TOML table → ``{key: scalar}``; a nested table value → ``{key: {…}}`` (mirrors environments)."""
    try:
        with path.open("rb") as fh:
            raw = tomllib.load(fh)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        raise CodeSetError(f"code set {path.name!r}: invalid TOML — {exc}") from exc
    # tomllib already rejects duplicate keys (TOMLDecodeError), so no extra dup check is needed.
    return dict(raw)


# --- active-set holder + accessor --------------------------------------------

# The active code sets, as a ContextVar so import-time (load_config publishes the set, then imports
# config modules in the same thread/context) AND call-time (the RegistryRunner re-publishes the live
# set around a router/handler run) both resolve, and a reload swaps cleanly by resetting the var (no
# stale set leaks — unlike a bare module-global, a ContextVar's reset token restores the prior value
# even if loads/reloads overlap). Defaults to None = "no active set" (a code_set() call then fails
# loud) rather than {} so "no codesets dir" and "called outside a load/run" stay distinguishable.
_active: ContextVar[dict[str, CodeSet] | None] = ContextVar("mefor_active_code_sets", default=None)


def set_active(code_sets: dict[str, CodeSet] | None) -> Any:
    """Publish ``code_sets`` as the active set and return a reset token (pass it to :func:`reset`).

    Used by callers that can't bracket the active span with a ``with`` (e.g. an async worker that
    publishes around a single transform call). Prefer :func:`activated` where a ``with`` block fits."""
    return _active.set(code_sets)


def reset(token: Any) -> None:
    """Restore the active set to what it was before the matching :func:`set_active`."""
    _active.reset(token)


@contextmanager
def activated(code_sets: dict[str, CodeSet] | None) -> Iterator[None]:
    """Make ``code_sets`` the active set for the duration of the ``with`` block, then restore.

    The loader brackets config-module import with this; a runner brackets each router/handler run with
    it — so ``code_set()`` resolves both at import time and at call time, and the prior set is always
    restored (clean swap, no leak)."""
    token = _active.set(code_sets)
    try:
        yield
    finally:
        _active.reset(token)


def code_set(name: str) -> CodeSet:
    """Return the active code set ``name`` (a frozen, read-only :class:`CodeSet`).

    Call it at a config module's top level to capture a table once (``DIET = code_set("epic_diets")``)
    or inside a handler at call time (``code_set("epic_diets").get(x)``) — both resolve against the
    set the loader/runner has published. A missing code set raises :class:`CodeSetError` (fail loud);
    :func:`messagefoundry.config.wiring.code_set` (the authoring surface) re-raises it as a
    :class:`~messagefoundry.config.wiring.WiringError`."""
    active = _active.get()
    if active is None:
        raise CodeSetError(
            f"code_set({name!r}) called with no active code sets — code sets resolve only while a "
            "config bundle is being loaded or its graph is running (load it via load_config())"
        )
    try:
        return active[name]
    except KeyError:
        available = ", ".join(sorted(active)) or "(none)"
        raise CodeSetError(
            f"no such code set {name!r} — expected a file codesets/{name}.csv or "
            f"codesets/{name}.toml relative to the --config dir; available: {available}"
        ) from None
