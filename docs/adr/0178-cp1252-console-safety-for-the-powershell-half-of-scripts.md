# 0178 — cp1252 console safety for the PowerShell half of `scripts/`

- **Status:** Accepted
- **Date:** 2026-08-28
- **Related:** BACKLOG #1030 · [CLAUDE.md](../../CLAUDE.md) §11 · `tests/test_cp1252_console_safety.py`

---

## Context

CLAUDE.md §11 forbids glyphs in prose partly on a correctness ground it states plainly: they
"raise `UnicodeEncodeError` on a stock Windows cp1252 console — which cost four separate failures
in one session."

The gate that enforces this covered `scripts/**/*.py` and `messagefoundry/**/*.py`. Its own
docstring said why PowerShell was left out: the `.ps1` surface "has no equivalent reconfigure, so
generalising to PowerShell is a different decision and is left to the existing per-file gates."

**The ungated surface was the larger one.** Measured 2026-08-28: **54 `.ps1` files against 47
`.py`** under `scripts/`.

**The control, run before any code was written.** The same character (U+2192) was planted in
`scripts/asvs/apply.py` and in `scripts/coord/claim.ps1`, then one gate was run once:

```
E   AssertionError: scripts that can abort a cp1252 console:
E       scripts\asvs\apply.py carries 1 non-cp1252 character(s) [U+2192] and does NOT
E       reconfigure sys.stdout -- printing any of them aborts on a stock Windows console
FAILED tests/test_cp1252_console_safety.py::test_no_script_can_abort_a_cp1252_console
```

The offenders list has exactly one entry. `claim.ps1`, carrying the identical character, is
absent. With **only** the `.ps1` poisoned the suite was fully green — 23 passed.

**The PowerShell failure mode is worse, and that is measured rather than assumed.** Driven through
both real hosts with the console pinned to cp1252, every arm returned **rc=0 and none raised**. The
character came back as `?`, or as three wrong characters, and the script reported success. Python
raises a catchable `UnicodeEncodeError` and leaves a traceback; PowerShell substitutes silently.

The class is current, not historical: the probe written for this ADR aborted on its own output
mid-session with `UnicodeEncodeError: 'charmap' codec can't encode character ... in position 119`.

## Decision

**Gate `scripts/**/*.ps1` on cp1252-encodability, exempting a file that assigns
`[Console]::OutputEncoding`.** The gate extends the existing test module rather than adding a second
file, so one docstring owns all three surfaces.

### The exemption, re-derived from measurement

This is the hard part of the item, and the obvious substitute for `sys.stdout.reconfigure` is
**wrong on its own**. Measured 2026-08-28 on WinPS 5.1.26100 and pwsh 7.6.5, console forced to
cp1252 for every run:

| host | source BOM | `[Console]::OutputEncoding` | decode | encode | survives |
|---|---|---|---|---|---|
| WinPS 5.1 | no | no | BAD | ok | NO |
| WinPS 5.1 | no | **YES** | BAD | BAD | **NO** |
| WinPS 5.1 | YES | no | ok | BAD | NO (substituted `?`) |
| WinPS 5.1 | YES | YES | ok | ok | YES |
| pwsh 7.6 | no | no | ok | BAD | NO (substituted `?`) |
| pwsh 7.6 | no | **YES** | ok | ok | **YES** |
| pwsh 7.6 | YES | no | ok | BAD | NO |
| pwsh 7.6 | YES | YES | ok | ok | YES |

**There are two independent channels, and Python has one.** Source **decoding** — WinPS 5.1 reads a
BOM-less file as ANSI, pwsh 7 defaults to UTF-8 — and output **encoding**, fixed by
`[Console]::OutputEncoding`. **Either alone leaves the character destroyed.** This is the
"silently-failing decode direction" the ledger row records as unowned.

**An instrument lie was caught building that table, and it is recorded because it reads as a clean
result.** A naive "are the arrow's UTF-8 bytes in stdout" test reports **true** on row 1. There the
source is misread as ANSI, so the string in memory is three characters (U+00E2 U+2020 U+2019), and
cp1252 encodes those back to `0xE2 0x86 0x92` — byte-identical to UTF-8 U+2192. The bytes
round-trip by accident while the string is corrupt. A cell counts as surviving only when **both**
channels are correct.

**A prior unlanded attempt at this gate is refuted by row 2.** Commit `673474806`, never landed and
200 commits behind `origin/main`, matched `[Console]::OutputEncoding =` and deliberately required
nothing else, reasoning that requiring more "would turn a capability check into a style check". Row
2 is that predicate's blind spot: on WinPS 5.1 a BOM-less hardened file is **still broken**, and the
gate would report it clean.

**The predicate is kept anyway, but as a host-conditional claim rather than a universal one.** This
repository standardises on pwsh 7 — measured 2026-08-28, **19 `pwsh` references** across
`.github/`, `.claude/`, `scripts/` and CLAUDE.md, and **zero `powershell.exe`**. Row 6 governs, and
on it the assignment alone **is** sufficient. Under WinPS 5.1 it is not. That caveat is
load-bearing, not decorative: it is the entire reason the host assumption is written down instead of
left implicit in a regex.

**Why a BOM is not also required.** On the governing host a BOM is neither necessary (row 6 survives
without one) nor sufficient (row 7 fails with one). It matters only on WinPS 5.1, which nothing here
invokes. And **0 of 54 `.ps1` files carry one today**, so requiring it would be a 54-file rewrite
riding an item that is otherwise a zero-diff ratchet. That is a separate decision.

### A side effect the Python remedy does not have

Python's `reconfigure` rebinds one process's own wrapper. **The PowerShell assignment mutates the
shared console.** Measured: a child took the code page from 1252 to 65001, and `GetConsoleOutputCP()`
still returned **65001 after that child exited**, while the parent's cached
`[Console]::OutputEncoding` still reported 1252 — so the parent's own view of the damage was stale.

The remedy is correct and is still the right thing to require. But it is not free, and a reader
comparing the two surfaces should not assume the analogy is exact.

## Acceptance Criteria

- **AC-1** — WHEN a `.ps1` under `scripts/` carries a character cp1252 cannot encode and does not
  assign `[Console]::OutputEncoding`, THE SYSTEM SHALL fail, naming the file and the codepoint.
  → `tests/test_cp1252_console_safety.py::test_no_powershell_script_can_abort_a_cp1252_console`
- **AC-2** — WHERE such a file assigns `[Console]::OutputEncoding`, THE SYSTEM SHALL exempt it with
  the character still present — the remedy is hardening the stream, never scrubbing the source.
  → `tests/test_cp1252_console_safety.py::test_a_synthetic_powershell_offender_is_caught_and_a_hardened_one_is_not`
- **AC-3** — IF a character is non-ASCII but cp1252 CAN encode it (U+00E9, U+2014), THEN THE SYSTEM
  SHALL NOT fire; the gate discriminates on encodability, never on ASCII.
  → `tests/test_cp1252_console_safety.py::test_the_powershell_detector_discriminates_on_encodability_not_on_ascii`
- **AC-4** — THE SYSTEM SHALL assert its own inventory (at least 45 `.ps1`, including `claim.ps1`),
  so a collapsed walk fails instead of reporting clean.
  → `tests/test_cp1252_console_safety.py::test_the_powershell_scan_actually_covers_something`
- **AC-5** — IF a `.ps1` will not decode as UTF-8, THEN THE SYSTEM SHALL fail rather than skip it.
  → `tests/test_cp1252_console_safety.py::test_every_powershell_script_decodes_as_utf8`
- **AC-6** — THE SYSTEM SHALL treat a READ of `[Console]::OutputEncoding`, a `-eq` comparison, a
  promissory comment, and the unrelated `$OutputEncoding` variable as NOT hardening.
  → `tests/test_cp1252_console_safety.py::test_the_powershell_hardening_signal_is_not_vacuous`

## Options considered

1. **Class-wide gate on encodability, exempting an `[Console]::OutputEncoding` assignment —
   CHOSEN.** Matches the shipped `.py` predicate on the same surface, and the host assumption that
   makes it sufficient is stated above rather than assumed.
2. **Cherry-pick `673474806`.** Rejected. Its walk and its ratchet-at-zero framing are sound and are
   reused; its exemption model is refuted by row 2, and it is 200 commits behind `origin/main`.
3. **Require a UTF-8 BOM as well.** Rejected for this item, not on principle. It is the correct
   answer for a repository that runs WinPS 5.1, and this one does not; it would touch all 54 files
   and turn a zero-diff ratchet into a bulk rewrite.
4. **Gate on reaching an unguarded stream, as the engine half does.** Rejected: that predicate
   exists because encodability fires 1,647 times across the engine. On this surface it fires **zero**
   times, so the wider and simpler predicate is affordable.

## Consequences

**Positive** — the class-wide gate now covers both halves of `scripts/`, on the larger of the two
surfaces. The measured two-channel table is written down, so the next reader does not re-derive it
and does not repeat the single-channel mistake.

**Negative / accepted** — the exemption is sufficient **only under pwsh 7**. If anything here is ever
run under Windows PowerShell 5.1, a hardened BOM-less file passes this gate and still corrupts its
output. The mitigation is the stated host assumption plus the measured zero `powershell.exe`
invocations, and the honest statement that this is a conditional claim.

**Scope, stated honestly.** This lands as a **ratchet at zero, not a repair.** Measured 2026-08-28,
**0 of 54 `.ps1` files carry a non-cp1252 character**, so this commit changes no script and fixes no
live break. No shipped entry point is broken. The zero is a **measurement, not a broken predicate**:
the same detector on the same run reports **29 distinct non-cp1252 codepoints** in `docs/BACKLOG.md`
as a positive control. This repository has produced a false zero on exactly this census before.

**Out of scope, and this gate cannot reach it.** The 496 U+26A0 warning signs are BACKLOG #1265.
They live in `docs/`, `tests/`, `ide/` and engine source — outside `scripts/**/*.ps1` entirely.
