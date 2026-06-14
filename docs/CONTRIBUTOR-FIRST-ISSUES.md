# Good first issues — draft (staging for Phase 1)

> **Status: draft / not yet posted.** These are candidate **`good first issue`** tickets to post on the
> public repo when the contributor program opens to outside code (Phase 1+, gated on the public-primary
> flip — see [CONTRIBUTOR-PROGRAM-PLAN.md](CONTRIBUTOR-PROGRAM-PLAN.md)). The steward should confirm each
> is still open and right-sized before posting, especially those tagged **(confirm scope)**. Each is
> intentionally small, self-contained, and additive — a real on-ramp, not busywork.

Post each as a GitHub issue with the labels shown. Suggested base labels: `good first issue` +
`help wanted`, plus an `area:*` tag.

---

## GFI-1 — Add an annotated example Router + Handler
**Labels:** `good first issue`, `area:examples`, `area:docs`
**Context:** `samples/config/` has ADT examples, but there's no compact, heavily-commented example that
walks a newcomer through the **filter → transform → fan-out** pattern end to end.
**Task:** add a new example module under `samples/config/` (shared helpers go in `_`-prefixed files,
which the loader skips) with a Router that forwards to a Handler, a Handler that filters then transforms
a field via `Message`, and a `Send` to two outbound connections. Use a synthetic message from
`messagefoundry generate`. Comment each step.
**Acceptance:** loads via the config loader; `python -m messagefoundry check` passes; no real PHI;
referenced from `docs/CONNECTIONS.md` or a short `samples/` README.
**Pointers:** `samples/config/IB_ACME_ADT.py`, [CONNECTIONS.md](CONNECTIONS.md), CLAUDE.md §4.

## GFI-2 — Write a "First 10 minutes" quickstart
**Labels:** `good first issue`, `area:docs`
**Context:** the README has setup commands but no single linear path from clone → running engine →
sending a test message → seeing it land.
**Task:** add `docs/QUICKSTART.md` taking a reader from a fresh clone to a delivered synthetic message
using the MLLP harness, with copy-paste commands for Windows PowerShell (and a bash note). Link it from
the README.
**Acceptance:** every command works on a clean checkout; uses only synthetic HL7; linked from README.
**Pointers:** README "Development" section, `harness/`, `samples/`.

## GFI-3 — Add a core-terms glossary
**Labels:** `good first issue`, `area:docs`
**Context:** newcomers must infer the precise meaning of Connection / Router / Handler / stage /
disposition from prose spread across several docs.
**Task:** add `docs/GLOSSARY.md` with one short, accurate paragraph per core term (Connection, Router,
Handler, the three stages, the disposition states, dead-letter / replay), cross-linking
`docs/ARCHITECTURE.md`. Keep definitions consistent with CLAUDE.md §1.
**Acceptance:** terms match the code / CLAUDE.md vocabulary exactly; linked from README / ARCHITECTURE.
**Pointers:** CLAUDE.md §1–§2, [ARCHITECTURE.md](ARCHITECTURE.md).

## GFI-4 — Document the remote-file connector  *(confirm scope)*
**Labels:** `good first issue`, `area:transport`, `area:docs`
**Context:** `messagefoundry/transports/remotefile.py` is a shipped transport, but `docs/CONNECTIONS.md`
has dedicated sections for MLLP / TCP / File / REST / Database / SOAP and **may** lack one for the
remote-file connector.
**Task:** confirm whether the remote-file connector is documented; if not, add a `CONNECTIONS.md`
section with its config schema, a runnable example, and any security / quarantine notes consistent with
the File connector's.
**Acceptance:** config keys match `remotefile.py`; example is runnable; matches the style of neighboring
connector sections.
**Pointers:** `messagefoundry/transports/remotefile.py`, [CONNECTIONS.md](CONNECTIONS.md), CLAUDE.md §11.

## GFI-5 — Tests for non-standard MSH encoding characters  *(confirm scope)*
**Labels:** `good first issue`, `area:parsing`, `area:tests`
**Context:** CLAUDE.md requires reading field / component / repetition / escape / subcomponent
separators from MSH rather than hardcoding `|^~\&`. Confirm the peek/parse path has explicit tests for a
message using *non-default* encoding characters.
**Task:** add (or extend) a unit test feeding a synthetic message with non-standard separators and
assert routing/peek reads the right fields. If coverage already exists, propose a smaller real gap.
**Acceptance:** new test fails before / passes after (or documents existing coverage); `pytest` green;
synthetic HL7 only.
**Pointers:** `messagefoundry/parsing/peek.py`, existing `tests/` parsing tests, CLAUDE.md §8.

---

*More candidates live in [BACKLOG.md](BACKLOG.md), but most backlog items are larger than a first issue.
When curating, prefer additive, low-blast-radius tasks; avoid anything touching the reliability
invariants, the store/queue, or auth — those are "discuss first" (see [GOVERNANCE.md](../GOVERNANCE.md)).*
