# Review standards

Pass this file to the `code-review` skill with the diff. Name it as an instruction to read it, not
as a bare path, or the skill reviews this file instead of the diff. Each rule is a judgement call
that no linter, type checker, test or hook makes for you. Each one says what a violation looks like
in a diff and where its source of record is. Read the source for the reasoning; this sheet does not
repeat it.

Cite the rule number in a finding, for example "R5: full body logged at INFO". The checks at the end
already run on every change, so do not re-check what they cover.

## Prose: deployment status and security writing

**R1. A not-deployed beta has no present-tense impact.** Flag a sentence that says harm is happening
now, such as "PHI is exposed" or "operators rely on this today". The fix is the conditional: "would
expose X on first deployment". Source: [CLAUDE.md](../CLAUDE.md) section 0, consequence 1.

**R2. "Not deployed" never relaxes a rule.** Flag a diff that cites zero deployments to lower a
severity, skip a gate or weaken a control. Source: [CLAUDE.md](../CLAUDE.md) section 0, *It cuts one
way only*.

**R3. No shim for users who do not exist.** Flag a compatibility layer, deprecation window or staged
migration whose only purpose is to protect a running site. Prefer the simple end state. Source:
[CLAUDE.md](../CLAUDE.md) section 0, consequence 2.

**R4. Review security prose for what a reader would do with it.** Apply SDS-3.4 to SDS-3.10 to any
added or changed security sentence: a restated fact, an enumeration that claims to be complete, a
control resting on a false premise, an instrument that answers an adjacent question. Source:
[Secure_Development_Standards.md](Secure_Development_Standards.md), *Reviewing security prose*. Do
not copy those rules into the finding; cite the identifier.

## PHI

**R5. No full message bodies in the general log at INFO or above.** Flag a log call that formats the
raw message, a segment dump or an exception that carries the payload. Source:
[CLAUDE.md](../CLAUDE.md) section 9, and [PHI.md](PHI.md) section 7.

**R6. Synthetic HL7 only.** Flag a test, fixture, sample or log excerpt that looks like a real person:
a plausible name with a real-shaped MRN, SSN or address. Source:
[CLAUDE.md](../CLAUDE.md) section 5, *Product security rules*, and
[CLAUDE.md](../CLAUDE.md) section 9.

**R7. De-identification goes through `messagefoundry/anon/`.** Flag new masking or pseudonymizing
code written beside the framework instead of a rule added to it. Source:
[CLAUDE.md](../CLAUDE.md) section 9, and [PHI.md](PHI.md) section 9.

## Python and asyncio

**R8. Catch specifically, and never swallow.** Flag `except Exception:` where a narrower type exists,
and any handler that drops the error without logging it, including `except ...: pass`. Bandit's
try-except-pass check is skipped in this repo, so nothing else catches it. Source:
[CLAUDE.md](../CLAUDE.md) section 6.

**R9. A bad message goes to the error or dead-letter path, never down with the connection.** Flag a
raise that would end a listener or worker on one bad input, and any path that accepts a message and
records no disposition. Source: [CLAUDE.md](../CLAUDE.md) section 2, *Count-and-log invariant*,
and [CLAUDE.md](../CLAUDE.md) section 6.

**R10. Never block the event loop.** Flag sync I/O, `time.sleep`, a blocking DB driver call or heavy
CPU work inside `async def` without `asyncio.to_thread` or an executor. Source:
[CLAUDE.md](../CLAUDE.md) section 6.

**R11. Long loops stop when told.** Flag a worker loop that ignores its stop signal, or one that
catches `CancelledError` and carries on. Source: [CLAUDE.md](../CLAUDE.md) section 6.

**R12. Untrusted input is validated before it reaches SQL, a path or a subprocess.** Flag SQL built by
string formatting, and a file path or argv built from a message field. Bandit's SQL-string check is
skipped here, so this is the reviewer's. Source: [CLAUDE.md](../CLAUDE.md) section 5, *Product
security rules*.

## Pipeline and HL7

**R13. Routers and transforms are pure.** Flag a `@router` or `@handler` that writes anywhere, reads
the wall clock, uses randomness or keeps module state. A read-only `db_lookup` or `fhir_lookup` in a
Handler is the sanctioned exception; on a Router it is a defect. Source:
[CLAUDE.md](../CLAUDE.md) section 2, *Reliability invariant*.

**R14. Never slice raw HL7 as a string.** Flag `raw[...]`, `split("|")` or `replace` on message text
that then goes back out. Work through the parsed model and re-encode. Flag a hardcoded `|^~\&` used
to parse or edit a received message; its separators come from its MSH. Writing MSH-1 and MSH-2 of a
new message is fine. Source: [messagefoundry/CLAUDE.md](../messagefoundry/CLAUDE.md), and
[CLAUDE.md](../CLAUDE.md) section 8.

**R15. No built channel element.** Flag a new class, runner or config surface that bundles inbound,
router, handlers and outbound into one object. The words "channel" and "route" are fine in prose.
Source: [CLAUDE.md](../CLAUDE.md) section 1, *No grouping unit*, and
[CLAUDE.md](../CLAUDE.md) section 12.

## Vocabulary

**R16. Connection, Router, Handler.** Flag new code or docs that call these building blocks by other
names, such as "source", "destination", "filter step" or "transformer", where the project term fits.
The existing `SourceConnector` and `DestinationConnector` class names are not a finding.
Source: [CLAUDE.md](../CLAUDE.md) section 12.

**R17. Always qualify "shard".** Flag a bare "shard" or "sharding". Write "engine shard" or "database
shard"; they are different axes. Source: [CLAUDE.md](../CLAUDE.md) section 12.

## Already enforced, so do not re-check

At least these run on every change. A finding they would raise is noise in a review.

| Check | What it covers |
|---|---|
| `ruff check`, `ruff format --check` | Style, imports, a bare `except:`, the bugbear family including B904, RUF006 |
| `mypy` strict, four legs in `ci.yml` | Types |
| `tests/test_dependency_boundaries.py` | PySide6 or FastAPI in engine packages; clients importing the engine |
| `tests/test_from_none_is_not_redaction.py` | New `raise ... from None` in engine code |
| `tests/test_link_resolution.py` | Relative markdown links |
| `tests/test_claude_section_citations.py` | `CLAUDE.md` section numbers cited anywhere |
| `tests/test_review_standards.py` | This file's pointers and its line cap |
| `ledger-gate` hook | ADR numbers not allocated with `alloc.ps1` |
| `new-glyph` hook | New glyphs on added lines of a staged diff (not commit messages) |
| `gitleaks` hook | Committed secrets |
| `bandit` hook | Python security lint, except the checks it skips |
