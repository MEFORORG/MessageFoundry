# Review standards

Pass this file to the `code-review` skill with the diff. Name it as an instruction to read it, not
as a bare path, or the skill reviews this file instead of the diff. Each rule is a judgement call
that no linter, type checker, test or hook makes for you. Each one says what a violation looks like
in a diff and where its source of record is. Read the source for the reasoning; this sheet does not
repeat it.

Cite the rule number in a finding, for example "R5: full body logged at INFO". Do not duplicate the
exact CI slice in the closing table; review everything outside that slice.

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

**R4. Review security prose for what a reader would do with it.** Apply SDS-3.1 to SDS-3.10 to any
added or changed security sentence -- at least unapproved alignment wording, a "NIST certified" or
unbacked claim, a restated fact, a closed enumeration, a control on a false premise, an adjacent
instrument, an unanchored surface list, or a record cleared past its capacity. Source:
[Secure_Development_Standards.md](Secure_Development_Standards.md), *A note on claims and wording*.
Cite the SDS identifier instead of copying the rule.

## PHI

**R5. No full message bodies or unscrubbed PHI in general logs.** Flag a log call that formats the
raw message, a segment dump, an exception carrying the payload, non-HL7 reply identifiers
(`InboundReply.body`), cleartext partner filenames in `OSError`, body-holding dataclass `repr()`, or
`print()` in a Router or Handler. Source: [CLAUDE.md](../CLAUDE.md) section 9, and [PHI.md](PHI.md) section 7.

**R6. Synthetic HL7 and synthetic identifiers only.** Flag a test, fixture, sample or log excerpt
that looks like a real person, partner or site: a plausible name with a real-shaped MRN, SSN or
address, a customer/vendor token, or a routable IPv4. Source:
[CLAUDE.md](../CLAUDE.md) section 5, *Product security rules outlive any method rewrite*, [CLAUDE.md](../CLAUDE.md) section 9, and [PHI.md](PHI.md) section 9.

**R7. De-identification goes through `messagefoundry/anon/` and mirrors `tee/anon/`.** Flag new
masking or pseudonymizing code written beside the framework, an edit to `messagefoundry/anon/` not
mirrored to `tee/anon/`, or prose calling default `anonymize_checked` output HIPAA Safe Harbor.
Source: [CLAUDE.md](../CLAUDE.md) section 9, and [PHI.md](PHI.md) section 9.

## Python and asyncio

**R8. Catch specifically, and never swallow.** Flag `except Exception:` where a narrower type exists,
`contextlib.suppress(Exception)`, and any handler that drops the error without logging it, including
`except ...: pass`. Bandit skips `B110` and at least `harness/`, `samples/` and `tests/`, so nothing
else catches it. Source: [CLAUDE.md](../CLAUDE.md) section 6.

**R9. A bad message goes to the error or dead-letter path, never down with the connection.** Flag a
raise that would end a listener or worker on one bad input, and any path that accepts a message and
records no disposition. Source: [CLAUDE.md](../CLAUDE.md) section 2, *Count-and-log invariant*,
and [CLAUDE.md](../CLAUDE.md) section 6.

**R10. Never block the event loop.** Flag sync I/O, `time.sleep`, a blocking DB driver call or heavy
CPU work inside `async def` without `asyncio.to_thread` or an executor. Source: [CLAUDE.md](../CLAUDE.md) section 6.

**R11. Long loops stop when told.** Flag a worker loop that ignores its stop signal, or one that
catches `CancelledError` and carries on. Source: [CLAUDE.md](../CLAUDE.md) section 6.

**R12. Untrusted input and dial-out hops are gated.** Flag SQL built by string formatting, a file
path or argv built from a message field, an outbound or poller hop bypassing `[egress]`
(`check_egress_allowed` / `check_source_allowed`), or a config error echoing a raw setting value.
Bandit skips `B404` and `B608`, plus at least `harness/`, `samples/` and `tests/`. Source: [CLAUDE.md](../CLAUDE.md) section 5, *Product security rules outlive any method rewrite*, [SECURITY.md](SECURITY.md), and [transports/base.py](../messagefoundry/transports/base.py).

## Pipeline and HL7

**R13. Routers and transforms are pure.** Flag a `@router` or `@handler` that writes I/O, reads the
wall clock (`datetime.now`, `time.time`), uses randomness or keeps module state. Pure `reference`,
`code_set`, `current_ingest_time` and `current_environment` are allowed in both; `SetState`,
`SetMeta`, `state_get`, `response_get` and read-only `db_lookup`/`fhir_lookup` are Handler-only
(never a Router). Source: [CLAUDE.md](../CLAUDE.md) section 2, *Reliability invariant*, [CONFIGURATION.md](CONFIGURATION.md), and [run_context.py](../messagefoundry/config/run_context.py).

**R14. Follow the two-tier HL7 and binary carriage rules.** Flag `raw[...]`, `split("|")`, `replace`
or hardcoded `|^~\&` on received HL7 (writing MSH-1/MSH-2 on a new message is fine), `hl7apy` on the
hot routing/transform path, HL7-parsing a non-`hl7v2` `RawMessage`, `latin-1` instead of `mfb64:v1:`
for binary bytes, or NAKing post-ACK stage failures instead of dead-lettering. Source: [messagefoundry/CLAUDE.md](../messagefoundry/CLAUDE.md), and [CLAUDE.md](../CLAUDE.md) section 8.

**R15. No built channel element.** Flag a new class, runner or config surface that bundles inbound,
router, handlers and outbound into one object. The words "channel" and "route" are fine in prose.
Source: [CLAUDE.md](../CLAUDE.md) section 1, *No grouping unit*, and [CLAUDE.md](../CLAUDE.md) section 12.

## Vocabulary

**R16. Connection, Router, Handler.** Flag new code or docs that call these building blocks by other
names, such as "source", "destination", "filter step" or "transformer", where the project term fits.
Existing transport-layer `Source*` and `Destination*` internals are not a finding. Source: [CLAUDE.md](../CLAUDE.md) section 12.

**R17. Always qualify "shard".** Flag a bare "shard" or "sharding". Write "engine shard" or "database
shard"; they are different axes. Source: [CLAUDE.md](../CLAUDE.md) section 12.

## Security, UI and hygiene

**R18. API and `/ui` gates match action sensitivity and channel scope.** Flag `@public_route` on a
non-public endpoint, a mutating route gated only by a read `Permission` or missing step-up auth, a
channel-bearing route marked `not_channel_bearing` or unfiltered on mutations, or a `/ui` route in
`messagefoundry_webconsole/` missing per-channel filtering. Source: [CLAUDE.md](../CLAUDE.md) section 2, and [SECURITY.md](SECURITY.md).

**R19. TLS-always, attested plaintext hops, and `cap_setting` for numeric caps.** Flag `verify=False`,
unattested non-loopback plaintext, disabling engine TLS without `tls_terminated_upstream`,
`trusted_proxies` and `plaintext_upstream_hop_acknowledged`, or `int(v) if v else None` truthiness
on numeric caps (`"0"` becomes zero instead of unlimited; use `cap_setting`/`positive_cap`). Source: [CLAUDE.md](../CLAUDE.md) section 2, [SECURITY.md](SECURITY.md), [ADR 0172](adr/0172-the-engine-always-serves-tls-minting-a-self-signed-certificate-on-first-run.md), and [transports/base.py](../messagefoundry/transports/base.py).

**R20. No new operator UI in PySide6, and no cross-thread widget calls.** Flag new operator surfaces
under `harness/` (they belong in `/ui`), any PyQt import, operational logic in widgets, or worker
threads updating Qt objects without `Signal`/`Slot`. Source: [CLAUDE.md](../CLAUDE.md) section 10, and [harness/CLAUDE.md](../harness/CLAUDE.md).

**R21. Host circuit breakers on machine-bound scripts, and non-vacuous controls.** Flag a command or
script that would do harm on the wrong machine without an `[Environment]::MachineName` check
(`exit`/`return` and `$env:COMPUTERNAME` are forbidden) ([CLAUDE.md](../CLAUDE.md) section 5), a
dynamic scan with no positive floor or exit-code check, or a guard test with no negative control ([Code_Quality_Standards.md](Code_Quality_Standards.md) section 4).

**R22. No glyphs anywhere, no drive-by glyph sweeps, and no ASVS vault leaks.** Because `new-glyph`
has no CI mirror, flag any unquoted glyph or emoji in added lines, commit messages or PR text, and
flag drive-by edits to existing glyphs outside a ruled slice ([CLAUDE.md](../CLAUDE.md) section 11).
Flag `"vault cell"` / `"gate cell"` ([CLAUDE.md](../CLAUDE.md) section 12) and prose ASVS verdicts or 3+ id-to-path pairs in public files or commits ([scripts/asvs/CLAUDE.md](../scripts/asvs/CLAUDE.md)).

**R23. No declined-by-design features, unvetted dependencies, or unallocated `#N` ids.** Flag visual
logic authoring beyond Steps view, Serial/ASTM connectivity, per-key message ordering, or ISO 5055
scoring ([CLAUDE.md](../CLAUDE.md) section 12); ad-hoc or hallucinated dependencies ([CLAUDE.md](../CLAUDE.md) section 7);
and unallocated `#N` citations ([CLAUDE.md](../CLAUDE.md) section 5).

## Enforced on CI -- do not duplicate these exact slices

At least these run on CI unless noted. Review everything outside the exact slice each row names.

| Check | Exact slice enforced |
|---|---|
| `ruff check`, `ruff format --check` | Style, imports, bare `except:`, bugbear (`B904`), `RUF006` (not overwritten/unawaited task refs) |
| `mypy` (`ci.yml`, Ubuntu leg) | Strict in `messagefoundry`, `messagefoundry_toolkit`, `messagefoundry_webconsole`, `scripts/asvs`, `harness.sinks`; relaxed + `ignore_errors` exemptions in `tests`; skips at least `packaging/messagefoundry-webconsole/tests`, `harness`, `tee`, `scripts`, `samples` |
| `tests/test_dependency_boundaries.py` | `PySide6`/`FastAPI`/`api`/`webconsole` in 5 engine subpackages; `anon` & `toolkit` isolation; direct `config`/`pipeline`/`store`/`transports` imports in `harness`/`tee`/`samples`/`webconsole` (not `_CLIENT_ALLOWED`, lazy root imports, other engine subpackages, or `ide`) |
| `tests/test_from_none_is_not_redaction.py` | Unclassified direct `raise ... from None` and direct new raises inside body-exception handlers in `messagefoundry/` and `messagefoundry_toolkit/` |
| `tests/test_link_resolution.py` | Relative markdown file/dir targets in public docs (not `#fragment` anchors or `file.py:N` line cites) |
| `tests/test_claude_section_citations.py` | Same-line `CLAUDE.md` section numbers within 60 chars in `.md`, `.py`, `.ps1`, `.yml` |
| `tests/test_review_standards.py` | This file's pointers, rule order and 150-line cap |
| `ledger-gate` (`--ci`) | Duplicate ADR numbers and new-ADR rows in `docs/adr/README.md` (CI cannot verify `alloc.ps1` ownership, edited ADR rows, or `#N` ids) |
| `new-glyph` (**local hook only -- no CI**) | Staged diff net glyphs locally only; skips commit messages, `--amend`, rebase, PR text and `EXEMPT_PATHS`/`EXEMPT_PREFIXES` -- still review (`R22`) |
| `gitleaks` + `forbidden-content` | Secrets, routable IPs, home paths, slugs, tight `id: verdict` pairs, and configured tokens on non-fork CI (skips unlisted names, prose verdicts, commit messages/PR comments; PR-body scan is advisory) |
| `bandit` + `semgrep` | Python SAST across `.` except excluded trees (skips `B101,B110,B404,B608` and at least `harness/`, `samples/`, `tests/`, `packaging/messagefoundry-webconsole/tests/`, `ide/`) |
