# ASVS packet D (OIDC and OAuth) -- vault handoff

**All six rows stay OPEN.** Their `Closing-act` is a scorecard re-score in the `MessageFoundry-vault`
clone, which a Builder cannot perform. Full per-row reasoning is in each item's
`RE-VERIFIED 2026-09-06 (ASVS packet D)` block in `docs/BACKLOG.md`; this page is the summary the
vault holder asked for. It follows the shape of `docs/ASVS-PACKET-B-CRYPTO-2026-09-06-FINDINGS.md`
and `docs/ASVS-PACKET-C-TRANSPORT-2026-09-06-FINDINGS.md`.

**Measurement note that applies throughout.** Every library fact was measured on the worktree venv
built from `requirements.lock`, not on the ambient interpreter. `cryptography` reports **50.0.1**,
matching the lock pin exactly, so the packet B hazard did not recur. Runtime: CPython **3.14.6**.
One absence is itself load-bearing and was confirmed on the same venv: **no OAuth, OIDC or JWT
library is installed at all** -- `authlib`, `pyjwt` and `python-jose` are absent, and `pyproject.toml`
declares none, against a control of 54 quoted dependency lines. An OAuth client cannot hide inside a
dependency.

| Item | Cell | What the verdict should become |
|---|---|---|
| #1155 | 10.1.1 | Stay **partial**, and amend rather than re-score. The enablement premise holds. The row's sharpest claim is **dead** -- `tls_hop_attested` does not cross silently off-loopback -- and it came from ADR 0153's own table, corrected here. Two counts are understated (7 construction sites to 14, 5 delivery sites to 7) and one custody delta should be downgraded to demand-gated design. |
| #1156 | 10.1.2 | Stay **partial**. Nine of nine acceptance-path limbs still hold. Delta 3 was understated and is **fixed here**; delta 1 is live and is being closed on two other PRs; delta 2 is live, confirmed by execution, and unbuilt. |
| #1157 | 10.2.1 | Stay **partial**. Nothing refuted, no product defect, and the code side is measurably stronger than the row records. The refusal ladder is **fourteen** values by execution, which is this row's own thirteen and **not** the fifteen the owner ruling states. |
| #1158 | 10.2.2 | Stay **partial**. **Not worked** -- claimed by another live session, with three open PRs already amending the row. Re-verification recorded so nobody re-derives it. The row's inverse trap is the one to watch: a negative equivalence result is not grounds to re-score down. |
| #1160 | 10.5.1 | Stay **partial**. The control could not be broken by execution. False sentence (a) is **dead**, proven over nine hostile inputs. Claim 8's mechanism is imprecise and should be corrected, not repeated. |
| #1351 | 10.4.13 | **`na` on scope is the reasoned recommendation, and it needs an owner ruling.** The row reasons from a paraphrase where the corpus holds the text. V10.4's `section_name` is "OAuth Authorization Server" and the engine hosts none. Two citation defects corrected. |

## The spine of this packet, stated once

Four of the six rows share one premise: a control is unconditional in code, but the flow that reaches
it ships OFF by default. The brief's question was whether the 2026-08-17 owner ruling settles them or
only #1155. **It settles more than one and fewer than all, and the discriminator is the ruling's own
sentence.**

Ruling 1 scopes itself, verbatim, to *"the six cells whose sole binding limb is that the federated-login
feature ships off"*. Measured against that premise:

- **#1156, #1157 and #1160 meet it squarely.** Each row's own text says enablement alone holds it
  short, and re-verification confirms every control limb still holds unconditionally. The ruling
  applies premise and disposition.
- **#1155 does not.** ASVS 10.1.1 ranges over three further OAuth minting paths that ship independently
  of `[auth].oidc_enabled`, and over a cleartext credential-hop configuration reachable without
  federated login at all. The ruling's *disposition* still holds -- the cell is permanently partial on
  the rubric gate either way -- but only by a different route. PR 943 reached the same finding
  independently.
- **#1158 meets it partly.** Its second binding limb is a standards equivalence question, now answered
  negative, not enablement.
- **#1351 is not in the family at all.** The family is enumerated in the 2026-08-08 default-off triage
  as 10.1.1, 10.1.2, 10.2.1, 10.2.2, 10.5.1 and 10.5.4. 10.4.13 is none of those; it is a contested
  cell filed six days after the ruling, and its question is rule-1 applicability, not enablement.

**The enablement premise itself was re-measured first, because it is the single fact that would have
changed every row.** It holds: `oidc_enabled: bool = False` at `messagefoundry/config/settings.py:2010`,
and across the whole tracked tree every `oidc_enabled = true` is prose or a test, against a control of
29 files carrying the name. Nothing has shipped on.

**Two things that would move this packet and have not happened.** The rulings are still not applied to
the record: measured against the vault at `d5560aed`, none of the seven cells' residuals carries the
2026-08-17 ruling, twenty days after it was given, with a control confirming the same instrument reads
"rule 5" and "partial" out of those same residuals. And a **siting** argument does not transfer from
#1351 to any other row here: 10.1.1 and 10.1.2 sit in "Generic OAuth and OIDC Security", 10.2.1 and
10.2.2 in "OAuth Client", 10.5.1 in "OIDC Client" -- all roles this engine genuinely occupies.

## What was built

**One code change and two documentation corrections. All three are small on purpose, because every
other code site these rows would touch is held by an open PR.**

1. **`messagefoundry/config/settings.py` -- the #1156 delta 3, fixed.** `oidc_flow_ttl_seconds` had no
   validator at all, so it was unbounded in **both** directions, not only above as the row records.
   `-5`, `0` and `100000000` all loaded, while the sibling `oidc_clock_skew_seconds` refused the same
   three in the paired run -- which is its own control. Two consequences neither the row nor the cell
   carries: a value at or below zero reaches the flow cookie's `Max-Age`, so the browser discards it on
   receipt and every federated login then fails `flow_binding_missing` with nothing naming the cause;
   and because `FlowCache._prune` reclaims only past-deadline entries while the cache is
   reject-when-full, an over-large value turns `oidc_flow_cache_max` abandoned logins into a console
   login outage a restart alone clears. Now bounded 30..1800, with the default unmoved so no doc-drift
   pin or SECURITY.md row is owed.
2. **`docs/adr/0153-...` -- the `tls_hop_attested` disposition.** The table said "ALLOW, silent". Driving
   `_enforce_shipped_hop` shows it warns off-loopback and is silent only on loopback. Corrected in
   place with the measurement and with the record of how far the error travelled.
3. **`docs/testing/VERIFY.md` -- the captured `id_token`.** The federation section tells an operator to
   put a live bearer-class artifact in a file and gave no handling, lifetime or deletion guidance,
   forty lines from the same document's "never a file" rule scoped to database credentials. A short
   subsection now covers placement, lifetime, deletion and what the tool does not do.

## Measurements worth carrying, with their controls

| Claim | How it was established | Control that fired in the same run |
|---|---|---|
| Federation still ships off | `oidc_enabled: bool = False` at `settings.py:2010`; whole-tree sweep finds only prose and tests | 29 tracked files carry the name |
| Enabling it takes fourteen site-supplied values | Driven to a successful load one value at a time, then leave-one-out | The full set loads; dropping any one refuses with its own message |
| `tls_hop_attested` warns off-loopback | Drove `_enforce_shipped_hop` at an enforcing PHI posture; ALLOW plus one WARNING line | A bare non-loopback hop refused, zero log lines, in the same run |
| The nonce check refuses rather than skips | Full `validate_id_token` ladder, real RS256 tokens, in-memory JWKS; six hostile shapes | A matching nonce accepted, principal returned |
| The non-ASCII nonce gap is closed | Non-ASCII in the token AND in the policy both land on the audited branch | The matching-nonce acceptance above |
| Federation off registers no route | Built a real FastAPI app, called `register` twice, listed routes: 0 off | 3 registered with it on |
| `oidc_flow_ttl_seconds` is unvalidated | `-5`, `0`, `100000000` all load | `oidc_clock_skew_seconds` refuses all three |
| `oidc_scopes` members are unconstrained | `offline_access`, a traversal string and `[]` all load | Three sibling validators refuse in the same process |
| The `__Host-` prefix still drops under the opt-out | Drove `set_oidc_flow_cookie` five ways | A cleartext arm dropped `Secure` too, so "did nothing" is excluded |
| Federation on a cleartext non-loopback origin loads | Constructed settings with `http://ops.example.com` | The same validator refuses an ABSENT origin |
| V10.4 is the authorization-server section | Pinned corpus `section_name`, SHA-256 `8201b20e...` | Byte-matches the digest the scorecard itself declares |
| The engine hosts no authorization server | 188 unique route paths enumerated; none AS-shaped | The same instrument returned `/ui/oidc/start` and `/ui/oidc/callback` |
| No PAR anywhere | Zero `pushed_authorization`, zero `request_uri` | Nine files match `code_challenge` |
| No RFC 9207 `iss` parameter | Two `iss` hits, both other things | Three `oidc_issuer` hits in `settings.py` |
| The rulings are still unapplied | Parsed the vault scorecard at `d5560aed`; no ruling phrase in any of the seven residuals | The same read finds "rule 5" and "partial" in those residuals |

## Two instrument defects found in the prior passes

**A doc read where a function should have been driven.** #1155's `tls_hop_attested` claim and its
ADR 0139 claim were both correct readings of documents that were themselves wrong or since superseded.
Neither error would have been caught by any re-check done by reading, which is what makes this the
general lesson of the packet rather than one row's footnote.

**A citation that was wrong when written, not drifted.** #1351 cites `ASVS-ASSESSMENT-METHOD.md:44-45`
for rule 1. Those lines are rule 2; rule 1 is at `:42-43`, and the file is byte-identical there at the
filing commit. Drift is repaired by re-anchoring; this needs correcting, and the two are easy to
confuse because both present as a stale line number.

## Deliberately not done

**Did not work #1158.** The coordination ledger shows it claimed by a live session, and three open PRs
already amend the row -- 943 (holds the claim; built the advisory issuer-to-endpoint arm), 963 (refutes
the refusing variant against four providers' discovery documents) and 969 (the destination-binding
limb). The re-verification is recorded in the banner rather than appended, because all three amend the
row's tail and a fourth block there would be pure conflict.

**Did not build the `__Host-` fallback (#1156 delta 1).** PR 934 and PR 945 both carry it. A third
change would collide. The finding recorded instead is the one with the shortest half-life: `__Secure-`
is in **zero** shipped Python at `ebdfa44a6`, so a re-scorer who reads PR 934's title and assumes it
landed grades against code that does not exist.

**Did not refuse federation on a cleartext non-loopback origin (#1156 delta 2).** Confirmed live by
execution and nobody is building it, but `messagefoundry/config/settings.py` is already held by four
open PRs, and choosing between refusing at load and warning is a posture decision that deserves its own
change rather than a rider on a validator fix. The measurement and the fix site are in the row.

**Did not constrain `oidc_scopes` members (#1155).** Confirmed unconstrained at every layer. The right
shape is an advisory grader on the existing `messagefoundry check` contract, following
`overbroad_smart_scopes` -- which is #1159's seam, held by another session this cycle.

**Did not touch `messagefoundry/__main__.py`.** The `--fed-id-token` help text deserves the same
pointer the VERIFY.md subsection now carries. Eight open PRs are editing that file.

**Did not build PAR (#1351), and that is the finding rather than an omission.** Applicability is rule 1
and it is unresolved. Building against a requirement that may not apply is what the 2026-08-23 pass did.

**Did not allocate an ADR** for the TTL bound. Its sibling cap was added without one, the change adds
no vocabulary and sets no boundary the section did not already have, and the reasoning that would fill
an ADR is in the validator's own comment where the next reader of that line will meet it.

**Did not floor `oidc_flow_cache_max`, and this is the least comfortable omission in the packet.** It
sits on the line directly below the field this change bounds, and its degenerate value is worse:
measured, `oidc_flow_cache_max = 0` raises `FlowCacheFullError` on the FIRST flow, because `put`
refuses at `len(entries) >= global_cap`, so zero denies every federated sign-in outright. `-1` also
loads. `docs/SECURITY.md` control 7 already documents this in terms, ending *"No validator floors it;
treat it as a security-relevant value"*, and `tests/test_security_doc_rate_limits.py` already pins the
behaviour. Two reasons it is not here rather than one. Adding the floor makes that documented sentence
**false**, so the fix has to carry a `docs/SECURITY.md` edit in the same change -- and that file is
held by **eight** open PRs. And the field belongs to a different control family with its own doc row
and its own tests, not to any row in this packet. The measurement is complete and the fix is about six
lines of the shape now sitting above it; it wants the seat that owns that row, in one change with the
doc correction.

## A class defect this packet found and cannot file

`AuthSettings` holds **22 of the 42 unbounded numeric fields** in `messagefoundry/config/settings.py`,
after this change. That is not a project without bounds discipline: fourteen other sections are fully
bounded, `RetentionSettings` 13 of 13 and `PipelineSettings` 9 of 9 among them. The discipline exists
and was not applied in the authentication section, which is the worst place for it to be missing.

Confirmed by execution, all of these load clean today: `password_min_length = 0`,
`lockout_threshold = 0`, `lockout_minutes = -1`, `max_sessions_per_user = -1`,
`step_up_max_age_seconds = 1_000_000_000`, and `login_rate_limit_per_ip = 0` -- the last of which
**disables the brute-force bound**, because `SlidingWindowRateLimiter` gates on
`bool(self._per_key)`. That one is fail-OPEN, while `oidc_flow_cache_max = 0` is fail-CLOSED, so
two limiters wired from adjacent fields in the same section give `0` opposite meanings and neither
is refused at load.

**The idle timeout belongs in that list, and it reaches the field by a different spelling.**
`session_idle_timeout_minutes` is an unbounded numeric `AuthSettings` field like the six above.
ADR 0118 moved its operator-facing name, so `_reject_relocated_keys` raises on the `[auth]`
spelling before the value reaches validation. The form an operator can write is
`[security].sign_out_after_idle_minutes`. Measured here, it loads clean at `0` and at `-1`, and
desugars through `_SECURITY_PASSTHROUGH` onto that same field. **Relocating a key to its canonical
home did not bound it.** The refusal governs where the switch lives, not what it may hold, so this
section's bounds gap survives the move. This packet's own first draft of the list used the `[auth]`
spelling, which no reader could have pasted; `tests/test_docs_cite_no_refused_config_keys.py`
caught it.

**A blanket floor would be wrong**, which is why this is a filing and not a sweep: `0` is a
documented, load-bearing "off" for at least `mfa_recovery_code_count`, `ad_session_recheck_seconds`
and `phi_read_rate_limit_global`. The deep fix is per-field semantics.

**No number is cited for this deliberately.** A Builder must not cite a `#N` it has not allocated, and
filing routes elsewhere. The subject is: *unbounded numeric settings in `AuthSettings`, with the
per-field zero semantics decided rather than defaulted*. The nearest existing precedent for how to
file it is the one-item-per-field row already in the ledger for `retry_max_attempts` having no floor.

## The one question this packet leaves open

**10.4.13 needs an owner ruling, not more evidence, and the cell already says so.** The requirement
carries no actor and its section is "OAuth Authorization Server". If an actor-free requirement inherits
its actor from its section, the cell is `na` and no build is owed. If it binds whoever operates a code
grant, it is `fail` under rule 3 -- not partial and not pass -- because no PAR code exists in any
configuration this engine admits. Every checkable fact around that question now holds; the fork itself
is a reading.

Whichever way it goes, the narrow engineering statement survives and needs a home: with federation on,
the authorization request travels the browser-visible front channel, where the identity provider is the
only party positioned to reject tampering. Under an `na` that becomes a hardening item beyond ASVS, and
if it is not filed the scoping answer will have cost real security value.

## Checks

**Green:** `ruff check .`, `ruff format --check .` (1263 files), `mypy messagefoundry` (strict, 268
files), the backlog status gate at 679 items each declaring exactly one status, and pytest over every
suite covering a touched file -- 276 across the OIDC, auth, service, verify, federation, HTTP-auth and
OIDC-interstitial modules, plus 227 across settings, security doc-drift, threat-model doc-drift and the
private-paths guard.

**The banner edits were verified with `parse_items`, not by eye.** All six rows report `is_open` true
and carry exactly one packet-D line inside the parsed banner run, against a pre-edit control in which
the same check failed on all six.

**Not run:** the full pytest suite did not finish inside the session. Hosted-runner-only legs -- the
Postgres and SQL Server store legs and `windows-service-smoke` -- were never visible from this worktree
and must be read on the PR.
