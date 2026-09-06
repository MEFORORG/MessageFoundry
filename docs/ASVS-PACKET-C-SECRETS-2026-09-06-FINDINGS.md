# ASVS packet C (service auth and secret access) -- vault handoff

**Both rows stay OPEN.** Their `Closing-act` is a scorecard re-score in the vault, which a Builder
cannot perform. Full per-row reasoning is in each item's `RE-VERIFIED 2026-09-06` block in
`docs/BACKLOG.md`; this page is the summary the vault holder asked for.

**Measurement note that applies throughout.** Every measurement was taken with the worktree's own
`.venv` interpreter (Python 3.14.6), bootstrapped from `requirements.lock`, not the ambient one.
Nothing in this packet turns on a third-party library version, so no lock-versus-installed
discrepancy of the kind packet B hit could arise here. The TLS behaviour measured below is CPython's
`ssl` plus the engine's own hardening, and the redaction behaviour is stdlib `re`.

**Every absence claim below carries a positive control that fired in the same run.** Where the
control a previous pass recorded did not reproduce, the replacement is named rather than the number
quietly changed.

| Item | Cell | What the verdict should become |
|---|---|---|
| #1181 | 12.3.5 | Stay **partial**, and re-anchor. Every load-bearing claim holds; every anchor in the row and its re-score has drifted. The hop the row calls "closable today" was already measured on a real socket by a test neither the row nor its re-score cites; three arms were missing and are added. It is also reachable in Posture B, which the source reads as forbidding. The reasoned cannot-pass still rests on the engine-to-SQL-Server store login. |
| #1183 | 13.3.2 | Stay **partial**, and replace the recorded basis entirely. The row's own suspicion is confirmed: both halves of the stated basis belong to sibling cells. Its redaction evidence is dead. The verdict survives on a limb the row does name but the residual does not rest on -- no read-privilege check exists anywhere in the engine. |

## #1181 (ASVS 12.3.5) -- what moved

**Anchors, all drifted, all re-measured.** `proxy_intra_service_auth` is at `config/settings.py:833`
(the row says `:771`, the research `:817`). Its sole read is at `:866` (the row `:804`, the re-score
and the research `:850`). The predicate's only consumer is `__main__.py:1954`.

**The absence claim holds.** One value comparison tree-wide, and it only asks whether the value is
`"none"`. The research's stated positive control (14 hits) did not reproduce for me; the replacement
is `policy.mode == "system"` / `== "pinned"` at `config/tls_policy.py:1343`, `:1346` -- two hits in
the same run, proving the probe can see a `Literal` branched on by value.

**The "closable today" claim was already measured, and the citation points at the wrong artifact.**
The re-score justifies it by reading `api/tls.py:58-62`. `test_real_mutual_tls_handshake_on_built_context`
has driven a real handshake against the exact context the serve path builds since the #200 residual,
covering both arms the re-score needed. Neither the row, its re-score nor its research names it.

**This pass built a second handshake harness before finding that one.** The duplicate was deleted
rather than landed. It is recorded because the rule it broke -- ask whether the work already exists
before you build it -- is the same reading error that put the row's citation on the source file
instead of on the test.

**Three arms were genuinely missing**, and are added beside the existing test, reusing its fixtures:
a certificate from an unconfigured issuer is refused, so presenting *some* certificate is not
enough; the causation control -- drop the client CA and the identical harness admits the
uncertificated peer, without which a refusal is equally consistent with a broken harness; and
reachability in the topology the setting is about.

**The one fact nobody had established.** `ensure_api_tls_material` returns `None` under
`tls_terminated_upstream`, which read alone says the mTLS this setting names is unreachable exactly
where it is declared. It is not: the operator-supplied branch sits above the no-mint one, so
terminator plus certificate plus client CA is a valid configuration and the engine really does
verify the proxy.

**Built.** Declaring `"mtls"` on a PHI instance while `[api].tls_client_ca_file` is unset now warns
at `serve`. It warns and never refuses: a sidecar in front of the engine can terminate the proxy's
mTLS legitimately, leaving a true `"mtls"` hop the engine sees as plaintext, so a refusal would rest
on an unobservable premise. `"network"` and `"shared_secret"` get no arm because nothing in the
process can read them.

The rule is a pure predicate in `config/tls_policy.py`, beside `in_process_tls_revocation_refused`,
so the whole 16-cell truth table is testable without a settings load. That is not tidiness: each
case reachable through `serve` costs a TOML, a `chdir` and five stubs to reach one boolean, so the
arm that *silences* the warning had no test -- and that is the arm a regression breaks quietly.

**The successor absence claim, specified in the same change as the row requires.** The old claim
("nothing branches on which value is set") now matches, for a diagnostic that changes no byte on any
wire. The claim that survives and decides the verdict is *no value of `proxy_intra_service_auth`
changes what the listener accepts*, pinned by `test_no_value_of_the_declaration_changes_the_listener`.

**One severity correction.** "A control that reports itself on while doing nothing" is exact. "An
operator would believe the hop was mutually authenticated" is weaker than it reads: the
configuration reference and the setting's own comment both say *attestation only, the engine
enforces nothing at run time*. Documentation is not a control (SDS-3.7), so the mechanism limb is
untouched; the belief limb rests on an operator not reading the one page describing the setting.

## #1183 (ASVS 13.3.2) -- what moved

**The row's suspicion is confirmed.** Both halves of the recorded basis belong to sibling cells, and
the anchor drifted as well: `require_managed_identity` is at `config/settings.py:521`, not `:488`.

**Premise dead on the whole redaction paragraph.** All five strings the row records surviving
verbatim, and the bearer defect it describes emitting the token, are redacted at `ebdfa44a6`.
Re-executed with the row's own two positive controls plus a negative control that must not be
touched, so a redactor that scrubbed everything could not have read as a pass. The row records its
own fix further down but never amended the survival list, so a reader who stops there carries six
dead findings away.

**Live, new, and fixed here.** `\b` does not fire after an underscore, so the engine's own
snake_case credential vocabulary was invisible to its own log redactor. Measured leaking verbatim:
`client_secret`, `bearer_token`, `basic_password`, `ad_bind_password`, `tls_key_password` and
`vault_token`. Five of the six are real identifiers in this tree. The exposure lands on both
surfaces the row names -- the support archive and `GET /logs/tail` -- because they share one
backstop. Fixed by widening the label group of two patterns with a separator-terminated prefix, plus
two families in the AST-derived domain guard so the mutation fixture proves the widened pattern is
what does the work.

**The first version of that fix shipped a new defect, and review caught it.** An unbounded prefix
makes both patterns quadratic in line length on exactly this surface: `_` suppresses the word
boundary but `.` and `-` do not, so an N-segment run gives the regex N start positions and the group
re-walks O(N) segments from each. Measured over 20 passes of one 6 KB run: 1.5 ms before the
widening, 827 ms unbounded, 11 ms bounded. Base64url uses `-`, so a JWT echoed into an upstream
error is precisely that shape. A repair for a confidentiality defect had opened an availability one.
Bounded at six segments, pinned by a guard proven to reject `*`, `+` and `{0,}`.

**The limb the verdict should rest on holds.** Zero read-class permission constants anywhere in
`messagefoundry/`, against 8 write-class sites in the same run. Both shipped permission predicates
are write-axis by construction. `pipeline/sandbox.py:616` still spawns the isolation worker with no
`env=`. Zero capability or token-introspection calls, against four `X-Vault-Token` sites as the
control.

**Why not the other verdicts.** Not `pass`: nothing in the engine grades who may read a key file.
Not `na`: the substrate argument fails on the project's own precedent, since the engine creates
these files, sets their permissions, and already refuses to start on an OS permission twice. Not
`fail`: `_assert_safe_config_source`, the trust-anchor guard, `_secure_file` and the derived
redaction domain are real and load-bearing.

## Deliberately not done

**Did not default `proxy_intra_service_auth` to `"mtls"`, and did not make any value enforcing.**
That is the exact shape #1181 exists to catch. The coherence warning is a diagnostic and the row
says so in the same sentence that specifies its successor absence claim.

**Did not answer whether an attestation-only setting should exist at all.** #1181 poses it and it is
an owner decision, not a build.

**Did not fix the separator-free prose form of a leaked credential** (`... failed with password
<value>`). A bare-space arm would eat `connection IB_DEMO_ADT bound, password rotation scheduled`,
which the redaction guard's own ordinary-diagnostics fixture pins. Under-redaction is the safe
direction there, and it is named rather than left looking overlooked.

**Did not build #1183's proposed work** -- the read-privilege preflight, the file-borne asset
registry, the process-principal self-check, the environment scrub, the subprocess environment. All
remain unallocated and by subject.

**Did not touch the store, Vault, OIDC, AI-broker or webhook hops.** They are #1181's and #1182's
inventory, re-measured here only to confirm the row's claims still hold.

## Checks

**Green, all on the worktree `.venv`:** `ruff check` and `ruff format --check` across
`messagefoundry` and `tests` (1,036 files); `mypy` strict, no issues in 268 source files; the backlog
status check at 679 items with both rows still declaring exactly one status; and pytest on every
suite covering a touched file -- `test_api_tls.py` (86, up from 82),
`test_log_redaction_secret_domain.py` (50), `test_support_bundle.py` and
`test_phi_logging_inventory.py` (43), plus `test_checks_gate_parity.py`, `test_security_config.py`,
`test_runbook_proxy_tls_floor.py` and `test_memory_encryption_readout.py` (70).

**Not run:** the full pytest suite did not finish inside the session. `test_cli.py` and the store
backend legs were not run locally. Hosted-runner-only legs were never visible here and must be read
on the PR.
