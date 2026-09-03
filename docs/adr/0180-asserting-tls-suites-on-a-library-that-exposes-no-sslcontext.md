# 0180 — Asserting TLS suites on a library that exposes no SSLContext

- **Status:** Accepted (amended 2026-09-03 — see Amendment A)
- **Date:** 2026-08-28
- **Related:** BACKLOG #1317 · `messagefoundry/config/tls_policy.py` (`harden_cipher_suites`, `build_asserted_https_handler`, `assert_ldap3_tls_suites`, `assert_hvac_tls_suites`) · `messagefoundry/auth/ldap.py` · `messagefoundry/config/secretprovider_vault.py` · `messagefoundry/store/keyprovider_vault.py` · `messagefoundry/store/crypto_transit.py` · `tests/test_tls_cipher_assertion_sites.py` · `.github/workflows/ci.yml`

---

## Context

BACKLOG #1317 hardened the engine's TLS cipher posture. Its core landed in `ae72f5828` and
`4e9bf38de`: `harden_cipher_suites` asserts that every suite a context would negotiate is
forward-secret, encrypting and peer-authenticating, and `build_asserted_https_handler` reaches the
context urllib builds for itself so the HTTP-family hops are checked rather than inherited.

The item's own row records what stayed open: *"ldap3, hvac and ODBC Driver 18 choose their own suites
and no engine object exists to assert on."* This ADR decides that remainder.

**The gap was measured before it was fixed**, with one instrument driving two real call sites:

| Arm | Site | `harden_cipher_suites` calls |
|---|---|---|
| A (positive control) | the HTTP-family opener | 1 |
| B (subject) | `LdapAuthenticator._server()` — the AD LDAPS bind | 0 |

Arm A proves the spy fires, so Arm B's zero is a missing call and not a dead instrument. Probing the
object the engine holds explains why: **an `ldap3.Tls` carries zero `SSLContext` attributes.** It
stores the arguments and builds the context inside `Tls.wrap_socket` at connect time, from
`create_default_context(Purpose.SERVER_AUTH, cafile=...)` plus `check_hostname = False` and
`verify_mode = validate`. There is no `ssl_context=` parameter to inject one through.

**What the gap is, and is not.** The suite list this hop actually resolves to is clean today — 17
suites, zero NULL, zero anonymous, zero non-forward-secret, at both `ad_tls_verify` settings. So the
defect is *inheritance without assertion*, the class `harden_cipher_suites`' own docstring names, not a
negotiable weak suite. A regression in the interpreter default, or a future `ssl_options` change,
would currently pass unnoticed here while every first-party hop caught it.

Severity is conditional per CLAUDE.md §0: with zero deployments, nothing is intercepted and no PHI is
exposed. A deploying site *would* cross an unasserted TLS context on its AD bind.

**The obvious fix is a trap, and it is measured.** `ldap3/core/tls.py` wraps `set_ciphers` in
`except ssl.SSLError: pass`. Routing suite policy through `ldap3.Tls(ciphers=...)`:

| cipher string | ldap3's result | resulting suites |
|---|---|---|
| none (today) | accepted | 17 = 14 TLS 1.2 + 3 TLS 1.3 |
| `ECDHE-RSA-AES256-GCM-SHA384` | accepted | 4 = 1 + 3 |
| `THIS-IS-NOT-A-SUITE` | **SSLError swallowed** | 3 = **0** + 3, TLS 1.2 list EMPTY |

A rejected string vanishes with no log line and silently strips every TLS 1.2 suite. That is a control
that cannot report its own failure — the false-premise shape SDS-3.7 forbids.

## Decision

**1. Assert a REBUILT context for the LDAPS hop, and pin the rebuild to ldap3's own construction by
measurement.**

`assert_ldap3_tls_suites(tls_kwargs, connector=...)` reconstructs what `Tls.wrap_socket` will build
from the same arguments and runs `harden_cipher_suites` on it, raising at construction.

This is deliberately weaker than `build_asserted_https_handler`, and the difference is the point.
That function can hold urllib's *own* context, so its test asks the discriminating question — *is this
the same object?* Here no such object exists, so identity has no answer and a replica is the only
instrument available. A replica is only honest if its drift is detectable, so two measurements stand in
for identity:

- **Context half.** `test_the_ldaps_replica_matches_the_context_ldap3_actually_builds` drives ldap3's
  **real** `wrap_socket` over a `socketpair` with `do_handshake=False`, captures the `SSLContext` off
  the resulting `SSLSocket`, and requires its suite list to equal the replica's. The replica is not
  re-derived either — it is taken off the `asserted_contexts` spy, so the comparison is between the
  exact object the shipped control checked and the exact object the hop will use. No peer, no network,
  but ldap3's own construction code really runs.
- **Argument half.** `_tls_kwargs()` is the single definition of the `Tls` arguments;
  `__init__` asserts it and `_server()` builds from it.
  `test_the_asserted_ldaps_arguments_are_the_ones_the_bind_uses` requires the two to agree. An
  equivalent context proves nothing if the bind is built from different arguments.

**2. REFUSE any `Tls` argument the replica cannot reproduce.** `_LDAP3_TLS_REPLICABLE_KWARGS` admits
`validate` and `ca_certs_file`. Anything else — `ciphers`, `version`, `ssl_options`,
`local_certificate_file` — raises. This converts the swallow trap above into a loud construction-time
error: a future edit reaching for `ciphers=` is refused rather than silently replicated wrongly.

**3. Assert once at construction, not per call.** The answer is fixed by configuration, `AuthService`
builds `LdapAuthenticator` eagerly, and `_server()` runs up to three times per login — so a per-call
replica would reload the OS trust store on the login path to re-derive an answer that cannot change.
A bad suite list now fails app startup rather than the first bind.

**4. `ca_certs_file` is accepted and NOT loaded.** Measured: a CA file changes the trust anchors and
not one entry of the negotiable suite list. Loading it in the replica would move a missing-CA failure
from connect time to construction time — a behaviour change on a control whose whole point is to
change nothing about the connection.

## Scope: the other two libraries the row names

**Vault (hvac) — NOT BUILT, concluded as research.** *Superseded 2026-09-03 by Amendment A below,
which built it. The paragraph is preserved because its reasoning is why the CI leg had to come first,
but its present-tense claims about CI and testability are no longer true — read the amendment.* The
row implies these are assertable from
`config/secretprovider_vault.py` and `store/keyprovider_vault.py`. They are not, today:

- Both do exactly one thing: `hvac.Client(url=, token=, allow_redirects=False)`. Zero `ssl`, zero
  `SSLContext`. hvac delegates to requests, which delegates to urllib3, which constructs and owns the
  context lazily per connection.
- **The scope note the row misses: there are THREE hvac clients, not two.**
  `store/crypto_transit.py` imports `_build_client` from `keyprovider_vault`, so the two construction
  points cover all three.
- **It cannot be verified here or in CI.** `hvac`, `requests` and `urllib3` are all absent from this
  interpreter, `hvac` is pinned but never installed (`requirements.lock:398`), and **no CI leg installs
  the `[vault]` extra** — measured across `.github/workflows/`, which installs
  `dev,harness,fhir,dicom,x12,xml,webauthn` plus `sqlserver`/`postgres`. The repo's own tests stand a
  recording fake in hvac's place.

Shipping a cipher assertion there would mean writing a security control that **no test in this project
can execute**, whose replica would have to mirror urllib3 internals rather than a documented
constructor, and whose only known injection point (`session=` with a custom `HTTPAdapter`) is a
*substitution* that changes pooling and redirect behaviour on a path with zero coverage. That is the
silent-control shape ADR 0158 catalogues, adopted deliberately. Recorded as unmeasured rather than
built.

**What would change this:** the `[vault]` extra installed on a CI leg. Then the honest instrument is
urllib3's **own** public constructor, `urllib3.util.ssl_.create_urllib3_context()` — the same function
urllib3 calls — not a hand-rolled look-alike.

**ODBC Driver 18 — OUT, permanently.** `store/sqlserver.py` contains no `ssl` usage at all; TLS is
expressed as connection-string keywords (`Encrypt`, `TrustServerCertificate`, `ServerCertificate`) and
terminated **inside the native driver**. There is no Python-side context to assert and no replica is
possible, because the suite list belongs to the driver and the OS TLS stack rather than to the
interpreter's OpenSSL. The posture that *is* reachable there — refusing `TrustServerCertificate=yes` /
`Encrypt=no` — is already enforced in that module. This is not a deferred item.

## Consequences

- The AD LDAPS bind is the seventh asserted site, and the first whose assertion runs on a rebuilt
  context. `tests/test_tls_cipher_assertion_sites.py` gains a section stating that plainly, so nobody
  reads it as an identity check.
- Raising `ValueError` (not `LdapError`) is deliberate: every other assertion site surfaces
  `ValueError`, and wrapping it would make a configuration refusal look like a connectivity failure.
- **The precedent this sets is narrow.** A replica is acceptable *only* where the library exposes no
  context AND its construction can be captured and compared in a test. Where the library's own context
  is reachable, assert it — substituting a look-alike silently changed ALPN and post-handshake auth
  when it was tried on the urllib hops. Where neither is possible (ODBC), say so rather than
  manufacturing a control.
- The `store/postgres.py` default arm stays an unasserted residual, unchanged and still pinned by its
  own test. This ADR does not touch it.

---

## Amendment A (2026-09-03) — the precondition was met, so the Vault arm is BUILT

This ADR named exactly one thing that would change the Vault verdict: *"the `[vault]` extra installed
on a CI leg. Then the honest instrument is urllib3's **own** public constructor,
`urllib3.util.ssl_.create_urllib3_context()`."* Owner-authorised 2026-09-03. Both halves shipped
together, and **the order is the point** — the leg came first, so the control has been executed.

**1. `[vault]` is installed on the `test` leg of `.github/workflows/ci.yml`.** That leg, and no other,
runs `tests/`, so it is the only install line that can exercise the assertion. Six small pure-Python
wheels, all already pinned in `requirements.lock` / `constraints.lock` — no re-lock was needed.
`tests/_extras_probe.py` now lists `vault`, so an interpreter without it announces the run as
INCOMPLETE instead of reporting a quiet green over skipped security tests.

**2. `assert_hvac_tls_suites` asserts a REBUILT context, pinned to urllib3's own constructor.** Same
shape as `assert_ldap3_tls_suites` and for the same reason, re-measured against the locked pins rather
than assumed:

| layer | holds an `SSLContext`? |
|---|---|
| `hvac.Client` | no — zero `ssl`/`context` attributes |
| its `requests.Session` | no |
| the `PoolManager` it builds | no — `connection_pool_kw == {'maxsize': 10, 'block': False}` |
| `requests.adapters._preloaded_ssl_context` | **gone in requests 2.34** (2.32 had it) |

So the context is built lazily per connection inside urllib3's
`_ssl_wrap_socket_and_match_hostname`, and the engine can never hold it. Driving a real `hvac.Client`
at a real socket shows urllib3 calling `create_urllib3_context` **once**, with
`{ssl_version: PROTOCOL_TLS, ssl_minimum_version: None, ssl_maximum_version: None, cert_reqs:
CERT_REQUIRED}`, yielding **17 suites — 14 TLS 1.2 + 3 TLS 1.3, zero NULL, zero anonymous, zero
non-forward-secret**. The bare replica matches that list exactly.

**One measurement corrects a guess this ADR came close to making.** `create_urllib3_context()` and
stdlib `create_default_context()` produce the **identical** 17 suites on the current OpenSSL. So the
reason to use urllib3's own constructor is *not* that a stdlib look-alike would differ today — it is
that only the real function tracks urllib3 if urllib3 ever narrows its own defaults. Stated because
"the look-alike is measurably wrong" would have been a satisfying and false argument.

**3. It REFUSES any `hvac.Client` argument it cannot replicate** (`_HVAC_CLIENT_REPLICABLE_KWARGS =
{url, token, allow_redirects}`). `session=` is the one that matters: it is the documented way to give
this hop a different TLS context, and a replica that accepted it would keep reporting a clean suite
list for a context the hop had stopped using. `verify=` is refused too, and **not** because it changes
the suite list — measured, `cert_reqs=CERT_NONE` yields the identical 17 — but because it is the knob
that turns peer verification off.

**4. Two construction points, three clients, and the sharing is now pinned by identity.**
`config/secretprovider_vault._build_client` and `store/keyprovider_vault._build_client` both assert;
`store/crypto_transit.py` imports the latter, and a test asserts `crypto_transit._build_client is
keyprovider_vault._build_client` rather than restating the claim in prose.

**5. The assertion and the construction read ONE kwargs dict.** The LDAPS site needed a second test
(`test_the_asserted_ldaps_arguments_are_the_ones_the_bind_uses`) because its asserted arguments and
its bind arguments lived in different methods. Here they cannot drift, because they are the same
object, so that whole failure mode is removed rather than tested for.

**6. `_build_client` moved OUT of its callers' `try` blocks**, in all three callers. Each had an
`except Exception` that relabels — *"could not read secret ... from Vault KV"*, *"could not
envelope-decrypt the store DEK"*, *"could not reach a Vault Transit key"* — which would have turned
this configuration refusal into what reads as a connectivity failure. That is the same mistake this
ADR records for the LDAPS site when it chose `ValueError` over `LdapError`. Fail-closed is unchanged:
both paths propagate and the subsystem refuses to come up.

**Mutation-proof, run rather than claimed.** Seven tests, five mutations, each applied alone with the
tree restored between: deleting the assertion from either construction point, making the
unreplicable-argument refusal inert, dropping `harden_cipher_suites` from the replica, and making the
replica build a context that *differs* from urllib3's — every one turns the suite RED, and the
restored tree returns green. The last is the one that matters for a replica: it proves the equivalence
test can detect drift rather than merely passing.

**ODBC Driver 18 is unchanged and stays OUT, permanently.** Nothing in this amendment bears on it.
