# 0147 — Hardened runtime isolation for Router/Handler code: IPC-brokered sandbox (extends ADR 0087)

- **Status:** Proposed  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-07-21
- **Related:** [ADR 0087](0087-sandbox-subprocess-isolation.md) (the subprocess worker this extends) · [ADR 0010](0010-handler-callable-db-lookup.md) / [ADR 0043](0043-fhir-read-lookup.md) (`db_lookup`/`fhir_lookup` — the sanctioned reads to re-enable) · [ADR 0144](0144-security-lint-gate-over-admin-authored-router-handler-config.md) (the *static* half of the 15.2.5 defense) · HANDLER-CODE-SHARED-RESPONSIBILITY.md · ASVS risk-acceptance register (`ASVS-L3-RISK-ACCEPTANCE-REGISTER.md`) theme 6 (15.2.5) · BACKLOG #197 · CLAUDE.md §2 · the 2026-07-21 runtime-isolation research pass

---

## Context

[ADR 0087](0087-sandbox-subprocess-isolation.md) built the opt-in per-inbound **subprocess worker** — a
real **address-space** boundary between admin-authored Router/Handler code and the engine's DEK / audit
chain / sockets. Two limits remain, and together they are the heaviest ASVS **15.2.5** residual:

1. **It confines only the address space.** A buggy or compromised worker can still `open()` files, connect
   sockets, and import packages *within the child* — the boundary stops it reaching the *parent's*
   secrets, not the *host's* filesystem/network. 15.2.5's goal is anti-pivot/blast-radius containment;
   an address-space boundary alone does not deny egress/filesystem/imports.
2. **It must FORBID the two sanctioned reads.** CLAUDE.md §2 grants a purity carve-out — a Handler may make
   a *"live, read-only lookup … `db_lookup` … or a FHIR read/search via `fhir_lookup` … run off the event
   loop."* Those bridge back onto the engine's asyncio loop via `run_coroutine_threadsafe`, which a process
   boundary breaks — so ADR 0087 **fails them closed** in the sandbox (its AC-5). A sandboxed feed that
   needs live enrichment therefore cannot use the sandbox at all.

The 2026-07-21 runtime-isolation research (adversarially verified, 24/25 claims) resolved the two open
questions this ADR turns on:

- **Confinement is platform-asymmetric.** On **Linux**, **Landlock** lets an *unprivileged* process
  restrict its own ambient filesystem and (port-based) network rights with **no root** — enforcement needs
  only the self-set `no_new_privs` flag, and the restriction applies to the thread and all descendants
  (exactly the persistent-worker model). On **Windows** there is **no Landlock/seccomp equivalent**;
  confinement is assembled from an **AppContainer / lowbox token** (capability-based default-deny across
  files/registry/network/credentials) plus admin-installed **Windows Filtering Platform (WFP)** egress
  filters. No single mechanism confines both OSes, and **AppContainer blocks loopback by default**
  (`IsLoopback`) and grants only coarse address ranges (`internetClient` = `0.0.0.0`–`255.255.255.255`,
  no per-destination allowlist).
- **The brokered-capability winner is an IPC request-broker.** For a *default-deny sandbox that still
  permits a narrow, host-mediated back-channel*, an **IPC request-broker to the parent** beats an OS
  egress-proxy: the proxy path inherits AppContainer's loopback block and lacks per-destination
  allowlisting, whereas an IPC broker is transport-agnostic, works identically on both platforms, and
  **matches how `db_lookup`/`fhir_lookup` already bridge to the parent's event loop**.

## Decision

**Extend the ADR 0087 `[sandbox]` seam with an `isolated` mode that (1) re-enables the sanctioned read-only
lookups through a parent-held IPC broker and (2) confines the worker at the OS level (default-deny
egress/filesystem/imports), per platform.** Proposed (design only — no code in this lane).

- **(1) IPC request-broker for `db_lookup`/`fhir_lookup`.** The trusted **parent** holds the DB/HTTP
  capability. A sandboxed Handler's `db_lookup`/`fhir_lookup` call, instead of bridging to the loop
  in-process, marshals a **typed request** over the existing ADR 0087 length-prefixed pipe; the **parent**
  validates it against the **same `[egress].allowed_db` / `[egress].allowed_http` authority** (unchanged —
  a compromised child cannot widen it), runs it **read-only, GET-only, off the loop**, and returns the
  result. This turns ADR 0087's fail-closed (AC-5) into a **working brokered read** under `mode=isolated`.
- **(2) OS-level confinement of the worker (default-deny; brokered lookups the only egress).**
  - **Linux — Landlock + seccomp.** The child, *after* spawn and *before* running any admin code,
    self-imposes a Landlock ruleset denying filesystem writes and network connect/bind outside a narrow
    allowlist (the store/config dirs read-only; no direct egress — the broker is the only path out), plus a
    seccomp-bpf filter over dangerous syscalls. Unprivileged (`no_new_privs`), no root, no `CAP_SYS_ADMIN`.
  - **Windows — AppContainer + WFP.** The child runs under an AppContainer/lowbox token (capability
    default-deny: no network, no file capability), with WFP per-destination egress filters for anything the
    deployment must allow. Because AppContainer blocks loopback, **the broker rides an inherited pipe/handle,
    not a loopback socket** — which the IPC design already assumes.
- **Denial routing unchanged.** A confinement fault (a denied syscall, a broker-rejected request, a worker
  crash) routes to **`ERROR`/dead-letter post-ACK** via the existing ADR 0087 paths — never a NAK, never a
  crashed connection (count-and-log invariant).
- **Default-off, byte-identical.** `mode=off` (default) and `mode=subprocess` (ADR 0087) are unchanged;
  `mode=isolated` is opt-in. The parent-side `[egress]` allowlist stays the single authority.

## Acceptance Criteria

> EARS; design-level — each binds to a test on build (to-resolve items settle first).

- **AC-1** — WHERE `[sandbox].mode=isolated`, WHEN a sandboxed Handler calls `db_lookup`/`fhir_lookup`,
  THE SYSTEM SHALL satisfy it via the parent broker (read-only, off-loop) rather than raise `SandboxError`.
- **AC-2** — THE SYSTEM SHALL validate every brokered request against the same `[egress].allowed_db` /
  `[egress].allowed_http` authority as the in-process path, **parent-side**, so a compromised child cannot
  reach a connection the allowlist forbids.
- **AC-3** — WHERE the host is Linux with Landlock, THE SYSTEM SHALL deny the worker filesystem-write and
  direct network access outside the configured allowlist (self-imposed, unprivileged).
- **AC-4** — WHERE the host is Windows, THE SYSTEM SHALL run the worker in an AppContainer/lowbox token
  that denies network/file by default, with the broker over an inherited handle (not a loopback socket).
- **AC-5** — IF a confinement or broker fault occurs, THEN THE SYSTEM SHALL route the message to
  `ERROR`/dead-letter post-ACK (never NAK, never crash the connection).

## Options considered

1. **IPC request-broker + per-platform OS confinement — CHOSEN.** The only clean cross-platform
   "deny everything, allow exactly these two brokered lookups" model; reuses the ADR 0087 pipe and the
   existing `[egress]` authority; matches how the lookups already bridge to the parent loop.
2. **OS egress-proxy / allowlist (WFP / Landlock / seccomp-notify) as the broker.** Rejected as the
   *primary* channel: inherits AppContainer's loopback block and its coarse address ranges (no
   per-destination allowlist). Retained as **defense-in-depth** for any residual egress, not for the
   sanctioned lookups.
3. **WASI component model (host-supplied capability imports).** Deferred: the capability model is the
   cleanest in principle (host imports are the only way out), but **CPython-on-WASM / Pyodide is immature**
   for this engine (C-extension deps, throughput) and was not covered by the research pass. A future path
   if CPython-on-WASI matures.
4. **gVisor / Firecracker microVM.** Deferred / host-delegated: real isolation but **Linux-only** (Firecracker
   is KVM-only, no Windows parity) with a throughput tax worst on small, syscall-heavy per-message work.
   An environment-delegated host control, not the in-engine cross-platform default.
5. **In-language sandbox (RestrictedPython / PyPy).** Rejected (ADR 0087 + research): explicitly **not** a
   security boundary.

## Consequences

**Positive** — Closes the heaviest 15.2.5 residual with a **hard, cross-platform** confinement AND re-enables
the sanctioned live lookups the ADR 0087 sandbox has to forbid — so the
shared-responsibility split is finally backed by a real
technical boundary (the property the AWS Lambda / Firecracker precedent pairs with its split).

**Negative / risks** — Confinement is **asymmetric** (Landlock Linux-only, AppContainer Windows-only): two
code paths + platform-specific CI matrices. A broker round-trip + confinement add throughput cost (measure
before committing). Kernel/OS floors: Landlock filesystem lands in 5.13, **network rules in ~6.7**; AppContainer
needs the WP-15 host controls for WFP. The broker adds a typed IPC protocol surface to secure. WASI remains
unresearched.

**Out of scope** — WASI/Pyodide execution; the static lint (ADR 0144); load-time top-level config exec (ADR
0087 keeps the `_assert_safe_config_source` DACL gate); making `mode=isolated` a default (opt-in by design).

## To resolve on acceptance

- [ ] The Windows AppContainer **loopback workaround** for the broker — inherited anonymous pipe vs a named
      pipe with an SDDL scoped to the container SID.
- [ ] The Landlock **network-allowlist kernel floor** (≥6.7 for net rules) + the seccomp profile; the
      degrade path on an older kernel (FS-only Landlock, or refuse `mode=isolated`).
- [ ] A **throughput benchmark** of the broker round-trip + confinement vs the ADR 0087 subprocess baseline.
- [ ] Whether this ships as `[sandbox].mode=isolated` (a third mode above `subprocess`) or a sub-flag on
      `subprocess`.
- [ ] A **WASI / CPython-on-WASM feasibility spike** (C-extension deps, throughput) before re-scoring option 3.
