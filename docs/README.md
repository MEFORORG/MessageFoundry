# MessageFoundry documentation

There are **377 markdown files** under `docs/`. Most of them are maintainer planning history, not
documentation. This page exists so you do not have to guess which is which.

**Filenames in this repository are unreliable signals.** `docs/CI.md` and `docs/ADOPTER-CI.md` describe
different repositories for opposite audiences. `docs/ASVS-L2-PHASE0-CHANGES.md` is operator notes.
`docs/testing/VERIFY.md` is an operator tool, not a test plan. Where a name misleads, this index says so
rather than repeating it.

> **Reporting a security vulnerability?** → **[`.github/SECURITY.md`](../.github/SECURITY.md)**, the
> disclosure policy. **Not** `docs/SECURITY.md`, which despite the identical filename is the
> authentication and RBAC reference. Two files, same name, different jobs.

---

## Start here — a new operator, in order

Six documents, in this sequence. Each one is cheap to read and answers a question that makes the next
one make sense.

1. **[EARLY-ADOPTER-GUIDE.md](EARLY-ADOPTER-GUIDE.md)** — the only doc that sequences the whole journey.
   It is an orchestration document: it ties the others together and adds the install-to-production
   rollout plan that nothing else carries. Read it first even if you skim it.
2. **[SYSTEM-REQUIREMENTS.md](SYSTEM-REQUIREMENTS.md)** — the cheap disqualifier, before you install
   anything. Hardware, OS, the Python floor, the three store backends, ports, and sizing by volume.
3. **[INSTALL-GUIDE.md](INSTALL-GUIDE.md)** — establishes the *deployment model*: a pinned, read-only
   engine wheel plus your own private git config repo (ADR 0017). This is the decision that is
   expensive to undo later, so understand it before you commit to a layout.
4. **[USER-GUIDE.md](USER-GUIDE.md)** — the task-oriented path. Clean machine → running engine → first
   message end to end → authoring connections, routers and handlers → operating the console and the
   VS Code extension → reading dispositions and troubleshooting.
5. **[DEPLOYMENT.md](DEPLOYMENT.md)** — **mandatory before any off-loopback bind.** Trust boundaries,
   the channel × TLS posture matrix, egress allow-lists, and the fail-closed bind guards that will
   otherwise refuse to start and leave you guessing why.
6. **[testing/VERIFY.md](testing/VERIFY.md)** — the gate before real traffic. `messagefoundry verify`
   is a wheel-only, on-box acceptance check that answers "is *this* box set up right, and does a
   message actually flow?"

Read alongside these, not after: **[SUPPORT-POLICY.md](SUPPORT-POLICY.md)** — only the latest version is
supported, and re-pinning a security release is mandatory and clocked.

Evaluating rather than installing? Start at **[FEATURE-MAP.md](FEATURE-MAP.md)**, the capability
catalog, and **[../CHANGELOG.md](../CHANGELOG.md)**, which is authoritative for what is actually built.

---

## Operators and adopters

| Document | What it answers |
|---|---|
| [EARLY-ADOPTER-GUIDE.md](EARLY-ADOPTER-GUIDE.md) | The whole install-to-production journey, in order. |
| [SYSTEM-REQUIREMENTS.md](SYSTEM-REQUIREMENTS.md) | Hardware, OS, Python floor, store backends, ports, sizing. |
| [INSTALL-GUIDE.md](INSTALL-GUIDE.md) | Pinned wheel + your own config repo; the ADR 0017 deployment model. |
| [USER-GUIDE.md](USER-GUIDE.md) | How do I actually do X — authoring, operating, troubleshooting. |
| [CONFIGURATION.md](CONFIGURATION.md) | Every settings key, what each gate refuses, and why. |
| [CONNECTIONS.md](CONNECTIONS.md) | Every transport and message type, and how to author each. |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Trust boundaries, TLS posture, egress, bind guards. Read before exposing anything. |
| [testing/VERIFY.md](testing/VERIFY.md) | On-box acceptance check: is this machine set up correctly? |
| [SUPPORT-POLICY.md](SUPPORT-POLICY.md) | What is supported, and the clock on re-pinning security releases. |
| [ANTIVIRUS-FIREWALL.md](ANTIVIRUS-FIREWALL.md) | Exact paths, processes and ports to exclude or open (Windows/NSSM). |
| [SERVICE.md](SERVICE.md) | Running the engine as a long-lived service. |
| [CLUSTERING.md](CLUSTERING.md) | Active/passive HA for the engine itself. |
| [CLOUD-DEPLOYMENT.md](CLOUD-DEPLOYMENT.md) | Multi-node HA on Kubernetes or cloud, with managed Postgres. |
| [CLOUD-PHI-HIPAA.md](CLOUD-PHI-HIPAA.md) | The PHI/HIPAA considerations that pair with cloud deployment. |
| [AOAG-DEPLOYMENT.md](AOAG-DEPLOYMENT.md) | Two-datacenter HA behind a SQL Server Always On AG. For DBAs. |
| [DEPLOY-SERVER-DB.md](DEPLOY-SERVER-DB.md) | Store setup on a real database server. |
| [ADOPTER-CI.md](ADOPTER-CI.md) | CI for **your config repo** — and honestly, what it does not prove. Not the engine's CI. |
| [ASVS-L2-PHASE0-CHANGES.md](ASVS-L2-PHASE0-CHANGES.md) | Operator notes for one hardening phase; §4–§5 are the living crypto and comms inventories. |
| [AI.md](AI.md) | How the shipped AI assistant is governed: modes, data scopes, RBAC, the PHI guarantee. |
| [DICOM.md](DICOM.md) · [HL7-VALIDATION.md](HL7-VALIDATION.md) · [CODESETS.md](CODESETS.md) | Per-domain references. |

## Developers building on the engine

| Document | What it answers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the engine decomposes: topology, store-as-queue, concurrency, module map. |
| [architecture-diagram.md](architecture-diagram.md) | The same structure as a picture. |
| [MENTAL-MODEL.md](MENTAL-MODEL.md) | The conceptual model behind the pipeline. |
| [FEATURE-MAP.md](FEATURE-MAP.md) | The capability catalog — what exists, what is deferred, what was declined. |
| [adr/](adr/) | **150 files.** Architecture decision records: *why* a thing is the way it is. Append-only history — a decision is superseded by a new ADR, never rewritten. Start at [adr/README.md](adr/README.md). |

## Security reviewers

| Document | What it answers |
|---|---|
| [../.github/SECURITY.md](../.github/SECURITY.md) | **Vulnerability disclosure policy.** Report here. |
| [SECURITY.md](SECURITY.md) | Authentication and RBAC — *not* the disclosure policy, despite the name. |
| [PHI.md](PHI.md) | Where PHI can and cannot go, and what the engine guarantees. |
| [ASVS-L2-PHASE0-CHANGES.md](ASVS-L2-PHASE0-CHANGES.md) | §4 key/crypto inventory and §5 communications inventory, both CI-drift-guarded. §1–§3 are a historical phase changelog. |
| [Secure_Development_Standards.md](Secure_Development_Standards.md) | The standards the build process holds itself to. |
| [SECURITY-LOOSENING.md](SECURITY-LOOSENING.md) | The inverse of a hardening guide: every `[security]` switch defaults to the protective position, and this is what moving one off it costs. |
| [SECURITY-DOCS-POLICY.md](SECURITY-DOCS-POLICY.md) | **Read this before hunting for a threat model.** The threat model, the ASVS assessments and the risk-acceptance register are deliberately *not* published; this explains what is public, what is withheld, and how to ask. |

## Maintainers and contributors

| Document | What it answers |
|---|---|
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | How to contribute. |
| [CI.md](CI.md) | What runs on a PR in **this** repo and which checks gate a merge. Not `ADOPTER-CI.md`. |
| [Code_Quality_Standards.md](Code_Quality_Standards.md) | The quality rubric. Contains a dated (July 2026) graded self-assessment — treat the grade as a snapshot. |
| [BACKLOG.md](BACKLOG.md) | **777 KB / 7,157 lines.** The maintainer work surface — ranked, deferred and declined items, including superseded sections. A required CI check keeps it current, but it is *not* a description of the product. For what the engine does, use `FEATURE-MAP.md`; for what is built, `CHANGELOG.md`. |
| [SECURITY-REMEDIATION-LEDGER.md](SECURITY-REMEDIATION-LEDGER.md) | Single-writer coordination ledger for the 2026-06-26 audit-wave remediation. A dated work record, not a posture statement. |
| [SESSION-MAIL.md](SESSION-MAIL.md) | The async session-to-session mail lane, for the peers the realtime channel cannot address (VS Code-launched and cross-login sessions). **A prototype, deliberately not wired.** Read its trust boundary and content rule before sending anything: the write side is unauthenticated by design, and delivery copies the body into a transcript no prune reaches. |

---

## Historical and planning artifacts

These directories are **dated records kept for provenance. Do not follow them as instructions** — many
describe plans that were superseded, and several state "next steps" that shipped long ago.

| Directory | Size | What it is |
|---|---|---|
| [benchmarks/](benchmarks/) | ~42 files | Measurement records and inter-session review notes. The numbers are dated; the *method* is the reusable part. |
| [design/](design/) | 4 files | Engineering design notes behind the threading and sharding ADRs. |
| [archive/backlog/](archive/backlog/) | 1 file | Closed backlog items, moved here verbatim when an item closes. |
| [quality-gates/](quality-gates/) | 1 file | A single gate record. |

`research/` and `archive/throughput/` were here until 2026-08-31, along with the maintainer
test-planning tree and the business and legal working documents. ADR 0160's D1 test keeps them out of
this repository: a tracked file has to be something an operator running MessageFoundry needs, or
something a security reviewer assessing it needs, and exploratory notes, superseded plans, QA planning
and commercial working papers are none of those. They are kept privately for provenance, so a citation
naming one of them still tells you where something was decided even though the link will not resolve
here. The one file in the test tree an operator actually runs stayed:
[testing/VERIFY.md](testing/VERIFY.md), listed above.

Security material is decided by a different rule and mostly stays —
[SECURITY-DOCS-POLICY.md](SECURITY-DOCS-POLICY.md) states it, and says how to ask for what is withheld.

Individually dated documents worth knowing are historical rather than current:

- **[CI-SELFHOSTED-RUNNER.md](CI-SELFHOSTED-RUNNER.md)** — carries its own **RETIRED** banner. The
  runners are de-registered. It also still contains a "the repo is private" security rationale that the
  retirement itself invalidates.
- **[CI-QUALITY.md](CI-QUALITY.md)** — a plain-language summary dated **June 20, 2026**, written for a
  non-technical evaluator. Its test counts have since moved; `CI.md` is the accurate technical version.
- **[REMOTE-CONSOLE.md](REMOTE-CONSOLE.md)** and
  **[REMOTE-CONSOLE-CUSTOMER-GUIDE.md](REMOTE-CONSOLE-CUSTOMER-GUIDE.md)** — both describe the
  **retired** PySide6 desktop console (BACKLOG #103, 2026-07-13).
- **[AI-OFF-MATRIX.md](AI-OFF-MATRIX.md)** — a coverage matrix from an internal plan. Its subject
  (working in the IDE with AI assist switched off) matters to adopters in PHI environments, but the
  document is keyed to internal item numbers.

---

## Repository-root documents

Not under `docs/`, and easy to miss:

| File | What it is |
|---|---|
| [../README.md](../README.md) | Project overview. |
| [../CHANGELOG.md](../CHANGELOG.md) | **Authoritative for build state** — what actually shipped, per release. |
| [../.github/SECURITY.md](../.github/SECURITY.md) | Vulnerability disclosure policy. |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) · [../GOVERNANCE.md](../GOVERNANCE.md) · [../MAINTAINERS.md](../MAINTAINERS.md) | Project process. |
| [../CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) · [../CLA.md](../CLA.md) | Participation terms. |
| [../LICENSE](../LICENSE) · [../NOTICE](../NOTICE) · [../COMMERCIAL-LICENSE.md](../COMMERCIAL-LICENSE.md) | Licensing. |

---

*This index is maintained by hand. If you add a document, add its row — and if it is a dated plan or a
one-off evaluation, put it under Historical and planning artifacts, not in a reference table.*
