# 0152. In-use data protection for PHI — platform memory-encryption attestation (ASVS 11.7.1)

Date: 2026-07-22

## Status

**Accepted (2026-07-22)** — plan in `docs/security/ASVS-11-7-1-IN-USE-DATA-PLAN.md`.

Build state at acceptance:

| | |
|---|---|
| **Rung 1** — platform read-out, report-only | **Built.** `config/memory_encryption.py`; four `memory_encryption_self_reported_*` / `..._readout_source` fields on `GET /security/posture`, plus the in-body disclaimer `memory_encryption_note` (`ENGINE_UI_SEAM` 12 → 13). |
| **Rung 2** — operator declaration | **Built.** `[security].memory_encryption_operator_declared` (default `false`); an **exposed PHI** instance without it **warns at every start**, and refuses only when the estate opts in via `[security].require_memory_encryption_declaration` (default `false`) under `enforcement = enforce`. A contradiction is warned + reported as the tri-state `memory_encryption_readout_contradicts_declaration`, never refused. See the *2026-07-22 amendment* below for why the refusal is opt-in and why the field is not called "attested". |
| **Rung 3** — cryptographic attestation | **Not built.** No quote acquisition, no signature verification, no vendor-chain handling. |
| **Windows rung 3** | **Recorded infeasible in practice** — see *Windows rung 3 — spike conclusion* below. It is **platform-blocked, not API-blocked**. |
| Deployment requirements + runbook | **Written** — [`docs/SYSTEM-REQUIREMENTS.md`](../SYSTEM-REQUIREMENTS.md#hardware-memory-encryption--required-for-an-asvs-level-3-phi-deployment), `OFF-LOOPBACK-DEPLOYMENT.md` § *In-use data protection* (ladder row 12), [`CONFIGURATION.md`](../CONFIGURATION.md). |

**Accepting this ADR does not re-score 11.7.1.** The evidence for `Fail → Partial` now exists (a gate, an
attestation of record, and a reported platform measurement) but the verdict is an owner decision on the
assessment of record, deliberately not a side effect of shipping the build.

## Context

MessageFoundry targets **ASVS Level 3** because it carries PHI. On the 2026-07-22 single-posture
re-score (`ASVS-L3-ASSESSMENT-2026-07-22.md`) exactly
one requirement scores **Fail**, and this is it:

> **11.7.1** — *Verify that full memory encryption is in use that protects sensitive data while it is
> in use, preventing access by unauthorized users or processes.*

Four facts frame the decision. Each was verified rather than assumed.

**It is Level-3-only and net-new in ASVS 5.0.** OWASP's own mapping records `v5.0.0-11.7.1:
tag-v4.0.3: ADDED`, with no reverse mapping from any 4.0.3 requirement into V11.7. It therefore cannot
affect an L1 or L2 claim — our L1+L2 subtotal is `140 / 67 / 0 / 46`, **zero Fails**. We are pursuing
it because L3 is the stated target for a PHI system, not because the conventional bar demands it.

**Memory hygiene is not memory encryption, and OWASP has already ruled on that distinction.** During
the 4.x→5.0 cull OWASP **deleted** 4.0.3's V8.3.6 (overwrite sensitive memory when no longer needed)
as *"NOT PRACTICAL"* — and **kept** 11.7.1. So the zeroization/locking family is explicitly not what
this requirement asks for. We already ship that family and it does not move this cell: `_secure_zero`
over a `bytearray` via `ctypes.memset` ([`store/crypto.py:163`](../../messagefoundry/store/crypto.py)),
`VirtualLock`/`mlock` residency ([`:185-199`](../../messagefoundry/store/crypto.py)), DEK zeroization
after install ([`:314-325`](../../messagefoundry/store/crypto.py)) and plaintext zeroization
([`:462`](../../messagefoundry/store/crypto.py)) all landed in #198.

**CPython can protect keys but not message bodies, and that asymmetry is structural.** A DEK is small,
short-lived, and we own the buffer — hence the work above. An HL7 message is not: it is `str` end to
end by design (python-hl7/hl7apy parse `str`, the store is TEXT, Routers and Handlers receive
`.text`), and every `.split()`, regex match, `.encode()` and f-string in the parse/transform path
allocates a fresh immutable copy that no application code can reach or wipe. `AesGcmCipher.decrypt`
returning plaintext as a CPython `str` is precisely the exposure the assessment cites. Rewriting the
PHI path to `bytearray` would be an architectural change that still would not encrypt RAM.

**Reading a local flag does not satisfy an L3 control.** `/proc/cpuinfo` flags (`sev`, `sev_snp`,
`sme`, `tdx`), sysfs entries and vendor CLI output are all produced by the OS whose integrity the
requirement is protecting against. A compromised kernel or hypervisor can forge every one of them.
Only a **CPU-signed attestation quote, verified against the silicon vendor's root PKI**, is evidence
rather than assertion.

## Decision

**The engine measures and reports; the deployment determines the verdict.** MessageFoundry will not
claim 11.7.1 from documentation, from configuration, or from a local capability flag. It will acquire
the strongest evidence available on the host, verify it where verification is cryptographically
possible, and surface the result as a first-class posture field an assessor can read.

Three rungs, each an honest verdict in its own right:

1. **Platform read-out (report-only).** Detect and surface memory-encryption state in
   `GET /security/posture`, alongside the existing FIPS-provider attestation (`fips_mode` /
   `openssl_version`, [ADR 0120](0120-fips-provider-mode-attestation-report-only-on-security-posture.md)) — same shape, same report-only
   discipline, same "None = undeterminable" honesty. **This alone does not satisfy 11.7.1** and the
   field must be named and documented so it cannot be mistaken for satisfying it.
2. **Operator declaration.** `[security].memory_encryption_operator_declared`, required of an exposed
   PHI instance, mirroring the established unverifiable-property pattern
   (`MEFOR_TLS_REVOCATION_ATTESTED`, [`__main__.py:1413-1430`](../../messagefoundry/__main__.py); the
   Posture-B proxy declarations). This is the rung at which the cell can honestly move **Fail →
   Partial**. *(Amended 2026-07-22: a missing declaration **warns**; the refusal is opt-in via
   `[security].require_memory_encryption_declaration`, and the setting is named `operator_declared`
   rather than `attested`. Both changes are recorded under* Amendment *below.)*
3. **Cryptographic attestation.** Request a hardware-signed report from the platform and verify its
   signature against the vendor root — AMD SEV-SNP via `/dev/sev-guest` (`SNP_GET_REPORT`), VCEK
   chain verified with the `cryptography` dependency we already have; Intel TDX via `/dev/tdx_guest`.
   *(Corrected 2026-07-22: those device nodes are the **direct guest-device** backend only, and are
   absent on paravisor platforms including Azure **Linux** CVMs — see the spike conclusion below.)*
   This is the only rung that can support **Partial → Pass**, and even then the verdict is
   **deployment-gated**: it is Pass on hardware that provides it and Partial on hardware that does
   not. The engine reports which.

Two boundaries are part of the decision, not caveats to it:

- **No cloud-provider SDK dependencies.** MessageFoundry is on-prem by design. Azure attestation
  clients, AWS Nitro enclave tooling and equivalent SDKs are out of scope; a hospital running on a
  confidential-VM platform is served by the same generic guest-side interfaces above. Any dependency
  added for rung 3 goes through the normal verify-then-lock rule (§7 of CLAUDE.md); the preferred
  outcome is **no new dependency** — stdlib `ioctl` plus `cryptography`.
- **Windows is a spike, not a promise.** The service ships as a Windows/NSSM deployment. The Linux
  guest interfaces above are well-trodden; a reliable in-guest Windows path for SEV-SNP/TDX
  attestation is *not* established to our satisfaction and must be investigated before any Windows
  commitment is made. Until it is, the honest posture on Windows is rung 1 + rung 2.
  **The spike ran (2026-07-22); the answer is below and it is the answer this bullet feared.**

## Amendment (2026-07-22) — rung 2's scoping and its vocabulary

Adversarial review of the first build found two defects in how rung 2 was expressed. Neither changes
what the rung *is*; both change what it is allowed to break and what it can be quoted as saying.

**1. A missing declaration warns; the refusal is opt-in.** The first build refused an exposed PHI
instance under the default `[security].enforcement = enforce`. Measured, that meant `--env dev` with
nothing declared, bound off-loopback, on Windows → `rc=2`. Three facts compound there:
[ADR 0148](0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) makes **every**
built-in environment name derive `DataClass.PHI`, `dev` included; "exposed" includes the
loopback-behind-proxy topology `OFF-LOOPBACK-DEPLOYMENT.md` *recommends*, which the Posture-B gate
deliberately spares from its own refusal for exactly this reason; and on **Windows the read-out is
always `null`**, so no host can clear such a gate by being correctly configured. The result was a
refusal that hard-stops a service which boots today, over a **host property the operator cannot change
by editing anything** — a breaking change nobody sanctioned.

The governing rule is the one [ADR 0151](0151-operator-surface-source-network-allow-list-security-allowed-client-networks.md)
states for its own companion refusal: *"only fire on the opt-in, so it cannot break an existing
deployment."* So the built shape is **warn always** (every environment, both `enforcement` settings),
with the refusal behind `[security].require_memory_encryption_declaration = true` (default `false`),
which the `enforcement` dial then modulates as usual. The consequence is accepted and stated: **rung 2
is a declaration of record with a standing warning, not a fail-closed gate**, unless an estate opts in.
The plan's "warn (never refuse) on non-production" is satisfied *a fortiori*.

Two smaller corrections travel with it. The read-out is **no longer accepted as a substitute** for the
declaration: allowing it made the one signal this ADR calls non-evidentiary the only input in the
feature able to *relax* a control (a wrongly-positive read-out, or a device node someone planted,
discharged the requirement with nobody declaring anything). And activation is probed with
`is_char_device()` rather than `exists()`, so a zero-byte regular file in `/dev` cannot manufacture one.

**2. "Attested" was the wrong word for the weakest fact.** Four of the fields carry `self_reported`;
the fifth was the only value with *no measurement behind it at all* — a bare operator boolean — and it
was the one called `attested`. In confidential computing, the exact domain of 11.7.1, attestation means
a CPU-signed quote verified against the silicon vendor's root PKI, which is rung 3 and is not built. The
codebase's in-house use of "attested" for unverifiable operator claims (`MEFOR_TLS_REVOCATION_ATTESTED`)
is a real convention, but it does not travel with a JSON body leaving the building, and
`"memory_encryption_attested": true` is precisely the quotable artifact this ADR exists to prevent.
Renamed to `memory_encryption_operator_declared` on both the setting and the posture field; the guard
test that previously *permitted* `attest` in a field name now bans it.

Three consequences of the same principle land here:

- **The evidence artifact carries its own disclaimer.** Every posture body now includes
  `memory_encryption_note` — the sentence stating that this is a self-report plus an unverified
  declaration, that neither satisfies 11.7.1, and what would (vendor-root-PKI-verified attestation,
  not built). The startup strings quote the same constant. Previously every disclaimer lived where an
  assessor never looks: comments, docstrings, this ADR, the console HTML.
- **The contradiction flag is tri-state and under-reports.** `memory_encryption_readout_contradicts_declaration`
  is `null` unless something was measured that *could* contradict — so an AMD SME / Intel TME host
  (memory-controller-wide encryption, arguably the most literal reading of 11.7.1, and a mechanism with
  no guest-visible activation signal at all), a container that does not map the device node, and
  Windows are never accused. A bare `bool` fused *corroborated*, *undeterminable* and *nobody claimed*
  into one `false` — on Windows, `false` by vacuity.
- **The runtime strings say what is missing.** They name the absent **declaration**, not an absent
  protection the engine cannot see, and they never assert a measurement that was not taken.

## Windows rung 3 — spike conclusion (2026-07-22)

**Windows rung 3 will not be built. It is platform-blocked, not API-blocked** — and that distinction is
the point of recording it, because the two age differently: an API gap invites a workaround, a missing
platform does not. Findings, from a documentation-only time-boxed spike (no lab hardware was available;
confidence is noted per claim):

**A workable in-guest Windows path does exist, and it is not the blocker.** Under a **Microsoft
paravisor** (Azure confidential VMs; plausibly Azure Local) the hardware report is fetched at VM boot and
written to reserved **vTPM NV indices** — `0x01400001` carries a 32-byte `HCLA` header plus the raw
SEV-SNP (or TDX) report. That is deliberately a **vTPM** interface, not a SEV/TDX device, so it is
identical across Linux and Windows guests and across AMD and Intel. It is reachable from CPython through
stdlib `ctypes` → `tbs.dll` (`Tbsi_Context_Create` / `Tbsip_Submit_Command`) with `cryptography` for the
ECDSA **P-384** verification, so **the "no new dependency, no cloud SDK, no C extension" target holds on
Windows**. *(High confidence — primary Microsoft documentation, and Microsoft's own Windows tooling for
this is itself pure-Python `ctypes`.)*

**The blocker is that the platform does not exist where we deploy.** No on-premises hypervisor a hospital
runs today will boot MessageFoundry's Windows Server VM as a confidential guest: Hyper-V on-premises has
**no** confidential VM through Windows Server 2025 (the vNext Insider "Trusted Launch" is Secure Boot +
vTPM, explicitly **not** memory encryption); VMware ESXi 9.0's SEV-SNP is a *Limited Availability* release
whose guest requirements are stated in Linux-kernel terms and does not list Windows as a supported
SEV-SNP guest; and a Windows confidential guest **requires a paravisor**, which off Azure/Azure Local
nobody ships. *(High confidence on each platform fact — primary Microsoft/Broadcom sources. The
conclusion that the reachable on-prem hospital population is effectively zero is stated as an
**inference** from those facts plus 5–7-year refresh cycles.)*

**Consequences taken:**

1. **On-premises Windows is capped at rung 1 + rung 2 — an honest Partial — for a procurement/platform
   reason, disclosed.** That is the outcome the plan's Phase 3 anticipated; we take it rather than build
   toward a platform that is not there.
2. **No Windows capability read-out is built, and none should be.** Rung 1 on Windows reports `unknown`
   (every field `null`). The genuine activation signal is Hyper-V CPUID leaf `0x4000000C`, which has no
   Win32 wrapper — reaching it from Python means a C extension or `VirtualAlloc` shellcode, and it is in
   any case guest-observable data produced by the layer this requirement distrusts. Never infer from
   `Win32_Processor`, a CPU model, or a registry key. If Windows rung 3 is ever built, the presence of a
   **signature-verifiable** report at NV `0x01400001` is simultaneously the activation signal and the
   evidence: one mechanism, and no flag that can be mistaken for compliance.
3. **The Linux framing in this ADR was wrong and is corrected here.** `/dev/sev-guest` is absent on
   **Azure Linux** confidential VMs too — the paravisor runs SNP in vTOM mode and hides the native
   interface. The real split is **direct guest device** (KVM / AWS / GCP) vs **vTPM NV index** (Azure,
   Azure Local), which is **orthogonal to the OS**. Any future rung 3 is *two acquisition backends × two
   operating systems*, not "Linux vs Windows".
4. **Two questions stay open and are not answerable from documentation** (both were looked for): whether
   Windows TBS command-blocking rejects an owner-hierarchy NV read of `0x01400001`, and how Windows-side
   TPM owner auth affects that read. If a lab is ever authorised, it is 1–2 days on an Azure SEV-SNP or
   TDX **Windows Server** VM with one pre-registered question that can actually fail: *does the service
   account, via `ctypes` → `tbs.dll`, complete `TPM2_NV_Read` of `0x01400001` without
   `TBS_E_COMMAND_BLOCKED`, and does the extracted report verify offline against a cached AMD chain?*
   Everything else is settled.

Ruled out and not to be revisited without new facts: **VBS enclaves** (`EnclaveGetAttestationReport` is
real, but the report is signed by a Microsoft **software** key and VBS isolation is VTL0/VTL1 separation,
not silicon memory encryption — and the protected code would have to live in a VTL1 enclave DLL, which
the CPython PHI path cannot); **Shielded VMs / Host Guardian Service** (vTPM + BitLocker; at-rest, not
in-use); and vendoring `Azure/cvm-attestation-tools` (pins Python 3.12.8, installs Chocolatey, builds from
git submodules) or Microsoft's prebuilt Windows platform-checker binary.

## Consequences

- The scorecard gains a genuine route off its only Fail, without buying a Pass with prose.
- `GET /security/posture` becomes the evidence artifact for this control — an assessor reads the
  declared platform state rather than taking a runbook sentence on trust. This costs an
  `ENGINE_UI_SEAM` bump (as ADR 0120 did). Because it *is* the artifact, it carries its own limits in
  the body (`memory_encryption_note`); see the Amendment above.
- **Rung 2 does not stop anyone from deploying.** Its default outcome is a standing warning on an
  exposed PHI instance, not a refusal — the property is a host property, unsatisfiable on Windows, so a
  default refusal would have hard-stopped working deployments over something no config edit can fix.
  The enforcement path exists (`[security].require_memory_encryption_declaration`) and is opt-in.
- A **Pass is not achievable by us alone.** It requires the deploying organization to run on
  SEV-SNP/TDX-capable hardware. That is a procurement fact, and stating it plainly in the deployment
  requirements is part of this decision.
- Verifying a SEV-SNP VCEK chain normally fetches from AMD's KDS over the network. On-prem and
  air-gapped hospitals cannot rely on that, so rung 3 must support an **operator-supplied, cached
  vendor certificate chain** or it will fail closed in exactly the environments we target.
- **Rung 3 is not built, so no Pass is reachable today on any platform** — Linux included. Rungs 1 + 2
  are the shipped posture everywhere; on **on-premises Windows** they are also the *ceiling*, per the
  spike conclusion above. Every deployment therefore sits at Partial-with-a-disclosed-residual until
  either rung 3 lands on a direct-guest-device platform or the deployment moves to one that supports it.
- The residual after all three rungs is unchanged and must stay disclosed: even under hardware memory
  encryption, plaintext PHI and the unwrapped DEK live in CPython heap during processing, protected
  from the host and hypervisor but not from an attacker who achieves code execution *inside* the
  guest.

## Alternatives considered

**Assert it in the system requirements and claim Pass.** Rejected. Documentation is not
implementation — the discipline the 2026-07-22 re-score ran under, and the one that caught this
codebase's real defects (a runbook whose config block aborts on its first key; a doc describing an
audit field that did not exist). Every delegated control that legitimately scores Pass here is
*enforced or attested at a gate*, not asserted in prose. The system-requirements line is necessary
and will be written — it is simply not sufficient.

**Scope the requirement N/A as an infrastructure-layer control.** Deferred, not adopted. ASVS does
sanction N/A with a recorded rationale, but its enumerated grounds are *absent functionality* and
*external processes acting on the application* — not "the control exists but the platform provides
it". A prior assessment used exactly this rationale and the 2026-07-22 re-score overturned it. The
argument may still be winnable, but it must survive adversarial review before being signed again, and
it is strictly weaker than measuring the property.

**Rewrite the PHI path to `bytearray`/`memoryview` with explicit wiping.** Rejected. Architectural,
defeated by CPython's copy semantics in the parse/transform path, and it produces memory *hygiene*
rather than memory *encryption* — the exact distinction OWASP drew when it deleted V8.3.6 and kept
11.7.1.

**Do nothing and carry the Fail.** Legitimate, and remains the fallback if rung 3 proves infeasible on
the target platform. One L3-only Fail on a hardware-dependent requirement, honestly disclosed, is
worth more to a customer questionnaire than a Pass that does not survive scrutiny.
