# Proposed backlog items from Fable review packet 13 (release, packaging, Windows deployment)

Seven proposals, no numbers. The Manager allocates serially after the packets land (common rule of
2026-09-12: packets do not run `alloc.ps1`). Each carries its duplicate-search result. The full
reproduction for every item is in the vaulted findings document
`docs/reviews/FABLE-PACKET-13-RELEASE-2026-09-11-FINDINGS.md`, cited below as "the packet 13
findings".

Numbers on unmerged pull requests are written without a hash on purpose:
`tests/test_dangling_citation_check.py` reds a hashed citation of a still-issuable number, and PR
1072 went red on exactly that.

---

## Proposal 1. the release job fetches sbomqs with a same-origin checksum and runs it inside the signing identity before the Sigstore step

> Filed - not started. Value **6/10** · Difficulty **2/10** · _no research_. `release.yml` downloads
> the `sbomqs` tarball and its `checksums.txt` from the same upstream GitHub release, compares one
> against the other, installs the binary with `sudo` and runs it, all inside the `release` job that
> holds `id-token: write`, `contents: write` and `attestations: write`, and before the Sigstore sign
> step. The checksum proves the two files match each other, not who published them.
> Verdict: build
> Research: none
> Closing-act: code

**Cluster:** release / supply chain. **Priority:** P2. **Verdict:** build.
**Severity:** no live exposure (sec. 0 -- zero deployments, and no compromise is claimed).
Conditional: **a replaced upstream release asset would execute with the identity that signs and
publishes the next release**, so a backdoored wheel would carry a valid Sigstore bundle and valid SLSA
provenance. The sign step's own comment names this hazard for the pip installs beside it; this step
is the same class through a different route.

### Why the existing rule does not see it

`tests/test_ci_venv_pinning.py` has a release-asset download rule that requires `sha256sum -c` and
forbids `curl | tar`. It is scoped to the blocking jobs of `security.yml` and does not read
`release.yml`. Its scoping reason, that an advisory job cannot turn a required context green, is
about contexts; the hazard here is the identity the job holds, and `continue-on-error` on the step
changes nothing about what the step executes.

### What closing looks like

Pin the asset's SHA-256 in the workflow, the way `install-service.ps1` pins NSSM, or verify the
upstream's signature over the checksums, or move SBOM scoring out of the signing job entirely
(security.yml already scores the same SBOM shape in a job with no publishing scopes). Extend the
pinning test's download rule to `release.yml`, keyed on the job's permissions rather than on
whether the job is required.

Acceptance: a workflow-shape test that fails when any step in a job holding `id-token: write`
fetches an executable without an in-repo pin or signature verification. Do not test by publishing.

**Duplicate search.** `#332` covers the pip-installed signing toolchain and mentions neither
`sbomqs`, `curl` nor `goreleaser`; its step 6 (PR 1039) hash-locks build and cyclonedx-bom and does
not touch this step. `#1485` names `sbomqs` only as a docs-placement note. `BACKLOG-CLOSED.md`
has no match. Not a duplicate.

---

## Proposal 2. nothing pins the H-13 log-directory ACL: deleting the call leaves every test green and the Windows smoke never reads the DACL it produced

> Filed - not started. Value **6/10** · Difficulty **2/10** · _no research_. With the
> `Set-SecureDataDirAcl -Path $DataDir` call in `install-service.ps1` replaced by a comment, six
> service and install test files reported 113 passed, 89 skipped, zero red. No test references the
> call. `windows-service-smoke` runs the installer and never runs `icacls` against the log
> directory; its only mention of the function is a comment.
> Verdict: build
> Research: none
> Closing-act: code

**Cluster:** Windows service install / test coverage. **Priority:** P2. **Verdict:** build.
**Severity:** no live exposure (sec. 0 -- zero deployments). Conditional: **a refactor that
dropped or reordered the call would ship green, and a first deployment would have world-readable
service logs again**, which is the June H-13 finding the call was written to close.

### Measured, with the fix beside it

The fix itself works: extracted from the live script and run against a temp directory, it stripped
the inherited `Users:(RX)` entry and left `SYSTEM` and `Administrators` only, and an unelevated
reader was then denied the log file. What is missing is the witness.

### What closing looks like

In `windows-service-smoke`, after the install step, run `icacls` on
`C:\ProgramData\MessageFoundry\logs` and assert that no `S-1-5-32-545`, `S-1-5-11` or `S-1-1-0`
ACE is present and that the run-as account holds M. Add a static assertion in
`tests/test_service_install_manifest.py` that the call exists on the default path and is ordered
after `ObjectName` is set. The config-directory ACL is indirectly witnessed already (the
config-source guard refuses to start otherwise); the data and log directory has no such witness,
because the service account is granted M either way.

Acceptance: the smoke goes red with the call removed; the manifest test goes red with the call
moved before `ObjectName`.

**Duplicate search.** 1553 (PR 1064) covers the `-AllowLocalSystem` rerun leaving the old account
without access, and asks for execution coverage of the account branches; it does not ask for a DACL
assertion. `#224` (closed) is the least-privilege default; `#44` (closed) is the key-file DACL.
Not a duplicate. Related to 1553 and could ship in the same change.

---

## Proposal 3. the harness and console wheel smoke steps read the version out of the filename and never install or import the wheel

> Filed - not started. Value **6/10** · Difficulty **2/10** · _no research_. `release.yml`'s
> "Smoke-check the harness wheel" and "Smoke-check the console wheel" steps derive `built` from
> `glob('*-dist/*.whl')[0]` with a regex over the filename and compare it to the tag. Neither
> creates a venv from the wheel, imports the package, or reads its `RECORD`. Only the engine's
> smoke installs its wheel, and 1583 records that even that one imports the checkout.
> Verdict: build
> Research: none
> Closing-act: code

**Cluster:** release / artifact verification. **Priority:** P2. **Verdict:** build.
**Severity:** no live exposure (sec. 0 -- zero deployments, and no defective artifact is claimed).
Conditional: **a release would attach, and with the publish variable set would publish, a harness
or console wheel that does not import**, with both smoke steps green. Hatchling writes the filename
from the version module regardless of what the force-include found, so a moved or empty package
tree changes nothing in the name.

### What closing looks like

For each second wheel: `python -I -m venv`, install the wheel, import the package with
`PYTHONSAFEPATH=1` from a source-free directory, assert the module's `__file__` lies inside the
venv, and compare `importlib.metadata.version(...)` to the tag. Have
`tests/test_release_pipeline.py` count one install-and-import per wheel-building job, the way it
already counts PEP 440 compares per job.

Acceptance: keep an intact checkout present and require a wheel with an empty package tree to fail
each smoke.

**Duplicate search.** 1583 (PR 1064) is the engine smoke's checkout-shadow defect and its fix does
not touch the second wheels; 1585 is the harness's unbounded dependency specifier; `#1193` is the
console's provenance under ASVS 15.2.4 and does not name the smoke. Not a duplicate; the fix should
share 1583's isolated-mode pattern.

---

## Proposal 4. the harness wheel ships harness/CLAUDE.md through a whole-directory force-include

> Filed - not started. Value **3/10** · Difficulty **1/10** · _no research_. A real build of
> `packaging/messagefoundry-harness` produced 101 members including `harness/CLAUDE.md`, the nested
> Claude Code conventions file. The engine sdist, engine wheel and console wheel were built on the
> same tree and are package-only.
> Verdict: build
> Research: none
> Closing-act: code

**Cluster:** packaging / published-artifact integrity. **Priority:** P3. **Verdict:** build.
**Severity:** no live exposure (sec. 0). Conditional: **a published harness wheel would carry
maintainer process text.** Nothing in that file is PHI or a secret and the root `CLAUDE.md` is
public in the same repository, so this is "ship only intended content" (rubric signal 6), not a
leak.

### What was ruled out

`__pycache__` does not ship: thirteen cache directories were created under `harness/` and a rebuild
carried zero `.pyc` members, so hatchling's default exclusions hold under force-include.

### What closing looks like

An `exclude` for `CLAUDE.md` under the harness wheel target, and a wheel-content allowlist test for
both second wheels mirroring the engine sdist one in `tests/test_release_pipeline.py`, so the next
non-package file under `harness/` or `messagefoundry_webconsole/` is caught before a tag.

**Duplicate search.** No open or closed item mentions the harness wheel's contents; `#1192` is
about engine subcommands in the engine wheel. Not a duplicate.

---

## Proposal 5. alloc.ps1 is not re-entrant: a re-run for the same worktree and title issues a second number instead of returning the claim it already wrote

> Filed - not started. Value **5/10** · Difficulty **2/10** · _no research_. Registry records
> 1607 and 1608 carry the identical title and the identical worktree, 53 seconds apart; the item
> was filed as 1608 and 1607 has no heading on any ref. The claim file is written before the
> announcement is printed, so a process killed in between leaves a claim its caller never hears
> about, and the allocation loop has no lookup for an existing claim by the same owner and title.
> Verdict: build
> Research: none
> Closing-act: code

**Cluster:** coordination tooling / ledger allocator. **Priority:** P3. **Verdict:** build.
**Severity:** no deployment axis (sec. 0). The cost is one burned number per kill, paid by this
repository's own sessions, and it is highest exactly when the machine is loaded enough to kill a
sweep.

### Why the existing instruments do not see it

`alloc_strand_sweep.py` classifies claims by whether their recorded worktree and branch can still
commit; here both keys are aligned, so the record reads as healthy. `scripts/worktree/remove.ps1`
refuses to remove a worktree holding a claim with no landed heading, which is the first time anyone
is told, and by then the number has been re-filed under the next one. `claim.ps1` does not share the
exposure: re-taking a key you already hold refreshes it.

### What closing looks like

Before the `CreateNew` loop, scan the registry directory for a record whose `worktree` equals the
owner tree and whose `title` equals `-Title`, and return that number with a note instead of issuing
a new one. A directory read, no sweep. Add a test that a second invocation with the same title and
owner returns the first number.

**Duplicate search.** `#1535` records a kill that left **no** claim (the sweep died first) and says
so explicitly. `#1534` is the per-ref process cost. `#1282` and `#1293` are about a deleted worktree.
`#1039` is about `worktree add --force`. None covers a claim written and then re-issued. Not a
duplicate.

---

## Proposal 6. uninstall-service.ps1 says only logs and the store remain; a logon right, an orphaned config ACE, a stripped inheritance and the cached NSSM binary also remain

> Filed - not started. Value **3/10** · Difficulty **2/10** · _no research_. The uninstaller
> removes the service registration and prints that the logs and store under the data directory are
> left in place; `docs/SERVICE.md` says the same. Also left, unmentioned: the SeServiceLogonRight
> grant made for the virtual account, the `NT SERVICE\<name>:(OI)(CI)RX` entry on the config
> directory (an unresolvable SID once the service is deleted), the inheritance strip applied by
> `-LockConfigDir`, and `bin\nssm.exe` under the data directory. The WER keys are documented as
> persistent elsewhere in the same document but not in its uninstall section.
> Verdict: build
> Research: none
> Closing-act: code

**Cluster:** Windows service install / removal. **Priority:** P3. **Verdict:** build.
**Severity:** no live exposure (sec. 0). Conditional: **an operator would believe a host was
returned to its pre-install state while a logon right and an orphaned ACE remain.** Each leftover
is minor; the defect is the completeness claim.

### What closing looks like

Print an inventory of what is left at the end of uninstall, and offer `-RemoveLogonRight` and
`-RestoreConfigAcl` switches for the two that need elevation to undo. Correct the docstring and the
`SERVICE.md` uninstall section in the same change.

Acceptance: drive the uninstaller with fakes and assert the inventory names every leftover the
installer creates; assert the two switches issue the reverse operations.

**Duplicate search.** 1558 (PR 1064) is the uninstaller's swallowed stop status and re-reads
nothing about what remains. `#99` is gMSA hardening. Not a duplicate.

---

## Proposal 7. security.yml's header names CodeQL as a required context and every job but two as required, and the live set disagrees on both

> Filed - not started. Value **2/10** · Difficulty **1/10** · _no research_. The header says every
> job except `sbom` and `trivy` is a required context; `released-line-audit` is advisory by its own
> comment. It says CodeQL "IS a required context"; the live branch protection read during the
> packet has 13 contexts and no CodeQL, `required-contexts.txt` matches those 13 exactly, and
> `#1384` records the CodeQL contexts as deliberately not required.
> Verdict: build
> Research: none
> Closing-act: doc

**Cluster:** CI / documentation accuracy. **Priority:** P3. **Verdict:** build.
**Severity:** no live exposure (sec. 0). Conditional: **a reader weakening a gate on the strength
of the header would be wrong about which gates block.** No control rests on the header:
`tests/test_security_posture.py` reads the checked-in required set.

### What closing looks like

Replace both enumerations with a pointer to `.github/required-contexts.txt` (SDS-3.5: state a
load-bearing fact once and link to it). One comment edit.

**Duplicate search.** `#1384` and `#1404` are about the checked-in file drifting from the server and
do not name the workflow header. Not a duplicate.

---

## Findings deliberately not filed

- Refuted or deprioritized in the packet 13 findings, section 7: the fork-PR structural-only scan
  (the `merge_group` run carries the secret), `ci-gate` counting skipped legs as passes (by design),
  the docs-only classifier, `__pycache__` under force-include, the NSSM download TOCTOU in an
  administrator's `%TEMP%`, the best-effort ACL warning, the `.floor-highwater` write under
  concurrency.
- Handed to packet 18: `docs/SERVICE.md`'s manual log-ACL recipe omits SYSTEM and uses the
  English "Administrators" name where the installer uses well-known SIDs.
- Already filed and cited rather than re-filed: 1550, 1583, 1584, 1546 (PR 1060), `#332` step 6
  (PR 1039), 1578, `#1390`, 1553, 1554, 1556, 1558, 1566, 1567, 1573, 1585, 1592.
