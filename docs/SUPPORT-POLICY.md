# Support & version policy

MessageFoundry is pre-1.0 and ships fast. This states the **support window**, the **adopter remediation
SLA**, and the **vendor/adopter responsibility split**, so re-pinning a security release is *mandatory
and clocked* — not "whenever someone looks."

## Supported versions

Only the **latest released version** is supported (pre-1.0). Security fixes land on the latest line;
there is **no back-port** to an older pin. Staying current *is* the support contract — the consumer
deployment model ([ADR 0017](adr/0017-consumer-deployment-model.md)) is built for it: the engine is a
read-only pinned wheel, so adopting a fix is a one-line `requirements.txt` bump + a green CI run.

## Adopter remediation SLA

Once a security release is available, adopt it (bump the engine pin, re-run your CI) within:

| Severity of the fixed issue | Adopt within |
|---|---|
| **Critical / KEV-listed** | **15 days** |
| **High** | **30 days** |
| Medium / Low | the next routine bump |

These mirror the **HIPAA Security Rule 2024 NPRM** (15-day critical / 30-day high patching proposal) as
a sensible default; your own risk acceptance may be tighter. The adopter-side **`audit-pin`** CI job
([`ADOPTER-CI.md`](ADOPTER-CI.md)) starts this clock automatically — a red `audit-pin` means the window
is open.

## Responsibility split (security is shared)

| The engine vendor (MEFOR) does | The adopter org does |
|---|---|
| Fast-response on dependency + own-code CVEs ([`SECURITY.md`](../.github/SECURITY.md) SLA) | Adopt security releases within the SLA above |
| Publish the fix + an advisory ([`security/ADVISORY-PROCESS.md`](security/ADVISORY-PROCESS.md)) | Watch the advisory channel / keep `audit-pin` green |
| Sign + attest release artifacts (SLSA / PEP 740) | Verify provenance on install (`verify-engine`) |
| Ship secure **defaults** (127.0.0.1 bind, auth required, deny-by-default egress) | Operate securely: config-dir ACLs, secrets, TLS posture, deployment |

Neither half alone closes the window: the vendor makes a fix available fast **and discoverable**; the
adopter adopts it fast. The SLA above is the adopter's half, made measurable.
