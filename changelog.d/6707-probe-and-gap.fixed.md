- **A Transit audit MAC 400 reads as a refused key version only when the probe under the latest
  version answers a well-formed MAC naming another version.** A probe answer that is not a
  well-formed MAC, at least an empty or versionless one, now takes the unconfirmed label
  (`AuditKeyVersionUnverifiedError`) whatever the reply says, where it took the refused label. The
  row still reads as a break: the startup walk reports it and raises its `audit-chain` alert, and
  a planted genesis row still opens with an ERROR naming that row. (vault `BACKLOG #6707`)
- **The text of a Transit audit MAC 400 not read as a version refusal now says its cause is
  unknown**, and names a refusal for another reason beside the two version causes. The Transit
  attestation's audit gap still says Transit refused the check when the reply's wording reads as a
  version refusal (wording a proxy can imitate), and now says the MAC could not be checked for at
  least an unconfirmed 400 and an outage the cipher raises, where it said Transit refused each. (vault `BACKLOG #6707`)
