- **A Transit audit MAC 400 takes the refused label only when the probe under the latest
  version answers a well-formed MAC naming another version.** A probe answer that is no
  well-formed MAC, at least an empty, versionless or non-text one, now takes the unconfirmed label
  (`AuditKeyVersionUnverifiedError`) whatever the reply says, and reads as a break at the row: the
  startup walk reports it and raises its `audit-chain` alert, and a planted genesis row opens with
  an ERROR naming that row. Two such answers, a text one starting `vault:v<the row's version>:`
  and a non-text one, made the check one that could not run before, with no alert; they are a
  break now too. (vault `BACKLOG #6707`)
- **The text of a Transit audit MAC 400 not read as a version refusal now says its cause is
  unknown**, and names a refusal for another reason beside the two version causes. The Transit
  attestation's audit gap still says Transit refused the check when the reply's wording reads as a
  version refusal and the probe answers a well-formed MAC (wording a proxy can imitate), and now
  says the MAC could not be checked for at least an unconfirmed 400 and an outage the cipher
  raises, where it said Transit refused each. (vault `BACKLOG #6707`)
