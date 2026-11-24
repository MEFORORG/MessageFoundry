- **A Transit audit MAC 400 reads as a refused key version only when the probe under the latest
  version answers a well-formed MAC naming another version.** An empty or versionless probe answer
  no longer clears it, so such a check now could not run instead of reading as a break.
  (vault `BACKLOG #6707`)
- **The text of a Transit audit MAC 400 whose reply names no version refusal now says its cause is
  unknown**, and names a refusal for another reason beside the two version causes. The Transit
  attestation's audit gap now says the check failed, not that Transit refused it, since an outage
  or a proxy's page reaches it too. (vault `BACKLOG #6707`)
