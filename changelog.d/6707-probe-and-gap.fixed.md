- **A Transit audit MAC 400 reads as a refused key version only when the probe under the latest
  version answers a well-formed MAC naming another version.** A probe answer that is not a
  well-formed MAC, at least an empty or versionless one, no longer clears it: the walk then could
  not run instead of reading a break, and a store open's genesis and pin checks raise its error
  rather than read a break. (vault `BACKLOG #6707`)
- **The text of a Transit audit MAC 400 not read as a version refusal now says its cause is
  unknown**, and names a refusal for another reason beside the two version causes. The Transit
  attestation's audit gap now says the row's MAC does not verify for a key version Vault's own
  reply refused, and that it could not be checked for at least an unconfirmed 400 and an outage
  the cipher raises, where it said Transit refused each. (vault `BACKLOG #6707`)
