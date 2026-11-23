- **One credential owns the `Authorization` header on a SOAP or REST outbound.** A SOAP outbound
  now refuses at construction a `bearer_token` beside a Basic pair, as REST and DICOMweb already
  did; it used to send Basic and drop the token without a word. A SOAP or REST outbound refuses a
  detached-JWS signing header named `Authorization`, in any spelling, beside a configured or
  minted credential for that header, at least HTTP Basic, a `bearer_token`, an OAuth2 or SMART
  provider, or an `Authorization` entry in `headers`. The signature is written after the
  credential, so it replaced the credential on every send; beside HTTP Digest it was already
  refused. The FHIR destination still refuses it only beside HTTP Digest. The static-credential
  inventory lists HTTP Basic alone where both a `bearer_token` and a Basic pair are set. It reads
  an `env()` `http_auth` as the build resolves it, and one it cannot resolve as HTTP Digest,
  except beside an OAuth2 or SMART provider whose enabled flags, and SMART token URL, are
  literal, since the build refuses Digest beside a bearer provider.
  (`BACKLOG #5526`)
