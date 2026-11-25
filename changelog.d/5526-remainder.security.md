- **A detached-JWS signing header named `Authorization` no longer replaces the credential on a SOAP, REST or FHIR outbound, and a SOAP outbound refuses a `bearer_token` beside a Basic pair.**
  A SOAP outbound now refuses at construction a `bearer_token` beside a Basic pair, as REST and DICOMweb already
  did; it used to send Basic and drop the token without a word. A SOAP, REST or FHIR outbound
  refuses a detached-JWS signing header named `Authorization`, in any spelling, beside a
  configured or minted credential for that header, at least HTTP Basic, a `bearer_token`, an
  OAuth2 or SMART provider, or an `Authorization` entry in `headers`. The signature is written
  after the credential, so it replaced the credential on every send; beside HTTP Digest it was
  already refused. The static-credential
  inventory lists HTTP Basic alone where both a `bearer_token` and a Basic pair are set. It reads
  an `env()` `http_auth` as the build resolves it, and one it cannot resolve as HTTP Digest,
  except beside an OAuth2 or SMART provider whose enabled flags, and SMART token URL, are
  literal. The build refuses Digest beside a bearer provider, but at least an `env()` OAuth2
  token URL with no `oauth2_enabled` key can still resolve the provider off, and the inventory
  does not list Digest there.
  (`BACKLOG #5526`)
