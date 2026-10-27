- **A `verify_tls = false` HTTP-family hop now refuses any static header outside a short
  allowlist.** The allowed names are `Accept`, `Content-Type`, `User-Agent` and `X-Request-ID`.
  Until now a secret under a neutral name, such as `X-Session`, crossed that hop, because the
  refusal read only names that look like a credential. The REST, SOAP, FHIR, DICOMweb and
  `FhirLookup` hops all apply it, and a credential-shaped value under an allowed name is still
  refused. A secret in the URL still crosses where the refusal cannot see it. A secret in the
  path crosses, because the engine cannot tell it apart from a legitimate path. A secret in a
  query parameter with a neutral name, such as `?sid=`, crosses too. See
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md#no-escape-sends-a-credential-to-an-unverified-peer).
  (`BACKLOG #3533`)
- **The AI broker refuses a plain `http` endpoint in every case.** Every call sends
  `[ai].api_key`, and `MEFOR_ALLOW_INSECURE_TLS` at `[security].enforcement = warn` used to
  release that key over `http`. No escape does now; use an `https` endpoint. (`BACKLOG #3533`)
