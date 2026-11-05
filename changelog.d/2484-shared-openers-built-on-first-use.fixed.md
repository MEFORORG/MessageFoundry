- **An OpenSSL build that refuses the engine's TLS 1.3 or signature-scheme list is now reported as
  a configuration refusal where the shared HTTPS opener is first used, not as a failed import.**
  The verifying, no-redirect opener shared by the REST, SOAP, FHIR, DICOMweb, SMART and AI-broker
  hops, and the one shared by alert webhooks, were built when their modules were imported, so
  on such a build importing either module raised. Both are now built on first use, so a hop that
  uses one is refused with the error that names the refused list and the linked OpenSSL.
  Accepted and refused handshakes do not change.
