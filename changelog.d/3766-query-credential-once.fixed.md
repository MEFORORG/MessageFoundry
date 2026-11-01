- **The URL query-credential WARNING now appears once on two more paths.** A reload into an engine
  started without a graph logged it twice, once from its build check and once from the start that
  follows. A start where one `FhirLookup` failed to build logged it up to three times for a lookup
  that did build. Each now logs it once. A `FhirLookup` that fails to build at a start still logs it
  once when its `url` resolved, so the URL is named while the lookup is down; its failure is
  recorded and alerted as before. The egress check now logs it before its refusals, so a connection
  it refuses, for example over an unlisted forward proxy, still logs it. Every refusal still runs on every build. See
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md). (`BACKLOG #3766`, `BACKLOG #2910`)
