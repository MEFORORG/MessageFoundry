- **The URL query-credential WARNING now appears once on two more paths.** A reload into an engine
  started without a graph logged it twice, once from its build check and once from the start that
  follows. A start where one `FhirLookup` failed to build logged it up to three times for a lookup
  that did build. Each now logs it once, and a `FhirLookup` that fails to build logs none; its failure
  is recorded and alerted as before. Every refusal still runs on every build. See
  [SECURITY-LOOSENING.md](../docs/SECURITY-LOOSENING.md). (`BACKLOG #3766`, `BACKLOG #2910`)
