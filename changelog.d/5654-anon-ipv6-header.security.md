- **The anonymizer's leak-check finds more routable IPv6 addresses and reads kept header
  components.** The IPv6 check reads an address joined by a dot to an allowed one, such as
  `fe80::1.4000:a1::5`, and an address written with fullwidth hex digits or colons. The dashed
  SSN, phone and IPv6 checks now read the components an `id`, `mrn`, `ssn` or `dln` rule keeps
  in a header field from MSH-3 on, as they read them in other fields. docs/PHI.md section 9 names forms the IPv6 check still misses. (`BACKLOG #5654`)
