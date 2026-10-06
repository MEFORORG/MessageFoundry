- **BREAKING: an off-loopback DICOM server (SCP) no longer counts a too-wide `source_ip_allowlist`
  as a peer control.** Every entry must now be a /8 or narrower for IPv4, or a /32 or narrower for
  IPv6, the same floors the HTTP intake gate applies. `["0.0.0.0/0"]` used to satisfy the gate while
  admitting everyone; now the SCP is refused at construction unless mTLS is set, and the error says
  the list is too wide. The floor rule moved into `messagefoundry/netaddr.py`, so the two gates share
  one function. mTLS still counts by presence, with no client-subject binding; that half is not
  built. (`BACKLOG #2622`)
