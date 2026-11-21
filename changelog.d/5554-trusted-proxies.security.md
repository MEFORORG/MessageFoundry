- **An `[api].trusted_proxies` refusal no longer quotes the entry it refused.** An entry that does
  not parse as an address or CIDR network, such as a URL with a password in its userinfo, was
  quoted in the refusal, and so in every place a settings failure is printed, at least `serve`'s
  stderr, `check` and `validate`, `graph` and `dryrun` under `--env`. The refusal now names the
  entry by its position in the list, as in `[api].trusted_proxies entry 2 is not a valid IP
  address or CIDR network`. The host-bits, zone and allow-list single-host refusals name the
  position too; their advice still names the address or network the entry parses to. A
  `[security].allowed_client_networks` entry that does not parse, or is IPv4-mapped, is refused the
  same way. (`BACKLOG #5554`)
