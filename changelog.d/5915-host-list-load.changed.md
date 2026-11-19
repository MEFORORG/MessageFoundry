- **A `host[:port]` allowlist entry no host can match is refused at config load, ports compare as
  numbers, and an `http(s)://` URL with no port is matched at the port it dials.** At least
  `[egress]` `allowed_mllp`, `allowed_tcp`, `allowed_http`, `allowed_db`, `allowed_remote`,
  `allowed_smtp`, `allowed_direct`, `allowed_proxy`, `allowed_syslog` and `[ai].allowed_endpoints`
  now refuse such an entry, a URL or a `*` pattern included, naming the list and the entry's
  position and never its text; in the shipped code it loaded and admitted nothing. A blank entry in
  a TOML list is refused too; the comma-separated environment form of the `[egress]` lists still
  drops blank items, as before. A JSON list given in one of those environment variables is refused:
  write it comma-separated. An `allowed_db` entry naming an IPv6 address is refused too, and a
  DATABASE `server` holding a colon is still refused as unlisted, now saying why. A port that
  reaches the check as text, such as `06661`, matches `host:6661`, and `host:443` admits
  `https://host/`, though at least a `proxy_url` with no port still matches only an entry that names
  no port. [CONFIGURATION.md](../docs/CONFIGURATION.md) says how an entry is read. (`BACKLOG #5915`)
