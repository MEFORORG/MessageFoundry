- **The ECH egress sidecar contract states a framing rule.** A conforming sidecar reads and re-sends
  every request and reply, so it must not re-frame them. It keeps each request's `Content-Length`,
  refuses ambiguous framing rather than cleaning it up, and drops its connection to the partner after
  a misframed reply. [samples/ech-sidecar/README.md](../samples/ech-sidecar/README.md) links to the
  front-proxy rules rather than restating them. (`BACKLOG #1125`)
