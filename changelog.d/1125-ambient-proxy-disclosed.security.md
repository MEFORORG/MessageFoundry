- **`serve` names a web proxy it picked up from the environment.** With `http_proxy`,
  `https_proxy` or `all_proxy` (in either case) or the Windows system proxy set, `serve` and
  `supervise` each log one WARNING at start. It names each proxy's host and port, never a user or
  password from its URL, and at least the engine hops that go through it, such as HTTP-family
  connections where no explicit `proxy_url` applies, the alert webhook and the Vault and OpenBao
  clients. With no proxy set it logs nothing. See
  [CONFIGURATION.md](../docs/CONFIGURATION.md#serve-names-an-environment-proxy-at-start).
  ([BACKLOG #1125](../docs/BACKLOG.md))
- **The deployment documents now state what a proxy in front of the engine must do about request
  framing.** A reverse proxy or load balancer must refuse the ambiguous request shapes the engine's
  own parser refuses, send each body with one `Content-Length`, and drop a connection after an
  error. A forward proxy named by `proxy_url` must not re-frame what it carries. See
  [DEPLOYMENT.md](../docs/DEPLOYMENT.md#a-proxy-in-front-of-the-api-must-refuse-the-request-shapes-the-engine-refuses).
  ([BACKLOG #1125](../docs/BACKLOG.md))
