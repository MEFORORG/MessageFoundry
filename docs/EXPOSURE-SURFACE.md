# What MessageFoundry exposes: a scoping map

**This page lists what the engine exposes and points to the document that holds each fact.** It is
for a site security team that runs an exposure-management program. Gartner calls that Continuous
Threat Exposure Management. Its first stage is scoping, which asks what each product exposes. This
page is the input to that stage for MessageFoundry.

It is a map, so it restates as little as it can. Where this page and a linked document disagree,
the linked document wins.

Three limits apply to the whole page:

- **It describes the engine as shipped.** What a deployment would expose depends on its
  configuration. [Read your own instance's lists](#read-your-own-instances-lists) says how to get
  that.
- **Its lists say "at least".** The full inventory of every interface is
  [section 5 of ASVS-L2-PHASE0-CHANGES.md](ASVS-L2-PHASE0-CHANGES.md#5-communications-inventory-asvs-1311).
  A test guards that inventory against drift, and the section says what the test can see.
- **Configuration is Python that runs inside the engine.** No allow-list on this page bounds what a
  Router or Handler module does. [DEPLOYMENT.md](DEPLOYMENT.md#egress-allow-lists) names the controls
  that do apply to that code.

---

## The engine listens on one operator socket, plus one socket per listening Connection

At least these open a listening socket. Each one binds loopback (`127.0.0.1`) by default.

| What listens | Bind address | Port | Read more |
|---|---|---|---|
| The operator API, the web console at `/ui` and the stats WebSocket, all on one socket | `127.0.0.1` while `[security].local_access_only` is true, the default. Otherwise `[security].listen_address` | `[api].port`, default `8765` | [Control-plane listeners](ASVS-L2-PHASE0-CHANGES.md#52-control-plane-listeners) |
| Each inbound Connection of type MLLP, raw TCP, X12, HTTP or DICOM C-STORE SCP | `[inbound].bind_host`, default `127.0.0.1`. A Connection can override it with `bind_address` | Set on the Connection. Only `DICOM()` has a default, `104` | [Message-plane connectors](ASVS-L2-PHASE0-CHANGES.md#51-message-plane-connectors) |

The other inbound types open no listening socket. A File Connection reads a directory. A
database-poll or remote-file (SFTP, FTP, FTPS) Connection dials out. Timer, loopback and
pass-through Connections reach no outside system.

These settings change the size of the operator surface:

- `[api].expose_docs` is false by default. Set to true, the engine also serves `/docs`, `/redoc` and
  `/openapi.json`.
- `[security].serve_web_console = false` stops the engine from mounting `/ui`.
- Under engine sharding, the supervisor gives each engine shard its own API port. Count one operator
  socket per engine shard.

For the firewall rule each listener needs, see
[ANTIVIRUS-FIREWALL.md](ANTIVIRUS-FIREWALL.md#windows-firewall). For the TLS and peer controls on
each listener, see the [channel matrix](DEPLOYMENT.md#channel--tls-posture-matrix).

## The engine dials out only to targets the operator sets

Each target below is one the operator sets. The engine's own update check makes no network call:
`[update_check].mode` accepts only `local`.

| Outbound hop | What limits the target | Read more |
|---|---|---|
| Outbound Connections, the `db_lookup` and `fhir_lookup` reads, and the database-poll and remote-file inbound types | The eight `[egress].allowed_*` lists, with `[security].block_unlisted_outbound` | [Egress allow-lists](DEPLOYMENT.md#egress-allow-lists) |
| SMART and OAuth2 token endpoints | `[egress].allowed_http` | [Egress allow-lists](DEPLOYMENT.md#egress-allow-lists) |
| Forward web proxy | `[egress].allowed_proxy` | [CONFIGURATION.md](CONFIGURATION.md#egress) |
| Alert webhook and alert email | `[alerts].webhook_allowed_hosts` and `[alerts].smtp_allowed_hosts` | [Egress allow-lists](DEPLOYMENT.md#egress-allow-lists) |
| AI assistance broker | `[ai].allowed_endpoints` | [AI.md](AI.md) |
| OpenID Connect identity provider | `[auth].oidc_allowed_endpoints` | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |
| Active Directory over LDAP | One target, `[auth].ad_server`. No allow-list | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |
| Store database on SQL Server or PostgreSQL | One target, `[store].server`. No allow-list. The default SQLite store is a local file | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |
| HashiCorp Vault, for the store key or for Connection secrets | One target each: `MEFOR_STORE_VAULT_ADDR` and `MEFOR_SECRETS_VAULT_ADDR` | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |
| Syslog forwarding and the startup clock check | `[logging].forward_host` and `[logging].ntp_peer` | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |
| Backup to a network share | `[backup].destination` | [Infrastructure hops](ASVS-L2-PHASE0-CHANGES.md#53-infrastructure-hops) |

The infrastructure-hops table also covers Kerberos sign-in and the browser leg of OpenID Connect.

Once `serve` is past the open-egress guard below, it turns `[security].block_unlisted_outbound` on
if the operator left it unset. A transport whose `[egress]` list is empty then refuses every
destination of its type.

Mirror each outbound firewall rule with its allow-list entry, so the two layers agree.
[ANTIVIRUS-FIREWALL.md](ANTIVIRUS-FIREWALL.md#windows-firewall) has the rules and the ports.

## Startup guards refuse an unsafe bind, and the operator socket always has TLS

`serve` checks the exposure before it opens a socket.
[DEPLOYMENT.md](DEPLOYMENT.md#bind-guard-behavior-summary) is the source of record for each guard,
its override and its exit code. A deploying site would meet at least these:

| Guard | What it does | Read more |
|---|---|---|
| Operator bind | Refuses a non-loopback operator bind that has neither an operator certificate (`[api].tls_cert_file`) nor a declared TLS terminator | [Before you expose off-loopback](DEPLOYMENT.md#before-you-expose-off-loopback) |
| Listener bind | Refuses a non-loopback MLLP, HTTP, DICOM, raw TCP or X12 listener that has no TLS. Raw TCP and X12 have no TLS to turn on | [Bind-guard behavior](DEPLOYMENT.md#bind-guard-behavior-summary) |
| TLS on the operator socket | The engine serves TLS on the operator socket. With no certificate configured, it mints a self-signed pair on first run and reuses it. One topology is excluded: with `[api].tls_terminated_upstream = true`, a reverse proxy terminates TLS and the engine speaks plaintext to it, so that hop is the site's to protect | [ADR 0172](adr/0172-the-engine-always-serves-tls-minting-a-self-signed-certificate-on-first-run.md) |
| Open egress | Under the default `[security].enforcement = enforce`, refuses to start while outbound egress is fully open: no destination list is populated and `[security].block_unlisted_outbound` is not set to true | [Egress allow-lists](DEPLOYMENT.md#egress-allow-lists) |

One more control acts on each request, after startup. `[security].allowed_client_networks` lists
the networks that may reach the operator socket. It is empty by default, which means no restriction.
It does not cover the inbound Connection listeners. Each of those takes its own
`source_ip_allowlist`. Behind a proxy the engine was not told about, or behind address translation,
this control cannot see the real client and does nothing. So treat it as a second layer behind a
host firewall.
[ADR 0151](adr/0151-operator-surface-source-network-allow-list-security-allowed-client-networks.md)
has the detail.

[SECURITY-LOOSENING.md](SECURITY-LOOSENING.md) lists every protective switch and what turning it off
costs.

## What sits on disk is listed in PHI.md

- [PHI.md, section 2](PHI.md#2-where-phi-lives--data-at-rest-inventory) is the inventory of where
  patient data rests.
- [ASVS-L2-PHASE0-CHANGES.md, section 4](ASVS-L2-PHASE0-CHANGES.md#4-key-management--cryptographic-inventory-asvs-1111--1112)
  is the inventory of keys.
- [ANTIVIRUS-FIREWALL.md](ANTIVIRUS-FIREWALL.md#path-exclusions) lists the Windows paths: the store
  file and its sidecars, the logs and the key files.

## Read your own instance's lists

| Question | Where to read it | Notes |
|---|---|---|
| Which Connections exist, of what type, on what host and port? | `messagefoundry graph --config <config dir> --json` | Offline. It reads the config directory and prints each inbound and outbound Connection with its type and settings |
| What is a running engine serving? | `GET /connections` | Needs the `monitoring:read` permission. One row per endpoint, with its method, peer and port |
| Which protective switches are off? | `messagefoundry security show`, or `GET /security/posture` on a running engine | Lists the effective `[security]` values and each active loosening |
| Which Connections carry a loosening, across all engine shards? | `messagefoundry check --config <config dir>` | It reads the whole config directory. `GET /security/posture` reports only the engine shard that answers |

## `messagefoundry verify` does not measure exposure

`verify` is an on-box acceptance check with five sections: host, store, smoke, manual and
federation. [testing/VERIFY.md](testing/VERIFY.md) is its reference. In short, it checks that the
host can run the engine, that the configured store opens, that one synthetic message routes, and
that the federated sign-in settings hold together.

It does not check at least these, read from `messagefoundry/verify/`:

- **Firewall rules, or reach from another host.** The `host.ports` row is always MANUAL. It only
  tests whether three ports are free on `127.0.0.1`.
- **The ports your Connections bind.** Those three ports are the `--mllp-port` value (default
  `2575`), a fixed `11112`, and `[api].port`. The row does not read your config directory.
- **The operator bind and its TLS.** The `manual.tls` row is MANUAL. A person confirms it.
- **Egress.** No row reads an `[egress]` list, and `verify` dials no partner. The self smoke is a dry
  run with no network. The live smoke sends one message to the engine's own listener.
- **Loosenings.** No row reads the loosening list. Use the posture read-out above.
- **Known vulnerabilities.** `verify` reads no advisory feed and no software bill of materials.

So a green run says nothing about exposure.
[What a green run proves](testing/VERIFY.md#what-a-green-run-proves--and-what-it-doesnt) states the
rest of its limits.

## Three documents feed a vulnerability program

| Input | Document | What to take from it |
|---|---|---|
| Component inventory | [SUPPLY-CHAIN.md](SUPPLY-CHAIN.md) | Each release carries a software bill of materials (SBOM) for Linux and one for Windows, a Vulnerability Exploitability eXchange (VEX) file, and signatures. Scan the SBOM for the platform you run |
| How the project ranks a dependency vulnerability | [.github/SECURITY.md](../.github/SECURITY.md#dependency-third-party-vulnerabilities) | Known exploited first (the CISA Known Exploited Vulnerabilities list), then the Exploit Prediction Scoring System (EPSS) score. The Common Vulnerability Scoring System (CVSS) score only breaks ties |
| How long an old version stays covered | [SUPPORT-POLICY.md](SUPPORT-POLICY.md) | Only the latest release is supported, with no back-port. A clock runs on adopting each security release, and the page gives the days |

The threat model and the security assessments are not published.
[SECURITY-DOCS-POLICY.md](SECURITY-DOCS-POLICY.md) says what is withheld and how to ask for it.
