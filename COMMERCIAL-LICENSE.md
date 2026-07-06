# MessageFoundry Commercial License

> **⚠️ Not yet a binding offer — terms pending legal review.** This document describes the
> *intended* commercial-licensing posture for MessageFoundry. The specific terms (grant scope, fees,
> support, and usage thresholds) are **not finalized** and are subject to legal review before any
> commercial license is offered or executed. Nothing here is an offer, a contract, or legal advice.
> For current, binding terms, contact the maintainer (see [How to inquire](#how-to-inquire)).

## The short version

MessageFoundry is **open source under the GNU AGPL-3.0-or-later** (see [LICENSE](LICENSE)). For most
adopters — running the **unmodified** engine inside your own network to integrate your own systems —
the AGPL imposes **no source-disclosure obligation on you**, and **no commercial license is
required**.

A separate **commercial license** is intended for organizations whose use the AGPL does not
comfortably cover (see [Who needs one](#who-needs-a-commercial-license)). MessageFoundry follows the
standard **open-core / dual-licensing** model: the same engine is offered both under the AGPL and,
separately, under commercial terms. The project's ability to dual-license comes from the contributor
relicensing grant in the [Contributor License Agreement](CLA.md) (an Apache-ICLA-derived template that
is itself pending legal review).

## Who needs a commercial license

In the project's understanding of the AGPL — this is **not** legal advice, so confirm your own
situation — you do **not** need a commercial license to:

- Run the **unmodified** MessageFoundry engine inside your organization (including as a network
  service) to integrate your own systems.
- Author your own Connections / Routers / Handlers in a separate `--config` repo. The project's
  position is that adopter config loaded via `--config` is a **separate work**, not a derivative of
  the AGPL engine — see [docs/DUAL_LICENSING_PLAN.md](docs/DUAL_LICENSING_PLAN.md). (This position is
  itself pending legal review.)

You may need one if you intend to:

- **Modify the engine and distribute it, or operate your modified version as a network service**,
  without meeting the AGPL §13 obligation to provide your modified source to that service's users.
- **Embed or redistribute the engine inside a proprietary product** under terms incompatible with the
  AGPL's copyleft.

If you are unsure whether the AGPL covers your use, ask before assuming you need a commercial license.

## What it would cover (intended, not final)

A commercial license is intended to grant rights **in addition to** the AGPL — for example, the right
to modify and distribute or network-operate the engine without the AGPL §13 network-source obligation
— under negotiated terms. **Fees, support levels, the precise grant, and any usage thresholds are not
yet established.** Do not rely on any specific terms until they are published and counsel-reviewed.

## How to inquire

Commercial licensing is handled by **MessageFoundry Organization**, the project's owner and steward.
To inquire, contact the maintainer:

- GitHub: [@wshallwshall](https://github.com/wshallwshall) (see [MAINTAINERS.md](MAINTAINERS.md)).
- Or use the maintainer-contact instructions in [.github/SECURITY.md](.github/SECURITY.md).

A dedicated commercial-licensing contact address will be published when the offering is finalized.

## See also

- [LICENSE](LICENSE) — the AGPL-3.0-or-later text (your rights today).
- [CLA.md](CLA.md) — the contributor relicensing grant that enables dual-licensing.
- [docs/DUAL_LICENSING_PLAN.md](docs/DUAL_LICENSING_PLAN.md) — the dual-licensing posture and the open
  legal questions it depends on.
- [GOVERNANCE.md](GOVERNANCE.md) — how the project is governed.
