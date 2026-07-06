# Dual-Licensing Plan (open-core posture)

> **⚠️ Planning document — pending legal review.** This records the *intended* dual-licensing posture
> and the open legal questions it depends on. It is **not** legal advice and **not** a published
> commitment. The specific commercial terms are not finalized; see
> [../COMMERCIAL-LICENSE.md](../COMMERCIAL-LICENSE.md) for the consumer-facing (also pending) summary.
> Referenced by [ADR 0017](adr/0017-consumer-deployment-model.md) decision #6 and backlog item #13.

## Why dual-license

MessageFoundry ships open source under **AGPL-3.0-or-later**. The AGPL is chosen deliberately: its
**§13 network clause** means anyone who runs a *modified* engine as a network-accessible service must
offer that modified source to the service's users. That copyleft is the lever that:

- keeps community improvements to the engine itself open, and
- gives an organization that wants to **modify and then redistribute or privately network-operate the
  engine** a clear reason to take a separate **commercial license** instead.

This is the standard **open-core / dual-licensing** model: one codebase, offered under the AGPL *and*
(separately) under commercial terms.

## What makes dual-licensing possible

The project can offer the same code under a second, non-AGPL license only if it holds sufficient
rights over every contribution. Those rights come from the **Contributor License Agreement**
([../CLA.md](../CLA.md) §2): each contributor grants MessageFoundry Organization a perpetual,
irrevocable right to **license and relicense** their contribution under any terms — including
commercial terms — while **retaining their own copyright**. Without that grant, relicensing would
require unanimous contributor consent for every release. (This rests on finalization of the CLA
itself — see [Open questions](#open-questions-for-legal-review).)

## The "config is a separate work" position

ADR 0017 establishes a packaging boundary: the engine is a **read-only, pinned wheel**, and an
adopter's Connections / Routers / Handlers live in a **separate `--config` repo** that the engine
*loads* but does not incorporate into its own distribution. The intended legal position is that this
adopter config is a **separate work**, not a derivative of the AGPL engine — so authoring private
integration logic in `--config` does **not** trigger AGPL copyleft on that config.

**This position is legally undefined and pending counsel.** Whether `--config`-loaded Routers /
Handlers are a separate work versus a derivative work is a genuine, unresolved adoption question (see
ADR 0017, "The boundary and the AGPL posture"). It must be confirmed by legal review before it is
published as a statement adopters can rely on.

## Who a commercial license is for

In short: organizations that want to **modify the engine and then distribute it or operate the
modified version as a network service without the AGPL §13 source-offer**, or to **embed it in a
proprietary product** under AGPL-incompatible terms. See
[../COMMERCIAL-LICENSE.md](../COMMERCIAL-LICENSE.md) for the consumer-facing phrasing.

## Open questions for legal review

- The exact **registered legal form** of "MessageFoundry Organization" (the steward / licensor named
  in the CLA and the copyright notices). The name is decided; counsel confirms the registered form.
- Whether the **"config is a separate work"** position holds, and how to phrase it for publication.
- The **commercial license terms**: grant scope, fees / support, any usage thresholds, and the
  warranty / indemnity posture.
- Review and finalization of the **CLA** itself (currently an Apache-ICLA-derived template).
- **Governing-law / jurisdiction** alignment with the entity's actual formation (the CLA currently
  names the State of Iowa).
- A dedicated **commercial-licensing contact** channel.

## Status

Pending legal review (ADR 0017 decision #6 / backlog #13). The public `0.1.0` release is gated on
counsel sign-off of this posture, not merely on these artifacts existing.
