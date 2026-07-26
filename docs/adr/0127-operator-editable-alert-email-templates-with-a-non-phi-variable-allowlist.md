# ADR 0127 — Operator-editable alert-email templates with a non-PHI variable allowlist

- **Status:** Accepted (2026-07-17) — demand-gate build (lane `dg-s1a`); pushes/PR owner-approved.
- **Built:** Yes — additive. Three optional templates in
  [`config/settings.py`](../../messagefoundry/config/settings.py)
  (`[alerts].email_subject_template` / `email_body_template` / `email_html_template`), a **closed
  non-PHI variable allowlist** validated **at config-load** (fail-closed on any unknown reference), and
  a renderer in [`pipeline/alert_sinks.py`](../../messagefoundry/pipeline/alert_sinks.py)'s
  `EmailTransport`. Off by default (all three `None` → today's fixed subject/body byte-for-byte).
- **Related:** [ADR 0014](0014-alerting-rules-engine.md) (the rules engine + the notifier/transports
  this rides), [`docs/PHI.md`](../PHI.md) (§9 no-PHI-off-box), BACKLOG #138.

## Context

Alert emails today use a **fixed** subject (`[MessageFoundry] {SEVERITY} {type} — {connection}`) and a
generic key/value body. Operators asked to customise them — a partner-recognisable subject line, an
HTML-formatted body for their ticketing inbox, a house style. The blocker was never architectural
(BACKLOG #138's original decline cited handler *purity*, which binds `@router`/`@handler`, **not** a
notifier transport — CLAUDE.md §8: side effects belong in connections/transports). The real risk is
**PHI**: an alert email leaves the box, so a template must **never** be able to interpolate a message
body or an arbitrary HL7 field (`docs/PHI.md` §9 — nothing off-box that isn't reviewed metadata).

## Decision

### §1 — Three optional templates, off by default

Add `email_subject_template`, `email_body_template`, and `email_html_template` (all `str | None`,
default `None`) to `[alerts]`. When all three are `None` the email is byte-identical to today (fixed
subject, key/value plain-text body, no HTML part). Setting `subject`/`body` overrides those parts;
setting `html` adds an **HTML alternative** to a `multipart/alternative` message. The **plain-text part
is always kept** (an `email_html_template` alone still sends the default/plain body as the text part),
so the email is never HTML-only.

### §2 — A CLOSED non-PHI variable allowlist, enforced at config-load (fail-closed)

Templates are `{name}` placeholders over a **fixed frozenset** of non-PHI operational variables —
`severity`, `type`, `connection`, `timestamp`, `depth`, `oldest_age_seconds`, `cooldown_seconds`,
`rule_id`. **Any** other reference is **rejected at config-load** (`serve` / reload refuses; the
`alert` editor's validate-before-persist rolls back) with a message listing the allowed names —
**reject-on-unknown, fail-closed**. There is deliberately **no** `detail` / `reason` / message-field
variable: those are asserted PHI-free elsewhere, but the allowlist is **safe-by-design** — it admits
only variables that are *structurally* non-PHI (a severity enum, an event-type token, a connection
name, a timestamp, integer counts, a cooldown, an operator rule label), so a template **cannot** name a
message-derived value even by mistake. This is the guarantee BACKLOG #138 required.

The validator uses `string.Formatter().parse` (not `str.format`): every field name must be a **bare
allowlisted identifier** — attribute/index access (`{connection.__class__}`, `{0}`), conversions
(`{x!r}`), and format-specs (`{x:...}`) are all rejected, closing the `str.format` injection surface
(ASVS, ADR 0014 §"options considered" #3). Rendering re-walks the same parse and substitutes only
allowlisted values, so a template can express nothing but literal text + allowlisted names.

### §3 — HTML is escaped; the subject is single-lined

The renderer **HTML-escapes every substituted value** in the HTML part (the operator's literal markup
is left intact — only the interpolated values are escaped), so a value can never inject markup. The
**subject** strips CR/LF from the rendered result (header-injection defence — a subject is one header
line). The plain-text body is emitted unescaped (it is not markup). Values carry no PHI regardless, but
escaping + single-lining are defence-in-depth on the off-box surface.

### §4 — `rule_id` as an operator label

To support `{rule_id}`, `AlertRule` gains an optional `id: str | None` operator label (non-PHI free
text, never interpolated as code) carried through `AlertRuleSet.decide → _RuleDecision.rule_id` and
handed to the email renderer via an **internal** context the notifier's fan-out pops before any send
(so it never reaches the webhook, exactly like the #146 `_recipients` key). `cooldown_seconds` is the
effective per-event cooldown, sourced the same way. Both render to `""` when absent.

## Options considered

1. **Closed allowlist + `Formatter.parse` validation/rendering (chosen).** Fail-closed, no injection
   surface, PHI-safe by construction, off-by-default byte-identical.
2. **`str.format(**event)` / Jinja.** Rejected — `str.format` exposes attribute/index access and any
   event key (PHI leak + injection); a full template engine is a large dependency and a much bigger
   injection/PHI surface for a cosmetic feature.
3. **Open allowlist including `detail`/`reason`.** Rejected — those are free-form strings; even though
   asserted PHI-free today, admitting them makes the allowlist not *structurally* safe (a future
   detail string could carry message-derived text). Safe-by-design beats trust-the-source here.

## Consequences

**Positive** — operators get partner-recognisable subjects + HTML bodies without touching code; the
allowlist makes an accidental PHI reference **impossible to configure** (rejected at load, not caught at
send); off-by-default keeps every existing deployment byte-identical.

**Negative / residual** — the allowlist is intentionally small (no message-derived values ever); an
operator wanting a message field in an alert must go through the PHI-review gate (out of scope, and the
point). Templates are global to the email transport (not per-rule); a per-rule template is a documented
follow-up (a per-rule `AlertRule.recipients` already routes #146, and severity/type/connection/rule_id
already differentiate recipients).
