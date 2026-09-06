# mefor-write-prose-or-a-finding

> Split out of [CLAUDE.md](../../CLAUDE.md) on 2026-09-05. Prohibitions that bind
> before this task starts stay in that file, which loads automatically. Read it first.


This is load-bearing because the wrong premise silently corrupts severity, urgency, and prose
across the repo. **Two consequences, and they pull in opposite directions — apply both:**

1. **Present-tense impact claims are factually false.** *"PHI is exposed"*, *"customers are
   affected"*, *"operators rely on this today"*, *"live feeds are shipping X"*, *"this needs an
   incident response"* — none of these are true of anything here. Write beta defects in the
   conditional: **"would expose X on first deployment"**, *"a deploying site would hit Y"*, *"is
   wrong in the shipped code"*. False present tense does not stay local; it propagates into
   security scorecards, review registers, BACKLOG banners and public docs, and a security record
   asserting a live exposure that does not exist is exactly the *"compensating control resting on
   a false premise"* defect §11 forbids.
2. **Hypothetical migration costs are vacuous.** *"breaks a running deployment on upgrade"*,
   *"operators need notice / a migration window / a deprecation period"*, *"backward compatibility
   with what sites have configured"* — there is nothing to break and nobody to notify, so the cost
   of a breaking change is currently **zero**. Prefer the simple, correct end state over a staged
   migration or compatibility shim; those are real costs paid to protect users who do not exist.

Add focused `CLAUDE.md` files in subpackages (e.g. `auth/`) only when local conventions
diverge enough to warrant it; keep this root file general.

---

- Specs/requirements in **Markdown**, kept consistent across the project.
- Document each connector/transport and transform with its config schema and an example
  message.
