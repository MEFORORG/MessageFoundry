# DEFERRAL RESOLUTIONS -- the tracked register a ruling leaves a mark in

A backlog row may defer part of itself to a condition: *"build slice 1; leave the VIP mechanism
gated on the owner's privileged-helper decision."* The row records the CONDITION. Nothing has ever
recorded the RESOLUTION, so deciding leaves no mark and the row reads as waiting forever.

That is not a hypothetical. On 2026-09-10 one ruling lifted the ADR 0056 privileged-helper pause and
staled three artefacts at once -- [#1494](BACKLOG.md), [#1495](BACKLOG.md) and
[ADR 0056](adr/0056-engine-managed-vip-failover.md). Two of the three were repaired by accident,
because a commit happened to be editing nearby. Nothing directed either fix.
[BACKLOG #1527](BACKLOG.md) is the row.

**This file is that mark.** One line per resolved condition, dated, tracked in git, readable by a
machine.

## How to use it

1. A ruling resolves a condition. Append one row here, the same day.
2. The row gets a `key` -- a short slug naming the CONDITION, not the item.
3. A backlog row that defers to that condition writes the same key into its own Verdict statement,
   as `[ruling-key: <key>]`.
4. `scripts/docs/deferral_resolution_screen.py` joins the two and reports any open row still
   declaring a deferral whose key is recorded here. That row is stale, and now something says so.

Step 3 is what makes a ruling reach every row it touched. The key is written once per deferral, by
whoever files the deferral, while they still know what they are waiting for. Nobody has to remember
later which rows a decision reached -- the screen finds them.

## What this cannot do, stated plainly

**Writing the row is a human act and no tool removes it.** A decision made in conversation leaves no
artefact unless somebody writes one. What the screen removes is the SILENCE: an unrecorded ruling no
longer disappears, because the deferral it should have resolved keeps ageing in the advisory report
until somebody either records the ruling or edits the row.

So the honest claim is narrow. This does not guarantee that a ruling gets written down. It
guarantees that not writing it down stays visible.

## Where this is NOT the record

`scripts/coord/owner_log.py` also records rulings, on its `answer_sent` leg. That ledger lives under
the git common dir and is **not tracked**, so CI cannot read it and it does not survive a fresh
clone. It is fleet coordination state, and it answers *"is this seat still waiting?"*. This file is
a repository record, and it answers *"has this condition been settled?"*. Keep them apart.

## The register

Append-only. Rows are added, never rewritten. Columns, in order:

| column | meaning |
| --- | --- |
| `date` | ISO `YYYY-MM-DD`, the day the condition was resolved |
| `key` | the condition's slug: lower-case, `a-z0-9._-`, at least three characters |
| `resolution` | what was decided, in one line |
| `authority` | who or what settled it: `owner`, a measurement, a landed ADR |
| `sources` | where to read the evidence: an item, a commit, an ADR |

A row whose `date` is not an ISO date is reported as malformed rather than dropped. A dropped row
would take a real resolution out of the join with nothing saying so.

| date | key | resolution | authority | sources |
| --- | --- | --- | --- | --- |
| 2026-09-10 | adr-0056-privileged-helper | the ADR 0056 privileged-helper pause is lifted; the VIP helper may be built | owner | [#1494](BACKLOG.md), `a653e8920`, `b8555c287`, [ADR 0056](adr/0056-engine-managed-vip-failover.md) |
