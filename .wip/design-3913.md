# Design: row #3913, closing steps 2 to 4

Read against engine `origin/main` `72ac872c9cd` on 2026-11-22.

## Where the row stands on main

- Step 1 follows #3965, closed by decision d20261101T204118636-1d24a5 after engine PR 2651
  built the step-up return audit budget (`AuthService.allow_step_up_return_audit`). Not this design.
- Step 5 (finding 4) is built by engine PR 2651.
- Step 6 is read in the row's pass-1101c banner and stays with #3965.
- Steps 2 to 4 each offer "build X, or one written line here keeps it". These are the
  choices this design makes.

## Step 2, finding 1: who builds the return key

The tree: `messagefoundry_webconsole/routes/oidc.py` defines `_step_up_return_key(user_id)` and
the callback calls `auth.oidc_step_up_flow(flow_id)`, then
`auth.allow_reauth_attempt(_step_up_return_key(staged.user_id))`.

- Option A, a seam method. `AuthService` peeks the flow and charges the key in one call, and the
  console stops building the key. This adds a method the console calls, so it moves the web
  console seam digest in `messagefoundry/api/_ui_seam.py` and touches `auth/service.py` and the
  console route. Wave 6 terms say not to move the seam digest, and open PRs touch all three files.
- Option B, keep the key in the console. No code change.

Neither option weakens a control: the key, the limiter and the 429 are the same either way. A is
an information-hiding cleanup, not a control.

Pick: B, now. A is only blocked by the wave's seam-digest rule, so it can be re-briefed as a seam
change once the open seam PRs have landed.

## Step 3, finding 2: what `_step_up_actor` reads

The tree: `AuthService._step_up_actor(flow)` loads the session the flow staged, then its user, and
returns the username, or `<oidc>` when the flow names no session or the session is gone.

- Option A, read `flow.step_up_user_id`. It still needs `_load_user` to get a username, so it
  saves one session read. It also changes attribution: a refusal on a flow whose session was
  revoked or expired would name the account instead of `<oidc>`. That is a change to what an audit
  row records, which the row itself calls out of scope.
- Option B, keep the session load. No code change, and audit attribution stays as shipped.

Pick: B. It changes no behaviour and adds no acceptance. Option A is a behaviour change to audit
attribution, which is a decision about the record rather than a cleanup.

## Step 4, finding 3: the per-user and global split, stated in several places

The tree: `docs/SECURITY.md` states the step-up return's limiter split in at least the 6.1.1
prose paragraph (the one ending "with no ceiling across users"), the defenses table (controls 3
and 11), the Route to limiter map row for `GET /ui/oidc/callback`, and the Business-logic limits
rows *Sign-in attempts* and *Credential ceremonies*. `docs/CONFIGURATION.md` and
`docs/SECURITY-LOOSENING.md` also mention the step-up return's audit budget. `tests/test_docs_security_pathways.py` pins tokens in
several of those places.

- Option A, state it once and link. Keep the full statement in one place, cut the other rows to
  the route's limiter plus a link, and re-pin the doc tests. The per-route tables still have to
  name which limiter each route draws, so the cut is to the rationale and the key name, not to
  the mapping. This is a multi-section rewrite of `docs/SECURITY.md`, which open PRs touch and
  where wave 6 terms ask for small, local edits.
- Option B, keep the copies. No change.

Neither option weakens a control. A is the SDS-3.5 end state.

Pick: B in this wave, because A is not a small, local edit to a file open PRs are editing. A stays
the better end state and can be briefed as its own docs change once those PRs land.

## Result

All three picks are the "keep" branch, so none produces engine code, and there is nothing to build
or test here. Each needs the row's "one written line here", which is a vault ledger edit and not a
Builder's in this wave. Proposed lines, for the seat that writes the ledger:

- Step 2: "The return key stays in the console (`_step_up_return_key` in
  `messagefoundry_webconsole/routes/oidc.py`). A seam method would move the console seam digest;
  re-brief it as a seam change if wanted."
- Step 3: "`_step_up_actor` keeps the session load, so a refusal on a flow whose session is gone
  stays filed under `<oidc>`. Reading the staged user id would change audit attribution."
- Step 4: "The copies stay for now. Stating the split once in `docs/SECURITY.md` is the SDS-3.5
  end state, to be briefed as a docs change once the open PRs on that file land."
