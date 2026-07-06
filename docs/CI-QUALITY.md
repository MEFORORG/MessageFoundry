# How Automated Testing Protects MessageFoundry's Code Quality

*A plain-language summary — June 20, 2026.*

## The headline

- **Every proposed change is automatically run through about 2,500 tests** before it can be approved.
- **Every change accepted into the main codebase is run through about 2,600 tests** — the same 2,500,
  plus roughly 100 extra checks that require real databases to run.

Because each round of testing runs on four different system setups (Windows and Linux, across two
software versions), that adds up to roughly **10,000 individual test runs** every single time.

## What is a "test"?

A test is a small automated check that confirms one part of the software still works as intended. They
run by themselves, in minutes, with no one watching. If a required test fails, the change is
automatically blocked until the problem is fixed — so a mistake can't quietly slip into the product.

## Two checkpoints

- **When someone proposes a change.** All the everyday checks run — the gate a change must pass before
  a teammate approves it.
- **When a change is added to the official codebase.** Everything above runs again, plus heavier checks
  that use real databases and a full Windows installation — the things too slow or costly to run on
  every proposal.

## What our repository runs automatically

- **Behavior tests** — about 2,500 automated checks of what the software actually does.
- **Style & safety of the code** — automatic formatting plus type-checking that catches whole
  categories of bugs early.
- **Security scanners** — look for insecure code, accidentally exposed passwords, and known weaknesses
  in outside software.
- **Supply-chain checks** — track and audit every outside software package we depend on, with a
  recorded inventory.
- **Patient-data guards** — block any real patient information or customer names from reaching the
  open-source code.
- **Editor add-on** — our companion VS Code extension is built and tested too.
- **Real-database & resilience tests** — full suites against real SQL Server and PostgreSQL, plus load
  and failure-recovery tests.
- **Windows service install** — a test that installs, runs, and removes the engine as a real Windows
  service.
- **Contributor agreement** — confirms every outside contributor has signed our CLA.

## Why two levels?

Running every check on every proposal would be slow and expensive — the database and Windows tests
cost the most. So we run the fast, comprehensive checks on every proposal and save the heaviest ones
for when a change is actually accepted. The trade-off: once in a while a problem only the heavy tests
can catch appears just after a change is accepted rather than before — and the team is alerted right
away when that happens.

---

*Figures measured June 20, 2026. Exact counts vary slightly as the test suite grows. The source of
truth for what runs is the workflow files under [`.github/workflows/`](../.github/workflows/).*
