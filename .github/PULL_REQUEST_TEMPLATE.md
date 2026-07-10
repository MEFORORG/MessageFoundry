<!-- Thanks for contributing to MessageFoundry! Please read CONTRIBUTING.md and GOVERNANCE.md first. -->

## What this changes

<!-- A short description of the change and the motivation. Link any related issue or ADR. -->

Closes #

<!-- If this PR completes (or partly completes) a numbered item in docs/BACKLOG.md, name it here as
     `BACKLOG #N`. CI then requires you to update that item's status banner in this same PR — the
     step whose omission left #60 (turnkey DR) reading "PRE-RESERVED" long after it had shipped, and
     that stale banner was later repeated as fact. Delete the line if no backlog item applies. -->

Implements: BACKLOG #

## Type of change

- [ ] Bug fix (a test reproducing the bug is included)
- [ ] New Connection/transport or example Router/Handler
- [ ] Documentation
- [ ] Refactor / internal change
- [ ] Architecture change (an ADR under `docs/adr/` is included or linked)

## Checklist

- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md) and will agree to the [CLA](../CLA.md) (the bot records it).
- [ ] If this touches the reliability invariants, store/queue, staged pipeline, auth/RBAC, or the
      code-first graph model, I **discussed it first** via an issue/ADR (see [GOVERNANCE.md](../GOVERNANCE.md)).
- [ ] **No real PHI or customer data** anywhere in the diff, tests, fixtures, screenshots, or commit
      messages — synthetic HL7 only (`python -m messagefoundry generate`).
- [ ] Tests added/updated for new behavior.
- [ ] Gates pass locally: `ruff check .`, `ruff format --check .`, `mypy messagefoundry`, and
      `pytest -q` (`QT_QPA_PLATFORM=offscreen` for console tests). `python -m messagefoundry check` is green.
- [ ] Uses **Connection / Router / Handler** vocabulary; no new declarative "channel" element; no
      GUI/web-framework imports in the engine packages; no Black.
- [ ] Docs updated if behavior or configuration changed.
- [ ] If this completes a `docs/BACKLOG.md` item, its status banner is updated in **this** PR
      (`> ✅ **SHIPPED …**`), and the item no longer carries an open `🔢`/`🚧` banner. Every item must
      declare exactly one status — enforced by `tests/test_backlog_status_check.py`.
