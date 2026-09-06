# mefor-ledger-numbers

> Split out of [CLAUDE.md](../../CLAUDE.md) on 2026-09-05. Prohibitions that bind
> before this task starts stay in that file, which loads automatically. Read it first.


  **ONE HOLDOUT, and it is a machine-parsed contract, not an exemption.** `docs/BACKLOG.md` and
  `docs/archive/backlog/BACKLOG-CLOSED.md` encode item status as a banner alphabet
  (`scripts/docs/backlog_status_check.py`: `_CLOSED = "✅⛔🪦"`, `_OPEN = "🔢🚧"`), and
  `.github/workflows/backlog-hygiene.yml` quotes it in its remediation text. **283 banners across the
  two files and 12 referencing files** — changing it is a migration with its own item, not a doc edit,
  and until it lands those five glyphs stay. **No NEW glyph vocabulary may be introduced anywhere**,
  and nothing outside those two files may adopt one.

  **When you must read that alphabet, import `parse_items` from `backlog_status_check.py`. Never
  re-derive it.** It *defines* item status — the banner block ends at the first line that is neither
  blank nor a blockquote — and a hand-rolled scan is a second, silently different definition. That is
  the same single-source rule `ledger_check.py` already states for `PUBLIC_BACKLOG_FLOOR`.
