- **The `[harness]` extra now requires `PySide6>=6.6,<6.12`, where 0.5.1 allowed any later
  release.** PySide6 6.12 moves the Qt web engine and PDF modules out of `pyside6-addons` into two
  new distributions, `pyside6-pdf` and `pyside6-webengine`, that
  [RISKY-COMPONENTS.md](../docs/RISKY-COMPONENTS.md) does not yet assess. The cap holds until it
  does. It also withholds any Qt fix shipped only in 6.12 or later. An install that already has
  PySide6 6.12 moves back to 6.11. The lock already pinned 6.11.2, so no pinned version moves.
  (Dependabot PR 2416)
