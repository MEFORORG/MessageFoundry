- **The repository's locks, and so the container image, move FastAPI from 0.143.0 to 0.143.1, and
  `pyproject.toml` now requires `fastapi>=0.143.1`.** 0.143.1 is the first release with the
  `RouteContext` shape the FastAPI 0.151 route-context entry describes. The required CI legs install
  through `constraints.lock`, so the lock decides which shape they exercise; before this, they ran
  the route-gate walk against only a simulated read of the new shape. 0.143.1 was published on
  2026-10-14, past the five-day release cooldown `.github/dependabot.yml` sets for this ecosystem.
  FastAPI 0.153.0, on which the route tests also pass, was published on 2026-10-20 and waits for
  that cooldown. The floor moves with the lock, because no required leg runs the older shape, so
  `pyproject.toml` no longer allows a release that has it. The advisory `dependency floors`
  workflow therefore installs 0.143.1 as the floor. No advisory prompted this.
  0.143.1 needs no newer Starlette, and the lock keeps 1.8.0. Not refreshed here:
  `security/bundled-code-survey.json` and `security/risky-component-readings.json` still describe
  FastAPI 0.142.2. They are dated snapshots made by hand. (`BACKLOG #3916`)
