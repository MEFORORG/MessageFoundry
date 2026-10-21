- **The repository's locks, and so the container image, move FastAPI from 0.143.0 to 0.143.1, and
  `pyproject.toml` now requires `fastapi>=0.143.1`.** 0.143.1 is the first release whose
  `RouteContext` answers from the rebuilt route, the shape the route-gate walk and the refusal count
  now read. The required CI legs install through `constraints.lock`, so the lock decides which
  shape they exercise; before this, they ran the walk against only a simulated read of the new
  shape. 0.143.1 was published on 2026-10-14, past the five-day release cooldown
  `.github/dependabot.yml` sets for this ecosystem. When this lock moved, newer releases, such as
  0.153.0 (published 2026-10-20), were still inside it. The floor moves with the lock, because no
  required leg runs the older shape, so `pyproject.toml` no longer allows a release that has it.
  This supersedes the 0.140.0 and 0.142.0 floors other entries state. The advisory
  `dependency floors` workflow therefore installs 0.143.1 as the floor. No advisory prompted this.
  0.143.1 needs no newer Starlette, and the lock keeps 1.8.0. Not refreshed here:
  `security/bundled-code-survey.json` and `security/risky-component-readings.json` still describe
  FastAPI 0.142.2. They are dated snapshots made by hand. (`vault BACKLOG #3916`)
