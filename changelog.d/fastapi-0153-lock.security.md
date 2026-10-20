- **The repository's locks, and so the container image, move FastAPI from 0.143.0 to 0.153.0.**
  0.153.0 has the `RouteContext` shape that 0.143.1 introduced, so the required CI legs now run
  the route-gate walk on the real shape, where before only a simulated read of it ran on 0.143.0.
  The move spans at least two releases FastAPI labels breaking: 0.150.0 treats an unselected
  browser file input as missing, and 0.151.0 validates an explicit JSON `null` in a request body
  instead of substituting the parameter's default. The engine and web console suites pass on
  0.153.0. 0.153.0 needs no newer Starlette, and the lock keeps 1.8.0; `pyproject.toml`'s
  `fastapi>=0.142.0` range is unchanged. Not refreshed here: `security/bundled-code-survey.json`
  and `security/risky-component-readings.json` still describe FastAPI 0.142.2. They are dated
  snapshots made by hand.
