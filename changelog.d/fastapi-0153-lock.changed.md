- **The repository's locks, and so the container image, move FastAPI from 0.143.0 to 0.153.0.**
  The required CI legs now run the route-gate walk on the `RouteContext` shape the FastAPI 0.151
  route-context entry describes, where before only a simulated read of it ran. No advisory
  prompted this. FastAPI labels at least seven releases in the span breaking, 0.145.0 through
  0.151.0. Among them: 0.145.0 removes `FastAPI(openapi_prefix=...)` and `**extra`, 0.146.0
  deprecates `root_path`, 0.148.0 changes how defaults of request parameters and models are
  handled, and 0.147.0, 0.149.0, 0.150.0 and 0.151.0 change how omitted or empty form, file and
  JSON `null` values are read. The engine and web console suites pass on 0.153.0; no test was
  written for these changes. 0.153.0 needs no newer Starlette, and the lock keeps 1.8.0;
  `pyproject.toml`'s `fastapi>=0.142.0` range is unchanged. Not refreshed here:
  `security/bundled-code-survey.json` and `security/risky-component-readings.json` still describe
  FastAPI 0.142.2. They are dated snapshots made by hand.
