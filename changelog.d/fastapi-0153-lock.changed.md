- **The repository's locks, and so the container image, move FastAPI from 0.143.0 to 0.153.0.**
  0.153.0 is past the `RouteContext` change that 0.143.1 made, so the required CI legs now run the
  route-gate walk on that shape rather than only on the older one. Nothing else moves: 0.153.0
  needs no newer Starlette, and the lock keeps 1.8.0. `pyproject.toml`'s `fastapi>=0.142.0` range
  is unchanged. Not refreshed here: `security/bundled-code-survey.json` still describes an earlier
  FastAPI wheel. It is a dated snapshot made by hand.
