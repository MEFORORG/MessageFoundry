- **The route walk and the refusal count read FastAPI 0.143.1 and later.** From 0.143.1, FastAPI's
  `RouteContext` forwards an unknown attribute to the route it serves, not to its own record, so
  reading `starlette_route` through it returned nothing. The route walk in
  `scripts/security/route_gates.py` then refused every include of a plain route or WebSocket by
  name, and `GET /security/posture` would have dropped an included WebSocket's refusal count. Both
  now read the rebuilt route from the context's own record, which every release from the 0.142.0
  floor to 0.153.0 carries. Request-time refusal was never affected: an undeclared route was still
  refused.
