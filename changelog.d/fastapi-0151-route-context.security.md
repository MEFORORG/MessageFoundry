- **The route-gate walk and the refusal count work on FastAPI 0.143.1 and later.** From 0.143.1,
  a FastAPI `RouteContext` for an included non-API route answers its properties and its attribute
  fallback from the rebuilt route it serves, not from its own record. Reading `starlette_route`
  through that fallback therefore found nothing. The route walk in
  `scripts/security/route_gates.py` refused, by name, at least every included plain route,
  WebSocket and mount, and `GET /security/posture` would have dropped an included WebSocket's
  refusal count. Both now read the rebuilt route from the context's own record. The route tests
  pass on at least FastAPI 0.142.0, 0.143.0, 0.143.1, 0.151.0 and 0.153.0. Request-time refusal
  was not affected: an undeclared route was still refused.
