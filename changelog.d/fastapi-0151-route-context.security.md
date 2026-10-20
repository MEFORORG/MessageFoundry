- **The route-gate walk and the refusal count read the `RouteContext` shape of FastAPI 0.143.1.**
  From 0.143.1, a FastAPI `RouteContext` for an included non-API route answers its properties and
  its attribute fallback from the rebuilt route it serves, not from its own record, so reading
  `starlette_route` through that fallback found nothing. On an app with such an include, the walk
  in `scripts/security/route_gates.py` raised `MissingFastAPISymbol` for at least every included
  plain route, WebSocket and mount, and `GET /security/posture` would have dropped an included
  WebSocket's refusal count. The app `create_app` builds registers no included route, so its own
  walk rows were unchanged; the failures were in the walk's tests, which build such apps. Both now
  read the rebuilt route from the context's own record. The route tests pass on at least FastAPI
  0.142.0, 0.143.0, 0.143.1, 0.151.0 and 0.153.0. Request-time refusal of an undeclared route was
  not affected.
