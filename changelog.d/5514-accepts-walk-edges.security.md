- **An `accepts=` predicate that reaches `state_get` or `response_get` through an attribute, a
  container or `self` fails `validate`.** The load-time walk did not follow a class or instance
  attribute (`Readers.get`), a module-level tuple, list, dict or set holding the accessor or a
  helper that reads it, a bound method's `self.getter`, or `staticmethod(state_get)`, so a
  suppression filter built that way would see an empty view in the router phase and pass every
  message. Each now refuses at load and at `check`, as a direct read does. The lookups are static,
  so no author code runs. (`BACKLOG #5514`)
