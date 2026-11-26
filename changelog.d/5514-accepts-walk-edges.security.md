- **The `accepts=` load-time walk follows more of the routes to `state_get` and `response_get`.**
  A predicate that reaches either accessor through a class or instance attribute
  (`Readers.get`), a module-level tuple, list, dict or set holding the accessor or a helper that
  reads it, a bound method's `self.getter`, or `staticmethod(state_get)` now fails `validate` and
  `check`, as a direct read does. Before, a suppression filter built that way passed the walk and
  would see an empty view in the router phase, passing every message. The walk's lookups are
  static, so no author code runs. The walk still misses at least these shapes, and a predicate
  built from one still passes it: a module-level instance's method called unbound
  (`FILTER.check(msg)`, `partial(Cls.m, obj)`), Python 3.14's combined load of two locals,
  `self` read through `EXTENDED_ARG` or `LOAD_DEREF`, an attribute held in `__slots__`, and a
  classmethod's `cls.reader`. (`BACKLOG #5514`)
