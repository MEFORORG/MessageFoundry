- **A step-up refusal made in a route body after its gate admitted the request now writes
  `auth.gate_refused`.** A `proof_in_route` route's gate writes `auth.permission_granted`, and the
  route then spends the bound proof (`spend_step_up_action`) or checks the session window
  (`refuse_unless_step_up_window_live`). In the shipped code a refusal there left the grant row and
  no row for the refusal. It now also writes an `auth.gate_refused` row naming the same permission
  and a `reason` of `step_up`, only where the gate wrote its grant row. No request is allowed that
  was refused before. A refusal whose row cannot be written answers with a server error instead of
  the 403, as a gate's own refusal already does. (`BACKLOG #1197`)
