- **The step-up refusals of `spend_step_up_action` and `refuse_unless_step_up_window_live`, made
  in a route body after its `proof_in_route` gate admitted the request, can now write an
  `auth.gate_refused` row.** In the shipped code they wrote no row of their own.
  `_record_route_refusal` in `messagefoundry/api/security.py` says when the row is written. No
  request is allowed that was refused before. (`BACKLOG #1197`)
