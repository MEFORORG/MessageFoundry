- **An operation cut off before it answered is answered as a page on the web console, and its 503
  names an approval only for a release.** When an outliving operation is cancelled while its
  request still waits, at least by the shutdown drain, a `/ui` request now gets the console's
  "Outcome unknown" page rather than the engine's raw JSON. That covers at least the approve,
  upload and upload delete routes, and any other `/ui` route that lets the error reach the app's
  handler. A `/ui` bulk control or bulk purge reports such a target as "outcome unknown" in its
  results, not as "error". A path outside `/ui` still gets the JSON 503. The 503 text names an approval only when the
  operation ran as an approval's release, and then tells the operator to read its state, and to
  resolve it if it reads interrupted. The approval gate's own shielded
  writes and its claim now answer such a cancellation as a handled error too, rather than a bare
  cancellation that escaped the API's exception handling: a cut-off write is still logged at ERROR
  by the gate, and a cut-off claim answers 503 naming the claim, not a store failure. A request
  that is itself being cancelled still gets its cancellation. (`BACKLOG #5903`)
