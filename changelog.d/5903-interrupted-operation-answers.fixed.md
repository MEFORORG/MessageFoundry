- **An operation cut off before it answered is answered as a page on the web console, and its 503
  names an approval only for a release.** When the shutdown drain cancels a long operation while
  its request still waits, the `/ui` approve and upload routes now render the engine's "outcome is
  unknown" text as a page, and the `/ui` upload delete lands on a notice of its own, rather than
  each showing the engine's raw JSON. The 503 text tells the operator to resolve the approval only
  when the operation ran as an approval's release. The approval gate's own shielded writes and its
  claim now answer such a cancellation as a handled error too, rather than a bare cancellation
  that escaped the API's exception handling; a request that is itself being cancelled still gets
  its cancellation. The `/ui` DR and config-reload routes still answer it as JSON, as they answer
  every engine error. (`BACKLOG #5903`)
