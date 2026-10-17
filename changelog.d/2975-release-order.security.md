- **A release goes public only after every PyPI upload its run makes.** The harness upload is now a step
  of the engine's `publish-pypi` job, after the engine, so one approval of the `pypi` environment
  covers the toolkit, engine and harness uploads, and that job waits on the harness build. The
  engine's GitHub release is published only after all of them; with `PUBLISH_HARNESS` unset, the
  harness is not uploaded and the release still goes public. The console's GitHub release is now
  created as a draft too, and a new job publishes it once its wheel is on PyPI. The release job
  takes its PyPI digests right after the last step that writes the published files.
  (`vault BACKLOG #2975`)
