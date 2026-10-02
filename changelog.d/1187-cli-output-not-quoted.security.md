- **An IDE error from a `--json` CLI call no longer quotes the CLI's output.** When the command's
  stdout is not JSON, or is empty, the message now names the subcommand, its exit code and a byte
  count, and says to run the command in a terminal to read the output. Before, the message quoted
  the start of stdout (through Node's JSON parse error) or the whole stderr. That text could carry
  message data, and it showed in the Live Debug lens title, the status-bar tooltip and the Test
  Bench failure toasts. The CLI's own `{"error": ...}` body still shows as before: every path that
  composes it in `dryrun`, `validate` and `graph` builds it from configuration and path facts before
  any message is read, as `ide/src/cliJson.ts` records. (ASVS 14.2.6, vault `BACKLOG #1187`)
- **`messagefoundry dryrun` sends a `print()` in a config module, Router or Handler to stderr.**
  Stdout now carries only the JSON result, so a debugging print no longer breaks the IDE's parse.
  Nothing redacts what an author's own print writes, so stderr is no safer than stdout; see
  [PHI.md](../docs/PHI.md). (vault `BACKLOG #1187`)
