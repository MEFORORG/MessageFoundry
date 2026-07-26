# Semgrep --test fixture (ADR 0144 Inc 3). Its basename MUST match the rule file
# (messagefoundry/security/semgrep/handler-security.yml) so `semgrep --test` pairs them and checks the
# `# ruleid:` / `# ok:` annotations below. ast-parsed only, never executed; undefined names are fine.
import logging
from pathlib import Path
from pickle import loads as pk
from subprocess import run as r

log = logging.getLogger(__name__)


# (1) inter-statement PHI-to-log taint — the single-expression AST scan misses this.
@handler("h_interstmt")  # noqa: F821
def h_interstmt(msg):
    body = msg.raw
    # ruleid: mf-handler-phi-to-log
    log.info(body)
    return Send("OB", msg)  # noqa: F821


# .debug is below the PHI bar; msg.control_id is HL7 MSH envelope metadata (sanitized) — both clean.
@handler("h_log_ok")  # noqa: F821
def h_log_ok(msg):
    # ok: mf-handler-phi-to-log
    log.debug(msg.raw)
    # ok: mf-handler-phi-to-log
    log.info("processed %s", msg.control_id)
    return Send("OB", msg)  # noqa: F821


# (1b) the generic logger.log(level, body) method is also a sink.
@handler("h_log_method")  # noqa: F821
def h_log_method(msg):
    # ruleid: mf-handler-phi-to-log
    log.log(logging.INFO, msg.raw)
    return Send("OB", msg)  # noqa: F821


# (2) aliased-import evasion — Semgrep resolves the alias; the name-literal AST scan misses it.
@handler("h_aliased")  # noqa: F821
def h_aliased(msg):
    # ruleid: mf-handler-ambient-subprocess
    r(["/bin/echo", msg.raw])
    # ruleid: mf-handler-ambient-deserialization
    pk(msg.raw)
    # ruleid: mf-handler-ambient-eval-exec
    eval(msg.text)
    return Send("OB", msg)  # noqa: F821


# (3) message data into the db_lookup STATEMENT (positive) vs the parameterized params dict (ok).
@handler("h_sqli")  # noqa: F821
def h_sqli(msg):
    mrn = msg["PID-3.1"]
    # ruleid: mf-handler-sqli-db-lookup
    db_lookup("MPI", "select * from p where mrn = '" + mrn + "'")  # noqa: F821
    # ok: mf-handler-sqli-db-lookup
    db_lookup("MPI", "select npi from p where mrn = :mrn", {"mrn": mrn})  # noqa: F821
    return Send("OB", msg)  # noqa: F821


# (4) message body written to a file — Path-specific write sinks (bare .write is Control A's job).
@handler("h_file")  # noqa: F821
def h_file(msg):
    # ruleid: mf-handler-phi-to-file
    Path("/tmp/x.hl7").write_text(msg.encode())
    return Send("OB", msg)  # noqa: F821
