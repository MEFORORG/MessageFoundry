# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
# Semgrep --test fixture (ADR 0144 Inc 3). Its basename MUST match the rule file
# (messagefoundry/security/semgrep/handler-security.yml) so `semgrep --test` pairs them and checks the
# `# ruleid:` / `# ok:` annotations below. ast-parsed only, never executed; undefined names are fine.
import codecs
import io
import logging
import os
import shutil
import tempfile
from builtins import open as bopen
from pathlib import Path
from pickle import loads as pk
from subprocess import run as r

import messagefoundry as mf
from messagefoundry import db_lookup as dl

log = logging.getLogger(__name__)
opener = open


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


# (4) message body written to a file through a Path write method.
@handler("h_file")  # noqa: F821
def h_file(msg):
    # ruleid: mf-handler-phi-to-file
    Path("/tmp/x.hl7").write_text(msg.encode())
    return Send("OB", msg)  # noqa: F821


# (5) BACKLOG #5380: a module-qualified decorator is a taint source like the bare one.
@mf.handler("h_qualified")
def h_qualified(msg):
    body = msg.raw
    # ruleid: mf-handler-phi-to-log
    log.info(body)
    return Send("OB", msg)  # noqa: F821


@mf.router("r_qualified")
def r_qualified(msg):
    # ruleid: mf-handler-phi-to-log
    print(msg.raw)
    return ["h_qualified"]


# (5b) BACKLOG #5380: an undecorated underscore helper's parameters are taint sources, because a
# Handler hands it the message or values read from it.
def _helper_log(m):
    # ruleid: mf-handler-phi-to-log
    log.warning(m.raw)


def _helper_sql(mrn):
    # ruleid: mf-handler-sqli-db-lookup
    db_lookup("MPI", f"select * from p where mrn = '{mrn}'")  # noqa: F821


def _helper_file(body):
    # ruleid: mf-handler-phi-to-file
    Path("/tmp/h.hl7").write_bytes(body)


class _Formatter:
    # self is not a source, so logging an attribute of it stays clean.
    def _render(self):
        # ok: mf-handler-phi-to-log
        log.info(self.banner)


# A public undecorated function is not a source: nothing ties it to a message.
def public_util(value):
    # ok: mf-handler-phi-to-log
    log.info(value)


# A dunder is not a helper.
def __getattr__(name):
    # ok: mf-handler-phi-to-log
    log.info(name)


# (6) BACKLOG #5381: the statement or query reached with connection= as a keyword, through a module
# alias and through an import alias; FhirRaw and the FhirToken system half are author syntax.
@handler("h_sqli_forms")  # noqa: F821
def h_sqli_forms(msg):
    mrn = msg["PID-3.1"]
    # ruleid: mf-handler-sqli-db-lookup
    db_lookup(connection="MPI", statement="select * from p where mrn = '" + mrn + "'")  # noqa: F821
    # ruleid: mf-handler-sqli-db-lookup
    mf.db_lookup("MPI", "select * from p where mrn = '" + mrn + "'")
    # ruleid: mf-handler-sqli-db-lookup
    mf.fhir_lookup(connection="epic", query="Patient/" + mrn)
    # ruleid: mf-handler-sqli-db-lookup
    dl("MPI", "select * from p where mrn = '" + mrn + "'")
    # ruleid: mf-handler-sqli-db-lookup
    fhir_lookup("epic", "Patient", {"code": FhirRaw(mrn)})  # noqa: F821
    # ruleid: mf-handler-sqli-db-lookup
    fhir_lookup("epic", "Patient", {"code": mf.FhirRaw(value=mrn)})  # noqa: F821
    # ruleid: mf-handler-sqli-db-lookup
    fhir_lookup("epic", "Patient", {"identifier": FhirToken(mrn, "x")})  # noqa: F821
    # ruleid: mf-handler-sqli-db-lookup
    fhir_lookup("epic", "Patient", {"identifier": FhirToken(code="x", system=mrn)})  # noqa: F821
    # ok: mf-handler-sqli-db-lookup
    db_lookup(connection="MPI", statement="select npi from p where mrn = :mrn", params={"mrn": mrn})  # noqa: F821
    # ok: mf-handler-sqli-db-lookup
    mf.db_lookup("MPI", "select npi from p where mrn = :mrn", {"mrn": mrn})
    # ok: mf-handler-sqli-db-lookup
    fhir_lookup("epic", "Patient", {"identifier": FhirToken("MRN", mrn)})  # noqa: F821
    # ok: mf-handler-sqli-db-lookup
    fhir_lookup("epic", "Patient", {"_sort": FhirRaw("status,-date")})  # noqa: F821
    return Send("OB", msg)  # noqa: F821


# (7) BACKLOG #5382: file egress the ambient-authority lint does not see -- a non-literal mode,
# codecs.open, an import-aliased and a name-aliased open, os.write, tempfile and shutil.
@handler("h_file_forms")  # noqa: F821
def h_file_forms(msg, mode):
    body = msg.encode()
    with open("/tmp/a.hl7", mode) as fh:
        # ruleid: mf-handler-phi-to-file
        fh.write(body)
    out = codecs.open("/tmp/b.hl7", "w", "utf-8")  # noqa: SIM115
    # ruleid: mf-handler-phi-to-file
    out.write(body)
    # ruleid: mf-handler-phi-to-file
    bopen("/tmp/c.hl7", "w").write(body)  # noqa: SIM115
    # ruleid: mf-handler-phi-to-file
    opener("/tmp/d.hl7", "w").write(body)
    # ruleid: mf-handler-phi-to-file
    os.write(3, body)
    with tempfile.NamedTemporaryFile("w", delete=False) as tmpf:
        # ruleid: mf-handler-phi-to-file
        tmpf.writelines([body])
    # ruleid: mf-handler-phi-to-file
    shutil.copyfileobj(io.BytesIO(body), sink)  # noqa: F821
    buf = io.StringIO()
    # ok: mf-handler-phi-to-file
    buf.write(body)
    with open("/tmp/e.log", "w") as fh2:
        # ok: mf-handler-phi-to-file
        fh2.write("processed")
    return Send("OB", msg)  # noqa: F821
