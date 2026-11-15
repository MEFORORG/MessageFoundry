# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No CI leg weakens TLS to its database, and no serve step sets the retired data-class key.

THE RULE, AND WHAT CHANGED IT. Owner ruling 2026-11-14 (vault BACKLOG #3533 item 2): a store login
over ``trust_server_certificate=true`` or ``encrypt=false`` is refused, and so is a SQL Server
DATABASE connection login over the same, whatever ``MEFOR_ALLOW_INSECURE_TLS`` or
``[security].enforcement`` says. So a CI leg that still sets ``MEFOR_STORE_TRUST_SERVER_CERTIFICATE``
true or ``MEFOR_STORE_ENCRYPT`` false cannot open its store on any posture. The server-DB legs serve
a certificate generated in a step (``scripts/ci/db-tls-cert.sh``) and pin it or trust it instead.

This module used to hold the opposite guard: that a serve step which trusts a self-signed server
certificate also sets ``[security].enforcement = warn``, because the escape was honoured only there.
That pairing came from the ``load test (smoke, sqlserver)`` legs going RED for four nights
(2026-07-27..30) on ``ValueError: SQL Server TLS is weakened``. It cannot be satisfied any more, so
the guard now refuses the weakening itself, at PR time, rather than on a nightly. It reads every
workflow's `env:` mappings (workflow, job and step) and every `run:` body, where an `export`, a
`docker run -e`, a `>> $GITHUB_ENV` line or a PowerShell `$env:` assignment sets the variable.
It does not read test code, or a value a script computes, so a test that builds its own weakened
connection string is outside it.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

_TRUST = "MEFOR_STORE_TRUST_SERVER_CERTIFICATE"
_ENCRYPT = "MEFOR_STORE_ENCRYPT"
_RETIRED = "MEFOR_SECURITY_HANDLES_REAL_PATIENT_DATA"
_TRUTHY = {"true", "1", "yes", "on"}
_FALSY = {"false", "0", "no", "off"}
#: An assignment in a `run:` body: `export X=v`, `-e X=v`, `X=v >> $GITHUB_ENV`, `$env:X = "v"`.
_RUN_WEAKENED = re.compile(
    r"(?i)\b(?:" + _TRUST + r"\s*=\s*['\"]?(?:true|1|yes|on)\b"
    r"|" + _ENCRYPT + r"\s*=\s*['\"]?(?:false|0|no|off)\b)"
)


def _workflows() -> dict[str, dict[str, Any]]:
    yaml = pytest.importorskip("yaml")
    from tests._workflow_contexts import WORKFLOWS

    return {
        path.name: yaml.safe_load(path.read_text(encoding="utf-8"))
        for path in sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])
    }


def _weakened(env: dict[str, Any]) -> list[str]:
    """The weakened-TLS store settings ``env`` names, as ``NAME=value``."""
    found = []
    if str(env.get(_TRUST, "")).strip().lower() in _TRUTHY:
        found.append(f"{_TRUST}={env[_TRUST]}")
    if str(env.get(_ENCRYPT, "")).strip().lower() in _FALSY:
        found.append(f"{_ENCRYPT}={env[_ENCRYPT]}")
    return found


def _offenders(workflows: dict[str, dict[str, Any]]) -> tuple[int, list[str]]:
    """(env blocks plus run bodies examined, each one that weakens TLS to the store).

    An env block counts at the workflow, job or step level; a run body counts only where a step has
    one, so the examined count is not inflated by `uses:` steps.
    """
    examined = 0
    out: list[str] = []
    for wf_name, wf in workflows.items():
        blocks: list[tuple[str, Any]] = [(f"{wf_name} (workflow env)", wf.get("env"))]
        for job_key, job in (wf.get("jobs") or {}).items():
            blocks.append((f"{wf_name}:{job_key} (job env)", (job or {}).get("env")))
            for step in (job or {}).get("steps") or []:
                name = str((step or {}).get("name") or "<unnamed>")
                where = f"{wf_name}:{job_key} step {name!r}"
                blocks.append((where, (step or {}).get("env")))
                run = (step or {}).get("run")
                if not isinstance(run, str):
                    continue
                examined += 1
                out.extend(f"{where} runs {m.group(0)}" for m in _RUN_WEAKENED.finditer(run))
        for where, env in blocks:
            if not isinstance(env, dict):
                continue
            examined += 1
            out.extend(f"{where} sets {hit}" for hit in _weakened(env))
    return examined, out


def test_the_scan_sees_a_weakened_leg() -> None:
    """Positive control: the scanner fires on each weakening, at each level it reads."""
    synthetic = {
        "w.yml": {
            "env": {_ENCRYPT: "false"},
            "jobs": {
                "j": {
                    "env": {_TRUST: "true"},
                    "steps": [
                        {"name": "s", "env": {_TRUST: True, _ENCRYPT: False}},
                        {
                            "name": "r",
                            "run": (
                                f"export {_ENCRYPT}=false\n"
                                f"echo {_TRUST}=true >> $GITHUB_ENV\n"
                                f"docker run -e {_ENCRYPT}=no img\n"
                                f'$env:{_TRUST} = "1"\n'
                            ),
                        },
                    ],
                },
                "clean": {
                    "steps": [
                        {"name": "ok", "env": {_TRUST: "false", _ENCRYPT: "true"}},
                        {"name": "ok-run", "run": f"export {_ENCRYPT}=true {_TRUST}=false"},
                        {"name": "action", "uses": "actions/checkout@v4"},
                    ]
                },
            },
        }
    }
    examined, offenders = _offenders(synthetic)
    # 4 env blocks (workflow, job j, step s, step ok) + 2 run bodies (r, ok-run); `uses:` adds none.
    assert examined == 6
    assert offenders == [
        f"w.yml:j step 'r' runs {_ENCRYPT}=false",
        f"w.yml:j step 'r' runs {_TRUST}=true",
        f"w.yml:j step 'r' runs {_ENCRYPT}=no",
        f"w.yml:j step 'r' runs {_TRUST} = \"1",
        f"w.yml (workflow env) sets {_ENCRYPT}=false",
        f"w.yml:j (job env) sets {_TRUST}=true",
        f"w.yml:j step 's' sets {_TRUST}=True",
        f"w.yml:j step 's' sets {_ENCRYPT}=False",
    ]


def test_no_ci_leg_weakens_tls_to_its_database() -> None:
    examined, offenders = _offenders(_workflows())
    print(f"[ci-leg-tls] examined {examined} env block(s) and run body(ies) across every workflow")
    # Liveness: the server-DB legs alone carry dozens of env blocks.
    assert examined > 30, f"expected the workflows' env blocks, found {examined}"
    assert not offenders, (
        "a CI leg weakens TLS to its database, which the engine refuses at every posture whatever "
        "MEFOR_ALLOW_INSECURE_TLS says (owner ruling 2026-11-14, vault BACKLOG #3533 item 2):\n  "
        + "\n  ".join(offenders)
        + "\nServe a certificate the leg can verify instead: scripts/ci/db-tls-cert.sh makes one; "
        "pin it with MEFOR_STORE_SSL_ROOT_CERT or add it to the runner's trust store."
    )


def _serve_steps_with_env(workflow: str) -> list[tuple[str, str, dict[str, Any]]]:
    """(job key, step name, env) for every step that STARTS THE ENGINE with an ``env:`` block."""
    doc = _workflows()[workflow]
    out: list[tuple[str, str, dict[str, Any]]] = []
    for key, job in (doc.get("jobs") or {}).items():
        for step in (job or {}).get("steps") or []:
            env = (step or {}).get("env")
            run = str((step or {}).get("run") or "")
            if isinstance(env, dict) and "messagefoundry serve" in run:
                out.append((key, str((step or {}).get("name") or "<unnamed>"), env))
    return out


def test_no_leg_still_sets_the_retired_declaration() -> None:
    """The retired key is refused at LOAD, so a leg that still sets it fails at start, not at review.

    It covers every serve step, because ``handles_real_patient_data`` was a convenience anywhere a CI
    box wanted a quiet start. A leg that kept it would die on ``[security].handles_real_patient_data
    was REMOVED``, which is a clear message but arrives a nightly too late (BACKLOG #1279).
    """
    steps = _serve_steps_with_env("ci.yml")
    assert steps, "no `messagefoundry serve` step found in ci.yml — this guard would scan nothing"
    offenders = [
        f"ci.yml:{job} — step {step!r} still sets {_RETIRED}"
        for job, step, env in steps
        if _RETIRED in env
    ]
    assert not offenders, (
        "a CI leg sets a config key the loader REFUSES:\n  "
        + "\n  ".join(offenders)
        + f"\n{_RETIRED} was removed in BACKLOG #1279 — every instance carries patient data. Set the "
        "individual switch the leg actually needs (see the refusal message, which names them)."
    )
