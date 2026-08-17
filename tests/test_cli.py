# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""CLI introspection subcommands (validate/graph/dryrun/hl7schema) emit JSON for the IDE."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"
ADT_A01 = (
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260101\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


def _out_json(capsys: pytest.CaptureFixture[str]) -> object:
    return json.loads(capsys.readouterr().out)


def test_gen_key_prints_a_valid_store_key(capsys: pytest.CaptureFixture[str]) -> None:
    import base64

    assert main(["gen-key"]) == 0
    key = capsys.readouterr().out.strip()
    assert len(base64.b64decode(key, validate=True)) == 32  # a usable 32-byte key
    # round-trips through the cipher factory (i.e. it's accepted as MEFOR_STORE_ENCRYPTION_KEY)
    from messagefoundry.store.crypto import make_cipher

    assert make_cipher(key).encrypt("x") != "x"


def test_validate_clean_sample(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validate", "--config", str(SAMPLES_CONFIG), "--json"]) == 0
    assert _out_json(capsys) == []


def test_top_level_help_encodes_on_legacy_windows_codepage(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Regression: `messagefoundry --help` crashed with UnicodeEncodeError on a cp1252/charmap
    # console because of a U+2192 arrow in the adr-analyze subparser help. Render the help string
    # in-process and assert it survives a cp1252 encode -- reproduces the Windows-only crash on any
    # runner without touching the real terminal (argparse --help raises SystemExit after printing).
    with pytest.raises(SystemExit):
        main(["--help"])
    help_text = capsys.readouterr().out
    assert "adr-analyze" in help_text, "top-level help did not render the subcommand list"
    try:
        help_text.encode("cp1252")
    except UnicodeEncodeError as exc:
        bad = help_text[exc.start]
        pytest.fail(f"top-level --help is not cp1252-encodable: U+{ord(bad):04X} {bad!r}")


def test_validate_reports_problems(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "bad.py").write_text("raise ValueError('boom')\n", encoding="utf-8")
    assert main(["validate", "--config", str(tmp_path), "--json"]) == 1
    diags = _out_json(capsys)
    assert isinstance(diags, list) and len(diags) == 1
    assert diags[0]["file"].endswith("bad.py")


def test_graph_of_sample(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["graph", "--config", str(SAMPLES_CONFIG), "--json"]) == 0
    g = _out_json(capsys)
    inbound = {c["name"]: c for c in g["inbound"]}
    # samples/config ships: the ADT file-archive route, the env()-driven ACME route, the X12 EDI route
    # (IB_PARTNER_X12, ADR 0012), the WS-* SOAP submit (ADR 0015), and the X12 RTE route (ADR 0016).
    assert {"IB_Test_ADT", "IB_ACME_ADT", "IB_PARTNER_X12"} <= set(inbound)
    adt_in = inbound["IB_Test_ADT"]
    assert adt_in["router"] == "adt_router" and adt_in["type"] == "mllp"
    assert inbound["IB_PARTNER_X12"]["type"] == "x12"
    assert {c["name"] for c in g["outbound"]} >= {
        "FILE-OUT_Test_ADT",
        "OB_ACME_ADT",
        "OB_PAYER_X12",
    }
    assert {r["name"] for r in g["routers"]} == {
        "adt_router",
        "acme_adt_router",
        "partner_x12_router",
        "immunization_router",
        "bodycred_router",  # #236 SOAP body-secret submit (IB_IMMUNIZATION_BODYCRED_VXU.py)
        "rte_request_router",
        "rte_response_router",
        "fhir_router",
        "sr_router",
        "demo_oru_router",  # per-feed "Hybrid" layout demo (IB_DEMO_ORU_router.py)
        "stream_mdm_router",  # #149 streaming: MDM-with-embedded-PDF pass-through (IB_STREAM_MDM.py)
        "pdf_mdm_router",  # #149 streaming: PDF-file → base64 → MDM build (IB_PDF_TO_MDM.py)
    }
    assert {h["name"] for h in g["handlers"]} == {
        "archive",
        "acme_adt_handler",
        "partner_x12_handler",
        "immunization_submit_handler",
        "bodycred_submit_handler",  # #236 SOAP body-secret submit (IB_IMMUNIZATION_BODYCRED_VXU.py)
        "rte_query_handler",
        "rte_result_handler",
        "fhir_handler",
        "sr_to_oru",
        "demo_oru_relay",  # per-feed "Hybrid" layout demo (IB_DEMO_ORU_handler.py)
        "stream_mdm_handler",  # #149 streaming (IB_STREAM_MDM.py)
        "pdf_mdm_handler",  # #149 streaming (IB_PDF_TO_MDM.py)
    }
    # env()-driven settings serialize JSON-safely as {"env": key}, never a raw EnvRef object
    acme_out = next(c for c in g["outbound"] if c["name"] == "OB_ACME_ADT")
    assert acme_out["settings"]["host"] == {"env": "acme_adt_host"}
    # source locations power the clickable graph tree (go-to-definition)
    assert adt_in["file"].endswith("adt.py") and adt_in["line"] > 0
    adt_router = next(r for r in g["routers"] if r["name"] == "adt_router")
    assert adt_router["file"].endswith("adt.py") and adt_router["line"] > 0
    # best-effort wiring edges (router→handler, handler→outbound) power the flow tree
    assert adt_router["handlers"] == ["archive"]
    archive = next(h for h in g["handlers"] if h["name"] == "archive")
    assert archive["sends"] == ["FILE-OUT_Test_ADT"]


def test_dryrun_of_sample(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    msg = tmp_path / "a.hl7"
    msg.write_bytes(ADT_A01.encode("utf-8"))
    # --show-phi: include full bodies (the IDE Test Bench renders these from the developer's own files)
    # --inbound: samples/config has multiple inbounds now, so simulate the ADT one explicitly.
    rc = main(
        [
            "dryrun",
            "--config",
            str(SAMPLES_CONFIG),
            "--inbound",
            "IB_Test_ADT",
            "--messages",
            str(msg),
            "--json",
            "--show-phi",
        ]
    )
    assert rc == 0
    results = _out_json(capsys)
    assert isinstance(results, list) and len(results) == 1
    r = results[0]
    assert r["source"] == "a.hl7"
    assert r["disposition"] == "received"
    assert r["message_type"] == "ADT^A01"
    assert [d["to"] for d in r["deliveries"]] == ["FILE-OUT_Test_ADT"]
    assert "MSH" in r["raw"]  # before/after diff source
    assert "MSH" in r["deliveries"][0]["payload"]  # would-send body
    assert r["summary"] is not None  # --show-phi includes the PHI summary (MRN/name)


def test_dryrun_redacts_bodies_by_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    msg = tmp_path / "a.hl7"
    msg.write_bytes(ADT_A01.encode("utf-8"))
    rc = main(
        [
            "dryrun",
            "--config",
            str(SAMPLES_CONFIG),
            "--inbound",
            "IB_Test_ADT",
            "--messages",
            str(msg),
            "--json",
        ]
    )
    assert rc == 0
    results = _out_json(capsys)
    assert isinstance(results, list) and len(results) == 1
    r = results[0]
    # full bodies (raw + would-send payloads) are withheld without --show-phi — no PHI to stdout
    assert "MSH" not in r["raw"] and "DOE" not in r["raw"]
    assert "redacted" in r["raw"]
    assert all("redacted" in d["payload"] for d in r["deliveries"])
    # the PHI summary (MRN + patient name) is gated too (H-12) — no PID-derived value reaches stdout
    assert r["summary"] is None
    assert "DOE" not in json.dumps(r)
    # routing metadata stays — that's what dryrun is for
    assert r["message_type"] == "ADT^A01" and r["control_id"] == "MSG1"


def test_dryrun_splits_batched_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    batch = tmp_path / "batch.hl7"
    batch.write_bytes((ADT_A01 + ADT_A01.replace("MSG1", "MSG2")).encode("utf-8"))
    rc = main(
        [
            "dryrun",
            "--config",
            str(SAMPLES_CONFIG),
            "--inbound",
            "IB_Test_ADT",
            "--messages",
            str(batch),
            "--json",
        ]
    )
    assert rc == 0
    results = _out_json(capsys)
    assert isinstance(results, list) and len(results) == 2  # both messages, not just the first
    assert results[0]["control_id"] == "MSG1" and results[1]["control_id"] == "MSG2"
    assert all(r["path"].endswith("batch.hl7") for r in results)  # source path for the debugger


def test_dryrun_missing_messages_path(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["dryrun", "--config", str(SAMPLES_CONFIG), "--messages", "nope-xyz", "--json"])
    assert rc == 1
    assert "error" in _out_json(capsys)  # type: ignore[operator]


def test_hl7schema_emits_segments(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["hl7schema", "--json"]) == 0
    schema = _out_json(capsys)
    assert schema["version"] == "2.5.1"
    assert "PID" in schema["segments"]


# --- WP-5: rotate-key + serve at-rest gate -----------------------------------


def test_rotate_key_reencrypts_under_active_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import asyncio

    from messagefoundry.store.crypto import generate_key, make_cipher
    from messagefoundry.store.store import MessageStore

    monkeypatch.chdir(tmp_path)  # isolate: no stray messagefoundry.toml in CWD
    db = tmp_path / "rot.db"
    key_a, key_b = generate_key(), generate_key()

    async def seed() -> None:
        s = await MessageStore.open(db, cipher=make_cipher(key_a))
        try:
            await s.enqueue_message(channel_id="ch", raw=ADT_A01, deliveries=[("d", ADT_A01)])
        finally:
            await s.close()

    asyncio.run(seed())

    # Rotate to B with A supplied as the retired bridge key, via the CLI (env-configured keys).
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", key_b)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEYS_RETIRED", key_a)
    assert main(["rotate-key", "--db", str(db)]) == 0
    assert "re-encrypted" in capsys.readouterr().out

    async def read_with_b_only() -> int:
        s = await MessageStore.open(db, cipher=make_cipher(key_b))  # retired key no longer needed
        try:
            return len(await s.list_messages())
        finally:
            await s.close()

    assert asyncio.run(read_with_b_only()) == 1  # readable under the new key alone


def test_rotate_key_requires_a_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    assert main(["rotate-key", "--db", str(tmp_path / "any.db")]) == 2
    assert "MEFOR_STORE_ENCRYPTION_KEY" in capsys.readouterr().err


def test_rotate_key_unbuilt_provider_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A non-default [store].key_provider that isn't built yet (an external HSM/KMS/Vault provider) must
    # fail CLOSED with a clean exit-2 + an actionable message, not a traceback (ADR 0019, ASVS 13.3.3).
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_KEY_PROVIDER", "aws_kms")
    assert main(["rotate-key", "--db", str(tmp_path / "any.db")]) == 2
    assert "aws_kms" in capsys.readouterr().err  # the message names the offending provider


def test_serve_refuses_without_key_when_require_encryption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(
        "[store]\nrequire_encryption = true\n", encoding="utf-8"
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 2
    assert "require_encryption" in capsys.readouterr().err


def test_serve_refuses_in_prod_without_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A PRODUCTION PHI instance must not run keyless: serve fails closed (H3, gated on data_class==phi).
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)  # never reached, but be safe
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "prod"]) == 2
    err = capsys.readouterr().err
    assert "PHI instance" in err and "UNENCRYPTED at rest" in err and "prod" in err


def test_serve_refuses_in_staging_without_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # H3: a NON-production PHI instance (staging) now REFUSES keyless too (was a warn) — the keyless
    # refusal is gated on data_class==phi, NOT the environment label, because dev/staging routinely hold
    # near-real PHI. This is the secure-by-default tightening (OWASP *Fail Securely* / SDS §4.3 PW.9).
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "staging"]) == 2
    err = capsys.readouterr().err
    assert "PHI instance" in err and "UNENCRYPTED at rest" in err and "staging" in err


def test_serve_keyless_phi_override_starts_with_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # H3 override: [store].allow_unencrypted_phi=true is the explicit, audited opt-out that lets a PHI
    # instance start keyless — it WARNS (and audits) rather than refusing, distinct from a default
    # refusal. (`require_encryption=true` would still win; tested separately.)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    # enforcement=warn reproduces the historical non-production dial (single-flag keyless override starts
    # with a warning); under default enforce the second ack would be required (tested for prod above).
    (tmp_path / "messagefoundry.toml").write_text(
        'security.enforcement = "warn"\nsecurity.allow_unencrypted_phi = true\n', encoding="utf-8"
    )
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "staging"]) == 0
    err = capsys.readouterr().err
    assert "allow_unencrypted_phi" in err and "UNENCRYPTED at rest" in err and "staging" in err


def test_serve_keyless_prod_phi_single_flag_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # TIGHTENING (ADR 0140): on PRODUCTION, allow_unencrypted_phi ALONE no longer boots keyless — the
    # deliberate production ack allow_unencrypted_phi_under_strict_enforcement is also required, otherwise serve
    # fails closed. (Non-production keeps the single-flag path — see the staging test above.)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(
        "security.allow_unencrypted_phi = true\n", encoding="utf-8"
    )
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "prod"]) == 2
    err = capsys.readouterr().err
    assert "allow_unencrypted_phi_under_strict_enforcement" in err and "UNENCRYPTED at rest" in err


def test_serve_keyless_prod_phi_both_acks_starts_with_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Both acks (allow_unencrypted_phi + allow_unencrypted_phi_under_strict_enforcement) boot a PRODUCTION instance
    # keyless with a loud audited warning; the other prod gates (egress/retention/alerts) are pre-cleared
    # so only the keyless posture is under test. Loopback default => the MFA gate never trips.
    toml = (
        "security.allow_unencrypted_phi = true\n"
        "security.allow_unencrypted_phi_under_strict_enforcement = true\n"
        "security.block_unlisted_outbound = true\n" + _SECURE_RETENTION + _SECURE_ALERTS
    )
    rc, _ = _run_secure_serve(tmp_path, monkeypatch, toml, env="prod", key=False)
    assert rc == 0
    err = capsys.readouterr().err
    assert "UNENCRYPTED at rest" in err and "prod" in err


def test_serve_require_encryption_overrides_keyless_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # require_encryption=true wins over allow_unencrypted_phi=true: the refusal is unconditional.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(
        "security.allow_unencrypted_phi = true\n[store]\nrequire_encryption = true\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "staging"]) == 2
    assert "require_encryption" in capsys.readouterr().err


def test_serve_quiet_in_dev_without_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # GIVEN 1 (ADR 0148): dev now derives PHI, so a genuinely-synthetic box declares the opt-out
    # explicitly (handles_real_patient_data=false). A synthetic instance keyless start is allowed and
    # quiet — the H3 refusal is gated on data_class==phi. (CI parity: synthetic stays key-free.)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = false\n", encoding="utf-8"
    )
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    assert "UNENCRYPTED at rest" not in capsys.readouterr().err


def test_serve_keyless_custom_phi_env_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # H3 gates on data_class, not the env NAME: a CUSTOM env explicitly marked phi (e.g. a 'test' box
    # holding near-real PHI) refuses keyless exactly like prod/staging — the EF-3 perception-gap fix.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = true\nsecurity.production_instance = false\n"
        '[ai]\nenvironment = "test"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "test"]) == 2
    err = capsys.readouterr().err
    assert "PHI instance" in err and "UNENCRYPTED at rest" in err and "test" in err


def test_serve_keyless_poc_phi_env_refuses_decoupled_from_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # DEPLOY-17 decoupling proof: a mislabeled/benign-named instance ('poc') that DECLARES PHI
    # (data_class=phi, production=false) still fails closed keyless — the H3 refusal keys on
    # data_class==phi, NOT the environment label, so a free-form name gets no free pass.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = true\nsecurity.production_instance = false\n"
        '[ai]\nenvironment = "poc"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "poc"]) == 2
    err = capsys.readouterr().err
    assert "PHI instance" in err and "'poc'" in err and "UNENCRYPTED at rest" in err


def test_serve_keyless_poc_phi_env_refuses_when_production_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # DEPLOY-17 name-independence mirror: the SAME benign 'poc' name with production=true takes the
    # identical keyless refusal path — the fail-closed decision is driven by data_class==phi, never
    # the env label or the production flag alone.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = true\nsecurity.production_instance = true\n"
        '[ai]\nenvironment = "poc"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "poc"]) == 2
    err = capsys.readouterr().err
    assert "PHI instance" in err and "'poc'" in err and "UNENCRYPTED at rest" in err


def test_serve_refuses_open_egress_in_prod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # With a key configured (so the keyless gate passes), a production PHI instance whose outbound
    # egress is fully unrestricted (no [egress].deny_by_default, no allowlists) fails closed.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(
        "MEFOR_STORE_ENCRYPTION_KEY", "x" * 44
    )  # passes the keyless gate (mocked app)
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "prod"]) == 2
    err = capsys.readouterr().err
    assert "egress is UNRESTRICTED on a production" in err


def test_serve_warns_open_egress_in_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # enforcement=warn reproduces the historical non-production dial: unrestricted egress only WARNS and
    # still starts (under default enforce it refuses — the dial is decoupled from the production tier).
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)  # silence the keyless warning
    (tmp_path / "messagefoundry.toml").write_text(
        'security.enforcement = "warn"\n', encoding="utf-8"
    )
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "staging"]) == 0
    err = capsys.readouterr().err
    assert "egress is UNRESTRICTED in a PHI-carrying environment" in err and "staging" in err


# --- C3: required active environment + custom-name posture (ADR 0017) --------


def test_serve_requires_active_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # No --env and no [ai].environment: serve refuses (no silent PROD default), so a missing env can
    # never resolve another environment's values/secrets.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG)]) == 2
    assert "no active environment" in capsys.readouterr().err


def test_serve_custom_env_requires_explicit_posture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A custom env name with no [ai].data_class/[ai].production refuses — posture is never inferred
    # from a free-form name (ADR 0017).
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "test"]) == 2
    assert "handles_real_patient_data" in capsys.readouterr().err


def test_serve_custom_env_with_posture_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A custom env with an explicit posture starts cleanly (app + uvicorn mocked).
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = false\nsecurity.production_instance = false\n"
        '[ai]\nenvironment = "test"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG)]) == 0


# --- non-loopback API bind guard (--allow-insecure-bind) ---------------------


def test_serve_refuses_non_loopback_bind_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Auth is enabled by default, so this exercises the cleartext-bind refuse, not the no-auth gate:
    # Phase 1 has no API TLS, so a non-loopback bind must fail closed unless the operator opts in.
    # GIVEN 1 (ADR 0148): declare synthetic so the PHI gates stay quiet and only the bind gate decides.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = false\n"
        'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n',
        encoding="utf-8",
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 2
    assert "refusing to serve the API on non-loopback" in capsys.readouterr().err


def test_serve_allows_non_loopback_bind_with_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from messagefoundry.store.crypto import generate_key

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())  # silence the at-rest warning
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)  # don't actually serve
    # GIVEN 1 (ADR 0148): declare synthetic so the enforce clamp doesn't refuse the PHI cleartext bind
    # — this test is about the --allow-insecure-bind flag path on a synthetic instance.
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = false\n"
        'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n',
        encoding="utf-8",
    )
    assert (
        main(["serve", "--config", str(SAMPLES_CONFIG), "--allow-insecure-bind", "--env", "dev"])
        == 0
    )
    err = capsys.readouterr().err
    assert "--allow-insecure-bind" in err and "cleartext" in err  # warned, but served


def test_serve_loopback_bind_needs_no_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from messagefoundry.store.crypto import generate_key

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    # GIVEN 1 (ADR 0148): declare synthetic so the PHI egress/retention/notify gates stay quiet and
    # only the loopback-bind (no-flag) behavior is under test.
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = false\nsecurity.local_access_only = true\n",
        encoding="utf-8",
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    assert "non-loopback" not in capsys.readouterr().err  # loopback never trips the guard


def test_serve_non_loopback_with_auth_off_refused_despite_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The opt-in flag accepts the cleartext-PHI risk; it must NOT also wave through serving a
    # full-privilege, unauthenticated API to the network — that stays a hard refuse regardless.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "messagefoundry.toml").write_text(
        'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n'
        "security.require_sign_in = false\n",
        encoding="utf-8",
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--allow-insecure-bind"]) == 2
    err = capsys.readouterr().err
    assert "enabled=false" in err  # the no-auth gate fired...
    assert "refusing to serve the API on non-loopback" not in err  # ...not the bind gate


def test_serve_refuses_auth_off_behind_declared_terminator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # BACKLOG #1013 (positive regression): auth entirely off behind a DECLARED TLS terminator is exposed
    # exactly like an off-loopback bind — the API would answer as a full-privilege identity with no
    # authentication — so the auth-off startup arm must refuse it, not only the non-loopback case. A
    # loopback bind (default local_access_only) + a declared terminator -> instance_exposed True, auth
    # off. The arm returns before the env-required check (like the non-loopback case above), so no --env,
    # store key, or server mock is needed.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "messagefoundry.toml").write_text(
        "security.require_sign_in = false\n"
        "[api]\n"
        "tls_terminated_upstream = true\n"
        'trusted_proxies = ["10.0.0.1"]\n',  # settings.py requires this alongside the terminator
        encoding="utf-8",
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG)]) == 2
    err = capsys.readouterr().err
    # rc alone is not enough: the later env-required gate also returns 2, so the message asserts are
    # what give this test teeth (they disappear if the arm reverts to the bare bind check).
    assert "enabled=false" in err  # the no-auth gate fired
    assert (
        "tls_terminated_upstream" in err or "reverse proxy" in err
    )  # named the terminator exposure


def test_serve_auth_off_on_unexposed_loopback_still_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from messagefoundry.store.crypto import generate_key

    # BACKLOG #1013 (negative control): the arm was WIDENED, not broadened to fire on any auth-off. A
    # true loopback dev instance with no declared terminator (instance_exposed False) is the supported
    # no-auth flow and must still start silently.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = false\n"
        "security.local_access_only = true\n"
        "security.require_sign_in = false\n",
        encoding="utf-8",
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    # The widened arm stayed silent because the instance is not exposed.
    assert "refusing to serve with [auth] enabled=false" not in capsys.readouterr().err


def test_serve_auth_on_behind_terminator_unaffected_by_arm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # BACKLOG #1013: the arm is inert under auth ON even when exposed. A synthetic loopback instance
    # behind a declared terminator is instance_exposed True, but auth is on by default (require_mfa
    # defaults on -> the MFA-at-exposure gate stays quiet; synthetic keeps the PHI gates quiet), so the
    # auth-off arm must not fire.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = false\n"
        "security.local_access_only = true\n"
        "[api]\n"
        "tls_terminated_upstream = true\n"
        'trusted_proxies = ["10.0.0.1"]\n',
        encoding="utf-8",
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    assert "enabled=false" not in capsys.readouterr().err  # the arm did not fire (auth is on)


def test_serve_insecure_bind_clamp_keys_on_enforcement_not_tier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # GIVEN 2 (ADR 0148): the --allow-insecure-bind cleartext-bind clamp is keyed on
    # [security].enforcement, NOT the production tier — so a PHI instance at the default `enforce`
    # REFUSES the cleartext bind even on *staging* (decoupled from the tier, exactly like every other
    # posture gate; byte-identical to the historical prod refuse), and `enforcement=warn` permits it.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)  # pass the keyless gate
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    base = (
        'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n'
        "security.handles_real_patient_data = true\nsecurity.block_unlisted_outbound = true\n"
    )
    # default enforce → a *staging* PHI cleartext bind is REFUSED at the bind gate (not just prod).
    (tmp_path / "messagefoundry.toml").write_text(base, encoding="utf-8")
    assert (
        main(
            ["serve", "--config", str(SAMPLES_CONFIG), "--allow-insecure-bind", "--env", "staging"]
        )
        == 2
    )
    err = capsys.readouterr().err
    assert "enforcement=enforce" in err and "cannot relax a PHI cleartext bind" in err
    # enforcement=warn reproduces the historical non-production dial: the same bind warns + serves.
    (tmp_path / "messagefoundry.toml").write_text(
        base + 'security.enforcement = "warn"\n', encoding="utf-8"
    )
    assert (
        main(
            ["serve", "--config", str(SAMPLES_CONFIG), "--allow-insecure-bind", "--env", "staging"]
        )
        == 0
    )
    assert "--allow-insecure-bind" in capsys.readouterr().err  # warned, served


# --- MFA-at-exposure posture (sec-mfa-on; off-loopback bind + [auth].require_mfa) ----------------
#
# An exposed (non-loopback) PHI bind with require_mfa off is single-factor over the network: refuse on
# a production PHI instance, warn on a non-production PHI instance, stay quiet on synthetic. These
# reach the MFA gate through a declared TLS-terminating reverse proxy (Posture-B) — #200 (ADR 0092)
# clamped --allow-insecure-bind so it can no longer wave a PRODUCTION-PHI cleartext bind past the
# exposed-gate, so an exposed prod bind now exposes via a real TLS-terminated proxy — with the keyless
# and open-egress gates pre-satisfied (a key + [egress].deny_by_default), so only the MFA posture is
# under test. create_managed_app + uvicorn are mocked so no socket is opened.
#
# BACKLOG #187 flipped the GLOBAL default to require_mfa ON, so an omitted [auth] section no longer
# leaves the gate exposed — a test that wants the single-factor-at-exposure gate to FIRE must now opt
# out explicitly (require_mfa = false). _expose_toml writes that opt-out by default.


class _PassingProbe:
    """Stand-in for TlsFloorProbe: the startup ladder reads only `.ok` and `.describe()`.

    Stubbed to PASS for the same reason `uvicorn.run` is -- these cases test CONFIG gates, and
    the probe's own network behaviour is covered by tests/test_tls_floor_probe.py. Stubbing it
    to FAIL would assert the probe rather than the ladder."""

    ok = True

    def describe(self) -> str:
        return "stubbed probe (test)"


def _expose_toml(
    tmp_path: Path,
    *,
    require_mfa: bool = False,
    enforcement: str | None = None,
    synthetic: bool = False,
    public_origin: str | None = None,
) -> None:
    """A non-loopback bind (exposed via a declared TLS-terminating proxy) with egress locked down.

    Exposed via Posture-B (``tls_terminated_upstream`` + ``trusted_proxies``) rather than a cleartext
    ``--allow-insecure-bind``: #200 (ADR 0092) clamped that flag so it can no longer wave a
    production-PHI cleartext bind past the exposed-gate, so the prod cases would otherwise be refused at
    the bind gate before ever reaching the MFA gate. The Posture-B intra-service auth + attested TLS
    floor are declared so the Posture-B fail-closed gate is pre-satisfied and only require_mfa is under
    test.

    require_mfa defaults False — the single-factor-at-exposure posture these tests probe. Since BACKLOG
    #187 flipped the default ON, this must be written explicitly for the gate to fire; pass True to
    assert the gate stays silent when MFA is required."""
    auth = "true" if require_mfa else "false"
    # enforcement=warn reproduces the historical non-production dial (the gate WARNS + starts) — the
    # security REFUSE/WARN dial is decoupled from the production tier, so a staging-warn case sets it.
    enforce_line = f'security.enforcement = "{enforcement}"\n' if enforcement else ""
    # GIVEN 1 (ADR 0148): dev now derives PHI, so the synthetic-dev exposure case declares the opt-out
    # explicitly to keep the PHI gates (keyless/egress/MFA) relaxed the way the old dev default did.
    synthetic_line = "security.handles_real_patient_data = false\n" if synthetic else ""
    # Pass every non-MFA exposure gate (Posture-B declarations + egress deny-by-default + the #186/#188
    # secure retention + SMTP-alert channels) so require_mfa is the ONLY posture under test.
    (tmp_path / "messagefoundry.toml").write_text(
        enforce_line + synthetic_line + "security.local_access_only = false\n"
        'security.listen_address = "0.0.0.0"\n'
        f"security.require_mfa = {auth}\n"
        "security.block_unlisted_outbound = true\n"
        "security.delete_message_bodies_after_days = 30\n"
        # ADR 0152 rung 2: an EXPOSED PHI instance without an in-use data-protection declaration
        # WARNS at every start (it refuses only behind require_memory_encryption_declaration).
        # Declared here with the rest of the non-MFA plumbing so no case in this file is reading
        # the LAST rung's output while asserting on the one under test.
        "security.memory_encryption_operator_declared = true\n"
        # BACKLOG #1026: a PHI instance behind a declared terminator under `enforce` now REFUSES
        # without a public address, because the ASVS 12.1.1 probe dials it and an unset value
        # silently disabled that check. Opt-in (default None) so only the cases that reach the
        # refusal declare it and the rest of this file is untouched. The AUTHORED key is
        # `[security].web_console_public_address` -- ADR 0118 retired `[api].public_origin`, which
        # is the internal settings name and is refused outright.
        + (
            f'security.web_console_public_address = "{public_origin}"\n'
            if public_origin is not None
            else ""
        )
        + '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.1"]\n'
        'proxy_intra_service_auth = "network"\nproxy_tls_min_version = "1.2"\n'
        "[retention]\ndead_letter_days = 30\n" + _SECURE_ALERTS,
        encoding="utf-8",
    )


# --- #186/#188 secure-by-default serve gates (retention / egress deny-by-default / security notify) --
#
# These gates mirror the sanctioned open-egress / MFA-at-exposure posture: a PRODUCTION PHI instance
# REFUSES to start, a non-production PHI instance (staging) WARNS, a synthetic instance (dev) is quiet.
# The building blocks below let a PRODUCTION PHI serve pass every PRIOR gate so exactly one new gate is
# under test per case (a locked-down egress, a bounded retention, and a real SMTP channel). See
# messagefoundry/__main__.py.
_SECURE_RETENTION = (
    "security.delete_message_bodies_after_days = 30\n[retention]\ndead_letter_days = 30\n"
)
_SECURE_ALERTS = '[alerts]\nemail_smtp_host = "smtp.example.org"\nemail_from = "sec@example.org"\n'


def _run_secure_serve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    toml: str,
    *,
    env: str = "prod",
    key: bool = True,
) -> tuple[int, dict[str, object]]:
    """Serve ``toml`` with create_managed_app + uvicorn mocked; return (rc, captured app kwargs).

    ``key`` sets a store encryption key (passes the keyless gate) so only the secure-by-default gates
    under test decide the outcome; ``captured`` exposes what serve threaded into create_managed_app
    (used to prove the egress deny-by-default effective flip)."""
    monkeypatch.chdir(tmp_path)
    if key:
        monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    else:
        monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(toml, encoding="utf-8")
    captured: dict[str, object] = {}

    def _capture_app(**kw: object) -> object:
        captured.update(kw)
        return object()

    monkeypatch.setattr("messagefoundry.api.create_managed_app", _capture_app)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    rc = main(["serve", "--config", str(SAMPLES_CONFIG), "--env", env])
    return rc, captured


def test_serve_refuses_exposed_without_mfa_in_prod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)  # passes the keyless gate
    _expose_toml(tmp_path)
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert (
        main(["serve", "--config", str(SAMPLES_CONFIG), "--allow-insecure-bind", "--env", "prod"])
        == 2
    )
    assert "require_mfa off; refusing to start" in capsys.readouterr().err


def test_serve_warns_exposed_without_mfa_in_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # enforcement=warn reproduces the historical non-production dial: the gate WARNS and still starts
    # (the security dial is decoupled from the production tier — staging under default enforce refuses).
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)  # silence the keyless warning
    _expose_toml(tmp_path, enforcement="warn")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert (
        main(
            ["serve", "--config", str(SAMPLES_CONFIG), "--allow-insecure-bind", "--env", "staging"]
        )
        == 0
    )
    err = capsys.readouterr().err
    assert "require_mfa off" in err and "single-factor" in err
    assert "refusing to start" not in err  # warned, did not refuse


def test_serve_quiet_exposed_without_mfa_in_synthetic_dev(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A synthetic instance (dev) stays quiet on the MFA posture (parity with keyless/egress gates).
    # GIVEN 1 (ADR 0148): dev now derives PHI, so synthetic is declared explicitly (synthetic=True).
    monkeypatch.chdir(tmp_path)
    _expose_toml(tmp_path, synthetic=True)
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert (
        main(["serve", "--config", str(SAMPLES_CONFIG), "--allow-insecure-bind", "--env", "dev"])
        == 0
    )
    assert "require_mfa" not in capsys.readouterr().err  # synthetic → no MFA advisory


def test_serve_exposed_with_mfa_on_starts_in_prod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # require_mfa on satisfies the posture, so a production exposed bind starts (gates all mocked).
    # Also satisfies the #186a retention + #188 security-notify prod gates (bounded windows + SMTP)
    # so the ONLY posture under test is require_mfa.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    _expose_toml(tmp_path, require_mfa=True, public_origin="https://mefor.example.org")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    monkeypatch.setattr(
        "messagefoundry.config.tls_probe.probe_tls_floor", lambda origin: _PassingProbe()
    )
    assert (
        main(["serve", "--config", str(SAMPLES_CONFIG), "--allow-insecure-bind", "--env", "prod"])
        == 0
    )
    assert "require_mfa off" not in capsys.readouterr().err


def test_serve_exposed_prod_phi_single_factor_ack_starts_with_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # ADR 0140: allow_single_factor_admin_when_exposed=true lifts the production single-factor-admin
    # refusal to the warn-and-start posture a non-production PHI exposure already takes (loud + audited).
    # The default-off refuse case is test_serve_refuses_exposed_without_mfa_in_prod (the ack is absent there).
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)  # passes the keyless gate
    (tmp_path / "messagefoundry.toml").write_text(
        "security.local_access_only = false\n"
        'security.listen_address = "0.0.0.0"\n'
        "security.require_mfa = false\n"
        "security.allow_single_factor_admin_when_exposed = true\n"
        "security.block_unlisted_outbound = true\n"
        "security.delete_message_bodies_after_days = 30\n"
        # ADR 0152 rung 2 declaration (see _expose_toml): the single-factor ACK is what is on
        # trial here, not the last rung in the ladder.
        "security.memory_encryption_operator_declared = true\n"
        # BACKLOG #1026, same reason: a declared-terminator PHI instance under `enforce` refuses
        # without a public address, and the single-factor ACK is what is on trial here.
        'security.web_console_public_address = "https://mefor.example.org"\n'
        '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.1"]\n'
        'proxy_intra_service_auth = "network"\nproxy_tls_min_version = "1.2"\n'
        "[retention]\ndead_letter_days = 30\n" + _SECURE_ALERTS,
        encoding="utf-8",
    )
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    monkeypatch.setattr(
        "messagefoundry.config.tls_probe.probe_tls_floor", lambda origin: _PassingProbe()
    )
    assert (
        main(["serve", "--config", str(SAMPLES_CONFIG), "--allow-insecure-bind", "--env", "prod"])
        == 0
    )
    err = capsys.readouterr().err
    assert "require_mfa off" in err and "single-factor" in err
    assert "refusing to start" not in err  # the ack downgraded refuse -> warn


def test_serve_refuses_exposed_without_mfa_even_with_ad_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The gate keys on require_mfa only — AD/Kerberos MFA is delegated to the directory — so an
    # AD-enabled prod exposed bind with require_mfa off is STILL refused, pinning the error text's
    # "safe even on an AD-only deployment (it gates only local Administrator accounts)".
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    monkeypatch.setenv("MEFOR_AUTH_AD_BIND_PASSWORD", "s3cret-pw")
    (tmp_path / "messagefoundry.toml").write_text(
        # Exposed via a declared TLS-terminating proxy (Posture-B) — #200 clamped --allow-insecure-bind
        # so it can no longer wave a prod-PHI cleartext bind past the exposed-gate; the MFA gate is
        # reached through a real TLS-terminated bind instead.
        "security.local_access_only = false\n"
        'security.listen_address = "0.0.0.0"\n'
        "security.require_mfa = false\n"
        "security.block_unlisted_outbound = true\n"
        '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.1"]\n'
        'proxy_intra_service_auth = "network"\nproxy_tls_min_version = "1.2"\n'
        # Opt out of the BACKLOG #187 secure default so the single-factor-at-exposure gate fires even
        # on an AD-enabled bind (the gate keys on require_mfa only; AD MFA is delegated to the directory).
        "[auth]\nad_enabled = true\n"
        'ad_server = "ldaps://dc1.example.com:636"\n'
        'ad_user_search_base = "ou=users,dc=example,dc=com"\n'
        'ad_bind_dn = "cn=svc,dc=example,dc=com"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert (
        main(["serve", "--config", str(SAMPLES_CONFIG), "--allow-insecure-bind", "--env", "prod"])
        == 2
    )
    assert "require_mfa off; refusing to start" in capsys.readouterr().err


def test_serve_loopback_never_trips_mfa_advisory_in_prod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The loopback default is not exposed, so even a production instance with require_mfa off is quiet.
    # Retention windows + SMTP satisfy the #186a/#188 prod gates so only the MFA advisory is under test.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    (tmp_path / "messagefoundry.toml").write_text(
        "security.local_access_only = true\n"
        "security.require_mfa = false\n"
        "security.block_unlisted_outbound = true\n" + _SECURE_RETENTION + _SECURE_ALERTS,
        encoding="utf-8",
    )
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "prod"]) == 0
    assert "require_mfa" not in capsys.readouterr().err


# --- #189 dual-control-at-exposure posture ([approvals].enabled, ASVS 2.3.5) ---------------------
#
# An exposed (non-loopback bind) PHI admin surface with [approvals].enabled off lets a single caller
# complete high-value actions (dead_letter_replay, connection_purge) with no second sign-off. This is
# WARN-ONLY by design (dual-control is off-by-default so a single-operator hospital is never wedged) —
# unlike the sec-mfa-on ladder there is no prod REFUSE (owner fork, tracked in __main__.py). Each
# exposed case sets [auth].require_mfa=true so the sec-mfa-on gate is pre-satisfied and only the
# approvals posture is under test; create_managed_app + uvicorn are mocked so no socket is opened.


def _dualctl_serve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    toml: str,
    *,
    env: str,
    allow_insecure: bool = True,
) -> int:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)  # passes the keyless gate
    (tmp_path / "messagefoundry.toml").write_text(toml, encoding="utf-8")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    argv = ["serve", "--config", str(SAMPLES_CONFIG), "--env", env]
    if allow_insecure:
        argv.append("--allow-insecure-bind")  # passes the cleartext-bind gate on the exposed bind
    return main(argv)


def test_serve_warns_exposed_without_approvals_in_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Exposed non-production PHI with dual-control off: WARN and still start. require_mfa on pre-clears
    # the sec-mfa-on gate so the [approvals] advisory is what's under test.
    rc = _dualctl_serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"\n'
        "security.local_access_only = false\n"
        'security.listen_address = "0.0.0.0"\n'
        "security.block_unlisted_outbound = true\n"
        "security.require_mfa = true\n",
        env="staging",
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "[approvals].enabled off" in err and "single caller's authority" in err
    assert "require_mfa off" not in err  # the MFA gate stayed silent (pre-satisfied)


def test_serve_quiet_exposed_without_approvals_in_synthetic_dev(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A synthetic instance (dev, data_class != PHI) stays quiet on the approvals posture, parity with
    # the keyless / MFA / retention gates. GIVEN 1 (ADR 0148): dev derives PHI now, so declare the
    # synthetic opt-out explicitly to keep the PHI gates relaxed.
    rc = _dualctl_serve(
        tmp_path,
        monkeypatch,
        "security.handles_real_patient_data = false\n"
        "security.local_access_only = false\n"
        'security.listen_address = "0.0.0.0"\n'
        "security.block_unlisted_outbound = true\n",
        env="dev",
    )
    assert rc == 0
    assert "approvals" not in capsys.readouterr().err


def test_serve_loopback_prod_quiet_on_approvals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Loopback byte-identity: admin_exposed is False on the loopback default, so even a production PHI
    # instance with approvals off never emits the advisory. Retention windows + SMTP satisfy the
    # #186a/#188 prod gates so the serve reaches rc 0 and only the approvals posture is under test.
    #
    # BACKLOG #326 re-keyed admin_exposed onto `instance_exposed` (off-loopback bind OR a declared
    # TLS-terminating proxy). This case is unchanged BY CONSTRUCTION: `instance_exposed` is also False
    # on a plain loopback bind with nothing declared, which is the property that keeps the loopback
    # default quiet. test_plain_loopback_is_not_instance_exposed pins the same invariant against the
    # MFA arm; both must hold or the re-key widened more than it was meant to.
    rc = _dualctl_serve(
        tmp_path,
        monkeypatch,
        "security.local_access_only = true\n"
        "security.block_unlisted_outbound = true\n" + _SECURE_RETENTION + _SECURE_ALERTS,
        env="prod",
        allow_insecure=False,  # loopback needs no flag
    )
    assert rc == 0
    assert "approvals" not in capsys.readouterr().err


def test_serve_exposed_with_approvals_on_no_warn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # [approvals].enabled on satisfies the posture, so an exposed PHI bind emits no dual-control
    # advisory (require_mfa on keeps the sec-mfa-on gate silent too).
    rc = _dualctl_serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"\n'
        "security.local_access_only = false\n"
        'security.listen_address = "0.0.0.0"\n'
        "security.block_unlisted_outbound = true\n"
        "security.require_mfa = true\n[approvals]\nenabled = true\n",
        env="staging",
    )
    assert rc == 0
    assert "[approvals]" not in capsys.readouterr().err


def _stub_protect_key(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Stub out real DPAPI + the icacls call; capture the read-grants protect-key passes through."""
    import messagefoundry.secrets_dpapi as dpapi_mod
    import messagefoundry.store.store as store_mod

    monkeypatch.setattr(dpapi_mod, "protect_key_to_file", lambda *a, **k: None)
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        store_mod,
        "_secure_file",
        lambda path, *, extra_read_grants=None: captured.update(grants=extra_read_grants),
    )
    return captured


def test_protect_key_grants_system_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # SYSTEM is always read-granted so a LocalSystem service can read the key at startup (BACKLOG #44).
    captured = _stub_protect_key(monkeypatch)
    assert main(["protect-key", "--out", str(tmp_path / "k.dpapi"), "--generate"]) == 0
    assert captured["grants"] == ["*S-1-5-18"]


def test_protect_key_grants_named_service_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # --grant-account adds the virtual / gMSA principal alongside SYSTEM.
    captured = _stub_protect_key(monkeypatch)
    rc = main(
        [
            "protect-key",
            "--out",
            str(tmp_path / "k.dpapi"),
            "--generate",
            "--grant-account",
            "NT SERVICE\\MessageFoundry",
        ]
    )
    assert rc == 0
    assert captured["grants"] == ["*S-1-5-18", "NT SERVICE\\MessageFoundry"]


# --- protect-key exit-2 branches (off-Windows + key-validation) ----------------------------------
#
# CLI-21 buildable slice: these drive the CLI's refusal paths that need neither Windows, real DPAPI,
# nor icacls. The real CryptProtectData round-trip + DACL enforcement stay @windows_only ci-leg tests
# (test_secrets_dpapi.py). Here we assert the CLI fails closed (rc==2) with the operator-facing message.


def test_protect_key_off_windows_refuses_with_windows_only_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # --generate mints a valid 32-byte key, so validation passes and control reaches protect_key_to_file;
    # off Windows that raises DpapiUnavailable -> the CLI must refuse (exit 2), not crash.
    import messagefoundry.secrets_dpapi as dpapi_mod

    def _raise(*_a: object, **_k: object) -> None:
        raise dpapi_mod.DpapiUnavailable("DPAPI is Windows-only")

    monkeypatch.setattr(dpapi_mod, "protect_key_to_file", _raise)
    rc = main(["protect-key", "--out", str(tmp_path / "k.dpapi"), "--generate"])
    assert rc == 2
    assert "protect-key is Windows-only" in capsys.readouterr().err


def test_protect_key_rejects_wrong_length_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A base64 key that decodes to the wrong byte count (16, not 32) is refused before any DPAPI call.
    import base64

    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", base64.b64encode(b"\x00" * 16).decode("ascii"))
    rc = main(["protect-key", "--out", str(tmp_path / "k.dpapi")])
    assert rc == 2
    assert "base64 of 32 bytes" in capsys.readouterr().err


def test_protect_key_rejects_non_base64_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A non-base64 value fails the decode -> raw="" -> the same 32-byte validation branch refuses it.
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "not valid base64!!!")
    rc = main(["protect-key", "--out", str(tmp_path / "k.dpapi")])
    assert rc == 2
    assert "base64 of 32 bytes" in capsys.readouterr().err


def test_protect_key_no_key_to_protect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # No env key and no --generate: there is nothing to protect, so the CLI refuses.
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    rc = main(["protect-key", "--out", str(tmp_path / "k.dpapi")])
    assert rc == 2
    assert "no key to protect" in capsys.readouterr().err


# --- L5b off-loopback browser-exposure ladder (ADR 0068 §8) --------------------------------------
#
# The new refusals/warnings EXTEND the existing gates (never weaken — the AC-6 and MFA-at-exposure
# tests above keep passing untouched). create_managed_app + uvicorn are mocked; only the ladder is
# under test.


def _l5b_serve(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, toml: str, env: str = "dev") -> int:
    from messagefoundry.__main__ import main

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    (tmp_path / "messagefoundry.toml").write_text(toml, encoding="utf-8")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    return main(["serve", "--config", str(SAMPLES_CONFIG), "--env", env])


def test_serve_ui_upstream_requires_public_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # ADR 0068 §7 (owner-confirmed upgrade-time change): a DECLARED reverse proxy makes the Host
    # header client-forwardable — serve_ui + tls_terminated_upstream REFUSES without public_origin.
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        "security.serve_web_console = true\n"
        "security.block_unlisted_outbound = true\n"
        '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.2"]\n',
    )
    assert rc == 2
    assert "requires [api].public_origin" in capsys.readouterr().err


def test_serve_ui_upstream_with_public_origin_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The refusal's happy path: one config line satisfies it (the error message names it).
    # GIVEN 1 (ADR 0148): declare synthetic so the PHI retention/notify gates stay quiet — the /ui
    # ladder is the subject here.
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        "security.handles_real_patient_data = false\n"
        "security.serve_web_console = true\n"
        'security.web_console_public_address = "https://mefor.example.org"\n'
        "security.block_unlisted_outbound = true\n"
        '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.2"]\n',
    )
    assert rc == 0
    assert "requires [api].public_origin" not in capsys.readouterr().err


def test_serve_ui_http_public_origin_refused_with_declared_tls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # An http:// public origin contradicts a declared TLS posture (upstream mode here; the
    # in-process-TLS twin shares the same condition via [api].tls_enabled).
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        "security.serve_web_console = true\n"
        'security.web_console_public_address = "http://mefor.example.org"\n'
        "security.block_unlisted_outbound = true\n"
        '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.2"]\n',
    )
    assert rc == 2
    assert "public_origin is http://" in capsys.readouterr().err


def test_serve_ui_warns_on_undeclared_proxy_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # public_origin set on an unprotected loopback instance = the undeclared-proxy heuristic:
    # WARN (cookie ships without Secure until the posture is declared) but still start.
    # GIVEN 1 (ADR 0148): declare synthetic so the PHI retention/notify gates stay quiet.
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        "security.handles_real_patient_data = false\n"
        "security.serve_web_console = true\n"
        'security.web_console_public_address = "https://mefor.example.org"\n'
        "security.block_unlisted_outbound = true\n",
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "proxy posture is undeclared" in err


def test_serve_ui_exposed_emits_842_guidance_and_new_ip_advisory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # An exposed console (declared upstream) on a PHI env: the 8.4.2 runbook pointer (info) and
    # the admin_new_ip_step_up advisory (warning; the default deliberately stays False).
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"\n'
        "security.serve_web_console = true\n"
        'security.web_console_public_address = "https://mefor.example.org"\n'
        "security.require_mfa = true\n"
        "security.block_unlisted_outbound = true\n"
        '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.2"]\n',
        env="staging",
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "OFF-LOOPBACK-DEPLOYMENT.md (ASVS 8.4.2)" in err
    assert "admin_new_ip_step_up off" in err


def test_serve_ui_declared_proxy_requires_mfa_on_prod_phi(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # PR-B review fix (ADR 0068 §8): the MFA-at-exposure gate keys on the same exposure signal as
    # the ladder — the runbook's RECOMMENDED topology (loopback bind BEHIND a declared proxy) is
    # treated exactly like an off-loopback bind: refuse on production PHI with require_mfa off.
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        # require_mfa = false opts out of the BACKLOG #187 secure default so the exposure gate fires.
        """security.serve_web_console = true
security.web_console_public_address = "https://mefor.example.org"
security.require_mfa = false
security.block_unlisted_outbound = true
[api]
tls_terminated_upstream = true
trusted_proxies = ["10.0.0.2"]
""",
        env="prod",
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "declared reverse proxy" in err and "require_mfa off; refusing to start" in err


def test_serve_ui_declared_proxy_warns_mfa_on_staging_phi(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # enforcement=warn reproduces the historical non-production warn tier (parity with the off-loopback
    # bind gate); the security dial is decoupled from the production tier.
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        # require_mfa = false opts out of the BACKLOG #187 secure default so the exposure gate fires.
        """security.enforcement = "warn"
security.serve_web_console = true
security.web_console_public_address = "https://mefor.example.org"
security.require_mfa = false
security.block_unlisted_outbound = true
[api]
tls_terminated_upstream = true
trusted_proxies = ["10.0.0.2"]
""",
        env="staging",
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "declared reverse proxy" in err and "single-factor over the network" in err


# --- BACKLOG #326: the exposure predicate must not read the mutated console flag ------------------
#
# `settings.api.serve_ui` is flipped False IN PLACE by both ADR 0143 degrade arms (console wheel
# absent; default-on console meeting an exposed bind) BEFORE the exposure gates read it. Keying
# `admin_exposed` on it therefore made the MFA-at-exposure refusal unreachable on the runbook's
# RECOMMENDED topology — a loopback bind BEHIND a declared reverse proxy with the console left at its
# default — while the ADR 0152 arm two hundred lines later called the very same boot exposed.
#
# These cases pin the corrected keying (`instance_exposed`) from OUTSIDE the engine: by exit code and
# by operator-visible text, never by reading the source. The two arms above already cover an
# EXPLICITLY-enabled console; what was missing was every arm where the console is not explicitly on.
#
# Each later production-PHI gate (bounded retention windows, the security-notification channel, the
# ADR 0152 in-use-data-protection declaration) is pre-satisfied, so exactly one gate decides each case.
_EXPOSURE_PRELUDE = (
    "security.local_access_only = true\n"  # LOOPBACK bind — the whole point of these cases
    "security.block_unlisted_outbound = true\n"
    "security.delete_message_bodies_after_days = 30\n"
    "security.memory_encryption_operator_declared = true\n"
)
_EXPOSURE_TAIL = (
    "[retention]\ndead_letter_days = 30\n"
    '[alerts]\nemail_smtp_host = "smtp.example.org"\nemail_from = "sec@example.org"\n'
)
_DECLARED_PROXY = (
    '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.1"]\n'
    'proxy_intra_service_auth = "network"\nproxy_tls_min_version = "1.2"\n'
)


def test_serve_default_console_declared_proxy_still_requires_mfa_on_prod_phi(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # ARM C — the load-bearing case. Loopback bind behind a DECLARED proxy with [security].
    # serve_web_console left at its DEFAULT: the ADR 0143 auto-degrade clears serve_ui, so the old
    # `admin_exposed = not is_loopback or ui_exposed` was False and this production PHI instance
    # started with single-factor admin on the network. It must refuse.
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        # require_mfa = false opts out of the BACKLOG #187 secure default so the exposure gate fires.
        _EXPOSURE_PRELUDE + "security.require_mfa = false\n" + _EXPOSURE_TAIL + _DECLARED_PROXY,
        env="prod",
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "require_mfa off; refusing to start" in err
    assert "declared reverse proxy" in err


def test_serve_console_explicitly_disabled_still_requires_mfa_on_prod_phi(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # ARM D — an operator who EXPLICITLY turns the console off is in the identical exposure posture:
    # the single-factor admin surface is the JSON API, which is served either way. Keying on the
    # console flag made "I disabled the browser console" silently disable an MFA refusal too.
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        _EXPOSURE_PRELUDE
        + "security.require_mfa = false\nsecurity.serve_web_console = false\n"
        + _EXPOSURE_TAIL
        + _DECLARED_PROXY,
        env="prod",
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "require_mfa off; refusing to start" in err


def test_serve_default_console_declared_proxy_warns_dual_control_on_phi(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The #189 dual-control arm reads the SAME `admin_exposed`, so it degraded with the same flag.
    # require_mfa on pre-clears the sec-mfa-on gate, leaving only the approvals posture under test.
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"\n'
        + _EXPOSURE_PRELUDE
        + "security.require_mfa = true\n"
        + _EXPOSURE_TAIL
        + _DECLARED_PROXY,
        env="prod",
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "[approvals].enabled off" in err and "single caller's authority" in err


def test_exposure_desc_names_the_proxy_not_the_console(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The refusal has to name a trigger the operator can act on. It used to read "([api].serve_ui +
    # tls_terminated_upstream)" — grammatical, and false for every arm the fix newly catches, because
    # serve_ui is False by the time the message is built. Pinned by BEHAVIOUR (the emitted text), not
    # by a comment: on arm C the whole serve emits no other `serve_ui`, measured at HEAD.
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        _EXPOSURE_PRELUDE + "security.require_mfa = false\n" + _EXPOSURE_TAIL + _DECLARED_PROXY,
        env="prod",
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "serve_ui" not in err, (
        "the exposure description names [api].serve_ui as the trigger, but serve_ui is False on every "
        "arm this refusal newly catches — the operator would go looking for a flag that is already off"
    )
    assert "tls_terminated_upstream" in err


def test_plain_loopback_is_not_instance_exposed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The byte-identity guard the re-key must not break, and the pin on the NARROW predicate. A plain
    # loopback bind with nothing declared is not exposed, so neither the MFA refusal nor the #189
    # dual-control advisory may fire — even on a production PHI instance with both knobs off. This is
    # why `console_exposed` (which also counts a bare `public_origin`) was NOT reused here: nothing has
    # been declared in that case, so exposure is an INFERENCE, and an inference must not refuse. It
    # must not be silent either — test_undeclared_proxy_warns_about_single_factor_admin covers that
    # half. This case sets no `public_origin`, so it exercises neither arm: it is the floor, where the
    # correct output is nothing at all.
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        _EXPOSURE_PRELUDE + "security.require_mfa = false\n" + _EXPOSURE_TAIL,
        env="prod",
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "require_mfa off" not in err
    assert "approvals" not in err


def test_undeclared_proxy_warns_about_single_factor_admin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The residual the narrow predicate leaves open must be WARNED about, not merely documented.

    `instance_exposed` deliberately excludes a set `public_origin` with no declared terminator, and
    the operator docs say that case "still only warns". Measured while this arm was written, it did
    not: the only other candidate is the ADR 0068 §8 undeclared-proxy heuristic, which (a) is about
    the /ui session cookie and HSTS and says nothing about admin factors, and (b) is gated on
    `settings.api.serve_ui`, which the ADR 0143 auto-degrade clears in place for exactly this input —
    a DEFAULT-on console plus a set `public_origin`. So on the commonest shape of this posture the
    startup said nothing whatever about single-factor admin, and a compensating control cited in four
    operator docs did not exist (CLAUDE.md §11: a compensating control must not rest on a false
    premise).

    Both halves are asserted: the new warning is present, and the §8 heuristic is NOT — which is what
    makes this arm load-bearing rather than duplicative.
    """
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        _EXPOSURE_PRELUDE
        + "security.require_mfa = false\n"
        + 'security.web_console_public_address = "https://mefor.example.org"\n'
        + _EXPOSURE_TAIL,
        env="prod",
    )
    assert rc == 0, "an UNDECLARED proxy is an inference — it must warn, never refuse"
    err = capsys.readouterr().err
    assert "UNDECLARED reverse proxy" in err and "single-factor over the network" in err
    assert "session cookie ships WITHOUT Secure" not in err, (
        "the ADR 0068 §8 heuristic fired after all — re-check whether this arm is still needed, and "
        "correct the docs either way"
    )


# --- ADR 0143: the browser console is ON by default (loopback secure-context) ---------------------


def test_serve_ui_default_on_loopback_mounts_ui(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # ADR 0143: a BARE loopback serve (no [security]) mounts /ui by DEFAULT and no exposure gate
    # refuses. create_managed_app is captured so we can assert the console is on (serve_ui=True) and
    # the loopback secure-context signal (loopback=True) threads through to the app.
    captured: dict[str, object] = {}
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    # GIVEN 1 (ADR 0148): declare synthetic so the bare loopback serve stays quiet on the PHI gates and
    # only the ADR 0143 default-on console behavior is under test.
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = false\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        "messagefoundry.api.create_managed_app", lambda **kw: captured.update(kw) or object()
    )
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    rc = main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"])
    assert rc == 0
    assert captured["serve_ui"] is True  # console mounted by default (ADR 0143)
    assert (
        captured["loopback"] is True
    )  # loopback secure-context signal threaded (http://127.0.0.1)
    # no /ui exposure-gate refusal on the loopback default
    assert "refusing to serve the browser ops dashboard" not in capsys.readouterr().err


def test_serve_ui_explicit_offloopback_still_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # ADR 0143: the off-loopback /ui refusals are UNCHANGED for an EXPLICITLY-enabled console — an
    # explicit serve_web_console=true behind a declared upstream proxy with no public_origin STILL
    # refuses (the console stays opt-in + TLS-gated off-box).
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        "security.serve_web_console = true\n"
        "security.block_unlisted_outbound = true\n"
        '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.2"]\n',
    )
    assert rc == 2
    assert "requires [api].public_origin" in capsys.readouterr().err


def test_serve_ui_default_on_offloopback_degrades_json_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # ADR 0143: the console defaults ON for LOOPBACK binds only. A DEFAULT-on (not explicitly requested)
    # console on an off-loopback bind AUTO-DEGRADES to JSON-only rather than tripping the /ui exposure
    # refusal — so a previously-working off-loopback JSON serve is not turned into a start failure.
    # GIVEN 1 (ADR 0148): declare synthetic so the PHI retention/notify gates stay quiet.
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        "security.handles_real_patient_data = false\n"
        "security.block_unlisted_outbound = true\n"
        '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.2"]\n',
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "on by default (ADR 0143) for LOCAL loopback binds only" in err
    assert "requires [api].public_origin" not in err  # the /ui refusal did NOT fire


def test_serve_ui_default_on_public_origin_degrades_json_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # ADR 0143: the `public_origin` branch of console_exposed also auto-degrades a DEFAULT-on console to
    # JSON-only (pins the second OR-branch, not just tls_terminated_upstream). A set
    # web_console_public_address with no explicit serve_web_console must NOT trip the /ui exposure refusal.
    # GIVEN 1 (ADR 0148): declare synthetic so the PHI retention/notify gates stay quiet.
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        "security.handles_real_patient_data = false\n"
        "security.block_unlisted_outbound = true\n"
        'security.web_console_public_address = "https://ops.example.com"\n',
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "on by default (ADR 0143) for LOCAL loopback binds only" in err


# --- #186a secure-by-default data retention (bounded PHI-body windows) ----------------------------


def test_serve_auto_bounds_an_unset_body_window_in_prod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """UNSET now DEFAULTS to 30 on the enforce dial rather than refusing (owner ruling 2026-07-30).

    This test previously asserted rc == 2 for exactly this config. The change is deliberate and the
    trade is real: a production PHI instance with an unset window used to refuse to start, which forced
    an operator to choose a number; it now starts bounded at 30. What survives is the fail-closed path
    for an EXPLICIT 0 — see the refusal test below, which is the other half of this pair.

    Mutation: drop the auto-bound block — reds, because rc becomes 2 and the window stays 0.
    """
    rc, captured = _run_secure_serve(
        tmp_path,
        monkeypatch,
        "security.block_unlisted_outbound = true\n[retention]\ndead_letter_days = 30\n"
        + _SECURE_ALERTS,
    )
    assert rc == 0
    assert captured["retention_settings"].messages_days == 30  # type: ignore[attr-defined]
    err = capsys.readouterr().err
    assert "[security].delete_message_bodies_after_days" in err and "defaulted ON (30 days)" in err


def test_serve_refuses_an_explicitly_disabled_body_window_in_prod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An EXPLICIT 0 still refuses — the fail-closed path the auto-bound narrows but does not remove.

    This is the half of the posture that must not regress: "unbounded by accident" is still prevented,
    because typing 0 is a deliberate act and is still refused unless the audited opt-out is set.

    Mutation: treat an explicit 0 as unset (drop `model_fields_set`) — reds, because the window is
    silently defaulted to 30 and rc becomes 0.
    """
    rc, _ = _run_secure_serve(
        tmp_path,
        monkeypatch,
        "security.block_unlisted_outbound = true\nsecurity.delete_message_bodies_after_days = 0\n"
        "[retention]\ndead_letter_days = 30\n" + _SECURE_ALERTS,
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "[security].delete_message_bodies_after_days" in err and "refusing to start" in err


def test_serve_refuses_unbounded_dead_letter_retention_in_prod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The dead-letter body window is its OWN PHI-at-rest window (a dead-lettered message stays
    # replayable, i.e. full PHI, until dead_letter_days purges it): messages_days bounded but
    # dead_letter_days unbounded STILL refuses — closes the previously-unbounded dead-letter gap.
    rc, _ = _run_secure_serve(
        tmp_path,
        monkeypatch,
        "security.block_unlisted_outbound = true\nsecurity.delete_message_bodies_after_days = 30\n"
        "[retention]\ndead_letter_days = 0\n" + _SECURE_ALERTS,
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "[retention].dead_letter_days" in err and "refusing to start" in err


def test_serve_retention_auto_bounds_in_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # WP243 (#243, ASVS 14.2.7): non-production PHI (staging) with no [retention] windows now AUTO-BOUNDS
    # each unset window to 30 days (secure-by-default) instead of merely warning — and never refuses.
    rc, captured = _run_secure_serve(
        tmp_path,
        monkeypatch,
        # enforcement=warn reproduces the non-production dial: unset windows AUTO-BOUND (not refuse).
        'security.enforcement = "warn"\nsecurity.block_unlisted_outbound = true\n'
        + _SECURE_ALERTS,  # no [retention] windows
        env="staging",
    )
    assert rc == 0
    retention = captured["retention_settings"]
    assert retention.messages_days == 30 and retention.dead_letter_days == 30  # type: ignore[attr-defined]
    err = capsys.readouterr().err
    assert "defaulted ON (30 days)" in err
    # The AUTO-BOUNDED windows must not appear in the warn-only line — that is what "auto-bound rather
    # than merely warn" means. This used to assert the phrase was absent ENTIRELY, which worked only
    # while the classification held nothing but auto-bounded windows; state_max_age_days and
    # search_preset_days now legitimately warn, so the narrow assertion is the one that keeps testing
    # the original intent instead of the coincidence.
    warn_line = next((ln for ln in err.splitlines() if "accumulate without bound" in ln), "")
    assert "[security].delete_message_bodies_after_days" not in warn_line, warn_line
    assert "[retention].dead_letter_days" not in warn_line, warn_line
    assert "refusing to start" not in err


def test_serve_auto_bounds_retention_on_loopback_phi(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # WP243 (#243, ASVS 14.2.7): a declared-PHI loopback instance ([ai].data_class=phi on a dev-named
    # box) with no [retention] windows auto-bounds both PHI-body windows to 30 days.
    rc, captured = _run_secure_serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"\nsecurity.handles_real_patient_data = true\n'
        "security.block_unlisted_outbound = true\n" + _SECURE_ALERTS,
        env="dev",
    )
    assert rc == 0
    retention = captured["retention_settings"]
    assert retention.messages_days == 30 and retention.dead_letter_days == 30  # type: ignore[attr-defined]
    assert "defaulted ON (30 days)" in capsys.readouterr().err


def test_serve_retention_respects_explicit_zero_in_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # TRAP-C: an EXPLICIT 0 window on non-prod PHI is respected (model_fields_set), NOT auto-bounded —
    # it stays 0 and the instance warns about the deliberately-unbounded window rather than defaulting it.
    rc, captured = _run_secure_serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"\nsecurity.block_unlisted_outbound = true\n'
        "security.delete_message_bodies_after_days = 0\n"
        "[retention]\ndead_letter_days = 30\n" + _SECURE_ALERTS,
        env="staging",
    )
    assert rc == 0
    retention = captured["retention_settings"]
    assert retention.messages_days == 0  # type: ignore[attr-defined]  # explicit 0 respected, not bumped
    assert retention.dead_letter_days == 30  # type: ignore[attr-defined]
    assert "PHI message bodies accumulate without bound" in capsys.readouterr().err


def test_serve_retention_quiet_in_synthetic_dev(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A synthetic instance (dev) is exempt from the retention gate — byte-identical keyless start.
    # GIVEN 1 (ADR 0148): dev derives PHI now, so declare the synthetic opt-out explicitly.
    rc, _ = _run_secure_serve(
        tmp_path,
        monkeypatch,
        "security.handles_real_patient_data = false\n",
        env="dev",
        key=False,
    )
    assert rc == 0
    assert "retention" not in capsys.readouterr().err.lower()


def test_serve_allow_unbounded_phi_override_starts_in_prod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The explicit, audited opt-out: [security].allow_keeping_phi_indefinitely=true downgrades the prod refusal
    # to a loud warning and starts (keep-forever retention accepted in writing).
    rc, _ = _run_secure_serve(
        tmp_path,
        monkeypatch,
        "security.block_unlisted_outbound = true\nsecurity.allow_keeping_phi_indefinitely = true\n"
        + _SECURE_ALERTS,
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert (
        "allow_keeping_phi_indefinitely=true" in err
        and "retains PHI message bodies indefinitely" in err
    )


# --- #186c egress deny-by-default effective flip (production PHI) ---------------------------------


def test_serve_egress_deny_by_default_flips_on_prod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A production PHI instance that left [egress].deny_by_default unset gets it flipped ON (effective),
    # and the exact settings.egress object (deny_by_default=True) is threaded into create_managed_app,
    # so the wiring_runner enforcement sees the fail-closed posture. An allowlist is set so the
    # all-or-nothing open-egress gate above stays silent and only the flip is exercised.
    rc, captured = _run_secure_serve(
        tmp_path,
        monkeypatch,
        _SECURE_RETENTION + '[egress]\nallowed_mllp = ["10.0.0.5"]\n' + _SECURE_ALERTS,
    )
    assert rc == 0
    assert captured["egress_settings"].deny_by_default is True  # type: ignore[attr-defined]
    assert (
        "block_unlisted_outbound defaulted ON for a production PHI instance"
        in capsys.readouterr().err
    )


def test_serve_egress_explicit_deny_false_warns_in_prod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The explicit, audited opt-out: [security].block_unlisted_outbound=false on a production PHI instance keeps
    # the allow-any posture (NOT flipped) and emits a loud warning.
    rc, captured = _run_secure_serve(
        tmp_path,
        monkeypatch,
        "security.block_unlisted_outbound = false\n"
        + _SECURE_RETENTION
        + '[egress]\nallowed_mllp = ["10.0.0.5"]\n'
        + _SECURE_ALERTS,
    )
    assert rc == 0
    assert captured["egress_settings"].deny_by_default is False  # type: ignore[attr-defined]
    assert "block_unlisted_outbound=false on a production PHI instance" in capsys.readouterr().err


def test_serve_egress_flip_fires_in_staging_phi(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # WP243 (#243, ASVS 13.2.4/13.2.5): the deny-by-default effective flip now fires on ANY PHI
    # instance, not just production — a staging PHI instance with the field unset gets deny_by_default
    # flipped ON (the notice reads "PHI instance", not "production PHI instance", off production).
    rc, captured = _run_secure_serve(
        tmp_path,
        monkeypatch,
        _SECURE_RETENTION + '[egress]\nallowed_mllp = ["10.0.0.5"]\n' + _SECURE_ALERTS,
        env="staging",
    )
    assert rc == 0
    assert captured["egress_settings"].deny_by_default is True  # type: ignore[attr-defined]
    err = capsys.readouterr().err
    assert "block_unlisted_outbound defaulted ON for a PHI instance" in err
    assert "production PHI instance" not in err


def test_serve_auto_denies_egress_on_loopback_phi(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # WP243 (#243): a declared-PHI loopback instance (a dev-named box that sets [ai].data_class=phi)
    # with no [egress] section still gets deny_by_default flipped ON — the flip keys on DECLARED PHI,
    # not the built-in env name. (Open egress also warns on the non-prod instance; the flip closes it.)
    rc, captured = _run_secure_serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"\nsecurity.handles_real_patient_data = true\n'
        + _SECURE_RETENTION
        + _SECURE_ALERTS,
        env="dev",
    )
    assert rc == 0
    assert captured["egress_settings"].deny_by_default is True  # type: ignore[attr-defined]
    assert "block_unlisted_outbound defaulted ON for a PHI instance" in capsys.readouterr().err


def test_serve_egress_flip_skipped_for_synthetic_dev(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Byte-identical guard (TRAP-D): a NON-PHI (synthetic dev) serve is untouched by the WP243
    # broadening — deny_by_default stays False and no flip notice is emitted. GIVEN 1 (ADR 0148): dev
    # derives PHI now, so declare the synthetic opt-out explicitly to keep the flip skipped.
    rc, captured = _run_secure_serve(
        tmp_path,
        monkeypatch,
        'security.handles_real_patient_data = false\n[egress]\nallowed_mllp = ["10.0.0.5"]\n',
        env="dev",
        key=False,  # synthetic — the flip keys on declared PHI
    )
    assert rc == 0
    assert captured["egress_settings"].deny_by_default is False  # type: ignore[attr-defined]
    assert "defaulted ON" not in capsys.readouterr().err


# --- #188 out-of-band security-notification channel effective by default -------------------------


def test_serve_refuses_no_security_notify_channel_in_prod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A production PHI instance with no out-of-band security-notification channel (no SMTP) refuses:
    # account-security events would have only the pull-only feed. Egress + retention pre-satisfied so
    # only the notify gate decides.
    rc, _ = _run_secure_serve(
        tmp_path,
        monkeypatch,
        "security.block_unlisted_outbound = true\n" + _SECURE_RETENTION,  # no [alerts] SMTP
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "no out-of-band security-notification channel" in err and "refusing to start" in err


def test_serve_refuses_when_notify_security_events_off_in_prod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The gate reads the [auth].notify_security_events kill-switch too: SMTP configured but the switch
    # OFF builds no notifier (api/app.py needs BOTH), so it is treated as an absent channel and refuses.
    rc, _ = _run_secure_serve(
        tmp_path,
        monkeypatch,
        "security.block_unlisted_outbound = true\n"
        + _SECURE_RETENTION
        + _SECURE_ALERTS
        + "[auth]\nnotify_security_events = false\n",
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "no out-of-band security-notification channel" in err and "refusing to start" in err


def test_serve_notify_warns_not_refuses_in_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # enforcement=warn reproduces the non-production dial: a missing notify channel only WARNS + starts.
    rc, _ = _run_secure_serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"\nsecurity.block_unlisted_outbound = true\n'
        + _SECURE_RETENTION,  # no SMTP
        env="staging",
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "account-security events have no push" in err
    assert "refusing to start" not in err  # warned, did not refuse


def test_serve_security_notifications_required_override_starts_in_prod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The explicit, audited opt-out: [alerts].security_notifications_required=false accepts the
    # pull-only /me/security-events feed in writing, downgrading the prod refusal to a warning.
    rc, _ = _run_secure_serve(
        tmp_path,
        monkeypatch,
        "security.block_unlisted_outbound = true\n"
        + _SECURE_RETENTION
        + "[alerts]\nsecurity_notifications_required = false\n",  # opt-out, no SMTP
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "security_notifications_required=false" in err
    assert "no out-of-band security-event push" in err


def test_serve_notify_quiet_in_synthetic_dev(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A synthetic instance (dev) is exempt from the security-notification gate — byte-identical start.
    # GIVEN 1 (ADR 0148): dev derives PHI now, so declare the synthetic opt-out explicitly.
    rc, _ = _run_secure_serve(
        tmp_path,
        monkeypatch,
        "security.handles_real_patient_data = false\n",
        env="dev",
        key=False,
    )
    assert rc == 0
    assert "security-notification" not in capsys.readouterr().err


def test_serve_require_encryption_starts_with_configured_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # CRYPTO-6 (serve guard): [store].require_encryption is a PRESENCE guard, not a key-usability
    # validator. With a configured MEFOR_STORE_ENCRYPTION_KEY — even a fresh/foreign key that matches
    # nothing on disk — serve STARTS (exit 0); the guard neither runs a decrypt-probe nor refuses. This
    # locks the boundary an audit mistook for a bug: a configured-but-unusable key is caught at RUNTIME
    # by per-row dead-lettering (see tests/test_store_encryption.py), NOT at startup. Contrast
    # test_serve_refuses_without_key_when_require_encryption (no key configured → refuse).
    from messagefoundry.store.crypto import generate_key

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())  # a configured (foreign) key
    # GIVEN 1 (ADR 0148): declare synthetic so the PHI egress/retention/notify gates stay quiet and
    # only the require_encryption presence guard is under test.
    (tmp_path / "messagefoundry.toml").write_text(
        "security.handles_real_patient_data = false\n[store]\nrequire_encryption = true\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    assert "require_encryption" not in capsys.readouterr().err  # presence satisfied → no refusal
