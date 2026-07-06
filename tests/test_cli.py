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
        "rte_request_router",
        "rte_response_router",
        "fhir_router",
        "sr_router",
    }
    assert {h["name"] for h in g["handlers"]} == {
        "archive",
        "acme_adt_handler",
        "partner_x12_handler",
        "immunization_submit_handler",
        "rte_query_handler",
        "rte_result_handler",
        "fhir_handler",
        "sr_to_oru",
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
    (tmp_path / "messagefoundry.toml").write_text(
        "[store]\nallow_unencrypted_phi = true\n", encoding="utf-8"
    )
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "staging"]) == 0
    err = capsys.readouterr().err
    assert "allow_unencrypted_phi" in err and "UNENCRYPTED at rest" in err and "staging" in err


def test_serve_require_encryption_overrides_keyless_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # require_encryption=true wins over allow_unencrypted_phi=true: the refusal is unconditional.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(
        "[store]\nrequire_encryption = true\nallow_unencrypted_phi = true\n", encoding="utf-8"
    )
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "staging"]) == 2
    assert "require_encryption" in capsys.readouterr().err


def test_serve_quiet_in_dev_without_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # dev is synthetic-only by policy (data_class != phi), so a keyless start is allowed and quiet — the
    # H3 refusal is gated on data_class==phi, not the environment label. (CI parity: synthetic stays
    # key-free.)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
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
        '[ai]\nenvironment = "test"\ndata_class = "phi"\nproduction = false\n', encoding="utf-8"
    )
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "test"]) == 2
    err = capsys.readouterr().err
    assert "PHI instance" in err and "UNENCRYPTED at rest" in err and "test" in err


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
    # A non-production PHI instance (staging) only WARNS on unrestricted egress and still starts —
    # the fail-closed escalation is production-only.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)  # silence the keyless warning
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
    assert "data_class" in capsys.readouterr().err


def test_serve_custom_env_with_posture_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A custom env with an explicit posture starts cleanly (app + uvicorn mocked).
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(
        '[ai]\nenvironment = "test"\ndata_class = "synthetic"\nproduction = false\n',
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
    monkeypatch.chdir(tmp_path)
    (tmp_path / "messagefoundry.toml").write_text('[api]\nhost = "0.0.0.0"\n', encoding="utf-8")
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 2
    assert "refusing to serve the API on non-loopback" in capsys.readouterr().err


def test_serve_allows_non_loopback_bind_with_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from messagefoundry.store.crypto import generate_key

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())  # silence the at-rest warning
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)  # don't actually serve
    (tmp_path / "messagefoundry.toml").write_text('[api]\nhost = "0.0.0.0"\n', encoding="utf-8")
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
    (tmp_path / "messagefoundry.toml").write_text('[api]\nhost = "127.0.0.1"\n', encoding="utf-8")
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"]) == 0
    assert "non-loopback" not in capsys.readouterr().err  # loopback never trips the guard


def test_serve_non_loopback_with_auth_off_refused_despite_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The opt-in flag accepts the cleartext-PHI risk; it must NOT also wave through serving a
    # full-privilege, unauthenticated API to the network — that stays a hard refuse regardless.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "messagefoundry.toml").write_text(
        '[api]\nhost = "0.0.0.0"\n[auth]\nenabled = false\n', encoding="utf-8"
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--allow-insecure-bind"]) == 2
    err = capsys.readouterr().err
    assert "enabled=false" in err  # the no-auth gate fired...
    assert "refusing to serve the API on non-loopback" not in err  # ...not the bind gate


# --- MFA-at-exposure posture (sec-mfa-on; off-loopback bind + [auth].require_mfa) ----------------
#
# An exposed (non-loopback) PHI bind with require_mfa off is single-factor over the network: refuse on
# a production PHI instance, warn on a non-production PHI instance, stay quiet on synthetic. These
# reach the MFA gate via --allow-insecure-bind (passes the cleartext-bind gate) with the keyless and
# open-egress gates pre-satisfied (a key + [egress].deny_by_default), so only the MFA posture is under
# test. create_managed_app + uvicorn are mocked so no socket is opened.


def _expose_toml(tmp_path: Path, *, extra: str = "") -> None:
    """A non-loopback bind with egress locked down (so the open-egress gate is silent)."""
    (tmp_path / "messagefoundry.toml").write_text(
        '[api]\nhost = "0.0.0.0"\n[egress]\ndeny_by_default = true\n' + extra, encoding="utf-8"
    )


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
    # Non-production PHI (staging) only WARNS and still starts — the fail-closed refuse is prod-only.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)  # silence the keyless warning
    _expose_toml(tmp_path)
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
    monkeypatch.chdir(tmp_path)
    _expose_toml(tmp_path)
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
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    _expose_toml(tmp_path, extra="[auth]\nrequire_mfa = true\n")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert (
        main(["serve", "--config", str(SAMPLES_CONFIG), "--allow-insecure-bind", "--env", "prod"])
        == 0
    )
    assert "require_mfa off" not in capsys.readouterr().err


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
        '[api]\nhost = "0.0.0.0"\n'
        "[egress]\ndeny_by_default = true\n"
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
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    (tmp_path / "messagefoundry.toml").write_text(
        '[api]\nhost = "127.0.0.1"\n[egress]\ndeny_by_default = true\n', encoding="utf-8"
    )
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "prod"]) == 0
    assert "require_mfa" not in capsys.readouterr().err


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
        '[api]\nserve_ui = true\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.2"]\n'
        "[egress]\ndeny_by_default = true\n",
    )
    assert rc == 2
    assert "requires [api].public_origin" in capsys.readouterr().err


def test_serve_ui_upstream_with_public_origin_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The refusal's happy path: one config line satisfies it (the error message names it).
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        '[api]\nserve_ui = true\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.2"]\n'
        'public_origin = "https://mefor.example.org"\n[egress]\ndeny_by_default = true\n',
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
        '[api]\nserve_ui = true\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.2"]\n'
        'public_origin = "http://mefor.example.org"\n[egress]\ndeny_by_default = true\n',
    )
    assert rc == 2
    assert "public_origin is http://" in capsys.readouterr().err


def test_serve_ui_warns_on_undeclared_proxy_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # public_origin set on an unprotected loopback instance = the undeclared-proxy heuristic:
    # WARN (cookie ships without Secure until the posture is declared) but still start.
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        '[api]\nserve_ui = true\npublic_origin = "https://mefor.example.org"\n'
        "[egress]\ndeny_by_default = true\n",
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
        '[api]\nserve_ui = true\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.2"]\n'
        'public_origin = "https://mefor.example.org"\n'
        "[auth]\nrequire_mfa = true\n[egress]\ndeny_by_default = true\n",
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
        """[api]
serve_ui = true
tls_terminated_upstream = true
trusted_proxies = ["10.0.0.2"]
public_origin = "https://mefor.example.org"
[egress]
deny_by_default = true
""",
        env="prod",
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "declared reverse proxy" in err and "require_mfa off; refusing to start" in err


def test_serve_ui_declared_proxy_warns_mfa_on_staging_phi(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Non-production PHI keeps the warn tier (parity with the off-loopback-bind gate).
    rc = _l5b_serve(
        tmp_path,
        monkeypatch,
        """[api]
serve_ui = true
tls_terminated_upstream = true
trusted_proxies = ["10.0.0.2"]
public_origin = "https://mefor.example.org"
[egress]
deny_by_default = true
""",
        env="staging",
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "declared reverse proxy" in err and "single-factor over the network" in err
