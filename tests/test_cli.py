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
    # samples/config ships two routes: the ADT file-archive route and the env()-driven ACME route.
    assert {"IB_Test_ADT", "IB_ACME_ADT"} <= set(inbound)
    adt_in = inbound["IB_Test_ADT"]
    assert adt_in["router"] == "adt_router" and adt_in["type"] == "mllp"
    assert {c["name"] for c in g["outbound"]} >= {"FILE-OUT_Test_ADT", "OB_ACME_ADT"}
    assert {r["name"] for r in g["routers"]} == {"adt_router", "acme_adt_router"}
    assert {h["name"] for h in g["handlers"]} == {"archive", "acme_adt_handler"}
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


def test_serve_refuses_without_key_when_require_encryption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(
        "[store]\nrequire_encryption = true\n", encoding="utf-8"
    )
    assert main(["serve", "--config", str(SAMPLES_CONFIG)]) == 2
    assert "require_encryption" in capsys.readouterr().err


def test_serve_warns_in_prod_without_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)  # don't actually serve
    # environment defaults to 'prod', so the no-key at-rest warning fires (serve still starts).
    assert main(["serve", "--config", str(SAMPLES_CONFIG)]) == 0
    assert "UNENCRYPTED at rest" in capsys.readouterr().err


# --- non-loopback API bind guard (--allow-insecure-bind) ---------------------


def test_serve_refuses_non_loopback_bind_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Auth is enabled by default, so this exercises the cleartext-bind refuse, not the no-auth gate:
    # Phase 1 has no API TLS, so a non-loopback bind must fail closed unless the operator opts in.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "messagefoundry.toml").write_text('[api]\nhost = "0.0.0.0"\n', encoding="utf-8")
    assert main(["serve", "--config", str(SAMPLES_CONFIG)]) == 2
    assert "refusing to serve the API on non-loopback" in capsys.readouterr().err


def test_serve_allows_non_loopback_bind_with_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from messagefoundry.store.crypto import generate_key

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())  # silence the at-rest warning
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)  # don't actually serve
    (tmp_path / "messagefoundry.toml").write_text('[api]\nhost = "0.0.0.0"\n', encoding="utf-8")
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--allow-insecure-bind"]) == 0
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
    assert main(["serve", "--config", str(SAMPLES_CONFIG)]) == 0
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
