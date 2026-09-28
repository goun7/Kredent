"""
Tests for the Kredent CLI, exercised as real subprocesses.

Running the CLI as a subprocess is deliberate: it proves the entry points work
from a clean interpreter, exactly as a user would invoke them, rather than only
under pytest's in-process harness.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def run_cli(*args, env_extra=None, cwd=None, input_text=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    if env_extra:
        env.update(env_extra)
    res = subprocess.run(
        [sys.executable, "-m", "kredent.cli", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd) if cwd else str(ROOT),
        input=input_text,
    )
    return res


def _throwaway_home(tmp_path):
    return {"KREDENT_HOME": str(tmp_path / "kredent-home")}


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


def test_cli_create_persists_and_hides_seed(tmp_path):
    res = run_cli(
        "create",
        "--name", "billing-bot",
        "--controller", "did:web:acme.example",
        "--capabilities", "tool-call", "x402-pay",
        env_extra=_throwaway_home(tmp_path),
    )
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["status"] == "stored"
    assert data["agent_id"].startswith("did:key:z6Mk")
    assert "seed_hex" not in data
    assert data["identity_document"]["controller"] == "did:web:acme.example"
    assert data["identity_document"]["capabilities"] == ["tool-call", "x402-pay"]


def test_cli_create_ephemeral_returns_seed_once(tmp_path):
    res = run_cli("create", env_extra=_throwaway_home(tmp_path))
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["status"] == "ephemeral"
    assert "seed_hex" in data
    assert "warning" in data
    # Nothing was persisted.
    assert run_cli("list", env_extra=_throwaway_home(tmp_path)).stdout.strip() == (
        "No stored identities. Use `kredent create --name <name>` to create one."
    )


def test_cli_list_reports_stored_names(tmp_path):
    home = _throwaway_home(tmp_path)
    run_cli("create", "--name", "a", env_extra=home)
    run_cli("create", "--name", "b", env_extra=home)
    res = run_cli("list", env_extra=home)
    assert res.returncode == 0
    assert json.loads(res.stdout)["identities"] == ["a", "b"]


def test_cli_delete(tmp_path):
    home = _throwaway_home(tmp_path)
    run_cli("create", "--name", "a", env_extra=home)
    res = run_cli("delete", "a", env_extra=home)
    assert res.returncode == 0
    assert "deleted" in res.stdout
    assert run_cli("delete", "a", env_extra=home).returncode == 1


# ---------------------------------------------------------------------------
# attest + verify: the end-to-end flow
# ---------------------------------------------------------------------------


def test_cli_attest_and_verify_roundtrip(tmp_path):
    home = _throwaway_home(tmp_path)
    run_cli("create", "--name", "billing-bot", env_extra=home)

    att_path = tmp_path / "att.json"
    res = run_cli(
        "attest",
        "--name", "billing-bot",
        "--claim", '{"action":"deployed","service":"billing-api","version":"1.4.2"}',
        "--out", str(att_path),
        env_extra=home,
    )
    assert res.returncode == 0, res.stderr
    assert att_path.exists()

    doc = json.loads(att_path.read_text())
    assert doc["type"] == "KredentAttestation"
    assert doc["claim"]["service"] == "billing-api"

    res = run_cli("verify", str(att_path), env_extra=home)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["valid"] is True
    assert data["agent_id"] == doc["issuer"]


def test_cli_verify_reads_stdin(tmp_path):
    home = _throwaway_home(tmp_path)
    run_cli("create", "--name", "a", env_extra=home)
    res = run_cli(
        "attest", "--name", "a", "--claim", '{"action":"x"}', env_extra=home
    )
    assert res.returncode == 0, res.stderr

    res2 = run_cli("verify", env_extra=home, input_text=res.stdout)
    assert res2.returncode == 0, res2.stderr
    assert json.loads(res2.stdout)["valid"] is True


def test_cli_verify_rejects_forged_file(tmp_path):
    home = _throwaway_home(tmp_path)
    run_cli("create", "--name", "a", env_extra=home)
    res = run_cli("attest", "--name", "a", "--claim", '{"action":"x"}', env_extra=home)
    doc = json.loads(res.stdout)
    doc["claim"]["action"] = "something-else"

    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(doc))

    res2 = run_cli("verify", str(forged), env_extra=home)
    assert res2.returncode == 1
    data = json.loads(res2.stdout)
    assert data["valid"] is False
    assert data["error_code"] == "INVALID_SIGNATURE"


def test_cli_attest_requires_a_source(tmp_path):
    home = _throwaway_home(tmp_path)
    res = run_cli("attest", "--claim", '{"action":"x"}', env_extra=home)
    assert res.returncode != 0


def test_cli_attest_rejects_bad_claim(tmp_path):
    home = _throwaway_home(tmp_path)
    run_cli("create", "--name", "a", env_extra=home)
    res = run_cli("attest", "--name", "a", "--claim", "not-json", env_extra=home)
    assert res.returncode != 0
    assert "not valid JSON" in res.stderr


def test_cli_attest_with_seed_hex(tmp_path):
    home = _throwaway_home(tmp_path)
    res = run_cli("create", env_extra=home)
    seed_hex = json.loads(res.stdout)["seed_hex"]

    res2 = run_cli(
        "attest", "--seed-hex", seed_hex, "--claim", '{"action":"y"}', env_extra=home
    )
    assert res2.returncode == 0, res2.stderr
    # Verify the attestation by piping it back in on stdin.
    assert run_cli("verify", env_extra=home, input_text=res2.stdout).returncode == 0


def test_cli_attest_rejects_short_seed(tmp_path):
    home = _throwaway_home(tmp_path)
    res = run_cli("attest", "--seed-hex", "abcd", "--claim", '{"a":1}', env_extra=home)
    assert res.returncode != 0


# ---------------------------------------------------------------------------
# reputation
# ---------------------------------------------------------------------------


def test_cli_reputation_with_explicit_metrics(tmp_path):
    home = _throwaway_home(tmp_path)
    res = run_cli("create", env_extra=home)
    did = json.loads(res.stdout)["agent_id"]

    res2 = run_cli(
        "reputation",
        did,
        "--rel", "0.95",
        "--acc", "0.90",
        "--stab", "0.85",
        "--transactions", "100",
        "--total-claims", "5",
        "--refuted-claims", "0",
        env_extra=home,
    )
    assert res2.returncode == 0, res2.stderr
    rep = json.loads(res2.stdout)["reputation"]
    assert rep["tier"] == "TIER_A"
    assert rep["reliability"] == 0.95


def test_cli_reputation_from_ledger(tmp_path):
    home = _throwaway_home(tmp_path)
    res = run_cli("create", env_extra=home)
    did = json.loads(res.stdout)["agent_id"]

    ledger_path = tmp_path / "ledger.json"
    ledger_path.write_text(
        json.dumps(
            [
                {"event_type": "confirmation", "agent_id": did},
                {"event_type": "confirmation", "agent_id": did},
                {"event_type": "contradiction", "agent_id": did},
            ]
        )
    )
    res2 = run_cli("reputation", did, "--ledger", str(ledger_path), env_extra=home)
    assert res2.returncode == 0, res2.stderr
    out = json.loads(res2.stdout)
    assert out["source"] == str(ledger_path)
    assert out["reputation"]["total_claims"] >= 1
    assert out["reputation"]["attestations_verified"] == 2


def test_cli_reputation_accepts_stored_name(tmp_path):
    home = _throwaway_home(tmp_path)
    run_cli("create", "--name", "a", env_extra=home)
    res = run_cli("reputation", "a", env_extra=home)
    assert res.returncode == 0, res.stderr
    assert "reputation" in json.loads(res.stdout)


def test_cli_version():
    res = run_cli("--version")
    assert res.returncode == 0
    assert "kredent" in res.stdout


def test_cli_requires_a_subcommand():
    res = run_cli()
    assert res.returncode != 0
