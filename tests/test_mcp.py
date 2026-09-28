"""
Tests for the Kredent MCP server.

Two layers are covered:

1. The tool handlers directly, which is where the logic lives and which must
   work without any MCP transport.
2. The full JSON-RPC handshake over stdio, which proves the server actually
   speaks the protocol a client will use.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

from kredent.mcp_server import (  # noqa: E402
    SERVER_NAME,
    TOOL_HANDLERS,
    call_tool,
)


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------


def test_exposes_the_four_documented_tools():
    assert set(TOOL_HANDLERS) == {
        "create_identity",
        "attest",
        "verify",
        "reputation",
    }


def test_unknown_tool_raises():
    with pytest.raises(ValueError):
        call_tool("does_not_exist", {})


def test_call_tool_tolerates_none_arguments():
    with pytest.raises(ValueError):
        call_tool("attest", None)


# ---------------------------------------------------------------------------
# create_identity
# ---------------------------------------------------------------------------


def test_create_identity_persists_and_hides_seed(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    out = call_tool("create_identity", {"name": "mcp-agent"})
    assert out["persisted"] is True
    assert out["agent_id"].startswith("did:key:z6Mk")
    assert "seed_hex" not in out


def test_create_identity_ephemeral_returns_seed(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    out = call_tool("create_identity", {"persist": False})
    assert out["persisted"] is False
    assert "seed_hex" in out
    assert "warning" in out


def test_create_identity_requires_name_when_persisting(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    with pytest.raises(ValueError, match="requires a 'name'"):
        call_tool("create_identity", {"persist": True})


# ---------------------------------------------------------------------------
# attest + verify
# ---------------------------------------------------------------------------


def test_attest_and_verify_via_tools(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    created = call_tool("create_identity", {"name": "a"})
    did = created["agent_id"]

    att = call_tool("attest", {"name": "a", "claim": {"action": "deployed"}})
    assert att["issuer"] == did
    assert att["type"] == "KredentAttestation"

    result = call_tool("verify", {"attestation": att})
    assert result["valid"] is True
    assert result["agent_id"] == did


def test_attest_rejects_missing_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    with pytest.raises(ValueError, match="No stored identity"):
        call_tool("attest", {"name": "ghost", "claim": {"a": 1}})


def test_attest_requires_a_source(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    with pytest.raises(ValueError, match="either 'name' or 'seed_hex'"):
        call_tool("attest", {"claim": {"a": 1}})


def test_attest_requires_a_claim(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    call_tool("create_identity", {"name": "a"})
    with pytest.raises(ValueError, match="non-empty 'claim'"):
        call_tool("attest", {"name": "a", "claim": {}})


def test_verify_flags_a_forged_attestation(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    created = call_tool("create_identity", {"name": "a"})
    att = call_tool("attest", {"name": "a", "claim": {"action": "x"}})
    att["claim"]["action"] = "forged"
    result = call_tool("verify", {"attestation": att})
    assert result["valid"] is False
    assert result["error_code"] == "INVALID_SIGNATURE"


def test_verify_requires_a_document(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="'attestation' object"):
        call_tool("verify", {"attestation": "not-an-object"})


# ---------------------------------------------------------------------------
# reputation
# ---------------------------------------------------------------------------


def test_reputation_from_supplied_events(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    created = call_tool("create_identity", {"name": "a"})
    did = created["agent_id"]

    out = call_tool(
        "reputation",
        {
            "agent_id": did,
            "events": [
                {"event_type": "confirmation"},
                {"event_type": "confirmation"},
                {"event_type": "contradiction"},
            ],
        },
    )
    assert out["source"] == "provided_events"
    assert out["reputation"]["attestations_verified"] == 2


def test_reputation_without_events_is_the_cold_start_floor(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    out = call_tool("reputation", {"agent_id": "did:key:z6MkNew"})
    assert out["source"] == "no_events_supplied"
    # With zero transactions the damping term is ~0, so the score is near zero.
    assert out["reputation"]["score"] < 0.01
    assert "note" in out


def test_reputation_requires_agent_id():
    with pytest.raises(ValueError, match="'agent_id'"):
        call_tool("reputation", {"agent_id": ""})


def test_reputation_rejects_non_array_events():
    with pytest.raises(ValueError, match="must be an array"):
        call_tool("reputation", {"agent_id": "did:key:z6MkA", "events": "nope"})


# ---------------------------------------------------------------------------
# Full JSON-RPC handshake over stdio
# ---------------------------------------------------------------------------


def _spawn_server(tmp_path):
    env = dict(os.environ)
    env["KREDENT_HOME"] = str(tmp_path / "home")
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.Popen(
        [sys.executable, str(ROOT / "mcp" / "kredent_mcp.py")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        env=env,
        cwd=str(ROOT),
    )


class _Client:
    def __init__(self, proc):
        self.proc = proc
        self._next = 0

    def _send(self, method, params=None, is_notif=False):
        self._next += 1
        mid = self._next
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not is_notif:
            msg["id"] = mid
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        if is_notif:
            return None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("server closed stdout")
            data = json.loads(line)
            if data.get("id") == mid:
                return data


def test_mcp_handshake_and_tool_roundtrip_over_stdio(tmp_path):
    proc = _spawn_server(tmp_path)
    try:
        client = _Client(proc)
        init = client._send(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "kredent-tests", "version": "0.1"},
            },
        )
        assert "error" not in init, init
        server_info = init["result"]["serverInfo"]
        assert server_info["name"] == SERVER_NAME

        client._send("notifications/initialized", is_notif=True)

        listed = client._send("tools/list", {})
        names = [t["name"] for t in listed["result"]["tools"]]
        assert set(names) == {"create_identity", "attest", "verify", "reputation"}

        created = client._send(
            "tools/call",
            {"name": "create_identity", "arguments": {"name": "stdio-agent"}},
        )
        payload = json.loads(created["result"]["content"][0]["text"])
        assert payload["agent_id"].startswith("did:key:z6Mk")

        attested = client._send(
            "tools/call",
            {"name": "attest", "arguments": {"name": "stdio-agent", "claim": {"a": 1}}},
        )
        att = json.loads(attested["result"]["content"][0]["text"])

        verified = client._send(
            "tools/call", {"name": "verify", "arguments": {"attestation": att}}
        )
        result = json.loads(verified["result"]["content"][0]["text"])
        assert result["valid"] is True
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_mcp_unknown_tool_returns_an_error_result_not_a_crash(tmp_path):
    proc = _spawn_server(tmp_path)
    try:
        client = _Client(proc)
        client._send(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "kredent-tests", "version": "0.1"},
            },
        )
        client._send("notifications/initialized", is_notif=True)
        res = client._send("tools/call", {"name": "no_such_tool", "arguments": {}})
        assert res["result"]["isError"] is True
    finally:
        proc.terminate()
        proc.wait(timeout=10)