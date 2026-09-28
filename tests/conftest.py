"""
Shared fixtures for the Kredent test suite.
"""

from __future__ import annotations

import os

import pytest

# Every test run must use a throwaway home so a developer's real identity store
# is never touched. Set before importing kredent.
os.environ.setdefault("KREDENT_HOME", "/tmp/kredent-test-home")

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from kredent import crypto  # noqa: E402
from kredent.attest import DEFAULT_KID  # noqa: E402
from kredent.crypto import generate_seed, keypair_from_seed  # noqa: E402
from kredent.models import AgentID, VerificationKey  # noqa: E402
from kredent.store import store_identity  # noqa: E402


@pytest.fixture
def sample_keypair():
    seed = generate_seed()
    raw_pub, multibase_pub, did = keypair_from_seed(seed)[1:]
    return seed, raw_pub, multibase_pub, did


@pytest.fixture
def sample_seed():
    return generate_seed()


@pytest.fixture
def sample_agent(sample_keypair):
    seed, raw_pub, multibase_pub, did = sample_keypair
    vkey = VerificationKey(
        kid=DEFAULT_KID,
        public_key_multibase=multibase_pub,
        purposes=["attestation", "call-signing"],
    )
    return AgentID(
        agent_id=did,
        version="1.0.0",
        created_at="2026-09-13T00:00:00Z",
        controller="did:legal:tr:vkn:1234567890",
        keys=[vkey],
        capabilities=["tool-call", "catalog-solve"],
    )


@pytest.fixture
def stored_agent(tmp_path, monkeypatch):
    """A named identity persisted in a throwaway store."""
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kredent-home"))
    seed = generate_seed()
    return store_identity("fixture-agent", seed, controller="did:web:acme.example")


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    """Ensure no test can reach the developer's real ~/.kredent."""
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kredent-home"))
    yield


@pytest.fixture
def deterministic_seed() -> bytes:
    """A fixed seed so signature vectors are reproducible across runs."""
    return bytes.fromhex(
        "9d61b19deff52181de4d4021a206b16d4f9a2d5d5c3f2f4b7d9b5e1f8f7e6d5c"
    )
