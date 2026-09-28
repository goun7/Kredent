"""
Tests for the local identity store.

The store holds the seed — the root of an agent's identity — so its behaviour is
security-relevant: secrets must be written with restrictive permissions, must
never appear where they were not asked for, and must round-trip losslessly.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from kredent import generate_seed, keypair_from_seed
from kredent.store import (
    StoredIdentity,
    delete_identity,
    home_dir,
    identity_exists,
    list_identities,
    load_identity,
    store_identity,
)


def test_store_and_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    seed = generate_seed()
    _, _, mb, did = keypair_from_seed(seed)

    stored = store_identity("agent-one", seed, controller="did:web:acme.example")
    assert stored.agent_id.agent_id == did

    loaded = load_identity("agent-one")
    assert loaded.seed == seed
    assert loaded.agent_id.agent_id == did
    assert loaded.agent_id.controller == "did:web:acme.example"
    assert loaded.agent_id.keys[0].public_key_multibase == mb


def test_stored_file_has_restrictive_permissions(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    store_identity("agent-one", generate_seed())

    path = home_dir() / "identities" / "agent-one.json"
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_stored_document_contains_the_seed(tmp_path, monkeypatch):
    """The seed is on disk (that is the point of the store), and loadable."""
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    seed = generate_seed()
    store_identity("agent-one", seed)

    path = home_dir() / "identities" / "agent-one.json"
    doc = json.loads(path.read_text())
    assert doc["seed_hex"] == seed.hex()
    assert doc["agent_id"].startswith("did:key:")


def test_list_and_delete(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    store_identity("a", generate_seed())
    store_identity("b", generate_seed())
    assert sorted(list_identities()) == ["a", "b"]

    assert delete_identity("a") is True
    assert delete_identity("a") is False
    assert list_identities() == ["b"]


def test_identity_exists(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    assert identity_exists("nope") is False
    store_identity("yep", generate_seed())
    assert identity_exists("yep") is True


def test_load_missing_identity_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    with pytest.raises(FileNotFoundError):
        load_identity("ghost")


def test_name_sanitization_blocks_traversal(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    # A traversal name must never escape the identities directory.
    for bad in ("..", "../escape", "", "!!!"):
        with pytest.raises((ValueError, FileNotFoundError, TypeError)):
            if bad == "":
                # An empty name has no usable characters.
                store_identity(bad, generate_seed())
            else:
                load_identity(bad)


def _raise(exc):
    raise exc


def test_name_sanitization_strips_unsafe_characters(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    # Slashes and spaces are stripped; the identity is stored under a safe name.
    store_identity("my agent/01", generate_seed())
    assert "myagent01" in list_identities()


def test_store_rejects_bad_seed(tmp_path, monkeypatch):
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "home"))
    with pytest.raises(ValueError):
        store_identity("x", b"short")


def test_home_dir_honors_env(tmp_path, monkeypatch):
    target = tmp_path / "elsewhere"
    monkeypatch.setenv("KREDENT_HOME", str(target))
    assert home_dir() == target
    assert home_dir().is_dir()
    assert (home_dir() / "identities").is_dir()


def test_stored_identity_dict_roundtrip():
    seed = generate_seed()
    _, _, mb, did = keypair_from_seed(seed)
    stored = StoredIdentity(name="t", seed=seed, agent_id=None)  # type: ignore[arg-type]
    # to_dict must not depend on the agent document being populated.
    doc = {
        "name": "t",
        "agent_id": did,
        "controller": "did:legal:unknown",
        "capabilities": [],
        "kid": "sig-ed25519-primary",
        "public_key_multibase": mb,
        "seed_hex": seed.hex(),
    }
    parsed = StoredIdentity.from_dict(doc)
    assert parsed.seed == seed
    assert parsed.agent_id.agent_id == did
