"""
Local secrets and identity store.

Kredent never writes a private key anywhere by default. When a user explicitly
asks to persist an identity, it is stored in a single JSON file under
``~/.kredent/`` with ``0600`` permissions, containing the 32-byte seed.

Security notes
--------------
* The seed is the root of an agent's identity. Anyone holding it can sign
  attestations as that agent. Treat it as a credential, not as configuration.
* The store is a convenience for local development and single-agent hosts. It
  is deliberately not a vault, not an HSM and not a KMS — for production
  attestation, keep the seed in a real secrets manager and pass it in memory.
* ``KREDENT_HOME`` overrides the base directory, which keeps test runs from
  touching a developer's real identity store.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .crypto import ED25519_KEY_LEN, keypair_from_seed
from .models import AgentID
from .attest import create_agent_id, DEFAULT_KID

DEFAULT_HOME_DIRNAME = ".kredent"
IDENTITIES_SUBDIR = "identities"

# Historical alias retained for the Roboseal lineage.
LEGACY_HOME_DIRNAME = ".roboseal"


def home_dir() -> Path:
    """Resolve the Kredent data directory (honouring ``KREDENT_HOME``)."""
    env = os.environ.get("KREDENT_HOME")
    if env:
        path = Path(env).expanduser()
    else:
        candidate = Path.home() / DEFAULT_HOME_DIRNAME
        legacy = Path.home() / LEGACY_HOME_DIRNAME
        # Prefer the modern location; fall back to the legacy one if it exists
        # and the modern one does not, so pre-existing installs keep working.
        path = candidate if candidate.exists() or not legacy.exists() else legacy
    path.mkdir(parents=True, exist_ok=True)
    (path / IDENTITIES_SUBDIR).mkdir(parents=True, exist_ok=True)
    return path


def identities_dir() -> Path:
    return home_dir() / IDENTITIES_SUBDIR


def _identity_path(name: str) -> Path:
    safe = _sanitize_name(name)
    return identities_dir() / f"{safe}.json"


def _sanitize_name(name: str) -> str:
    if not name:
        raise ValueError("identity name must not be empty")
    cleaned = "".join(c for c in name if c.isalnum() or c in ("-", "_", "."))
    if not cleaned:
        raise ValueError(f"identity name {name!r} has no usable characters")
    if cleaned in (".", ".."):
        raise ValueError(f"identity name {name!r} is not allowed")
    return cleaned


def _restrict_permissions(path: Path) -> None:
    """Best-effort ``0600`` on POSIX. On other platforms this is a no-op."""
    try:
        path.chmod(0o600)
    except OSError:
        # Non-POSIX filesystems or read-only mounts: warn-free degradation.
        pass


@dataclass
class StoredIdentity:
    """An identity record as serialized to disk."""

    name: str
    seed: bytes
    agent_id: AgentID

    def to_dict(self) -> dict:
        _, _, multibase_pub, did = keypair_from_seed(self.seed)
        return {
            "name": self.name,
            "agent_id": self.agent_id.agent_id,
            "controller": self.agent_id.controller,
            "capabilities": list(self.agent_id.capabilities),
            "kid": self.agent_id.keys[0].kid if self.agent_id.keys else DEFAULT_KID,
            "public_key_multibase": multibase_pub,
            "seed_hex": self.seed.hex(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "StoredIdentity":
        from .models import VerificationKey

        seed = bytes.fromhex(data["seed_hex"])
        if len(seed) != ED25519_KEY_LEN:
            raise ValueError("stored seed is not 32 bytes")

        kid = data.get("kid", DEFAULT_KID)
        multibase_pub = data.get("public_key_multibase", "")
        agent_id = AgentID(
            agent_id=data["agent_id"],
            version="1.0.0",
            created_at="",
            controller=data.get("controller", "did:legal:unknown"),
            keys=[
                VerificationKey(
                    kid=kid,
                    public_key_multibase=multibase_pub,
                    purposes=["attestation", "call-signing"],
                )
            ],
            capabilities=list(data.get("capabilities", [])),
        )
        return cls(name=data["name"], seed=seed, agent_id=agent_id)


def store_identity(
    name: str,
    seed: bytes,
    controller: str = "did:legal:unknown",
    capabilities: Optional[list] = None,
    kid: str = DEFAULT_KID,
) -> StoredIdentity:
    """Persist a named identity (seed + document) to the local store."""
    if len(seed) != ED25519_KEY_LEN:
        raise ValueError(f"Ed25519 seed must be {ED25519_KEY_LEN} bytes")
    path = _identity_path(name)
    stored = StoredIdentity(
        name=_sanitize_name(name),
        seed=seed,
        agent_id=create_agent_id(
            seed, controller=controller, capabilities=capabilities, kid=kid
        ),
    )
    path.write_text(json.dumps(stored.to_dict(), indent=2, ensure_ascii=False))
    _restrict_permissions(path)
    return stored


def load_identity(name: str) -> StoredIdentity:
    """Load a named identity from the local store."""
    path = _identity_path(name)
    if not path.exists():
        raise FileNotFoundError(f"No stored Kredent identity named {name!r} in {identities_dir()}")
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"Identity file {path} is not valid JSON: {exc}") from exc
    return StoredIdentity.from_dict(data)


def list_identities() -> list:
    """List the names of stored identities."""
    out = []
    for path in sorted(identities_dir().glob("*.json")):
        try:
            out.append(path.stem)
        except OSError:
            continue
    return out


def delete_identity(name: str) -> bool:
    """Delete a stored identity. Returns True if something was removed."""
    path = _identity_path(name)
    if path.exists():
        path.unlink()
        return True
    return False


def identity_exists(name: str) -> bool:
    return _identity_path(name).exists()


__all__ = [
    "home_dir",
    "identities_dir",
    "StoredIdentity",
    "store_identity",
    "load_identity",
    "list_identities",
    "delete_identity",
    "identity_exists",
]
