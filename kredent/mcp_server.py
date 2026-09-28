"""
Kredent MCP server — protocol layer.

This module lives inside the ``kredent`` package rather than at the repository
root for one specific reason: a top-level directory named ``mcp`` would shadow
the installed ``mcp`` SDK on ``sys.path`` and break its own imports. Keeping the
implementation here avoids that collision entirely.

Exposes four tools over the Model Context Protocol so that an AI agent can
manage its own identity: ``create_identity``, ``attest``, ``verify`` and
``reputation``.

Security posture
----------------
``create_identity`` returns the seed **only** when ``persist=false`` is passed
explicitly. With ``persist=true`` (the default) the seed is written to the local
store with ``0600`` permissions and never placed on the transport at all.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

from kredent import __version__ as KREDENT_VERSION
from kredent.attest import DEFAULT_KID, create_agent_id, create_attestation, verify_attestation
from kredent.crypto import generate_seed, keypair_from_seed
from kredent.reputation import compute_reputation_score, reputation_from_events
from kredent.store import (
    delete_identity,
    identity_exists,
    list_identities,
    load_identity,
    store_identity,
)

SERVER_NAME = "kredent"
SERVER_VERSION = KREDENT_VERSION
SERVER_TITLE = "Kredent — Agent Identity & Reputation"

# ---------------------------------------------------------------------------
# Tool schemas (JSON Schema, consumed by MCP clients)
# ---------------------------------------------------------------------------

_CREATE_INPUT: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "description": (
                "A local name for this identity (e.g. 'billing-bot'). Required when persist "
                "is true; used only as a filename, never transmitted elsewhere."
            ),
        },
        "controller": {
            "type": "string",
            "description": "Optional controller DID or legal anchor, e.g. did:web:acme.com",
        },
        "capabilities": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Declared capabilities of the agent.",
        },
        "persist": {
            "type": "boolean",
            "default": True,
            "description": (
                "If true (default), the seed is stored locally with 0600 permissions and never "
                "returned over the transport. If false, nothing is written to disk and the "
                "seed_hex is returned once — the caller must store it in a secrets manager."
            ),
        },
    },
    "required": [],
}

_ATTEST_INPUT: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string",
            "description": "Name of a locally stored identity to sign with.",
        },
        "seed_hex": {
            "type": "string",
            "description": "A 32-byte Ed25519 seed as hex. Alternative to name.",
        },
        "claim": {
            "type": "object",
            "description": (
                "The claim being asserted, e.g. "
                '{"action":"deployed","service":"billing-api","version":"1.4.2"}'
            ),
        },
        "expires_at": {"type": "string", "description": "Optional ISO-8601 expiry timestamp."},
    },
    "required": ["claim"],
}

_VERIFY_INPUT: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "attestation": {"type": "object", "description": "The attestation document to verify."},
        "ignore_expiry": {
            "type": "boolean",
            "default": False,
            "description": "Skip the expiry check when verifying.",
        },
    },
    "required": ["attestation"],
}

_REPUTATION_INPUT: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "agent_id": {"type": "string", "description": "The agent's did:key identifier."},
        "events": {
            "type": "array",
            "description": (
                "Ledger events for the agent. Each item should have an event_type of "
                "'claim', 'confirmation' or 'contradiction'."
            ),
        },
        "reliability": {"type": "number", "minimum": 0, "maximum": 1, "default": 0.9},
        "accuracy": {"type": "number", "minimum": 0, "maximum": 1, "default": 0.9},
        "stability": {"type": "number", "minimum": 0, "maximum": 1, "default": 0.9},
    },
    "required": ["agent_id"],
}

_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "create_identity",
        "title": "Create an agent identity",
        "description": (
            "Generate a new Ed25519 keypair and publish a did:key identity for this agent. "
            "did:key is self-resolving, so the identity can be verified without a registry "
            "or any network access."
        ),
        "input_schema": _CREATE_INPUT,
    },
    {
        "name": "attest",
        "title": "Sign an attestation",
        "description": (
            "Sign a claim with the agent's key, producing a verifiable attestation. Anyone "
            "holding the attestation can verify offline that this agent made the claim."
        ),
        "input_schema": _ATTEST_INPUT,
    },
    {
        "name": "verify",
        "title": "Verify an attestation",
        "description": (
            "Independently verify a Kredent attestation. Checks the Ed25519 signature over the "
            "canonical document, the did:key binding, and the content-addressed id. Fully offline."
        ),
        "input_schema": _VERIFY_INPUT,
    },
    {
        "name": "reputation",
        "title": "Compute reputation",
        "description": (
            "Compute an agent's reputation score from a ledger of events. The score is a "
            "deterministic function of the events, so it can be recomputed and audited."
        ),
        "input_schema": _REPUTATION_INPUT,
    },
]


# ---------------------------------------------------------------------------
# Tool handlers — plain functions, easy to unit-test without a transport
# ---------------------------------------------------------------------------


def _tool_create_identity(args: Dict[str, Any]) -> Dict[str, Any]:
    persist = args.get("persist", True)
    name = args.get("name")
    controller = args.get("controller") or "did:legal:unknown"
    capabilities = args.get("capabilities") or ["tool-call"]

    if persist and not name:
        raise ValueError("create_identity with persist=true requires a 'name'")

    seed = generate_seed()
    _, raw_pub, multibase_pub, did = keypair_from_seed(seed)

    if persist:
        stored = store_identity(
            name, seed, controller=controller, capabilities=capabilities, kid=DEFAULT_KID
        )
        return {
            "created": True,
            "persisted": True,
            "name": stored.name,
            "agent_id": stored.agent_id.agent_id,
            "public_key_multibase": multibase_pub,
            "identity_document": stored.agent_id.to_dict(),
        }

    agent = create_agent_id(seed, controller=controller, capabilities=capabilities)
    return {
        "created": True,
        "persisted": False,
        "agent_id": did,
        "public_key_multibase": multibase_pub,
        "identity_document": agent.to_dict(),
        "seed_hex": seed.hex(),
        "warning": (
            "This seed is the root of the identity and is returned only because "
            "persist=false was requested. Nothing was written to disk; store it in a "
            "secrets manager now, as it cannot be recovered."
        ),
    }


def _tool_attest(args: Dict[str, Any]) -> Dict[str, Any]:
    claim = args.get("claim")
    if not isinstance(claim, dict) or not claim:
        raise ValueError("attest requires a non-empty 'claim' object")

    name = args.get("name")
    seed_hex = args.get("seed_hex")

    if name:
        if not identity_exists(name):
            raise ValueError(f"No stored identity named {name!r}")
        seed = load_identity(name).seed
    elif seed_hex:
        try:
            seed = bytes.fromhex(seed_hex)
        except ValueError:
            raise ValueError("seed_hex is not valid hexadecimal")
        if len(seed) != 32:
            raise ValueError("seed_hex must decode to exactly 32 bytes")
    else:
        raise ValueError("attest requires either 'name' or 'seed_hex'")

    attestation = create_attestation(seed, claim, expires_at=args.get("expires_at"))
    return attestation.to_dict()


def _tool_verify(args: Dict[str, Any]) -> Dict[str, Any]:
    doc = args.get("attestation")
    if not isinstance(doc, dict):
        raise ValueError("verify requires an 'attestation' object")
    result = verify_attestation(doc, check_expiry=not args.get("ignore_expiry", False))
    out: Dict[str, Any] = {
        "valid": result.valid,
        "status_code": result.status_code,
        "agent_id": result.agent_id,
        "message": result.message,
    }
    if result.error_code:
        out["error_code"] = result.error_code
    return out


def _tool_reputation(args: Dict[str, Any]) -> Dict[str, Any]:
    agent_id = args.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id:
        raise ValueError("reputation requires an 'agent_id'")

    if identity_exists(agent_id):
        agent_id = load_identity(agent_id).agent_id.agent_id

    events = args.get("events")
    if events:
        if not isinstance(events, list):
            raise ValueError("'events' must be an array")
        score = reputation_from_events(
            agent_id,
            events,
            reliability=float(args.get("reliability", 0.9)),
            accuracy=float(args.get("accuracy", 0.9)),
            stability=float(args.get("stability", 0.9)),
        )
        return {"agent_id": agent_id, "source": "provided_events", "reputation": score.to_dict()}

    score = compute_reputation_score(
        reliability=float(args.get("reliability", 0.9)),
        accuracy=float(args.get("accuracy", 0.9)),
        stability=float(args.get("stability", 0.9)),
        total_claims=0,
        refuted_claims=0,
        total_transactions=0,
    )
    return {
        "agent_id": agent_id,
        "source": "no_events_supplied",
        "reputation": score.to_dict(),
        "note": (
            "No events were supplied, so the score shown is the cold-start floor: a new "
            "identity starts near zero and earns credibility as confirmations accumulate."
        ),
    }


TOOL_HANDLERS: Dict[str, Any] = {
    "create_identity": _tool_create_identity,
    "attest": _tool_attest,
    "verify": _tool_verify,
    "reputation": _tool_reputation,
}


def call_tool(name: str, arguments: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Invoke a tool by name with JSON arguments.

    Raises ``ValueError`` on bad input so the transport layer can surface it as
    a tool error rather than a protocol crash.
    """
    handler = TOOL_HANDLERS.get(name)
    if handler is None:
        raise ValueError(f"Unknown tool: {name}")
    return handler(dict(arguments or {}))


# ---------------------------------------------------------------------------
# MCP server wiring
# ---------------------------------------------------------------------------


def _make_result(payload: Any, is_error: bool = False):
    from mcp.types import CallToolResult, TextContent

    text = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        isError=is_error,
    )


def build_server():
    """Construct the Kredent MCP server using the low-level callback API."""
    from mcp.server import Server
    from mcp.types import (
        CallToolRequest,
        CallToolRequestParams,
        CallToolResult,
        ListToolsResult,
        PaginatedRequestParams,
        Tool,
    )

    server = Server(
        SERVER_NAME,
        version=SERVER_VERSION,
        title=SERVER_TITLE,
        description=(
            "Issues and verifies agent identity and signed attestations (did:key, Ed25519), "
            "and computes auditable reputation scores."
        ),
        instructions=(
            "Use create_identity once per agent to establish a did:key identity, then attest "
            "to record claims that agent has made. Use verify to check any Kredent attestation "
            "offline. Seeds are persisted locally and never returned unless persist=false."
        ),
    )

    async def handle_list_tools(ctx, params) -> ListToolsResult:
        tools = [
            Tool(
                name=t["name"],
                title=t.get("title"),
                description=t["description"],
                input_schema=t["input_schema"],
            )
            for t in _TOOLS
        ]
        return ListToolsResult(tools=tools)

    async def handle_call_tool(ctx, params: CallToolRequestParams) -> CallToolResult:
        try:
            payload = call_tool(params.name, dict(params.arguments or {}))
            return _make_result(payload)
        except ValueError as exc:
            return _make_result({"error": str(exc)}, is_error=True)
        except FileNotFoundError as exc:
            return _make_result({"error": str(exc)}, is_error=True)

    server.add_request_handler("tools/list", PaginatedRequestParams, handle_list_tools)
    server.add_request_handler("tools/call", CallToolRequestParams, handle_call_tool)
    return server


async def run_stdio() -> None:
    from mcp.server import NotificationOptions
    from mcp.server.stdio import stdio_server

    server = build_server()
    options = server.create_initialization_options(NotificationOptions())
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, options)


def main() -> None:
    import asyncio

    try:
        asyncio.run(run_stdio())
    except KeyboardInterrupt:  # pragma: no cover
        pass


if __name__ == "__main__":  # pragma: no cover
    main()
