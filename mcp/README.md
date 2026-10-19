# Kredent MCP Server — agent identity & reputation

Model Context Protocol server (**2025-06-18**, JSON-RPC 2.0 over stdio)
exposing Kredent's four identity operations to any MCP client — Claude
Desktop, Cursor, Windsurf, Cline.

An agent that cannot be identified cannot be held to anything it said.
Kredent gives an agent a self-resolving `did:key` identity, lets it sign
claims, and lets anyone verify those claims **offline**.

## Tools

| Tool | What it does |
|---|---|
| `create_identity` | Generate an Ed25519 keypair and publish a self-resolving `did:key` identity. |
| `attest` | Sign a claim with a stored identity (or a raw seed), producing a self-contained attestation. |
| `verify` | Verify an attestation offline: Ed25519 signature, did:key binding, content-addressed id, expiry. |
| `reputation` | Compute a reputation score from a ledger of events — a deterministic, recomputable formula. |

## Install — 30 seconds, $0

```bash
pip install "kredent[mcp]"          # mcp SDK is the only extra
python mcp/kredent_mcp.py           # stdio JSON-RPC, from the repo root
```

Wire it into a client:

```json
{
  "mcpServers": {
    "kredent": { "command": "kredent-mcp" }
  }
}
```

Or from a checkout:

```json
{
  "mcpServers": {
    "kredent": {
      "command": "python",
      "args": ["/path/to/Kredent/mcp/kredent_mcp.py"]
    }
  }
}
```

## Example session

> **You:** Create an identity for the billing bot.
>
> **create_identity** → `{"agent_id": "did:key:z6Mk...",
> "public_key_multibase": "z6Mk...", "identity_document": {...}}`
>
> **You:** Attest that it deployed billing-api 1.4.2.
>
> **attest** → a self-contained attestation with an Ed25519 proof.
>
> **You:** Verify that attestation.
>
> **verify** → `{"valid": true, "agent_id": "did:key:z6Mk...",
> "status_code": "OK"}` — no network, no registry.

## Security posture

`create_identity` returns the seed **only** when `persist: false` is passed
explicitly. With `persist: true` (the default) the seed is written to the
local store with `0600` permissions and never placed on the transport at
all. Only the public half ever appears in an identity document.

## Verify it works (stdio handshake)

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' \
  | python mcp/kredent_mcp.py | head -1
```

## Registry

- Registry definition: [`mcp.json`](mcp.json)
- Smithery config: [`smithery.yaml`](smithery.yaml)
- How to publish (free tiers, no registration done yet):
  [`REGISTRIES.md`](REGISTRIES.md)
- Market position (agent-identity MCP landscape): `docs/arastirma/`
