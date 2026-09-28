# Kredent

**Agent identity & verifiable reputation for AI agents.**

Kredent gives an autonomous agent an identity it controls, and makes every claim
that identity signs independently checkable by anyone.

An agent gets a W3C `did:key` identifier. It signs attestations with Ed25519.
Anyone can verify a Kredent attestation offline, with zero network calls and
zero trusted registries, because the public key is embedded in the DID itself.

## Why

Agent payments, agent-to-agent delegation, and proof-of-work all hit the same
wall: a process can claim "I am agent X and I did Y," but nothing checks that
claim after the session ends. Kredent makes the claim a signed, content-addressed
attestation that a third party can verify years later, without asking anyone.

## Install

```bash
git clone https://github.com/goun7/Kredent
cd Kredent
pip install -e .
```

No runtime dependencies. The crypto is pure Python (Ed25519 verified against
`cryptography` in tests, RFC 8032 vectors included).

## Use

Create an identity:

```bash
kredent create --name "my-agent"
# -> did:key:z6Mk... + private key written to ~/.kredent (mode 0600, never committed)
```

Attest to something:

```bash
kredent attest --did did:key:z6Mk... --claim '{"task":"payment","amount":"0.25","currency":"usdc"}'
# -> attestation.json (JCS canonical, content-addressed id, expiry included)
```

Verify it, anywhere, with nothing but the file:

```bash
kredent verify attestation.json
# ACCEPT
```

Break any byte and it rejects:

```bash
# tamper with the claim -> kredent verify returns REJECT
```

Check reputation from a ledger of attestations:

```bash
kredent reputation --ledger ledger.jsonl --did did:key:z6Mk...
```

## MCP server

Kredent ships an MCP server (2025-06-18 spec) so an agent framework can use
identity as a tool: `create_identity`, `attest`, `verify`, `reputation`.

```bash
python -m kredent.mcp_server
```

## Honest limits

- This is a local-store tool. `~/.kredent/` holds keys on disk; there is no
  KMS integration yet.
- Reputation is computed from a ledger you supply. It is not a global score and
  there is no network of attesters.
- `did:key` is self-resolving and cannot be rotated. If a key is compromised the
  DID is done; recovery is an explicit non-goal of `did:key`.
- No private key is ever written to the repository. `.gitignore` covers
  `.kredent/` and every seed/key pattern.

## Status

163 tests passing, 0 failing. Apache-2.0 licensed.
