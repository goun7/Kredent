<p align="center"><img src="assets/logo.svg" width="96" alt="Kredent logo"></p>

# Kredent

[![CI](https://github.com/goun7/Kredent/actions/workflows/ci.yml/badge.svg)](https://github.com/goun7/Kredent/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/kredent)](https://pypi.org/project/kredent/)
[![Python](https://img.shields.io/pypi/pyversions/kredent)](https://pypi.org/project/kredent/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Identity and verifiable reputation for autonomous agents.**

Kredent gives a software agent a cryptographic identity it controls, lets it
sign claims about what it did, and lets anyone verify those claims offline —
with no registry, no resolver and no network access.

---

## Why

Agents are starting to transact on their own: calling APIs, negotiating prices,
making payments, deploying code. The infrastructure for this is being built
quickly, and it has a gap at its centre. It is straightforward to answer "was
this call authorised?" It is much harder to answer "who, exactly, made it, and
should I trust them?"

An API key answers the first question and fails the second. A key is a bearer
secret: whoever holds it can act as the agent, it says nothing about the agent's
history, and it stops being meaningful the moment it is rotated or leaked. Every
agent starts from zero on every new service, and no service can tell a reliable
agent from a careless one.

Kredent's position is that this is an identity problem before it is a payments
problem. Before an agent can be trusted to spend, it has to be *identifiable*
across services in a way that is not controlled by any one platform. That
requires an identifier that is portable by construction, and a history that is
verifiable by anyone rather than held inside a proprietary scoring system.

Two choices follow from that, and they are the whole of the design:

- **Identifiers are `did:key`.** The identifier is derived from the agent's own
  public key, so it is self-resolving: anyone can recover the verification key
  from the identifier alone, offline, with zero infrastructure. No platform
  issues it and no platform can revoke it.
- **History is a signed ledger, not a score.** An agent's reputation is a
  deterministic function of public, signed events. Any party can recompute it
  and confirm the number they were given is real, rather than trusting a
  platform's internal metric.

---

## What it is

A small Python library, a CLI, and an MCP server. Four operations:

| Operation | What it does |
|---|---|
| `create` | Generates an Ed25519 keypair and a `did:key` identity. |
| `attest` | Signs a claim, producing a self-contained attestation. |
| `verify` | Checks an attestation offline. Signature, key binding, integrity, expiry. |
| `reputation` | Computes a reputation score from a ledger of events. |

The signatures are Ed25519 ([RFC 8032](https://www.rfc-editor.org/info/rfc8032/))
over a JCS-canonical serialization ([RFC 8785](https://www.rfc-editor.org/info/rfc8785/)),
following the W3C [Data Integrity](https://www.w3.org/TR/vc-data-integrity/)
proof pattern. Request-level authentication uses
[RFC 9421](https://www.rfc-editor.org/info/rfc9421/) HTTP Message Signatures.

---

## Install

```bash
pip install kredent
```

Or from a checkout:

```bash
git clone https://github.com/goun7/Kredent.git
cd Kredent
pip install -e .
```

The core library has a single runtime dependency, the audited
[`cryptography`](https://cryptography.io/) library, used for Ed25519. That
dependency is optional in practice: the package bundles a pure-Python Ed25519
implementation that is used automatically when `cryptography` is absent, so
`kredent verify` works on a machine with nothing else installed.

The MCP server additionally needs the `mcp` package:

```bash
pip install "kredent[mcp]"
```

---

## Quickstart

Create an identity:

```console
$ kredent create --name billing-bot --controller did:web:acme.example
{
  "status": "stored",
  "name": "billing-bot",
  "agent_id": "did:key:z6MkhFUK6cNkNboTWN4VpRdKnMnH6y2RTXYFG6ve2EbziP7F",
  "public_key_multibase": "z6MkhFUK6cNkNboTWN4VpRdKnMnH6y2RTXYFG6ve2EbziP7F",
  "identity_document": { ... },
  "note": "The 32-byte seed was written to the local store with 0600 permissions. ..."
}
```

Sign a claim:

```console
$ kredent attest --name billing-bot \
    --claim '{"action":"deployed","service":"billing-api","version":"1.4.2"}' \
    --out attestation.json
wrote attestation.json
```

Verify it — anywhere, offline, with nothing but the file:

```console
$ kredent verify attestation.json
{
  "valid": true,
  "status_code": 200,
  "agent_id": "did:key:z6MkhFUK6cNkNboTWN4VpRdKnMnH6y2RTXYFG6ve2EbziP7F",
  "message": "Attestation verified: signature valid over canonical document"
}
```

That verification needs no network and no registry lookup. The public key is
recovered from the `did:key` in the attestation itself, so the only input is the
document you were handed.

Score an agent from a ledger of events:

```console
$ kredent reputation did:key:z6MkhFUK... \
    --transactions 40 --total-claims 30 --refuted-claims 2
{
  "agent_id": "did:key:z6MkhFUK...",
  "reputation": {
    "score": 0.6407,
    "tier": "TIER_B",
    ...
  }
}
```

Verification also reads from stdin, so it composes with anything:

```bash
cat attestation.json | kredent verify
```

### A worked Python example

```python
from kredent import generate_seed, create_attestation, verify_attestation

seed = generate_seed()                      # the root secret; keep it safe
att = create_attestation(
    seed,
    claim={"action": "deployed", "service": "billing-api", "version": "1.4.2"},
)

# Hand the attestation to anyone. They need nothing else to check it.
result = verify_attestation(att.to_json())
assert result.valid
print(result.agent_id)                      # -> did:key:z6Mk...
```

---

## Using it with an MCP host

Kredent ships an MCP server exposing the same four operations as tools, so an
agent can manage its own identity during a session.

```json
{
  "mcpServers": {
    "kredent": {
      "command": "kredent-mcp"
    }
  }
}
```

The tools:

| Tool | Purpose |
|---|---|
| `create_identity` | Generate a persistent `did:key` identity. |
| `attest` | Sign a claim with a stored identity. |
| `verify` | Verify an attestation offline. |
| `reputation` | Compute a reputation score from events. |

By default `create_identity` persists the seed locally with `0600` permissions
and never returns it over the transport. Passing `persist: false` returns the
seed once, for the caller to route into a secrets manager — nothing is written
to disk in that mode.

---

## How reputation works

Reputation is not an opaque score. It is a published formula over a public
ledger, so it can be recomputed and audited by anyone.

```
score = base_score × integrity_multiplier × volume_damping
```

- **`base_score`** — a weighted blend of reliability (0.40), accuracy (0.30) and
  stability (0.15), normalised to 1.0.
- **`integrity_multiplier`** — `max(0, 1 - 0.5 × contradiction_rate)`, so a
  history of refuted claims costs.
- **`volume_damping`** — `1 - exp(-n/30)`, the cold-start term.

Three consequences worth knowing:

**A new identity cannot look established.** With one transaction an agent
reaches about 3% of its nominal score. Farming a fake history is therefore slow
and expensive, and an agent that discards its identity to reset a bad
reputation starts again from near zero.

**Lying costs more than honesty pays.** A contradiction carries twice the weight
of a confirmation, so the expected value of fabricating a history is negative.

**Praise from nobodies is worth almost nothing.** Each event is weighted by the
counterparty's own reputation, so a ring of fresh identities confirming one
another accumulates almost nothing. A share of volume concentrated in a single
counterparty is flagged as a collusion pattern.

Tiers are thresholds on the score: `TIER_A` (≥ 0.85 with no refuted claims),
`TIER_B` (≥ 0.60), `TIER_C` (≥ 0.30), else `QUARANTINED`.

---

## Security model

**The seed is the identity.** A 32-byte Ed25519 seed is the root of everything:
anyone holding it can sign attestations as that agent, and there is no recovery.
Treat it as a credential. Kredent never writes it anywhere unless asked, writes
it with `0600` permissions when it does, and never returns it over the MCP
transport unless you explicitly request it.

**Verification is offline and keyless.** `kredent verify` performs no network
calls. It recovers the public key from the `did:key` in the document, so a
verifier has nothing to compromise and no resolver to attack.

**Every forgery path is a test case.** Tampering with the claim, the issuer, the
attestation id, or swapping in a signature from a different key are all rejected
with a distinct error code. The test suite pins these behaviours.

**Known limitations, stated plainly:**

- A `did:key` cannot be rotated or revoked. A compromised seed permanently burns
  the identity and its history. There is no remediation path within the
  protocol. For a long-lived agent that must survive key compromise, `did:web`
  would be the better method, and nothing prevents an operator from running that
  underneath.
- The protocol establishes *who signed a claim and that it is unaltered*. It
  does not establish that the claim is *true*. Grounding in reality requires
  evidence from outside the protocol.
- Reputation measures whether claims were confirmed or contradicted by parties
  willing to say so. It does not measure whether an agent's output was good;
  that is a judgement for a human or an evaluating model.
- Ed25519 is not post-quantum. The proof format carries an explicit
  `cryptosuite` field so a future suite can be introduced without changing the
  document model.
- The bundled pure-Python Ed25519 exists so verification works with zero
  dependencies. It is correct and cross-validated against `cryptography` and the
  RFC 8032 test vectors, but it is not constant-time and is not intended for
  high-volume signing. Install `cryptography` for that.

---

## Repository layout

```
kredent/             Core library
  crypto.py          Ed25519, base58btc, multibase, did:key resolution
  models.py          AgentID, Attestation, ReputationScore, ledger events
  canonical.py       JCS (RFC 8785) and RFC 9421 canonicalization
  attest.py          Attestation issuance and offline verification
  reputation.py      Scoring engine and anti-gaming filters
  ledger.py          Append-only calibration ledger
  store.py           Local identity store (0600 secrets)
  verifier.py        RFC 9421 request verification with replay protection
  cli.py             The `kredent` command
  mcp_server.py      MCP server implementation
mcp/kredent_mcp.py   Entry point for the MCP server
tests/               Test suite
docs/arastirma/      Research notes on DIDs, reputation and signature schemes
```

---

## Tests

```bash
pip install -e ".[dev]"
pytest
```

163 tests, covering the attestation lifecycle, every forgery path, did:key
round-tripping, JCS determinism, reputation math and anti-gaming filters, the
CLI as real subprocesses, and the MCP server over an actual JSON-RPC stdio
session.

---

## Research notes

The design decisions above are grounded in documented specifications. Notes and
sources are in [`docs/arastirma/`](docs/arastirma):

- [Decentralized identity (DID)](docs/arastirma/01-decentralized-identity.md)
- [did:key vs did:web for agents](docs/arastirma/02-did-key-vs-did-web.md)
- [Agent reputation systems](docs/arastirma/03-agent-reputation.md)
- [The signature stack](docs/arastirma/04-signature-schemes.md)

---

## Status

Working core. The attestation format is stable; the reputation model is still
being tuned against real event data and its weights may change. Do not treat a
reputation score as a decision-making oracle yet.

## License

Apache-2.0. See [LICENSE](LICENSE).
