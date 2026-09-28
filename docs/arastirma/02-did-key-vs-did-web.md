# did:key vs did:web vs Registry Methods — Which DID Method for Autonomous Agents?

**Research date:** 2026-09
**Scope:** A concrete comparison of DID methods against the requirements of
autonomous software agents, and the justification for Kredent's choice.

---

## TL;DR

`did:key` is the only widely implemented DID method whose resolution is a pure
function of the identifier itself: no DNS lookup, no HTTP fetch, no registry
query. For an agent that may run in a locked-down sandbox, that property is not
a convenience, it is a hard requirement. It costs you key rotation and recovery.
For long-lived organisational agents, `did:web` is the better trade; for
ephemeral task agents, `did:key` wins outright. Kredent optimises for the second
case while leaving room for the first.

---

## 1. The three families

### did:key — the registry-free method

The [did:key specification](https://raw.githubusercontent.com/w3c-ccg/did-method-key/main/index.html)
describes itself as "a non-registry based DID Method based on expanding a
cryptographic public key into a DID Document". Its stated advantages are direct:

> "immediate availability without network dependencies, deterministic resolution
> requiring no registry lookups, zero infrastructure costs, complete offline
> operation capability, and maximum simplicity in implementation."

The identifier *is* the key. For Ed25519, a `did:key` is `did:key:` followed by
the multibase encoding of the multicodec-prefixed public key (`z6Mk...`, where
the `0xed 0x01` tag marks an Ed25519 key). Resolution is decoding, and the
DID document is a deterministic expansion of that key.

**What you gain:** no registry to register with, no resolver to operate, no
network dependency, no downtime, no lookup latency, no cost.

**What you lose:** the identifier is permanent and immutable. Keys cannot be
rotated, revoked, or recovered. Losing the seed means losing the identity, full
stop.

### did:web — the DNS-anchored method

The [did:web method specification](https://w3c-ccg.github.io/did-method-web/)
grounds an identifier in a domain name: `did:web:example.com` resolves by
fetching `https://example.com/.well-known/does.json`. The motivation stated in
the spec is to reuse "a web domain's existing reputation" rather than
bootstrapping trust on a ledger.

**What you gain:** key rotation, multi-key documents, revocation, and
delegation to an organisation that outlives any single deployment. A did:web
document can list several keys, mark some as revoked, and add new ones.

**What you gain in cost:** it requires a live HTTPS endpoint under your control,
which means DNS, TLS, uptime and a server. Resolution can fail, be slow, or be
blocked by a sandbox's egress policy. The identifier is also coupled to a domain
you must keep paying for.

### Ledger and registry methods (did:ion, did:cheqd, did:ethr, ...)

These write DID operations to a ledger or anchoring system. They offer the
strongest key-rotation and revocation stories and the weakest operational
profile for a machine verifier: resolution requires reaching a specific
network, often with a specialised client, and inherits that network's
confirmation latency. For automated verification at volume, that is a poor fit.

---

## 2. Scored against agent requirements

| Requirement | did:key | did:web | Ledger methods |
|---|---|---|---|
| Works with no network | ✅ yes, by construction | ❌ requires HTTPS | ❌ requires network |
| Resolution latency | ~microseconds (decode) | one HTTP round trip | network-dependent |
| Key rotation | ❌ impossible | ✅ yes | ✅ yes |
| Key revocation | ❌ impossible | ✅ yes | ✅ yes |
| Key recovery | ❌ impossible | ✅ via controller | ✅ via controller |
| Cost to operate | zero | domain + hosting | ledger fees + infra |
| Implementation surface | ~100 lines | HTTP client + JSON | per-network client |
| Discovery / service endpoints | ❌ none | ✅ yes | ✅ yes |
| Suitable for ephemeral agents | ✅ ideal | ❌ overkill | ❌ overkill |
| Suitable for long-lived org agents | ❌ fragile | ✅ ideal | ✅ viable |

---

## 3. The agent case in detail

Consider the concrete shape of agent workloads. An agent is spawned to perform a
task, runs for minutes to hours, and is discarded. It may run inside a container
with no outbound network path at all — only an LLM API endpoint allowlisted. It
needs to sign calls and attestations throughout its run.

- **did:key** works because nothing is fetched. The identity exists the moment
  the key exists.
- **did:web** fails this case outright if egress is restricted, and it is
  operationally absurd to stand up a domain for a task agent that lives for
  eleven minutes.
- **Ledger methods** fail for the same reason, plus fees per operation.

Now consider the opposite case: an organisation's durable billing agent that
must survive key compromise. Here `did:key` is genuinely dangerous — a leaked
seed permanently burns the identity and its accumulated history. `did:web` is
the right answer, because rotation is the whole point.

The honest conclusion is that these are not competing for the same job. They are
two different points on a trade-off curve, and a well-designed protocol should
not pretend one covers both.

---

## 4. Why Kredent chose did:key

Kredent's primary identifier is `did:key` for four reasons, in priority order:

1. **Verification must be possible anywhere.** The entire value of a signed
   claim is that a third party can check it. If verification requires network
   access to a resolver, the vast majority of potential verifiers — agents in
   sandboxes, CI systems, air-gapped environments, offline audit pipelines —
   simply cannot participate. `did:key` makes verification a pure function of
   the document itself, which maximises the set of parties who can verify.
2. **It removes a trust dependency.** A resolver is a thing you have to trust.
   Removing it removes an attack surface and a failure mode, and removes the
   question "whose resolver do we use?" from every integration conversation.
3. **It is fast enough to be invisible.** Verification is a decode and an
   Ed25519 check, on the order of microseconds. Signature verification never
   appears on a critical path.
4. **Agents are frequently ephemeral.** The weakness of `did:key` — no rotation
   — is simply not a weakness for an identity that is disposable by design.

### The acknowledged trade-off

This is stated plainly because it is the main legitimate objection to the
choice: **a `did:key` identity cannot be recovered or rotated.** If an agent's
seed is compromised, the identity is permanently compromised, and any
reputation attached to it is lost. There is no remediation path within the
protocol.

Kredent mitigates rather than solves this:

- Seeds are held by the operator, never by the protocol, and the store writes
  them with `0600` permissions by default.
- Reputation is computed from a ledger, so an operator can migrate to a fresh
  identity and re-present the same evidence, though this is a manual operation
  and the new identity inherits none of the old one's history automatically.
- Nothing prevents an operator from using `did:web` for a durable agent and
  simply *also* issuing Kredent attestations. The attestation format binds to
  whatever did:key is named as issuer, so a deployment that needs rotation can
  run its own identity layer underneath.

A future version may support `did:web` as a first-class issuer method. It is not
a priority, because the ephemeral-agent case is the one with no good
alternative today.

---

## Sources

- [W3C CCG — The did:key Method v0.9](https://raw.githubusercontent.com/w3c-ccg/did-method-key/main/index.html) — non-registry DID method, key-expansion semantics
- [W3C CCG — did:web Method Specification](https://w3c-ccg.github.io/did-method-web/) — domain-anchored DIDs, rotation and multi-key documents
- [W3C — Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/) — DID Core, verification relationships, DID document data model
- [W3C — Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/) — proof pattern over canonicalized documents
- [IETF — RFC 8032, EdDSA (Ed25519)](https://www.rfc-editor.org/info/rfc8032/)
