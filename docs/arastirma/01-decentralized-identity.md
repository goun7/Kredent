# Decentralized Identity (DID): State of the Art, 2025–2026

**Research date:** 2026-09
**Scope:** What decentralized identity actually offers today, and where it still
falls short — specifically as a substrate for autonomous software agents.

---

## TL;DR

Decentralized identifiers are a W3C Recommendation that lets any entity hold an
identifier it controls without asking a registry, identity provider or
certificate authority for permission. The core spec is stable and widely
implemented. The hard parts are not the identifiers but everything around them:
key management, revocation, resolution, and the sheer weight of the surrounding
JSON-LD machinery. For machines rather than humans, the interesting sub-spec is
`did:key`, which trades rotation and recovery for the ability to work with zero
infrastructure.

---

## 1. The core specification

The foundational document is the **W3C Decentralized Identifiers (DIDs) v1.0**
specification, published as a W3C Recommendation on 19 July 2022.

> "Decentralized identifiers (DIDs) are a new type of identifier that enables
> verifiable, decentralized digital identity... In contrast to typical,
> federated identifiers, DIDs have been designed so that they may be decoupled
> from centralized registries, identity providers, and certificate authorities."

— [W3C, *Decentralized Identifiers (DIDs) v1.0*](https://www.w3.org/TR/did-core/)

The data model is deliberately small. A DID is a URI (`did:method:method-specific-id`)
that resolves to a **DID document** containing verification methods
(cryptographic keys) and service endpoints. The controller proves control by
satisfying a verification relationship — for example, producing a signature
under a key listed in the `assertionMethod` relationship.

Three properties matter for agents specifically:

1. **Permissionless control.** No entity issues or revokes the identifier. An
   agent generates a key and immediately has a globally unique, self-controlled
   identifier.
2. **Portability.** The identifier is a string. It can be embedded in a log
   line, an HTTP header, a database row or an attestation, and resolved by
   anyone.
3. **Cryptographic binding.** The identifier is bound to key material, so
   "which agent did this" reduces to "which key signed this".

---

## 2. Verifiable Credentials and Data Integrity

An identifier alone says nothing about behaviour. The W3C Verifiable Credentials
family addresses that layer, and as of 2025 it has solidified into two
Recommendations published the same day, 15 May 2025:

- **[Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model/)** —
  the issuer/holder/verifier model for expressing a claim that can be checked
  for tampering.
- **[Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)** —
  the mechanism for securing a document with a cryptographic proof, "especially
  through the use of digital signatures".

The Data Integrity specification is the one Kredent draws from directly. Rather
than wrap a document in an envelope, it attaches a `proof` block: the document is
canonicalized, the canonical form is signed, and the signature is embedded. A
verifier repeats the canonicalization and checks the signature. The pattern is
what makes a signed claim self-contained — no issuer endpoint needs to be
contacted to validate it.

For the specific cryptographic suite, the relevant spec is **[Data Integrity
EdDSA Cryptosuites](https://w3c.github.io/vc-di-eddsa/)** (editor's draft,
v1.1). It states the construction plainly:

> "The suites described in this specification use the RDF Dataset
> Canonicalization Algorithm or the JSON Canonicalization Scheme [RFC8785] to
> transform an input document into its canonical form. The canonical
> representation is then hashed and signed with a detached signature algorithm."

That sentence is, almost word for word, what Kredent's attestation format
implements: JCS canonicalization (RFC 8785), a detached Ed25519 signature over
the canonical bytes, and a proof block carrying the signature and the
verification method.

---

## 3. What still does not work

DID's critics are worth listening to, because they name real costs.

**Complexity.** The full stack — JSON-LD contexts, RDF dataset canonicalization,
linked-data signatures — is genuinely heavy. A conforming implementation pulls
in a graph-processing library and a context-resolution step that can require
network access. For a human logging into a website this is arguably tolerable;
for an agent signing ten thousand calls an hour it is not.

**Key management is the real problem.** Every DID method pushes the burden of
key custody onto the controller. There is no "forgot my password". If a human
loses a key, there is often no recovery; if an agent's seed is exfiltrated, the
identity is compromised with no adjudication layer. Methods that support
rotation and recovery (`did:web`, `did:ion`) buy that capability back by
introducing exactly the infrastructure `did:key` avoids.

**Revocation remains awkward.** Revoking a key requires either a registry write
or an out-of-band channel, and checking revocation requires reaching that
channel. Kredent's `verify` deliberately does not attempt this: an attestation
is valid or invalid on its own cryptography, and revocation is a policy
question the caller must layer on top.

**Abandonment risk.** A 2023 study of on-chain DID registrations found that a
substantial fraction of created DIDs are never used again — the classic
pattern of an identity created for a single transaction and then discarded.
This matters less for agents (which are frequently ephemeral by design) than it
does for the credibility of the ecosystem as a whole.

---

## 4. Why agents are a different case

Most DID work targets humans: wallet UX, selective disclosure, biometric
binding. Agents invert the priorities:

| Property | Human-first DID | Agent-first need |
|---|---|---|
| Key generation | Rare, must be guided | Constant, must be scriptable |
| Recovery | Essential | Often unnecessary (agent is ephemeral) |
| Volume | A few signatures per day | Thousands per hour |
| Offline operation | Nice to have | Required in many runtimes |
| Identity lifetime | Years | Minutes to months |

This is why `did:key` — long considered a "toy" method because it cannot rotate
keys — becomes the sensible default for agents. An agent that exists for the
duration of a task does not need rotation; it needs to be able to authenticate
from a sandbox with no outbound network path.

---

## 5. How Kredent positions itself

Kredent is deliberately not a full DID/VC stack. It is a thin layer that takes
the two parts of the ecosystem that work well for machines — self-resolving
`did:key` identifiers and the Data Integrity proof pattern — and stops there.
Specifically:

- Identifiers are `did:key`, so resolution is a pure function of the identifier
  string and never touches the network.
- Attestations follow the Data Integrity shape (canonicalize, sign, embed proof)
  but drop JSON-LD contexts and RDF canonicalization in favour of JCS, which is
  a single function rather than a graph walk.
- Reputation, which the VC model does not address at all, is modelled as a
  deterministic function of a public ledger rather than as a credential.

The gap this addresses is real: the VC family specifies how to make a claim
tamper-evident, but says nothing about whether the issuer is any good. That
second question is what reputation is for.

---

## Sources

- [W3C — Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/) — W3C Recommendation, 19 July 2022
- [W3C — Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model/) — W3C Recommendation, 15 May 2025
- [W3C — Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/) — W3C Recommendation, 15 May 2025
- [W3C — Data Integrity EdDSA Cryptosuites (editor's draft)](https://w3c.github.io/vc-di-eddsa/)
- [W3C CCG — The did:key Method v0.9](https://raw.githubusercontent.com/w3c-ccg/did-method-key/main/index.html)
- [IETF — RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/info/rfc8032/)
- [IETF — RFC 8785, JSON Canonicalization Scheme](https://www.rfc-editor.org/info/rfc8785/)
