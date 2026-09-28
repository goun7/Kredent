# The Signature Stack: Why Each Piece Exists

**Research date:** 2026-09
**Scope:** The four specifications Kredent builds on — Ed25519, JCS, HTTP
Message Signatures, and the W3C Data Integrity proof pattern — and the specific
failure each one exists to prevent.

---

## TL;DR

A signature is only meaningful if the verifier can reconstruct the exact bytes
the signer signed. That single requirement drives the entire design: Ed25519
provides fast, deterministic, small signatures; JCS (RFC 8785) provides the
deterministic byte serialization; the Data Integrity pattern defines how a
proof is attached without becoming part of what is signed; and RFC 9421 extends
the same ideas to whole HTTP requests. Each piece solves a concrete problem
that a naive "just sign the JSON" approach gets wrong.

---

## 1. Ed25519 — the signature algorithm

Specified in **[RFC 8032](https://www.rfc-editor.org/info/rfc8032/)**,
"Edwards-Curve Digital Signature Algorithm (EdDSA)", by Josefsson and
Liusvaara (January 2017, IRTF Crypto Forum Research Group).

Ed25519 is EdDSA instantiated over the Edwards form of Curve25519. The
properties that matter for agents:

- **Deterministic signatures.** Given the same key and message, the signature
  is always identical. This is a genuine advantage for a signing service: there
  is no RNG to fail or be subverted, and no risk of the classic
  random-nonce reuse catastrophe that has broken ECDSA deployments.
- **Small keys and signatures.** 32-byte keys, 64-byte signatures. Both fit
  comfortably in a header, a log line or a database column.
- **Speed.** Signing and verifying are fast enough that signature cost is
  negligible relative to any network or LLM call. Kredent's pure-Python
  implementation verifies in well under a millisecond, and the `cryptography`
  path is faster still.
- **Single required primitive.** Ed25519 needs SHA-512, which is in every
  standard library. This is what makes a zero-dependency verifier practical.

The relevant caveat is **seed reuse**: the 32-byte seed is the entire key. The
same seed must never be used for two different purposes, and anyone holding the
seed holds the identity. Kredent therefore treats the seed as the root secret
and never writes it anywhere unless explicitly asked.

RFC 8032's status is worth noting: it is **Informational**, not Standards Track
— a product of the IRTF rather than the IETF. It is nonetheless the
universally implemented reference for Ed25519, and its test vectors are the
conformance check every implementation should run. Kredent pins to them.

---

## 2. JCS — deterministic JSON serialization

Specified in **[RFC 8785](https://www.rfc-editor.org/info/rfc8785/)**, "JSON
Canonicalization Scheme", by Rundgren, Jordan and Erdtman (2020).

The problem is stated in the RFC's own abstract:

> "Cryptographic operations like hashing and signing need the data to be
> expressed in an invariant format so that the operations are reliably
> repeatable."

`json.dumps()` in Python is not that. Key order follows insertion order;
number formatting varies; whitespace is optional. Two correct JSON
serializations of the same object can differ byte-for-byte, so a signature over
"the JSON" verifies nowhere except on the machine that made it.

JCS fixes this by defining a single canonical form: sorted object keys,
specific number serialization (shortest round-trip representation), no
insignificant whitespace, UTF-8 output. A signer and a verifier on different
platforms in different languages then produce byte-identical input to the
signature function — which is the only condition under which a signature is
portable.

**Why this matters for Kredent specifically:** an attestation may be created by
an agent on one platform and verified by a completely unrelated party on
another. If canonicalization diverges by a single byte, verification fails.
This is the most common real-world bug in signing implementations, and JCS
exists precisely to eliminate it.

Kredent's JCS implementation covers the subset of JSON its documents use:
objects with string keys, arrays, strings, booleans, null, and finite numbers.
It explicitly rejects `NaN` and `Infinity`, matching the RFC's constraint that
JCS operates on the I-JSON subset.

---

## 3. The Data Integrity proof pattern

Specified in **[W3C Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)**,
a W3C Recommendation since 15 May 2025, with the Ed25519 suite in **[Data
Integrity EdDSA Cryptosuites](https://w3c.github.io/vc-di-eddsa/)**.

The construction, in the EdDSA suite's own words:

> "The suites described in this specification use the RDF Dataset
> Canonicalization Algorithm or the JSON Canonicalization Scheme [RFC8785] to
> transform an input document into its canonical form. The canonical
> representation is then hashed and signed with a detached signature algorithm."

The subtlety worth understanding is **what the signature is computed over**.
The proof block is attached to the document, but the proof cannot sign itself.
The standard approach — and the one Kredent follows — is to compute the
signature over the document with the proof block removed, then attach the
completed proof. The verifier strips the proof, re-canonicalizes, and checks.

Kredent additionally excludes the attestation's `id`, because the id is
*derived from* the signed content. Allowing it as an input to its own signature
would be circular; its integrity is instead guaranteed by re-deriving it during
verification and comparing.

This is a deliberate simplification of full Data Integrity. Kredent uses JCS
rather than RDF Dataset Canonicalization, which means it does not handle
JSON-LD `@context` semantics. That is a real limitation: documents are not
semantically interoperable with the wider VC ecosystem the way a conforming
suite would make them. The trade is that verification remains a single pure
function with no graph walk and no context resolution — which is the property
offline verification depends on.

---

## 4. RFC 9421 — HTTP Message Signatures

Specified in **[RFC 9421](https://www.rfc-editor.org/info/rfc9421/)**, "HTTP
Message Signatures", by Backman, Richer and Sporny (2024, Internet Standards
Track).

RFC 9421 addresses a different problem from attestations. An attestation says
"I did X". A request signature says "I am making this specific call, right
now". Both use the same key, but they serve different purposes, and Kredent
retains the request-signature path because both are needed in practice:

- To record what an agent did, use an attestation.
- To authenticate a live call to a gateway — where the gateway needs to know
  the caller is authorised *for this request*, not merely that it exists — use
  a request signature.

The RFC's construction builds a deterministic "signature base" from named
components of the HTTP message: the method, the authority, the target URI, a
content digest, the date, and the signature parameters themselves. Each line is
`"component": value`, and the whole is signed with a detached signature. The
content digest (`Content-Digest: sha-256=:<base64>:`) binds the body into the
signature without requiring the signer to hold the entire message, which is
what the RFC means when it notes that the mechanism "supports use cases where
the full HTTP message may not be known to the signer".

Kredent's verifier adds two checks beyond the signature itself, both of which
are standard practice from the RFC's security considerations:

- **Clock-drift window.** The signature's `created` timestamp must be within
  180 seconds of the verifier's clock, bounding how long a captured signature
  is replayable.
- **Replay cache.** The hash of each accepted signature is retained for the
  duration of the window, so an exact replay within the window is rejected.

---

## 5. What can actually go wrong

Being explicit about the failure modes, since these are what the design above
is defending against:

- **Canonicalization mismatch.** Signer and verifier produce different bytes.
  Prevented by JCS; detected immediately by cross-implementation testing.
- **Signing over mutable or unspecified fields.** If a field the verifier will
  fill in later is inside the signed set, the signature can never verify.
  Prevented by defining the signed payload explicitly (`unsigned_payload`).
- **Key confusion.** A signature from the right key on the wrong document, or
  the wrong key on the right document. Prevented by binding the verification
  method to the issuer DID and re-deriving the key from that DID.
- **Signature malleability.** Producing a *different* valid signature for the
  same message. Not a concern for Ed25519, which is not malleable.
- **Seed compromise.** The one failure no signature scheme can fix. Out of
  scope for the protocol; mitigated operationally by `0600` storage and by
  never returning the seed over the MCP transport unless explicitly requested.
- **Ed25519 is not post-quantum.** A sufficiently large quantum computer breaks
  it. This is a real long-term consideration and a reason the proof format
  carries an explicit `cryptosuite` field, so a future suite can be introduced
  without changing the document model.

---

## Sources

- [IETF — RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/info/rfc8032/)
- [IETF — RFC 8785, JSON Canonicalization Scheme](https://www.rfc-editor.org/info/rfc8785/)
- [IETF — RFC 9421, HTTP Message Signatures](https://www.rfc-editor.org/info/rfc9421/)
- [W3C — Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)
- [W3C — Data Integrity EdDSA Cryptosuites (editor's draft)](https://w3c.github.io/vc-di-eddsa/)
- [W3C CCG — The did:key Method v0.9](https://raw.githubusercontent.com/w3c-ccg/did-method-key/main/index.html)
