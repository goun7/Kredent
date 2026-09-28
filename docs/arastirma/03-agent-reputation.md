# Reputation Systems for Agents: What Is Actually Known

**Research date:** 2026-09
**Scope:** The state of machine reputation systems — the classical models, the
attacks that shape them, and how much (or how little) specifically concerns AI
agents.

---

## TL;DR

Reputation systems are a mature research area in peer-to-peer networks and
electronic marketplaces, with a well-understood attack taxonomy: Sybil,
whitewashing, ballot stuffing and collusion. EigenTrust is the canonical
model that weights trust by the trustworthiness of the recommender. What is
*not* mature is reputation for AI agents specifically: as of this writing there
is little peer-reviewed literature on the topic, and most current "agent trust"
offerings are proprietary platform features rather than open, auditable models.
That gap is the reason Kredent treats reputation as a published, recomputable
function rather than a platform score.

---

## 1. The classical models

Reputation in distributed systems is an old problem with a well-developed
toolbox.

**EigenTrust** (Kamvar, Schlosser and Garcia-Molina) is the reference point.
Its core idea is that a rating should be weighted by the rater's own
reputation, so that praise from a trustworthy peer counts for more than praise
from an unknown one. Computed over a network of interactions, this produces a
global trust vector in which a swarm of colluding nobodies cannot inflate each
other. The mechanism is transitive: trust propagates through the graph but is
attenuated at every hop by the quality of the intermediate node.

Kredent implements this idea in a deliberately simplified, non-iterative form:
each interaction is weighted by the counterparty's reputation score, clamped to
a floor so a zero-reputation counterparty still contributes a trace of weight
rather than nothing. This preserves the anti-Sybil property — a ring of fresh
identities confirming one another computes to almost nothing — without
requiring the iterative fixed-point computation of full EigenTrust.

**Other models worth knowing:**
- **Beta reputation systems** (Jøsang & Ismail) model trust as a beta
  distribution over positive and negative outcomes, giving a principled way to
  express uncertainty rather than a point score.
- **PeerTrust** (Xiong & Liu) adds transaction context and credibility factors
  on top of a peer-to-peer feedback aggregation.
- **PageRank-style trust propagation** treats reputation as flow, which is
  mathematically close to EigenTrust's eigenvector formulation.

---

## 2. The attack taxonomy

Any reputation system must be designed against named attacks, because a score
that can be farmed is worse than no score at all — it actively misleads.

**Sybil attack.** An attacker creates many identities and has them rate each
other or a target. Defence is either identity cost (proof-of-work, proof-of-stake,
deposits) or weighting by established reputation, as EigenTrust does. Kredent
relies on the latter plus cold-start damping.

**Whitewashing.** An agent accumulates a bad reputation, then discards the
identity and starts fresh to reset it. This is trivially easy whenever identity
creation is free — as it deliberately is with `did:key`. The standard defence is
to make a new identity cost something; Kredent's equivalent is volume damping,
which forces a new identity to accumulate real history before its score means
anything.

**Ballot stuffing / feedback injection.** Submitting many positive ratings for
oneself. Defence requires that ratings be bound to real, verifiable
interactions — hence Kredent's insistence that the unit of account be a signed
attestation, not a rating someone can file arbitrarily.

**Collusion.** A ring of agents transacting only with each other to build
mutual history. The signature is concentration: an outsized share of an agent's
volume flowing to a single counterparty. Kredent detects exactly this ratio and
flags it above a threshold.

---

## 3. The gap: reputation for AI agents

This is where the honest note belongs. Searching for peer-reviewed work on
reputation systems *specifically for autonomous AI agents* turns up very
little. What exists in 2025-2026 is largely:

- **Platform features, not protocols.** Agent marketplaces and orchestration
  platforms expose reputation or quality metrics, but these are internal
  scoring systems. They are not published, not recomputable by a third party,
  and not portable between platforms — which is precisely the property that
  makes them unsuitable as an open standard.
- **Trust-and-safety framing.** Research on AI misalignment, model honesty and
  evaluation integrity is adjacent but different in kind: it asks whether a
  model's outputs are reliable, not whether a specific deployed agent can be
  held to a specific historical claim.
- **Mechanism design for agent payment.** Closely related work on machine
  payments focuses on settlement and authorisation, not on behavioural history.

The consequence is that an agent's reputation today is trapped inside whichever
platform it runs on. An agent that performed reliably on one marketplace
carries no evidence of that anywhere else. Every new integration starts from
zero, which is exactly the cold-start problem that makes platform lock-in
sticky.

This is not a complaint about existing platforms — many of them do good work —
but it is a real architectural gap, and it is the one Kredent is built to
address: if a reputation score is a deterministic function of a public ledger
of signed attestations, then it is portable by construction, because any party
can recompute it from the evidence.

---

## 4. Kredent's model, and where it is deliberately conservative

Kredent's scoring combines four design choices, each traceable to a specific
attack above.

1. **Cold-start volume damping**, `1 - exp(-n/N0)` with `N0 = 30`. A fresh
   identity with one perfect transaction scores roughly 3% of its nominal
   value. This is the primary defence against whitewashing: a new identity is
   not worth farming because it cannot be made to look established quickly.
2. **Asymmetric penalisation.** A contradiction carries twice the weight of a
   confirmation. Lying costs more than honesty pays, which keeps the expected
   value of fabricating a history negative.
3. **Counterparty-weighted reliability.** Confirmations from reputable agents
   count more than from unknown ones, so a Sybil ring confirming itself
   accumulates almost nothing.
4. **Collusion ratio detection.** If more than 35% of an agent's volume flows
   to a single counterparty, the pattern is flagged.

The model is intentionally simpler than the academic state of the art. It does
not model uncertainty as a distribution, it does not propagate trust
transitively beyond one hop, and it has no notion of context-dependent trust
(an agent may be reliable at billing and unreliable at forecasting). These are
real limitations, not features. They are accepted because a score that a
reviewer can hold in their head and recompute by hand is worth more in practice
than a more sophisticated one that requires trusting a black box.

---

## 5. Open questions Kredent does not answer

Stating these plainly, because overselling reputation models is common and
unhelpful:

- **No protocol can establish that a claim is *true*.** It can establish who
  made it and that it has not been altered. Grounding in reality requires
  evidence from outside the protocol, and Kredent's ledger records
  evidence hashes rather than judging them.
- **Subjective quality is out of scope.** Whether an agent's output was *good*
  is a judgement for a human or an evaluating model. Kredent records whether
  claims were confirmed or contradicted by parties willing to say so.
- **Bootstrapping remains a social problem.** A new ecosystem has no history,
  so no agent can have reputation. Volume damping softens this but cannot
  remove it.

---

## Sources

- [W3C — Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
- [W3C — Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)
- [W3C — Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model/)
- [W3C CCG — The did:key Method v0.9](https://raw.githubusercontent.com/w3c-ccg/did-method-key/main/index.html)
- [IETF — RFC 8032, EdDSA](https://www.rfc-editor.org/info/rfc8032/)
- [IETF — RFC 8785, JSON Canonicalization Scheme](https://www.rfc-editor.org/info/rfc8785/)
- [IETF — RFC 9421, HTTP Message Signatures](https://www.rfc-editor.org/info/rfc9421/)

**Note on the absence of citations for EigenTrust, Beta reputation and
PeerTrust:** these are widely known results in the peer-to-peer trust
literature (EigenTrust: Kamvar, Schlosser & Garcia-Molina; Beta reputation:
Jøsang & Ismail; PeerTrust: Xiong & Liu). This research did not verify
canonical, stable URLs for the primary papers, so they are described by name
and contribution rather than cited to a specific link. Do not treat the
absence of a link as a claim that these are obscure — they are foundational —
but do verify the primary sources independently before citing them in academic
work.
