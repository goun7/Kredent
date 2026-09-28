"""
Command-line interface for Kredent.

Workflow
--------
::

    kredent create  --name billing-bot          # generate an identity
    kredent attest  --name billing-bot --claim '{"action":"deployed","service":"billing-api"}'
    kredent verify  attestation.json            # verify, fully offline
    kredent reputation did:key:z6Mk...          # score from a ledger

The seed is written to the local store only when ``--name`` is given, and only
ever with ``0600`` permissions. Without ``--name`` nothing touches disk and the
seed is printed once, to stdout, for the caller to route into a real secrets
manager.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from . import __version__
from .attest import DEFAULT_KID, create_agent_id, create_attestation, verify_attestation
from .crypto import ED25519_KEY_LEN, generate_seed, keypair_from_seed
from .reputation import compute_reputation_score, reputation_from_events
from .store import (
    delete_identity,
    identity_exists,
    list_identities,
    load_identity,
    store_identity,
)


def _emit(obj, indent: int = 2) -> None:
    print(json.dumps(obj, indent=indent, ensure_ascii=False, sort_keys=False))


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


def cmd_create(args: argparse.Namespace) -> int:
    seed = generate_seed()
    _, raw_pub, multibase_pub, did = keypair_from_seed(seed)

    controller = args.controller or "did:legal:unknown"
    capabilities = args.capabilities or ["tool-call"]

    if args.name:
        stored = store_identity(
            args.name,
            seed,
            controller=controller,
            capabilities=capabilities,
            kid=DEFAULT_KID,
        )
        doc = stored.agent_id.to_dict()
        _emit(
            {
                "status": "stored",
                "name": stored.name,
                "agent_id": stored.agent_id.agent_id,
                "public_key_multibase": multibase_pub,
                "identity_document": doc,
                "note": (
                    "The 32-byte seed was written to the local store with 0600 "
                    "permissions. It is the root of this identity: anyone who "
                    "reads it can sign attestations as this agent."
                ),
            }
        )
        return 0

    # No --name: emit everything including the seed, nothing is persisted.
    agent = create_agent_id(seed, controller=controller, capabilities=capabilities)
    _emit(
        {
            "status": "ephemeral",
            "agent_id": did,
            "public_key_multibase": multibase_pub,
            "identity_document": agent.to_dict(),
            "seed_hex": seed.hex(),
            "warning": (
                "This seed is shown once and nothing was written to disk. Store "
                "it in a secrets manager now; there is no way to recover it."
            ),
        }
    )
    return 0


# ---------------------------------------------------------------------------
# attest
# ---------------------------------------------------------------------------


def _resolve_seed(args: argparse.Namespace) -> bytes:
    if args.name:
        stored = load_identity(args.name)
        return stored.seed
    if args.seed_hex:
        try:
            seed = bytes.fromhex(args.seed_hex)
        except ValueError as exc:
            raise SystemExit(f"error: --seed-hex is not valid hex: {exc}")
        if len(seed) != ED25519_KEY_LEN:
            raise SystemExit(
                f"error: --seed-hex must decode to {ED25519_KEY_LEN} bytes, got {len(seed)}"
            )
        return seed
    raise SystemExit("error: attestation requires either --name or --seed-hex")


def cmd_attest(args: argparse.Namespace) -> int:
    try:
        claim = json.loads(args.claim)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: --claim is not valid JSON: {exc}")

    if not isinstance(claim, dict) or not claim:
        raise SystemExit("error: --claim must be a non-empty JSON object")

    seed = _resolve_seed(args)

    try:
        attestation = create_attestation(
            seed,
            claim,
            issuer=args.issuer,
            kid=args.kid,
            expires_at=args.expires_at,
        )
    except ValueError as exc:
        raise SystemExit(f"error: {exc}")

    _emit(attestation.to_dict())

    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(attestation.to_json())
                fh.write("\n")
        except OSError as exc:
            raise SystemExit(f"error: could not write {args.out}: {exc}")
        print(f"wrote {args.out}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def _read_document(path: Optional[str]) -> str:
    if not path:
        return sys.stdin.read()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        raise SystemExit(f"error: could not read {path}: {exc}")


def cmd_verify(args: argparse.Namespace) -> int:
    text = _read_document(args.attestation)
    result = verify_attestation(text, check_expiry=not args.ignore_expiry)

    out = {
        "valid": result.valid,
        "status_code": result.status_code,
        "agent_id": result.agent_id,
        "message": result.message,
    }
    if result.error_code:
        out["error_code"] = result.error_code
    _emit(out)

    return 0 if result.valid else 1


# ---------------------------------------------------------------------------
# reputation
# ---------------------------------------------------------------------------


def cmd_reputation(args: argparse.Namespace) -> int:
    if args.agent_id and not args.agent_id.startswith("did:"):
        # Accept a stored identity name for convenience.
        if identity_exists(args.agent_id):
            args.agent_id = load_identity(args.agent_id).agent_id.agent_id

    if args.ledger:
        try:
            with open(args.ledger, "r", encoding="utf-8") as fh:
                events = json.load(fh)
        except OSError as exc:
            raise SystemExit(f"error: could not read ledger {args.ledger}: {exc}")
        except json.JSONDecodeError as exc:
            raise SystemExit(f"error: ledger is not valid JSON: {exc}")
        score = reputation_from_events(args.agent_id, events)
        _emit({"agent_id": args.agent_id, "source": args.ledger, "reputation": score.to_dict()})
        return 0

    score = compute_reputation_score(
        reliability=args.rel,
        accuracy=args.acc,
        stability=args.stab,
        total_claims=args.total_claims,
        refuted_claims=args.refuted_claims,
        total_transactions=args.transactions,
        is_quarantined=args.quarantined,
    )
    _emit({"agent_id": args.agent_id, "reputation": score.to_dict()})
    return 0


# ---------------------------------------------------------------------------
# list / delete (store management)
# ---------------------------------------------------------------------------


def cmd_list(args: argparse.Namespace) -> int:
    names = list_identities()
    if not names:
        print("No stored identities. Use `kredent create --name <name>` to create one.")
        return 0
    _emit({"identities": names})
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    if delete_identity(args.name):
        print(f"deleted identity {args.name!r}")
        return 0
    raise SystemExit(f"error: no stored identity named {args.name!r}")


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kredent",
        description=(
            "Identity and verifiable reputation for autonomous agents. "
            "Agents hold an Ed25519 key, identify as did:key, and sign claims; "
            "anyone can verify those claims offline."
        ),
    )
    parser.add_argument("--version", action="version", version=f"kredent {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # create
    p_create = subparsers.add_parser("create", help="Generate a new agent identity (did:key)")
    p_create.add_argument("--name", help="Persist the identity under this name in the local store")
    p_create.add_argument("--controller", help="Controller DID or legal anchor (e.g. did:web:acme.com)")
    p_create.add_argument("--capabilities", nargs="+", help="Declared capabilities of the agent")
    p_create.set_defaults(func=cmd_create)

    # attest
    p_attest = subparsers.add_parser("attest", help="Create and sign an attestation")
    src = p_attest.add_mutually_exclusive_group(required=True)
    src.add_argument("--name", help="Use the seed of a stored identity")
    src.add_argument("--seed-hex", help="32-byte Ed25519 seed in hex")
    p_attest.add_argument("--issuer", help="did:key issuer (defaults to the key derived from the seed)")
    p_attest.add_argument("--kid", default=DEFAULT_KID, help="Key identifier")
    p_attest.add_argument("--claim", required=True, help="JSON object describing the claim")
    p_attest.add_argument("--expires-at", help="ISO-8601 expiry timestamp")
    p_attest.add_argument("--out", help="Write the attestation to this file as JSON")
    p_attest.set_defaults(func=cmd_attest)

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify an attestation offline")
    p_verify.add_argument("attestation", nargs="?", help="Path to a JSON attestation (reads stdin if omitted)")
    p_verify.add_argument("--ignore-expiry", action="store_true", help="Do not check the expiry timestamp")
    p_verify.set_defaults(func=cmd_verify)

    # reputation
    p_rep = subparsers.add_parser("reputation", help="Compute an agent's reputation score")
    p_rep.add_argument("agent_id", help="Agent did:key (or a stored identity name)")
    p_rep.add_argument("--ledger", help="Path to a JSON ledger of calibration events")
    p_rep.add_argument("--rel", type=float, default=0.9, help="Reliability [0.0-1.0]")
    p_rep.add_argument("--acc", type=float, default=0.9, help="Accuracy [0.0-1.0]")
    p_rep.add_argument("--stab", type=float, default=0.9, help="Stability [0.0-1.0]")
    p_rep.add_argument("--transactions", type=int, default=0, help="Total transactions")
    p_rep.add_argument("--total-claims", type=int, default=0, help="Total claims made")
    p_rep.add_argument("--refuted-claims", type=int, default=0, help="Refuted claims count")
    p_rep.add_argument("--quarantined", action="store_true", help="Force quarantined status")
    p_rep.set_defaults(func=cmd_reputation)

    # list
    p_list = subparsers.add_parser("list", help="List stored identities")
    p_list.set_defaults(func=cmd_list)

    # delete
    p_del = subparsers.add_parser("delete", help="Delete a stored identity")
    p_del.add_argument("name", help="Name of the identity to delete")
    p_del.set_defaults(func=cmd_delete)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SystemExit:
        raise
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
