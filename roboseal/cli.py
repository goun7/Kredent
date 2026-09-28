"""
Command-line interface for Roboseal agent identity & RFC 9421 signatures.
"""

import argparse
import sys
import json
import time
from datetime import datetime, timezone
import base64

from roboseal.models import AgentID, VerificationKey
from roboseal.crypto import (
    generate_keypair,
    decode_multibase_pubkey,
    load_private_key_from_bytes,
    sign_detached,
)
from roboseal.canonical import (
    format_signature_headers,
    build_signature_base,
    compute_content_digest,
)
from roboseal.verifier import verify_http_request
from roboseal.reputation import compute_reputation_score


def cmd_keygen(args: argparse.Namespace) -> None:
    priv, pub, multibase_pub = generate_keypair()
    priv_bytes = priv.private_bytes_raw()
    priv_hex = priv_bytes.hex()

    agent_id_str = f"did:agent:68:key:{multibase_pub}"
    created_at = datetime.now(timezone.utc).isoformat()

    agent_obj = AgentID(
        agent_id=agent_id_str,
        version="1.0.0",
        created_at=created_at,
        controller=args.controller or "did:legal:unknown",
        keys=[
            VerificationKey(
                kid="sig-ed25519-primary",
                key_type="Ed25519VerificationKey2020",
                public_key_multibase=multibase_pub,
                purposes=["call-signing", "commitment-assertion"],
            )
        ],
        capabilities=args.capabilities or ["tool-call", "catalog-solve"],
    )

    output = {
        "agent_id_document": agent_obj.to_dict(),
        "private_key_seed_hex": priv_hex,
        "public_key_multibase": multibase_pub,
    }
    print(json.dumps(output, indent=2))


def cmd_sign(args: argparse.Namespace) -> None:
    priv_bytes = bytes.fromhex(args.private_key_hex)
    priv_key = load_private_key_from_bytes(priv_bytes)

    body_bytes = args.body.encode("utf-8") if args.body else b""
    content_digest = compute_content_digest(body_bytes)

    now_epoch = int(time.time())
    date_str = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

    signature_params = (
        f'("@method" "@authority" "@target-uri" "content-digest" "date");'
        f'created={now_epoch};keyid="{args.kid}";alg="ed25519"'
    )

    sig_base = build_signature_base(
        method=args.method,
        authority=args.authority,
        target_uri=args.target_uri,
        content_digest=content_digest,
        date_str=date_str,
        signature_params=signature_params,
    )

    raw_sig = sign_detached(priv_key, sig_base)
    headers = format_signature_headers(
        agent_id=args.agent_id,
        kid=args.kid,
        method=args.method,
        authority=args.authority,
        target_uri=args.target_uri,
        raw_body=body_bytes,
        signature_bytes=raw_sig,
        created_epoch=now_epoch,
        date_str=date_str,
    )

    print(json.dumps(headers, indent=2))


def cmd_verify(args: argparse.Namespace) -> None:
    pub_raw = decode_multibase_pubkey(args.public_key_multibase)
    headers = json.loads(args.headers_json)
    body_bytes = args.body.encode("utf-8") if args.body else b""

    result = verify_http_request(
        method=args.method,
        authority=args.authority,
        target_uri=args.target_uri,
        headers=headers,
        raw_body=body_bytes,
        public_key_raw=pub_raw,
    )

    print(json.dumps({
        "valid": result.valid,
        "status_code": result.status_code,
        "error_code": result.error_code,
        "agent_id": result.agent_id,
        "message": result.message,
    }, indent=2))

    if not result.valid:
        sys.exit(1)


def cmd_score(args: argparse.Namespace) -> None:
    score = compute_reputation_score(
        reliability=args.rel,
        accuracy=args.acc,
        stability=args.stab,
        total_claims=args.total_claims,
        refuted_claims=args.refuted_claims,
        total_transactions=args.transactions,
        is_quarantined=args.quarantined,
    )
    print(json.dumps(score.to_dict(), indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="roboseal",
        description="Roboseal: Autonomous Agent Identity & Verifiable Reputation Protocol CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate a new AgentID and Ed25519 keypair")
    p_keygen.add_argument("--controller", help="Controller DID or legal anchor")
    p_keygen.add_argument("--capabilities", nargs="+", help="List of capabilities")
    p_keygen.set_defaults(func=cmd_keygen)

    # sign
    p_sign = subparsers.add_parser("sign", help="Sign an HTTP request using RFC 9421")
    p_sign.add_argument("--private-key-hex", required=True, help="32-byte Ed25519 private seed in hex")
    p_sign.add_argument("--agent-id", required=True, help="Sender AgentID")
    p_sign.add_argument("--kid", default="sig-ed25519-primary", help="Key ID")
    p_sign.add_argument("--method", required=True, help="HTTP method (e.g. POST)")
    p_sign.add_argument("--authority", required=True, help="Host authority (e.g. api.agentshelf.org)")
    p_sign.add_argument("--target-uri", required=True, help="Full target URI")
    p_sign.add_argument("--body", default="", help="HTTP request body")
    p_sign.set_defaults(func=cmd_sign)

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify an RFC 9421 signed HTTP request")
    p_verify.add_argument("--public-key-multibase", required=True, help="Multibase public key (z...)")
    p_verify.add_argument("--method", required=True, help="HTTP method")
    p_verify.add_argument("--authority", required=True, help="Host authority")
    p_verify.add_argument("--target-uri", required=True, help="Full target URI")
    p_verify.add_argument("--headers-json", required=True, help="JSON dictionary of received headers")
    p_verify.add_argument("--body", default="", help="HTTP request body")
    p_verify.set_defaults(func=cmd_verify)

    # score
    p_score = subparsers.add_parser("score", help="Calculate reputation score")
    p_score.add_argument("--rel", type=float, required=True, help="Reliability [0.0 - 1.0]")
    p_score.add_argument("--acc", type=float, required=True, help="Accuracy [0.0 - 1.0]")
    p_score.add_argument("--stab", type=float, required=True, help="Stability [0.0 - 1.0]")
    p_score.add_argument("--transactions", type=int, required=True, help="Total transactions count")
    p_score.add_argument("--total-claims", type=int, default=0, help="Total claims made")
    p_score.add_argument("--refuted-claims", type=int, default=0, help="Refuted claims count")
    p_score.add_argument("--quarantined", action="store_true", help="Force quarantined status")
    p_score.set_defaults(func=cmd_score)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
