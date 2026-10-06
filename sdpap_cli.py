#!/usr/bin/env python3
import os
import sys
import json
import argparse
from typing import Any, Dict

# Импортируем продакшн-ядро
from sdpap_v3_production import (
    Ed25519KeyManager,
    SDPAPKernelProduction,
    MerkleTree,
    canonical_serialize,
    canonical_hash
)

def cmd_keygen(args):
    priv_hex, pub_hex = Ed25519KeyManager.generate_keypair()
    print("=========================================================")
    print("   SDPAP v3 & TGP Ed25519 Keypair Generator")
    print("=========================================================")
    print(f"SDPAP_PRIVATE_KEY_HEX={priv_hex}")
    print(f"SDPAP_PUBLIC_KEY_HEX={pub_hex}")
    print("=========================================================")
    
    if args.out_env:
        with open(args.out_env, "w", encoding="utf-8") as f:
            f.write(f"SDPAP_PRIVATE_KEY_HEX={priv_hex}\n")
            f.write(f"SDPAP_PUBLIC_KEY_HEX={pub_hex}\n")
        print(f"[+] Keys successfully saved to '{args.out_env}'")

def cmd_init_db(args):
    kernel = SDPAPKernelProduction(db_path=args.db, dotenv_path=args.env)
    print(f"[+] Database initialized at '{args.db}' in WAL mode with append-only triggers.")
    print(f"    Genesis State Version: {kernel.current_state.version}")
    print(f"    Genesis State Hash:    {kernel.current_state.state_hash}")

def cmd_sign(args):
    priv_key = Ed25519KeyManager.load_private_key("SDPAP_PRIVATE_KEY_HEX", args.env)
    payload = json.loads(args.payload)
    sig_hex = Ed25519KeyManager.sign_envelope(priv_key, args.version, args.nonce, payload)
    
    request_obj = {
        "version": args.version,
        "nonce": args.nonce,
        "payload": payload,
        "signature": sig_hex
    }
    
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(request_obj, f, indent=2, ensure_ascii=False)
        print(f"[+] Signed request saved to '{args.out}'")
    else:
        print(json.dumps(request_obj, indent=2, ensure_ascii=False))

def cmd_submit(args):
    kernel = SDPAPKernelProduction(db_path=args.db, dotenv_path=args.env)
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            req_data = json.load(f)
    else:
        req_data = json.loads(args.request_json)

    res = kernel.process_request(req_data)
    print(f"TGP Gate Execution Result: [{res}]")
    if res == "PASS":
        print(f" -> New State Version: {kernel.current_state.version}")
        print(f" -> New Merkle Root:   {kernel.current_state.merkle_root}")
    else:
        print(" -> Request REJECTED by TGP Execution Gate (Fail-Closed)")

def cmd_audit(args):
    kernel = SDPAPKernelProduction(db_path=args.db, dotenv_path=args.env)
    is_valid, msg = kernel.verify_full_integrity()
    print("=========================================================")
    print("   SDPAP v3 Tamper-Evident Ledger Integrity Audit")
    print("=========================================================")
    print(f"Audit Status:  {'[SUCCESS]' if is_valid else '[CORRUPTED]'}")
    print(f"Details:       {msg}")
    print(f"Current State: Version {kernel.current_state.version}")
    print(f"Merkle Root:   {kernel.current_state.merkle_root}")
    print("=========================================================")

def cmd_anchor(args):
    kernel = SDPAPKernelProduction(db_path=args.db, dotenv_path=args.env)
    anchor_cert = kernel.export_public_anchor()
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(anchor_cert, f, indent=2, ensure_ascii=False)
        print(f"[+] Green Anchor Certificate exported to '{args.out}'")
    else:
        print(json.dumps(anchor_cert, indent=2, ensure_ascii=False))

def cmd_proof(args):
    kernel = SDPAPKernelProduction(db_path=args.db, dotenv_path=args.env)
    proof_obj = kernel.generate_merkle_proof(args.sequence)
    print(json.dumps(proof_obj, indent=2, ensure_ascii=False))

def main():
    parser = argparse.ArgumentParser(description="SDPAP v3 & TGP Production CLI Tool")
    parser.add_argument("--env", default=".env", help="Path to .env file (default: .env)")
    parser.add_argument("--db", default="/workspace/scratch/sdpap_production.db", help="Path to SQLite database")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate Ed25519 keypair")
    p_keygen.add_argument("--out-env", help="Path to save output .env file")
    p_keygen.set_defaults(func=cmd_keygen)

    # init-db
    p_init = subparsers.add_parser("init-db", help="Initialize SQLite WAL database")
    p_init.set_defaults(func=cmd_init_db)

    # sign
    p_sign = subparsers.add_parser("sign", help="Sign request payload with Ed25519 private key")
    p_sign.add_argument("--version", type=int, required=True, help="State version")
    p_sign.add_argument("--nonce", required=True, help="Unique nonce string")
    p_sign.add_argument("--payload", required=True, help="JSON string payload")
    p_sign.add_argument("--out", help="Save output request JSON to file")
    p_sign.set_defaults(func=cmd_sign)

    # submit
    p_sub = subparsers.add_parser("submit", help="Submit request to TGP Gate")
    p_sub.add_argument("--file", help="Path to signed request JSON file")
    p_sub.add_argument("--request-json", help="Inline signed request JSON string")
    p_sub.set_defaults(func=cmd_submit)

    # audit
    p_audit = subparsers.add_parser("audit", help="Run ledger integrity audit")
    p_audit.set_defaults(func=cmd_audit)

    # anchor
    p_anchor = subparsers.add_parser("anchor", help="Export Green Anchor certificate")
    p_anchor.add_argument("--out", help="Save output certificate to file")
    p_anchor.set_defaults(func=cmd_anchor)

    # proof
    p_proof = subparsers.add_parser("proof", help="Generate Merkle Proof for sequence ID")
    p_proof.add_argument("--sequence", type=int, required=True, help="Sequence ID")
    p_proof.set_defaults(func=cmd_proof)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
