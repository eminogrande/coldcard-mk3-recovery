#!/usr/bin/env python3
"""Create and verify a BIP322 proof artifact from a CUDA/CPU hit JSON."""

import argparse
import json
from pathlib import Path

from coincurve import PrivateKey

from bip322 import PROOF_MSG, bech32_decode_prog, hash160, sign, verify


def load_hit(path: Path) -> dict:
    payload = json.loads(path.read_text())
    if isinstance(payload, list):
        if len(payload) != 1:
            raise ValueError(f"expected exactly one hit, got {len(payload)}")
        payload = payload[0]
    if not isinstance(payload, dict):
        raise ValueError("hit artifact must be a JSON object or one-item array")
    return payload


def archive_proof(hit_path: Path, address: str, output_path: Path) -> dict:
    hit = load_hit(hit_path)
    private_key = PrivateKey(bytes.fromhex(hit["priv"]))
    public_key = private_key.public_key.format(compressed=True)
    derived_h160 = hash160(public_key)
    address_h160 = bech32_decode_prog(address)

    if derived_h160 != address_h160:
        raise ValueError("recovered private key does not control the supplied address")
    if "h160" in hit and bytes.fromhex(hit["h160"]) != derived_h160:
        raise ValueError("hit h160 does not match the recovered private key")

    proof = sign(hit["priv"], address, PROOF_MSG)
    if not verify(address, proof, PROOF_MSG):
        raise RuntimeError("generated BIP322 proof failed internal verification")
    if verify(address, proof, PROOF_MSG + " (tampered)"):
        raise RuntimeError("generated BIP322 proof accepted a tampered message")

    artifact = {
        "scheme": "BIP322-simple-P2WPKH",
        "address": address,
        "message": PROOF_MSG,
        "proof_b64": proof,
        "verified": True,
        "source_hit": hit_path.name,
        "recovery": {
            key: hit[key]
            for key in ("pad", "skip", "idx", "h160")
            if key in hit
        },
    }
    output_path.write_text(json.dumps(artifact, indent=2) + "\n")
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("hit", type=Path)
    parser.add_argument("address")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    artifact = archive_proof(args.hit, args.address, args.output)
    print(f"archived: {args.output}")
    print(f"address:  {artifact['address']}")
    print(f"proof:    {artifact['proof_b64']}")
    print("verify:   True")


if __name__ == "__main__":
    main()
