#!/usr/bin/env python3
"""BIP322 simple message signatures for P2WPKH (bc1q...) addresses.

Sign:   prove control of a private key without moving funds.
Verify: offline check of a BIP322 simple proof.

Usage:
  bip322.py sign   <privkey_hex> <address>
  bip322.py verify <address> <proof_b64> <message>
  bip322.py selftest
"""
import base64
import hashlib
import struct
import sys

from coincurve import PrivateKey, PublicKey

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
PROOF_MSG = "Coldcard Mk3 weak-RNG research PoC - key control"


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def tagged_hash(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def bech32_polymod(values):
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def bech32_hrp_expand(hrp):
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def convertbits(data, frombits, tobits, pad=True):
    accumulator, bits, output = 0, 0, []
    max_value = (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            raise ValueError("invalid convertbits value")
        accumulator = (accumulator << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            output.append((accumulator >> bits) & max_value)
    if pad:
        if bits:
            output.append((accumulator << (tobits - bits)) & max_value)
    elif bits >= frombits or ((accumulator << (tobits - bits)) & max_value):
        raise ValueError("invalid witness-program padding")
    return output


def p2wpkh_address(program):
    if len(program) != 20:
        raise ValueError("only p2wpkh supported")
    hrp = "bc"
    data = [0] + convertbits(program, 8, 5)
    checksum_value = bech32_polymod(bech32_hrp_expand(hrp) + data + [0] * 6) ^ 1
    checksum = [(checksum_value >> (5 * (5 - index))) & 31 for index in range(6)]
    return hrp + "1" + "".join(CHARSET[value] for value in data + checksum)


def bech32_decode_prog(address):
    if address.lower() != address and address.upper() != address:
        raise ValueError("mixed case bech32 address")
    address = address.lower()
    hrp, separator, data = address.rpartition("1")
    if separator != "1" or hrp != "bc" or len(data) < 7:
        raise ValueError("only bc1 mainnet addresses supported")
    try:
        values = [CHARSET.index(char) for char in data]
    except ValueError as error:
        raise ValueError("invalid bech32 character") from error
    if bech32_polymod(bech32_hrp_expand(hrp) + values) != 1:
        raise ValueError("invalid bech32 checksum")
    if values[0] != 0:
        raise ValueError("only witness v0 supported")
    program = bytes(convertbits(values[1:-6], 5, 8, pad=False))
    if len(program) != 20:
        raise ValueError("only p2wpkh supported")
    return program


def ser_tx(version, vin, vout, locktime, witness=None):
    raw = struct.pack("<i", version)
    if witness is not None:
        raw += b"\x00\x01"
    raw += bytes([len(vin)])
    for txid, vout_n, script, seq in vin:
        raw += txid + struct.pack("<I", vout_n)
        raw += bytes([len(script)]) + script
        raw += struct.pack("<I", seq)
    raw += bytes([len(vout)])
    for value, script in vout:
        raw += struct.pack("<q", value)
        raw += bytes([len(script)]) + script
    if witness is not None:
        for stack in witness:
            raw += bytes([len(stack)])
            for item in stack:
                raw += bytes([len(item)]) + item
    raw += struct.pack("<I", locktime)
    return raw


def build_to_spend(message_hash, prog):
    script_sig = b"\x00\x20" + message_hash          # OP_0 push32 hash
    script_pubkey = b"\x00\x14" + prog               # p2wpkh
    return ser_tx(0, [(b"\x00" * 32, 0xFFFFFFFF, script_sig, 0)],
                  [(0, script_pubkey)], 0)


def bip143_sighash(to_spend_txid, prog):
    # sighash for to_sign spending to_spend:0 (value 0), SIGHASH_ALL
    outpoint = to_spend_txid + struct.pack("<I", 0)
    hash_prevouts = sha256d(outpoint)
    hash_sequence = sha256d(struct.pack("<I", 0))
    script_code = b"\x19\x76\xa9\x14" + prog + b"\x88\xac"
    output = struct.pack("<q", 0) + b"\x01\x6a"       # OP_RETURN out
    hash_outputs = sha256d(output)
    pre = (struct.pack("<i", 0) + hash_prevouts + hash_sequence + outpoint
           + script_code + struct.pack("<q", 0) + struct.pack("<I", 0)
           + hash_outputs + struct.pack("<I", 0) + struct.pack("<I", 1))
    return sha256d(pre)


def witness_bytes(stack):
    raw = bytes([len(stack)])
    for item in stack:
        raw += bytes([len(item)]) + item
    return raw


def sign(privkey_hex, address, message):
    priv = PrivateKey(bytes.fromhex(privkey_hex))
    pub = priv.public_key.format(compressed=True)
    prog = bech32_decode_prog(address)
    assert hash160(pub) == prog, "privkey does not match address"
    mh = tagged_hash("BIP0322-signed-message", message.encode())
    to_spend = build_to_spend(mh, prog)
    sighash = bip143_sighash(sha256d(to_spend), prog)
    sig = priv.sign(sighash, hasher=None) + b"\x01"
    return base64.b64encode(witness_bytes([sig, pub])).decode()


def verify(address, proof_b64, message):
    try:
        raw = base64.b64decode(proof_b64)
        assert raw[0] == 2
        sig_len = raw[1]
        sig = raw[2:2 + sig_len]
        off = 2 + sig_len
        pub_len = raw[off]
        pub = raw[off + 1:off + 1 + pub_len]
        assert len(pub) == 33 and off + 1 + pub_len == len(raw)
        prog = bech32_decode_prog(address)
        if hash160(pub) != prog:
            return False
        mh = tagged_hash("BIP0322-signed-message", message.encode())
        to_spend = build_to_spend(mh, prog)
        sighash = bip143_sighash(sha256d(to_spend), prog)
        return PublicKey(pub).verify(sig[:-1], sighash, hasher=None)
    except Exception:
        return False


def selftest():
    import os
    priv = PrivateKey(os.urandom(32))
    pub = priv.public_key.format(compressed=True)
    prog = hash160(pub)
    addr = p2wpkh_address(prog)
    proof = sign(priv.secret.hex(), addr, PROOF_MSG)
    assert verify(addr, proof, PROOF_MSG), "valid proof rejected"
    assert not verify(addr, proof, "wrong message"), "forged message accepted"
    print(f"[selftest] address: {addr}")
    print(f"[selftest] proof:   {proof}")
    print("[selftest] OK: sign->verify roundtrip passes, wrong message rejected")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        selftest()
    elif len(sys.argv) == 4 and sys.argv[1] == "sign":
        print(sign(sys.argv[2], sys.argv[3], PROOF_MSG))
    elif len(sys.argv) == 5 and sys.argv[1] == "verify":
        ok = verify(sys.argv[2], sys.argv[3], sys.argv[4])
        print(f"verify: {ok}")
        sys.exit(0 if ok else 1)
    else:
        print(__doc__)
        sys.exit(2)

