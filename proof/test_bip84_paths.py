"""Independent BIP84 path vectors and CUDA source-contract checks."""

import hashlib
import hmac
import struct
import unittest
from pathlib import Path

from coincurve import PrivateKey
from firstboot_flow import entropy_to_seed, rng_raw_first_boot

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def ckd_priv(key: bytes, chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    if index >= 0x80000000:
        data = b"\x00" + key
    else:
        data = PrivateKey(key).public_key.format(compressed=True)
    digest = hmac.new(chain_code, data + struct.pack(">I", index), hashlib.sha512).digest()
    child = (int.from_bytes(digest[:32], "big") + int.from_bytes(key, "big")) % N
    if child == 0 or int.from_bytes(digest[:32], "big") >= N:
        raise ValueError("invalid BIP32 child in fixed test vector")
    return child.to_bytes(32, "big"), digest[32:]


def derive(mnemonic: str, path: list[int]) -> bytes:
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic", 2048, 64)
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key, chain_code = digest[:32], digest[32:]
    for index in path:
        key, chain_code = ckd_priv(key, chain_code, index)
    return key


def polymod(values: list[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i, generator in enumerate(generators):
            if (top >> i) & 1:
                chk ^= generator
    return chk


def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> list[int]:
    acc = bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (tobits - bits)) & maxv)
    return out


def p2wpkh_address(key: bytes) -> str:
    pubkey = PrivateKey(key).public_key.format(compressed=True)
    program = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()
    data = [0] + convertbits(program, 8, 5)
    hrp = [ord(c) >> 5 for c in "bc"] + [0] + [ord(c) & 31 for c in "bc"]
    checksum_value = polymod(hrp + data + [0] * 6) ^ 1
    checksum = [(checksum_value >> (5 * (5 - i))) & 31 for i in range(6)]
    return "bc1" + "".join(CHARSET[x] for x in data + checksum)


class Bip84PathTests(unittest.TestCase):
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    account = [84 | 0x80000000, 0x80000000, 0x80000000]

    def test_official_receive_and_change_vectors(self):
        vectors = {
            (0, 0): "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
            (0, 1): "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
            (1, 0): "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
        }
        for (chain, index), expected in vectors.items():
            with self.subTest(chain=chain, index=index):
                key = derive(self.mnemonic, self.account + [chain, index])
                self.assertEqual(p2wpkh_address(key), expected)

    def test_cuda_exposes_explicit_path_ranges(self):
        source = (Path(__file__).parents[1] / "gpu/cuda/scan.cu").read_text()
        for required in (
            "struct PathRange",
            "range.indexStart + idxOff",
            "P.pathRangeCount",
            "case 'P':",
            "explicit -i cannot be combined with -P",
            "overlapping or duplicate -P path ranges",
            "hits[slot].chain = range.chain;",
            r'\"chain\": %u',
        ):
            self.assertIn(required, source)

    def test_planted_firstboot_path_endpoints(self):
        flow = rng_raw_first_boot(3547144342, 0, 0, 2, 17)
        self.assertIsNotNone(flow)
        assert flow is not None
        _, mnemonic = entropy_to_seed(bytes.fromhex(flow["entropy_hex"]))
        vectors = {
            (0, 0): "bc1qqf80a8pg8mzp5qyzacqv3w7jt595pjf0zzznew",
            (0, 7): "bc1q5t2n48pd40mjc5svy40jfnmarvgetuhv7d5yvh",
            (0, 8): "bc1qu669y2zjn3ptm9pjd20w250h5hsa786f0hjys6",
            (0, 19): "bc1q2fy60r6g38zpr4wfa0kv720a9dym83ymc247xd",
            (1, 0): "bc1qxye6kpf2v0j7ug0ytw5xgr94aukv38436lg2py",
            (1, 19): "bc1qj4tk4eefxa0fau9elysx9zac5ka7j0dxfdmc2h",
        }
        for (chain, index), expected in vectors.items():
            with self.subTest(chain=chain, index=index):
                key = derive(mnemonic, self.account + [chain, index])
                self.assertEqual(p2wpkh_address(key), expected)


if __name__ == "__main__":
    unittest.main()
