#!/usr/bin/env python3

import unittest

from coincurve import PrivateKey

from bip322 import (
    bech32_decode_prog,
    hash160,
    p2wpkh_address,
    sign,
    verify,
)


class Bip322Tests(unittest.TestCase):
    def setUp(self):
        self.private_key = bytes.fromhex(
            "1e5f1626daea69bd922bafc388577dc38ea5f00c482146d1f7c755a8bdd68839"
        )
        public_key = PrivateKey(self.private_key).public_key.format(compressed=True)
        self.address = p2wpkh_address(hash160(public_key))
        self.message = "Coldcard Mk3 weak-RNG research PoC - inert key-control proof"

    def test_sign_verify_and_negative_controls(self):
        proof = sign(self.private_key.hex(), self.address, self.message)

        self.assertTrue(verify(self.address, proof, self.message))
        self.assertFalse(verify(self.address, proof, self.message + "!"))

    def test_address_checksum_is_enforced(self):
        replacement = "q" if self.address[-1] != "q" else "p"
        bad_checksum = self.address[:-1] + replacement

        with self.assertRaisesRegex(ValueError, "checksum"):
            bech32_decode_prog(bad_checksum)

    def test_mixed_case_address_is_rejected(self):
        mixed_case = self.address[:3].upper() + self.address[3:]

        with self.assertRaisesRegex(ValueError, "mixed case"):
            bech32_decode_prog(mixed_case)


if __name__ == "__main__":
    unittest.main()
