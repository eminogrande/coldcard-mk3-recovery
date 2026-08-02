#!/usr/bin/env python3
"""Firmware-flow reference vectors for the COLDCARD Mk3 first-boot RNG path.

This models the random operations that happen before first-wallet seed creation:

1. Shuffle 32 empty nvstore slots.
2. Write three 4 KiB random-noise slots (48 calls to random.bytes(256)).
3. Process a configurable number of keypad scan sessions before Terms are saved.
4. Shuffle 32 slots for the first settings save.
5. Process a configurable number of keypad scan sessions before wallet creation.
6. Generate random.bytes(32), then SHA-256 it into BIP39 entropy.

The session counts are explicit because physical key timing and the selected PIN/UI
path are user-dependent. This module is a CPU reference and positive-control
vector generator; the CUDA implementation must reproduce its output exactly.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path

from coincurve import PrivateKey

MASK32 = 0xFFFFFFFF
CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
DEFAULT_WORDLIST = Path(__file__).resolve().parents[1] / "scan" / "bip39_english.txt"


@dataclass
class Yasmarang:
    pad: int
    n: int
    d: int
    dat: int = 0
    draws: int = 0

    def next(self) -> int:
        self.pad = (self.pad + self.dat + self.d * self.n) & MASK32
        self.pad = ((self.pad << 3) | (self.pad >> 29)) & MASK32
        self.n = self.pad | 2
        self.d = (self.d ^ ((self.pad << 31) + (self.pad >> 1))) & MASK32
        self.dat = (self.dat ^ (self.pad & 0xFF) ^ (self.d >> 8) ^ 1) & 0xFF
        self.draws += 1
        return (
            self.pad
            ^ ((self.d << 5) & MASK32)
            ^ (self.pad >> 18)
            ^ (self.dat << 1)
        ) & MASK32


@dataclass(frozen=True)
class FirstBootResult:
    raw: bytes
    entropy: bytes
    chip_skip: int
    mixer_skip: int


def standard_setup_post_terms_sessions(total_pin_digits: int) -> int:
    """Keypad sessions from Terms save to random.bytes(32) on the standard UI path.

    The user selects Choose PIN, acknowledges two warnings, enters the full PIN
    twice (three control presses per entry), then selects New Wallet. Valid Mk3
    PINs contain 4 through 12 total digits.
    """
    if not 4 <= total_pin_digits <= 12:
        raise ValueError("standard Mk3 PIN must contain 4 through 12 digits")
    return 2 * total_pin_digits + 10


def _new_generators(pad: int, rtc_tr: int, rtc_ssr: int) -> tuple[Yasmarang, Yasmarang]:
    if not 0 <= pad <= MASK32:
        raise ValueError("pad must fit uint32")
    if not 0 <= rtc_tr <= MASK32 or not 0 <= rtc_ssr <= MASK32:
        raise ValueError("RTC values must fit uint32")
    return (
        Yasmarang(pad=pad, n=rtc_tr, d=rtc_ssr),
        Yasmarang(pad=0x0A8CE26F, n=69, d=233),
    )


def _rand_below(chip: Yasmarang, mixer: Yasmarang, maximum: int) -> int:
    """Exact libngu _rand_below(), including its mixer-only rejection loop."""
    if maximum <= 1:
        return 0
    bit_length = maximum.bit_length()
    if bit_length >= 31:
        raise ValueError("firmware _rand_below requires bit_length < 31")
    mask = (2 << bit_length) - 1
    point = mixer.next() ^ chip.next()
    while True:
        value = point & mask
        if value < maximum:
            return value
        point ^= mixer.next()


def _shuffle_draws(chip: Yasmarang, mixer: Yasmarang, length: int) -> None:
    for index in range(length - 1, 0, -1):
        _rand_below(chip, mixer, index + 1)


def _random_bytes(chip: Yasmarang, mixer: Yasmarang, count: int) -> bytes:
    """Exact libngu my_random_bytes() state advancement and LE output."""
    output = bytearray()
    last = 0
    while count:
        chip_word = chip.next()
        if chip_word == last:
            raise RuntimeError("firmware RNG continuous-test failure")
        last = chip_word
        mixed = chip_word ^ mixer.next()
        take = min(4, count)
        output.extend(mixed.to_bytes(4, "little")[:take])
        count -= take
    return bytes(output)


def simulate_firstboot(
    pad: int,
    *,
    pre_terms_sessions: int,
    post_terms_sessions: int,
    rtc_tr: int = 0,
    rtc_ssr: int = 0,
) -> FirstBootResult:
    if pre_terms_sessions < 0 or post_terms_sessions < 0:
        raise ValueError("keypad session counts must be non-negative")

    chip, mixer = _new_generators(pad, rtc_tr, rtc_ssr)

    _shuffle_draws(chip, mixer, 32)
    for _slot in range(3):
        for _chunk in range(16):
            _random_bytes(chip, mixer, 256)

    for _ in range(pre_terms_sessions):
        _shuffle_draws(chip, mixer, 4)

    _shuffle_draws(chip, mixer, 32)

    for _ in range(post_terms_sessions):
        _shuffle_draws(chip, mixer, 4)

    chip_skip = chip.draws
    mixer_skip = mixer.draws
    raw = _random_bytes(chip, mixer, 32)
    return FirstBootResult(
        raw=raw,
        entropy=hashlib.sha256(raw).digest(),
        chip_skip=chip_skip,
        mixer_skip=mixer_skip,
    )


def fixed_skip_raw(
    pad: int,
    chip_skip: int,
    mixer_skip: int,
    *,
    rtc_tr: int = 0,
    rtc_ssr: int = 0,
) -> bytes:
    if chip_skip < 0 or mixer_skip < 0:
        raise ValueError("skip counts must be non-negative")
    chip, mixer = _new_generators(pad, rtc_tr, rtc_ssr)
    for _ in range(chip_skip):
        chip.next()
    for _ in range(mixer_skip):
        mixer.next()
    return _random_bytes(chip, mixer, 32)


def entropy_to_mnemonic(entropy: bytes, wordlist_path: Path = DEFAULT_WORDLIST) -> str:
    if len(entropy) != 32:
        raise ValueError("first-wallet entropy must be 32 bytes")
    words = wordlist_path.read_text().splitlines()
    if len(words) != 2048:
        raise ValueError(f"wordlist must contain 2048 words, got {len(words)}")
    checksum = hashlib.sha256(entropy).digest()[0]
    bits = int.from_bytes(entropy + bytes([checksum]), "big")
    return " ".join(words[(bits >> (264 - 11 * (i + 1))) & 0x7FF] for i in range(24))


def _ckd_private(key: bytes, chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    if index & 0x80000000:
        data = b"\x00" + key
    else:
        data = PrivateKey(key).public_key.format(compressed=True)
    digest = hmac.new(chain_code, data + index.to_bytes(4, "big"), hashlib.sha512).digest()
    left = int.from_bytes(digest[:32], "big")
    if left >= CURVE_N:
        raise RuntimeError("invalid BIP32 child: IL >= curve order")
    child = (left + int.from_bytes(key, "big")) % CURVE_N
    if child == 0:
        raise RuntimeError("invalid BIP32 zero child")
    return child.to_bytes(32, "big"), digest[32:]


def _hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def _convert_bits(data: bytes, from_bits: int, to_bits: int) -> list[int]:
    accumulator = 0
    bits = 0
    output: list[int] = []
    mask = (1 << to_bits) - 1
    for value in data:
        accumulator = (accumulator << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            output.append((accumulator >> bits) & mask)
    if bits:
        output.append((accumulator << (to_bits - bits)) & mask)
    return output


def _bech32_polymod(values: list[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _p2wpkh_address(program: bytes) -> str:
    data = [0, *_convert_bits(program, 8, 5)]
    hrp = "bc"
    expanded = [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]
    checksum_value = _bech32_polymod(expanded + data + [0] * 6) ^ 1
    checksum = [(checksum_value >> (5 * (5 - index))) & 31 for index in range(6)]
    return hrp + "1" + "".join(CHARSET[value] for value in data + checksum)


def _derive_bip84_leaf(seed: bytes, address_index: int) -> tuple[bytes, bytes, str]:
    if not 0 <= address_index <= MASK32:
        raise ValueError("address index must fit uint32")
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key, chain_code = digest[:32], digest[32:]
    for index in (84 | 0x80000000, 0x80000000, 0x80000000, 0, address_index):
        key, chain_code = _ckd_private(key, chain_code, index)
    public_key = PrivateKey(key).public_key.format(compressed=True)
    program = _hash160(public_key)
    return key, program, _p2wpkh_address(program)


def build_vector(
    *,
    pad: int,
    pre_terms_sessions: int,
    post_terms_sessions: int,
    address_index: int,
    rtc_tr: int = 0,
    rtc_ssr: int = 0,
    wordlist_path: Path = DEFAULT_WORDLIST,
) -> dict:
    flow = simulate_firstboot(
        pad,
        pre_terms_sessions=pre_terms_sessions,
        post_terms_sessions=post_terms_sessions,
        rtc_tr=rtc_tr,
        rtc_ssr=rtc_ssr,
    )
    mnemonic = entropy_to_mnemonic(flow.entropy, wordlist_path)
    seed = hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic.encode(),
        b"mnemonic",
        2048,
        dklen=64,
    )
    private_key, program, address = _derive_bip84_leaf(seed, address_index)
    return {
        "model": "synthetic Mk3 physical first-boot flow positive control; no funds received",
        "pad": pad,
        "rtc_tr": rtc_tr,
        "rtc_ssr": rtc_ssr,
        "pre_terms_keypad_sessions": pre_terms_sessions,
        "post_terms_keypad_sessions": post_terms_sessions,
        "chip_skip": flow.chip_skip,
        "mixer_skip": flow.mixer_skip,
        "idx": address_index,
        "raw": flow.raw.hex(),
        "entropy": flow.entropy.hex(),
        "priv": private_key.hex(),
        "h160": program.hex(),
        "address": address,
    }


def _write_private_json(path: Path, payload: dict) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump(payload, output, indent=2)
            output.write("\n")
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _parse_int(text: str) -> int:
    return int(text, 0)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pad", type=_parse_int, required=True)
    parser.add_argument("--pre-terms-sessions", type=int, default=2)
    parser.add_argument("--post-terms-sessions", type=int, required=True)
    parser.add_argument("--index", type=int, default=0)
    parser.add_argument("--rtc-tr", type=_parse_int, default=0)
    parser.add_argument("--rtc-ssr", type=_parse_int, default=0)
    parser.add_argument("--wordlist", type=Path, default=DEFAULT_WORDLIST)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-output", type=Path)
    args = parser.parse_args()

    vector = build_vector(
        pad=args.pad,
        pre_terms_sessions=args.pre_terms_sessions,
        post_terms_sessions=args.post_terms_sessions,
        address_index=args.index,
        rtc_tr=args.rtc_tr,
        rtc_ssr=args.rtc_ssr,
        wordlist_path=args.wordlist,
    )
    _write_private_json(args.output, vector)
    if args.target_output:
        args.target_output.write_text(vector["address"] + "\n")

    print(f"vector: {args.output}")
    print(f"address: {vector['address']}")
    print(f"chip_skip: {vector['chip_skip']}")
    print(f"mixer_skip: {vector['mixer_skip']}")


if __name__ == "__main__":
    main()
