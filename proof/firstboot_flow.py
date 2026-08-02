#!/usr/bin/env python3
"""CPU reference for the CORRECTED first-boot RNG flow.

Direct port of scan.cu's rngRawFirstBoot(): source-faithful fresh-device
sequence before make_new_wallet():
  shuffle(32)  -> 31 rand_below            (initial nvstore slot shuffle)
  48x random.bytes(256)=64 words each      (3 x 4KiB noise writes = 3072 words)
  P x shuffle(4) -> 3 rand_below each      (pre-Terms keypad sessions)
  shuffle(32)  -> 31 rand_below            (first settings/Terms save)
  Q x shuffle(4) -> 3 rand_below each      (post-Terms keypad sessions)
  random.bytes(32) -> 8 words              (the seed)

chip stream  = Yasmarang(pad, rtcTR, rtcSSR, 0)
mixer stream = Yasmarang(0x0A8CE26F, 69, 233, 0)   (fixed, public)
_rand_below rejections advance ONLY the mixer (pad-dependent).
raw[i] = chip.next() ^ mixer.next(); entropy = sha256(raw LE bytes).
"""
import hashlib, hmac, struct, json, sys

MIX_PAD, MIX_N, MIX_D = 0x0A8CE26F, 69, 233
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class Yas:
    __slots__ = ("pad", "n", "d", "dat")

    def __init__(self, pad, n, d, dat=0):
        self.pad, self.n, self.d, self.dat = pad & 0xFFFFFFFF, n & 0xFFFFFFFF, d & 0xFFFFFFFF, dat & 0xFF

    def next(self):
        self.pad = (self.pad + self.dat + self.d * self.n) & 0xFFFFFFFF
        self.pad = ((self.pad << 3) | (self.pad >> 29)) & 0xFFFFFFFF
        self.n = self.pad | 2
        self.d = (self.d ^ (((self.pad << 31) & 0xFFFFFFFF) + (self.pad >> 1))) & 0xFFFFFFFF
        self.dat = (self.dat ^ (self.pad & 0xFF) ^ (self.d >> 8) ^ 1) & 0xFF
        return (self.pad ^ ((self.d << 5) & 0xFFFFFFFF) ^ (self.pad >> 18) ^ ((self.dat << 1) & 0xFFFFFFFF)) & 0xFFFFFFFF


class Flow:
    def __init__(self, pad, rtcTR=0, rtcSSR=0):
        self.chip = Yas(pad, rtcTR, rtcSSR, 0)
        self.mixer = Yas(MIX_PAD, MIX_N, MIX_D, 0)
        self.chip_draws = 0
        self.mixer_draws = 0

    def _c(self):
        self.chip_draws += 1
        return self.chip.next()

    def _m(self):
        self.mixer_draws += 1
        return self.mixer.next()

    def rand_below(self, maximum):
        if maximum <= 1:
            return 0
        bit_length = 1
        while maximum >> bit_length:
            bit_length += 1
        mask = ((2 << bit_length) - 1) & 0xFFFFFFFF
        point = self._m() ^ self._c()
        while True:
            value = point & mask
            if value < maximum:
                return value
            point ^= self._m()          # mixer-only retry

    def shuffle(self, length):
        for index in range(length - 1, 0, -1):
            self.rand_below(index + 1)

    def discard_random_words(self, words):
        last = 0
        for _ in range(words):
            cw = self._c()
            if cw == last:
                return False
            last = cw
            self._m()
        return True


def rng_raw_first_boot(pad, rtcTR, rtcSSR, pre_terms, post_terms):
    f = Flow(pad, rtcTR, rtcSSR)
    f.shuffle(32)                      # initial nvstore find_spot shuffle
    for _ in range(48):                # 3 x 4KiB noise = 48 * random.bytes(256)=64 words
        if not f.discard_random_words(64):
            return None
    for _ in range(pre_terms):
        f.shuffle(4)
    f.shuffle(32)                      # first settings save shuffle
    for _ in range(post_terms):
        f.shuffle(4)
    raw = []
    last = 0
    for _ in range(8):
        cw = f._c()
        if cw == last:
            return None
        last = cw
        raw.append(cw ^ f._m())
    raw_bytes = b"".join(struct.pack("<I", w) for w in raw)
    entropy = hashlib.sha256(raw_bytes).digest()
    return {
        "pad": pad, "rtc_tr": rtcTR, "rtc_ssr": rtcSSR,
        "pre_terms": pre_terms, "post_terms": post_terms,
        "chip_skip": f.chip_draws - 8,   # draws before the 8 seed words
        "mixer_skip": f.mixer_draws - 8,
        "raw_hex": raw_bytes.hex(),
        "entropy_hex": entropy.hex(),
    }


# ---- BIP39 + BIP32 (stdlib) ----
def _wl():
    import os
    p = os.path.join(os.path.dirname(__file__), "..", "scan", "bip39_english.txt")
    return [w.strip() for w in open(p) if w.strip()]


def entropy_to_seed(entropy):
    words = _wl()
    cs = len(entropy) * 8 // 32
    bits = bin(int.from_bytes(entropy, "big"))[2:].zfill(len(entropy) * 8)
    bits += bin(hashlib.sha256(entropy).digest()[0])[2:].zfill(8)[:cs]
    mnemonic = " ".join(words[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11))
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic", 2048, 64)
    return seed, mnemonic


P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % P_FIELD == 0: return None
    if p == q:
        lam = (3 * p[0] * p[0]) * pow(2 * p[1], -1, P_FIELD) % P_FIELD
    else:
        lam = (q[1] - p[1]) * pow((q[0] - p[0]) % P_FIELD, -1, P_FIELD) % P_FIELD
    x3 = (lam * lam - p[0] - q[0]) % P_FIELD
    return (x3, (lam * (p[0] - x3) - p[1]) % P_FIELD)


def _mul(k, pt):
    r, a = None, pt
    while k:
        if k & 1: r = a if r is None else _add(r, a)
        a = _add(a, a)
        k >>= 1
    return r


def _pub(priv):
    x, y = _mul(int.from_bytes(priv, "big"), (GX, GY))
    return bytes([2 | (y & 1)]) + x.to_bytes(32, "big")


def _ckd(k, c, i):
    data = (b"\x00" + k + struct.pack(">L", i)) if i >= 0x80000000 else (_pub(k) + struct.pack(">L", i))
    I = hmac.new(c, data, hashlib.sha512).digest()
    return ((int.from_bytes(I[:32], "big") + int.from_bytes(k, "big")) % N).to_bytes(32, "big"), I[32:]


def bip84_priv(seed64, index=0):
    I = hmac.new(b"Bitcoin seed", seed64, hashlib.sha512).digest()
    k, c = I[:32], I[32:]
    for i in (84 | 0x80000000, 0x80000000, 0x80000000, 0, index):
        k, c = _ckd(k, c, i)
    return k


def hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


if __name__ == "__main__":
    # Synthetic planted first-boot control. No funds. For validation only.
    pad = int(sys.argv[1], 0) if len(sys.argv) > 1 else 3547157718
    pre = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    post = int(sys.argv[3]) if len(sys.argv) > 3 else 22
    r = rng_raw_first_boot(pad, 0, 0, pre, post)
    seed64, mnemonic = entropy_to_seed(bytes.fromhex(r["entropy_hex"]))
    priv = bip84_priv(seed64, 0)
    r["mnemonic"] = mnemonic
    r["priv_hex"] = priv.hex()
    r["h160"] = hash160(_pub(priv)).hex()
    print(json.dumps(r, indent=2))
