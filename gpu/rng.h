// Exact replica of the vulnerable Coldcard RNG chain (vuln_rng.py).
#ifndef RNG_H
#define RNG_H

struct Mixer { unsigned pad, n, d, dat; };
inline Mixer newMixer() { return {0x0A8CE26Fu, 69u, 233u, 0u}; }
inline unsigned mixNext(thread Mixer& m) {
    m.pad = m.pad + m.dat + m.d * m.n;
    m.pad = (m.pad << 3) | (m.pad >> 29);
    m.n = m.pad | 2u;
    m.d = m.d ^ ((m.pad << 31) + (m.pad >> 1));
    m.dat = (m.dat ^ (m.pad & 0xFFu) ^ (m.d >> 8) ^ 1u) & 0xFFu;
    return m.pad ^ (m.d << 5) ^ (m.pad >> 18) ^ (m.dat << 1);
}

struct Chip { unsigned pad, n, d, dat; };
inline Chip newChip(unsigned pad32) { return {pad32, 69u, 233u, 0u}; }
inline unsigned chipNext(thread Chip& c) {
    c.pad = c.pad + c.dat + c.d * c.n;
    c.pad = (c.pad << 3) | (c.pad >> 29);
    c.n = c.pad | 2u;
    c.d = c.d ^ ((c.pad << 31) + (c.pad >> 1));
    c.dat = (c.dat ^ (c.pad & 0xFFu) ^ (c.d >> 8) ^ 1u) & 0xFFu;
    return c.pad ^ (c.d << 5) ^ (c.pad >> 18) ^ (c.dat << 1);
}

// raw[0..7] = chip^mixer words (little-endian on host). Hypothesis model:
// chip state n=rtcTR, d=rtcSSR (ccscan seedEntropy). skip = prior chip draws.
// Returns false if the on-device fatal (chip==last) would trigger.
inline bool rngRawHP(unsigned pad32, unsigned rtcTR, unsigned rtcSSR,
                     int skip, thread unsigned raw[8]) {
    Chip c = {pad32, rtcTR, rtcSSR, 0u};
    for (int i = 0; i < skip; i++) chipNext(c);
    Mixer m = newMixer();
    unsigned last = 0;
    for (int i = 0; i < 8; i++) {
        unsigned cv = chipNext(c);
        if (i > 0 && cv == last) return false;
        last = cv;
        raw[i] = cv ^ mixNext(m);
    }
    return true;
}

// Universal model (rtc TR=69, SSR=233 frozen).
inline bool rngRaw(unsigned pad32, int skip, thread unsigned raw[8]) {
    return rngRawHP(pad32, 69u, 233u, skip, raw);
}
#endif
