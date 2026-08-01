// secp256k1 for Metal: field mod p (8x32 limbs), Jacobian points, mul by G.
// Correct over fast: plain double-and-add. Optimize later if profiling says so.
#ifndef SECP256K1_H
#define SECP256K1_H

// p = 2^256 - 2^32 - 977
// n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

struct Fe { uint l[8]; };        // little-endian limbs, kept < ~2^256 (lazy)
struct Pt { Fe x, y, z; };       // Jacobian; inf iff z == 0

constant uint SECP_P[8]  = {0xFFFFFC2Fu,0xFFFFFFFEu,0xFFFFFFFFu,0xFFFFFFFFu,
                            0xFFFFFFFFu,0xFFFFFFFFu,0xFFFFFFFFu,0xFFFFFFFFu};
constant uint SECP_N[8]  = {0xD0364141u,0xBFD25E8Cu,0xAF48A03Bu,0xBAAEDCE6u,
                            0xFFFFFFFEu,0xFFFFFFFFu,0xFFFFFFFFu,0xFFFFFFFFu};
// G in affine
constant uint SECP_GX[8] = {0x16F81798u,0x59F2815Bu,0x2DCE28D9u,0x029BFCDBu,
                            0xCE870B07u,0x55A06295u,0xF9DCBBACu,0x79BE667Eu};
constant uint SECP_GY[8] = {0xFB10D4B8u,0x9C47D08Fu,0xA6855419u,0xFD17B448u,
                            0x0E1108A8u,0x5DA4FBFCu,0x26A3C465u,0x483ADA77u};

inline bool feIsZero(thread const Fe& a) {
    uint v = 0; for (int i = 0; i < 8; i++) v |= a.l[i];
    return v == 0;
}

// full reduce: bring a (<2^264ish) into [0,p). a must fit in 9 limbs conceptually.
inline void feNormalize(thread Fe& a) {
    // fold top: while carry out of limb7, add carry*(2^32+977)
    ulong c = a.l[7] >> 0; // no-op; normalization strategy: subtract p while >= p, plus carry fold
    (void)c;
    // first: propagate any 32-bit overflows assumed already done by callers.
    // subtract p up to twice (covers a < 3p)
    for (int rep = 0; rep < 3; rep++) {
        // if a >= p then a -= p
        bool ge = true;
        for (int i = 7; i >= 0; i--) {
            if (a.l[i] > SECP_P[i]) break;
            if (a.l[i] < SECP_P[i]) { ge = false; break; }
        }
        if (!ge) break;
        ulong borrow = 0;
        for (int i = 0; i < 8; i++) {
            ulong d = ulong(a.l[i]) - SECP_P[i] - borrow;
            a.l[i] = uint(d & 0xFFFFFFFFu);
            borrow = (d >> 63) & 1;
        }
    }
}

inline void feAdd(thread Fe& r, thread const Fe& a, thread const Fe& b) {
    ulong acc = 0;
    for (int i = 0; i < 8; i++) {
        acc += ulong(a.l[i]) + b.l[i];
        r.l[i] = uint(acc & 0xFFFFFFFFu);
        acc >>= 32;
    }
    // fold carry (0 or 1): 2^256 = 2^32 + 977 = 0x1000003D1 (mod p)
    if (acc) {
        ulong t = ulong(r.l[0]) + 0x1000003D1u;
        r.l[0] = uint(t & 0xFFFFFFFFu);
        ulong carry = t >> 32;
        for (int i = 1; i < 8 && carry; i++) {
            t = ulong(r.l[i]) + carry;
            r.l[i] = uint(t & 0xFFFFFFFFu);
            carry = t >> 32;
        }
    }
    feNormalize(r);
}

inline void feSub(thread Fe& r, thread const Fe& a, thread const Fe& b) {
    ulong borrow = 0;
    for (int i = 0; i < 8; i++) {
        ulong d = ulong(a.l[i]) - b.l[i] - borrow;
        r.l[i] = uint(d & 0xFFFFFFFFu);
        borrow = (d >> 63) & 1;
    }
    if (borrow) {
        // add p back
        ulong acc = 0;
        for (int i = 0; i < 8; i++) {
            acc += ulong(r.l[i]) + SECP_P[i];
            r.l[i] = uint(acc & 0xFFFFFFFFu);
            acc >>= 32;
        }
    }
    feNormalize(r);
}

// propagate carry into limbs from index k; v < 2^64
inline void limbAdd(thread uint r[16], int k, ulong v) {
    while (v && k < 16) {
        ulong t = ulong(r[k]) + (v & 0xFFFFFFFFu);
        r[k] = uint(t & 0xFFFFFFFFu);
        v = (v >> 32) + (t >> 32);
        k++;
    }
}

inline void feMul(thread Fe& r, thread const Fe& a, thread const Fe& b) {
    uint t[16];
    for (int i = 0; i < 16; i++) t[i] = 0;
    for (int i = 0; i < 8; i++) {
        ulong carry = 0;
        for (int j = 0; j < 8; j++) {
            ulong prod = ulong(a.l[i]) * ulong(b.l[j]) + ulong(t[i+j]) + carry;
            t[i+j] = uint(prod & 0xFFFFFFFFu);
            carry = prod >> 32;
        }
        limbAdd(t, i+8, carry);
    }
    // fold high limbs: 2^256 = 2^32 + 977 (mod p). Two passes for stray carries.
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 15; i >= 8; i--) {
            uint c = t[i];
            if (!c) continue;
            t[i] = 0;
            limbAdd(t, i-8, ulong(c) * 977u);
            limbAdd(t, i-7, ulong(c));
        }
    }
    for (int i = 0; i < 8; i++) r.l[i] = t[i];
    feNormalize(r);
}

inline void feSqr(thread Fe& r, thread const Fe& a) { feMul(r, a, a); }

inline void feMulSmall(thread Fe& r, thread const Fe& a, uint m) {
    ulong acc = 0;
    for (int i = 0; i < 8; i++) {
        acc += ulong(a.l[i]) * ulong(m);
        r.l[i] = uint(acc & 0xFFFFFFFFu);
        acc >>= 32;
    }
    // acc < m <= small: fold
    while (acc) {
        ulong v = (acc & 0xFFFFFFFFu);
        ulong t = ulong(r.l[0]) + v * 977u;
        r.l[0] = uint(t & 0xFFFFFFFFu);
        ulong carry = t >> 32;
        t = ulong(r.l[1]) + v + carry;
        r.l[1] = uint(t & 0xFFFFFFFFu);
        carry = t >> 32;
        int i = 2;
        while (carry && i < 8) {
            t = ulong(r.l[i]) + carry;
            r.l[i] = uint(t & 0xFFFFFFFFu);
            carry = t >> 32;
            i++;
        }
        acc >>= 32;
    }
    feNormalize(r);
}

// p - 2 for Fermat inversion
constant uint SECP_PM2[8] = {0xFFFFFC2Du,0xFFFFFFFEu,0xFFFFFFFFu,0xFFFFFFFFu,
                             0xFFFFFFFFu,0xFFFFFFFFu,0xFFFFFFFFu,0xFFFFFFFFu};

inline void feInv(thread Fe& r, thread const Fe& a) {
    Fe result;
    for (int i = 0; i < 8; i++) result.l[i] = 0;
    result.l[0] = 1;
    Fe base = a;
    for (int i = 0; i < 8; i++) {
        for (int b = 0; b < 32; b++) {
            if ((SECP_PM2[i] >> b) & 1u) feMul(result, result, base);
            Fe nb; feSqr(nb, base); base = nb;
        }
    }
    r = result;
}

inline void feFromBytesBE(thread Fe& r, thread const uchar* in) {
    for (int i = 0; i < 8; i++) {
        int o = 28 - i*4;
        r.l[i] = (uint(in[o])<<24)|(uint(in[o+1])<<16)|(uint(in[o+2])<<8)|uint(in[o+3]);
    }
}

inline bool ptIsInf(thread const Pt& p) { return feIsZero(p.z); }

inline void ptSetInf(thread Pt& p) {
    for (int i = 0; i < 8; i++) { p.x.l[i]=0; p.y.l[i]=0; p.z.l[i]=0; }
}

inline void ptDbl(thread Pt& p) {
    if (ptIsInf(p)) return;
    Fe a, b, c, d, e, f, t;
    feSqr(a, p.x);              // A = X^2
    feSqr(b, p.y);              // B = Y^2
    feSqr(c, b);                // C = B^2
    feAdd(t, p.x, b);           // (X+B)
    feSqr(t, t);                // (X+B)^2
    feSub(t, t, a);
    feSub(t, t, c);
    feAdd(d, t, t);             // D = 2*((X+B)^2-A-C)
    feMulSmall(e, a, 3);        // E = 3A
    feSqr(f, e);                // F = E^2
    feAdd(t, d, d);             // 2D
    Fe nx; feSub(nx, f, t);     // X' = F - 2D
    feSub(t, d, nx);            // D - X'
    feMul(t, e, t);             // E*(D-X')
    Fe c8; feMulSmall(c8, c, 8);
    Fe ny; feSub(ny, t, c8);    // Y' = E*(D-X') - 8C
    Fe nz; feMul(nz, p.y, p.z);
    feAdd(nz, nz, nz);          // Z' = 2YZ
    p.x = nx; p.y = ny; p.z = nz;
}

// full Jacobian + Jacobian
inline void ptAdd(thread Pt& p, thread const Pt& q) {
    if (ptIsInf(q)) return;
    if (ptIsInf(p)) { p = q; return; }
    Fe z1z1, z2z2, u1, u2, s1, s2, h, r, t;
    feSqr(z1z1, p.z);
    feSqr(z2z2, q.z);
    feMul(u1, p.x, z2z2);
    feMul(u2, q.x, z1z1);
    feMul(t, q.z, z2z2); feMul(s1, p.y, t);
    feMul(t, p.z, z1z1); feMul(s2, q.y, t);
    feSub(h, u2, u1);
    feSub(r, s2, s1);
    if (feIsZero(h)) {
        if (feIsZero(r)) { ptDbl(p); return; }
        ptSetInf(p); return;
    }
    Fe hh, hhh, v;
    feSqr(hh, h);
    feMul(hhh, h, hh);
    feMul(v, u1, hh);
    Fe nx, ny, nz;
    feSqr(nx, r);
    feSub(nx, nx, hhh);
    feSub(nx, nx, v);
    feSub(nx, nx, v);
    feSub(t, v, nx);
    feMul(t, r, t);
    Fe u1hhh; feMul(u1hhh, s1, hhh);
    feSub(ny, t, u1hhh);
    feMul(nz, p.z, q.z);
    feMul(nz, nz, h);
    p.x = nx; p.y = ny; p.z = nz;
}

inline Pt gPoint() {
    Pt g;
    for (int i = 0; i < 8; i++) { g.x.l[i]=SECP_GX[i]; g.y.l[i]=SECP_GY[i]; g.z.l[i]=0; }
    g.z.l[0] = 1;
    return g;
}

// mixed add: p (Jacobian) += q (affine). ~8 feMul, no ptDbl needed per bit.
inline void ptAddMixed(thread Pt& p, device const Pt& qd) {
    Pt q = qd;
    if (ptIsInf(q)) return;
    if (ptIsInf(p)) { p = q; p.z.l[0] = 1; return; }
    Fe z1z1, u2, s2, h, r, t;
    feSqr(z1z1, p.z);
    feMul(u2, q.x, z1z1);
    feMul(t, p.z, z1z1);
    feMul(s2, q.y, t);
    feSub(h, u2, p.x);
    feSub(r, s2, p.y);
    if (feIsZero(h)) {
        if (feIsZero(r)) { ptDbl(p); return; }
        ptSetInf(p); return;
    }
    Fe hh, hhh, v;
    feSqr(hh, h);
    feMul(hhh, h, hh);
    feMul(v, p.x, hh);
    Fe nx, ny, nz;
    feSqr(nx, r);
    feSub(nx, nx, hhh);
    feSub(nx, nx, v);
    feSub(nx, nx, v);
    feSub(t, v, nx);
    feMul(t, r, t);
    Fe pyhhh; feMul(pyhhh, p.y, hhh);
    feSub(ny, t, pyhhh);
    feMul(nz, p.z, h);
    p.x = nx; p.y = ny; p.z = nz;
}

// k*G via precomputed doublings table: table[j] = 2^j * G (affine).
// ~128 mixed adds avg instead of 256 x (ptAdd + ptDbl).
inline void mulGTable(thread Pt& r, thread const uchar k[32],
                      device const Pt* table) {
    ptSetInf(r);
    for (int byte = 31; byte >= 0; byte--) {
        for (int bit = 0; bit < 8; bit++) {
            if ((k[byte] >> bit) & 1) {
                int j = 8 * (31 - byte) + bit;
                ptAddMixed(r, table[j]);
            }
        }
    }
}

// k*G, k = 32 bytes big-endian. Plain double-and-add.
inline void mulG(thread Pt& r, thread const uchar k[32]) {
    ptSetInf(r);
    Pt b = gPoint();
    for (int byte = 31; byte >= 0; byte--) {
        for (int bit = 0; bit < 8; bit++) {
            if ((k[byte] >> bit) & 1) ptAdd(r, b);
            ptDbl(b);
        }
    }
}

inline void feToBytesBE(thread Fe& a, thread uchar* out) {
    feNormalize(a);
    for (int i = 0; i < 8; i++) {
        int o = 28 - i*4;
        out[o]   = uchar(a.l[i] >> 24); out[o+1] = uchar(a.l[i] >> 16);
        out[o+2] = uchar(a.l[i] >> 8);  out[o+3] = uchar(a.l[i]);
    }
}

// serialize compressed: 33 bytes
inline void ptSerialize(thread Pt& p, thread uchar out[33]) {
    Fe zinv, z2, ax, ay;
    feInv(zinv, p.z);
    feSqr(z2, zinv);
    feMul(ax, p.x, z2);
    feMul(ay, p.y, z2);
    feMul(ay, ay, zinv);
    feToBytesBE(ax, out + 1);
    feNormalize(ay);
    out[0] = (ay.l[0] & 1u) ? 0x03 : 0x02;
}

#endif // SECP256K1_H

