// SHA-512 + HMAC + PBKDF2 for Metal. Self-contained, no deps.
#ifndef SHA512_H
#define SHA512_H

struct Sha512 {
    ulong h[8];
    uchar buf[128];
    unsigned buflen;
    ulong total;
};

constant ulong K512[80] = {
    0x428a2f98d728ae22UL,0x7137449123ef65cdUL,0xb5c0fbcfec4d3b2fUL,0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL,0x59f111f1b605d019UL,0x923f82a4af194f9bUL,0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL,0x12835b0145706fbeUL,0x243185be4ee4b28cUL,0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL,0x80deb1fe3b1696b1UL,0x9bdc06a725c71235UL,0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL,0xefbe4786384f25e3UL,0x0fc19dc68b8cd5b5UL,0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL,0x4a7484aa6ea6e483UL,0x5cb0a9dcbd41fbd4UL,0x76f988da831153b5UL,
    0x983e5152ee66dfabUL,0xa831c66d2db43210UL,0xb00327c898fb213fUL,0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL,0xd5a79147930aa725UL,0x06ca6351e003826fUL,0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL,0x2e1b21385c26c926UL,0x4d2c6dfc5ac42aedUL,0x53380d139d95b3dfUL,
    0x650a73548baf63deUL,0x766a0abb3c77b2a8UL,0x81c2c92e47edaee6UL,0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL,0xa81a664bbc423001UL,0xc24b8b70d0f89791UL,0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL,0xd69906245565a910UL,0xf40e35855771202aUL,0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL,0x1e376c085141ab53UL,0x2748774cdf8eeb99UL,0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL,0x4ed8aa4ae3418acbUL,0x5b9cca4f7763e373UL,0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL,0x78a5636f43172f60UL,0x84c87814a1f0ab72UL,0x8cc702081a6439ecUL,
    0x90befffa23631e28UL,0xa4506cebde82bde9UL,0xbef9a3f7b2c67915UL,0xc67178f2e372532bUL,
    0xca273eceea26619cUL,0xd186b8c721c0c207UL,0xeada7dd6cde0eb1eUL,0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL,0x0a637dc5a2c898a6UL,0x113f9804bef90daeUL,0x1b710b35131c471bUL,
    0x28db77f523047d84UL,0x32caab7b40c72493UL,0x3c9ebe0a15c9bebcUL,0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL,0x597f299cfc657e2aUL,0x5fcb6fab3ad6faecUL,0x6c44198c4a475817UL
};

inline ulong ror64(ulong x, unsigned n) { return (x >> n) | (x << (64 - n)); }

inline void sha512Block(thread Sha512& s, thread const uchar* p) {
    ulong w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = (ulong(p[i*8]) << 56) | (ulong(p[i*8+1]) << 48) | (ulong(p[i*8+2]) << 40) |
               (ulong(p[i*8+3]) << 32) | (ulong(p[i*8+4]) << 24) | (ulong(p[i*8+5]) << 16) |
               (ulong(p[i*8+6]) << 8) | ulong(p[i*8+7]);
    }
    for (int i = 16; i < 80; i++) {
        ulong x = w[i-15], y = w[i-2];
        ulong s0 = ror64(x,1) ^ ror64(x,8) ^ (x >> 7);
        ulong s1 = ror64(y,19) ^ ror64(y,61) ^ (y >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    ulong a=s.h[0],b=s.h[1],c=s.h[2],d=s.h[3],e=s.h[4],f=s.h[5],g=s.h[6],hh=s.h[7];
    for (int i = 0; i < 80; i++) {
        ulong S1 = ror64(e,14) ^ ror64(e,18) ^ ror64(e,41);
        ulong ch = (e & f) ^ (~e & g);
        ulong t1 = hh + S1 + ch + K512[i] + w[i];
        ulong S0 = ror64(a,28) ^ ror64(a,34) ^ ror64(a,39);
        ulong mj = (a & b) ^ (a & c) ^ (b & c);
        ulong t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s.h[0]+=a; s.h[1]+=b; s.h[2]+=c; s.h[3]+=d; s.h[4]+=e; s.h[5]+=f; s.h[6]+=g; s.h[7]+=hh;
}


inline void sha512Init(thread Sha512& s) {
    s.h[0]=0x6a09e667f3bcc908UL; s.h[1]=0xbb67ae8584caa73bUL;
    s.h[2]=0x3c6ef372fe94f82bUL; s.h[3]=0xa54ff53a5f1d36f1UL;
    s.h[4]=0x510e527fade682d1UL; s.h[5]=0x9b05688c2b3e6c1fUL;
    s.h[6]=0x1f83d9abfb41bd6bUL; s.h[7]=0x5be0cd19137e2179UL;
    s.buflen = 0; s.total = 0;
}

inline void sha512Update(thread Sha512& s, thread const uchar* data, unsigned len) {
    s.total += len;
    while (len > 0) {
        unsigned room = 128 - s.buflen;
        unsigned take = room < len ? room : len;
        for (unsigned i = 0; i < take; i++) s.buf[s.buflen + i] = data[i];
        s.buflen += take; data += take; len -= take;
        if (s.buflen == 128) { sha512Block(s, s.buf); s.buflen = 0; }
    }
}

inline void sha512Final(thread Sha512& s, thread uchar out[64]) {
    ulong bits = s.total << 3;
    s.buf[s.buflen++] = 0x80;
    if (s.buflen > 112) {
        while (s.buflen < 128) s.buf[s.buflen++] = 0;
        sha512Block(s, s.buf);
        s.buflen = 0;
    }
    while (s.buflen < 112) s.buf[s.buflen++] = 0;
    for (int i = 0; i < 8; i++) s.buf[112 + i] = 0;
    for (int i = 0; i < 8; i++) s.buf[120 + i] = uchar(bits >> (56 - 8*i));
    sha512Block(s, s.buf);
    for (int i = 0; i < 8; i++) {
        out[i*8]   = uchar(s.h[i] >> 56); out[i*8+1] = uchar(s.h[i] >> 48);
        out[i*8+2] = uchar(s.h[i] >> 40); out[i*8+3] = uchar(s.h[i] >> 32);
        out[i*8+4] = uchar(s.h[i] >> 24); out[i*8+5] = uchar(s.h[i] >> 16);
        out[i*8+6] = uchar(s.h[i] >> 8);  out[i*8+7] = uchar(s.h[i]);
    }
}

inline void sha512once(thread const uchar* data, unsigned len, thread uchar out[64]) {
    Sha512 s; sha512Init(s); sha512Update(s, data, len); sha512Final(s, out);
}

inline void hmacSha512(thread const uchar* key, unsigned klen,
                       thread const uchar* msg, unsigned mlen,
                       thread uchar out[64]) {
    uchar kblock[128];
    for (int i = 0; i < 128; i++) kblock[i] = 0;
    if (klen > 128) {
        uchar kh[64]; sha512once(key, klen, kh);
        for (int i = 0; i < 64; i++) kblock[i] = kh[i];
    } else {
        for (unsigned i = 0; i < klen; i++) kblock[i] = key[i];
    }
    uchar pad[128];
    for (int i = 0; i < 128; i++) pad[i] = kblock[i] ^ 0x36;
    Sha512 s; sha512Init(s); sha512Update(s, pad, 128);
    sha512Update(s, msg, mlen);
    uchar ih[64]; sha512Final(s, ih);
    for (int i = 0; i < 128; i++) pad[i] = kblock[i] ^ 0x5c;
    sha512Init(s); sha512Update(s, pad, 128); sha512Update(s, ih, 64);
    sha512Final(s, out);
}

// PBKDF2-HMAC-SHA512, dkLen=64 (single block), salt = "mnemonic".
inline void pbkdf2Bip39(thread const uchar* pw, unsigned pwlen, thread uchar out[64]) {
    uchar saltblk[12] = {'m','n','e','m','o','n','i','c',0,0,0,1};
    uchar u[64];
    hmacSha512(pw, pwlen, saltblk, 12, u);
    uchar t[64];
    for (int i = 0; i < 64; i++) t[i] = u[i];
    for (int it = 1; it < 2048; it++) {
        uchar nu[64];
        hmacSha512(pw, pwlen, u, 64, nu);
        for (int i = 0; i < 64; i++) t[i] ^= nu[i];
        for (int i = 0; i < 64; i++) u[i] = nu[i];
    }
    for (int i = 0; i < 64; i++) out[i] = t[i];
}

#endif
