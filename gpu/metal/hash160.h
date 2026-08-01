// SHA-256 + RIPEMD-160 for Metal (for hash160). Self-contained.
#ifndef HASH160_H
#define HASH160_H

constant uint K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

inline uint ror32(uint x, unsigned n) { return (x >> n) | (x << (32 - n)); }

// Single-block-friendly SHA256 for arbitrary small messages (<= 119 bytes here).
inline void sha256once(thread const uchar* data, unsigned len, thread uchar out[32]) {
    uint h[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    uchar block[128];
    for (int i = 0; i < 128; i++) block[i] = 0;
    for (unsigned i = 0; i < len; i++) block[i] = data[i];
    block[len] = 0x80;
    unsigned nblocks = (len >= 56) ? 2 : 1;
    ulong bits = ulong(len) << 3;
    for (int i = 0; i < 8; i++) block[nblocks*64 - 8 + i] = uchar(bits >> (56 - 8*i));
    for (unsigned b = 0; b < nblocks; b++) {
        thread uchar* p = block + b*64;
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


// RIPEMD-160, single message block path (our input is always 32 bytes).
constant uint RL[80] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
    1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
    4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
};
constant uint RR[80] = {
    5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
    6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
    8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
    12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
};
constant uint SL[80] = {
    11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
    7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
    11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
    9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
};
constant uint SR[80] = {
    8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
    9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
    15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
    8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
};

inline uint ripemdF(int j, uint x, uint y, uint z) {
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
}

inline void ripemd160_32(thread const uchar in[32], thread uchar out[20]) {
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

inline void hash160(thread const uchar* data, unsigned len, thread uchar out[20]) {
    uchar sh[32];
    sha256once(data, len, sh);
    ripemd160_32(sh, out);
}

#endif
