package main

/*
#cgo CFLAGS: -I/opt/homebrew/opt/openssl@3/include
#cgo LDFLAGS: -L/opt/homebrew/opt/openssl@3/lib -lcrypto
#include <openssl/sha.h>
#include <string.h>

// PBKDF2-HMAC-SHA512, 2048 rounds, dkLen 64 (single block), with HMAC
// key pads cached across rounds: ~4.5 SHA512 compressions per round
// instead of ~9 with full HMAC re-init.
static void pbkdf2_cached(const char* pw, int pwlen, const char* salt, int saltlen, unsigned char* out) {
    unsigned char kblock[128];
    memset(kblock, 0, sizeof(kblock));
    if (pwlen > 128) {
        SHA512((const unsigned char*)pw, (size_t)pwlen, kblock);
    } else {
        memcpy(kblock, pw, (size_t)pwlen);
    }
    unsigned char ipad[128], opad[128];
    for (int i = 0; i < 128; i++) { ipad[i] = kblock[i] ^ 0x36; opad[i] = kblock[i] ^ 0x5c; }

    SHA512_CTX ictx, octx, tctx;
    SHA512_Init(&ictx); SHA512_Update(&ictx, ipad, 128);
    SHA512_Init(&octx); SHA512_Update(&octx, opad, 128);

    unsigned char u[64];
    unsigned char blk[4] = {0, 0, 0, 1};
    tctx = ictx; SHA512_Update(&tctx, salt, (size_t)saltlen); SHA512_Update(&tctx, blk, 4); SHA512_Final(u, &tctx);
    tctx = octx; SHA512_Update(&tctx, u, 64); SHA512_Final(u, &tctx);
    memcpy(out, u, 64);
    for (int i = 1; i < 2048; i++) {
        tctx = ictx; SHA512_Update(&tctx, u, 64); SHA512_Final(u, &tctx);
        tctx = octx; SHA512_Update(&tctx, u, 64); SHA512_Final(u, &tctx);
        for (int j = 0; j < 64; j++) out[j] ^= u[j];
    }
}
*/
import "C"
import "unsafe"

// pbkdf2_2048 uses OpenSSL SHA512 (hardware instructions on arm64) with
// cached HMAC pads.
func pbkdf2_2048(password, salt []byte) []byte {
	out := make([]byte, 64)
	C.pbkdf2_cached(
		(*C.char)(unsafe.Pointer(&password[0])), C.int(len(password)),
		(*C.char)(unsafe.Pointer(&salt[0])), C.int(len(salt)),
		(*C.uchar)(unsafe.Pointer(&out[0])))
	return out
}