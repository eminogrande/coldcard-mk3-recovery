// mscan - Metal host driver for scanKernel (Coldcard Mk3 weak-seed GPU sweep).
// Compiles kernel.metal + headers from source at runtime (no stale metallib).
// Usage: mscan -t targets.txt -w bip39_english.txt [-r rtcTR] [-s rtcSSR]
//          [-k skipMax] [-i idxMax] [-p padStart] [-b batchThreads] [-o hits.json]
#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

struct Params { uint64_t padStart; uint32_t skipMax, idxMax, targetCount, rtcTR, rtcSSR; };
struct Hit { uint32_t pad, skip, idx; uint8_t priv[32]; uint8_t h160[20]; };

static const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static int bech32Prog(const char *addr, uint8_t out[20]) {
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

static int cmp20(const void *a, const void *b) { return memcmp(a, b, 20); }

static char *readFile(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); exit(1); }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc(sz + 1);
    fread(buf, 1, sz, f); buf[sz] = 0; fclose(f);
    return buf;
}

// strip #include "..." lines (we concatenate headers manually)
static void appendStripped(NSMutableString *dst, const char *text) {
    char *copy = strdup(text);
    for (char *line = strtok(copy, "\n"); line; line = strtok(NULL, "\n")) {
        if (strstr(line, "#include \"")) continue;
        [dst appendFormat:@"%s\n", line];
    }
    free(copy);
}


int main(int argc, char **argv) {
    const char *targetsF = NULL, *wordsF = "bip39_english.txt", *outF = "hits_gpu.json";
    uint32_t rtcTR = 0, rtcSSR = 0, skipMax = 8, idxMax = 16;
    uint64_t padStart = 0, batchThreads = 1u << 22;
    int opt;
    while ((opt = getopt(argc, argv, "t:w:r:s:k:i:p:b:o:")) != -1) {
        switch (opt) {
        case 't': targetsF = optarg; break;
        case 'w': wordsF = optarg; break;
        case 'r': rtcTR = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 's': rtcSSR = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'k': skipMax = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'i': idxMax = (uint32_t)strtoul(optarg, NULL, 0); break;
        case 'p': padStart = strtoull(optarg, NULL, 0); break;
        case 'b': batchThreads = strtoull(optarg, NULL, 0); break;
        case 'o': outF = optarg; break;
        }
    }
    if (!targetsF) { fprintf(stderr, "-t targets.txt required\n"); return 2; }

    char *ttext = readFile(targetsF);
    uint8_t *progs = (uint8_t *)malloc(20 * 65536);
    uint32_t tcount = 0;
    for (char *line = strtok(ttext, "\n"); line; line = strtok(NULL, "\n")) {
        if (strlen(line) < 10) continue;
        if (bech32Prog(line, progs + 20 * tcount) != 0) { fprintf(stderr, "bad address: %s\n", line); return 2; }
        tcount++;
    }
    qsort(progs, tcount, 20, cmp20);
    fprintf(stderr, "[mscan] %u targets loaded\n", tcount);

    char *wtext = readFile(wordsF);
    uint8_t *words8 = (uint8_t *)calloc(2048, 8);
    uint32_t wcount = 0;
    for (char *w = strtok(wtext, "\n"); w && wcount < 2048; w = strtok(NULL, "\n")) {
        size_t l = strlen(w);
        if (l > 8) { fprintf(stderr, "word too long: %s\n", w); return 2; }
        memcpy(words8 + 8 * wcount, w, l);
        wcount++;
    }
    if (wcount != 2048) { fprintf(stderr, "wordlist %u != 2048\n", wcount); return 2; }

    NSMutableString *src = [NSMutableString new];
    appendStripped(src, readFile("../rng.h"));
    appendStripped(src, readFile("sha512.h"));
    appendStripped(src, readFile("hash160.h"));
    appendStripped(src, readFile("secp256k1.h"));
    appendStripped(src, readFile("kernel.metal"));

    @autoreleasepool {
        id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
        if (!dev) { fprintf(stderr, "no Metal device\n"); return 1; }
        fprintf(stderr, "[mscan] device: %s\n", [[dev name] UTF8String]);
        NSError *err = nil;
        id<MTLLibrary> lib = [dev newLibraryWithSource:src options:nil error:&err];
        if (!lib) { fprintf(stderr, "metal compile: %s\n", [[err localizedDescription] UTF8String]); return 1; }
        id<MTLFunction> fn = [lib newFunctionWithName:@"scanKernel"];
        id<MTLComputePipelineState> pipe = [dev newComputePipelineStateWithFunction:fn error:&err];
        if (!pipe) { fprintf(stderr, "pipeline: %s\n", [[err localizedDescription] UTF8String]); return 1; }
        id<MTLCommandQueue> queue = [dev newCommandQueue];

        id<MTLBuffer> tBuf = [dev newBufferWithBytes:progs length:20 * tcount options:MTLResourceStorageModeShared];
        id<MTLBuffer> wBuf = [dev newBufferWithBytes:words8 length:2048 * 8 options:MTLResourceStorageModeShared];
        id<MTLBuffer> hBuf = [dev newBufferWithLength:1024 * sizeof(struct Hit) options:MTLResourceStorageModeShared];
        id<MTLBuffer> cBuf = [dev newBufferWithLength:4 options:MTLResourceStorageModeShared];
        id<MTLBuffer> gBuf = [dev newBufferWithLength:256 * 96 options:MTLResourceStorageModeShared];

        // one-time G doublings table (single-thread setup kernel)
        id<MTLFunction> sfn = [lib newFunctionWithName:@"setupG"];
        id<MTLComputePipelineState> spipe = [dev newComputePipelineStateWithFunction:sfn error:&err];
        if (!spipe) { fprintf(stderr, "setup pipeline: %s\n", [[err localizedDescription] UTF8String]); return 1; }
        @autoreleasepool {
            id<MTLCommandBuffer> cb = [queue commandBuffer];
            id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
            [enc setComputePipelineState:spipe];
            [enc setBuffer:gBuf offset:0 atIndex:0];
            [enc dispatchThreads:MTLSizeMake(1, 1, 1) threadsPerThreadgroup:MTLSizeMake(1, 1, 1)];
            [enc endEncoding];
            [cb commit];
            [cb waitUntilCompleted];
        }
        fprintf(stderr, "[mscan] G table ready\n");


        uint64_t batchPads = batchThreads / skipMax;
        if (!batchPads) batchPads = 1;
        fprintf(stderr, "[mscan] rtc=%u/%u skipMax=%u idxMax=%u batch=%llu pads (%llu threads)\n",
                rtcTR, rtcSSR, skipMax, idxMax, batchPads, batchPads * skipMax);

        struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
        double elapsed0 = 0;
        uint64_t done = 0;
        for (uint64_t base = padStart; base < (1ULL << 32); base += batchPads) {
            struct Params P = { base, skipMax, idxMax, tcount, rtcTR, rtcSSR };
            *(uint32_t *)[cBuf contents] = 0;
            @autoreleasepool {
                id<MTLCommandBuffer> cb = [queue commandBuffer];
                id<MTLComputeCommandEncoder> enc = [cb computeCommandEncoder];
                [enc setComputePipelineState:pipe];
                [enc setBuffer:tBuf offset:0 atIndex:0];
                [enc setBuffer:wBuf offset:0 atIndex:1];
                [enc setBuffer:hBuf offset:0 atIndex:2];
                [enc setBuffer:cBuf offset:0 atIndex:3];
                [enc setBytes:&P length:sizeof(P) atIndex:4];
                [enc setBuffer:gBuf offset:0 atIndex:5];
                NSUInteger w = [pipe maxTotalThreadsPerThreadgroup];
                if (w > 256) w = 256;
                [enc dispatchThreads:MTLSizeMake(batchPads * skipMax, 1, 1)
                threadsPerThreadgroup:MTLSizeMake(w, 1, 1)];
                [enc endEncoding];
                [cb commit];
                [cb waitUntilCompleted];
            }
            uint32_t hits = *(uint32_t *)[cBuf contents];
            struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
            double dt = (t1.tv_sec - t0.tv_sec) + 1e-9 * (t1.tv_nsec - t0.tv_nsec);
            double batchDt = dt - elapsed0; elapsed0 = dt;
            done += batchPads;
            double rate = done / dt;
            double remain = ((double)(1ULL << 32) - padStart) - done;
            fprintf(stderr, "[mscan] pad~%llu  %.2f Mpads/s  batch %.1fs  eta %.1fh\n",
                    base + batchPads, rate / 1e6, batchDt, remain / rate / 3600);
            if (hits) {
                uint32_t n = hits < 1024 ? hits : 1024;
                struct Hit *H = (struct Hit *)[hBuf contents];
                FILE *o = fopen(outF, "w");
                fprintf(o, "[\n");
                for (uint32_t i = 0; i < n; i++) {
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
                fprintf(stderr, "[mscan] %u hit(s) -> %s\n", hits, outF);
                return 0;
            }
        }
    }
    fprintf(stderr, "[mscan] exhausted 2^32 x %u skip, no hit\n", skipMax);
    return 1;
}
