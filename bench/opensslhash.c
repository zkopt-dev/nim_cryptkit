#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// OpenSSL Low-level 해시 헤더들
#include <openssl/md2.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/whrlpool.h>

// OpenSSL 버전에 따라 SM3 로우레벨 헤더가 없을 수 있으므로 로컬 선언 또는 포함
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
#include <openssl/sm3.h>
#endif

#define BENCHMARK(name, code_block) do { \
    struct timespec start, end; \
    clock_gettime(CLOCK_MONOTONIC, &start); \
    { code_block } \
    clock_gettime(CLOCK_MONOTONIC, &end); \
    long long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec); \
    double elapsed_us = (double)elapsed_ns / 1000.0; \
    printf("%s took: %.2f μs (%lld ns)\n", name, elapsed_us, elapsed_ns); \
} while(0)

#define ITERATIONS 1000000

// 해시 체이닝을 위한 공용 버퍼 (가장 큰 WHIRLPOOL_DIGEST_LENGTH = 64바이트 기준)
unsigned char hash_buf[64] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};

int main() {
    printf("=== OpenSSL Low-Level Raw Hash Chaining Benchmark (1,000,000 iter) ===\n\n");

    // ==========================================
    // MD2 (Digest: 16 bytes)
    // ==========================================
#ifndef OPENSSL_NO_MD2
    {
        MD2_CTX ctx;
        BENCHMARK("MD2 Chaining", {
            for (int i = 0; i < ITERATIONS; i++) {
                MD2_Init(&ctx);
                MD2_Update(&ctx, hash_buf, MD2_DIGEST_LENGTH);
                MD2_Final(hash_buf, &ctx); // 결과를 다시 hash_buf에 써서 체이닝
            }
        });
    }
#endif

    // ==========================================
    // MD4 (Digest: 16 bytes)
    // ==========================================
    {
        MD4_CTX ctx;
        BENCHMARK("MD4 Chaining", {
            for (int i = 0; i < ITERATIONS; i++) {
                MD4_Init(&ctx);
                MD4_Update(&ctx, hash_buf, MD4_DIGEST_LENGTH);
                MD4_Final(hash_buf, &ctx);
            }
        });
    }

    // ==========================================
    // MD5 (Digest: 16 bytes)
    // ==========================================
    {
        MD5_CTX ctx;
        BENCHMARK("MD5 Chaining", {
            for (int i = 0; i < ITERATIONS; i++) {
                MD5_Init(&ctx);
                MD5_Update(&ctx, hash_buf, MD5_DIGEST_LENGTH);
                MD5_Final(hash_buf, &ctx);
            }
        });
    }

    // ==========================================
    // RIPEMD-160 (Digest: 20 bytes)
    // ==========================================
    {
        RIPEMD160_CTX ctx;
        BENCHMARK("RIPEMD-160 Chaining", {
            for (int i = 0; i < ITERATIONS; i++) {
                RIPEMD160_Init(&ctx);
                RIPEMD160_Update(&ctx, hash_buf, RIPEMD160_DIGEST_LENGTH);
                RIPEMD160_Final(hash_buf, &ctx);
            }
        });
    }

    // ==========================================
    // SHA-1 (Digest: 20 bytes)
    // ==========================================
    {
        SHA_CTX ctx;
        BENCHMARK("SHA-1 Chaining", {
            for (int i = 0; i < ITERATIONS; i++) {
                SHA1_Init(&ctx);
                SHA1_Update(&ctx, hash_buf, SHA_DIGEST_LENGTH);
                SHA1_Final(hash_buf, &ctx);
            }
        });
    }

    // ==========================================
    // SHA-224 (Digest: 28 bytes)
    // ==========================================
    {
        SHA256_CTX ctx;
        BENCHMARK("SHA-224 Chaining", {
            for (int i = 0; i < ITERATIONS; i++) {
                SHA224_Init(&ctx);
                SHA224_Update(&ctx, hash_buf, SHA224_DIGEST_LENGTH);
                SHA224_Final(hash_buf, &ctx);
            }
        });
    }

    // ==========================================
    // SHA-256 (Digest: 32 bytes)
    // ==========================================
    {
        SHA256_CTX ctx;
        BENCHMARK("SHA-256 Chaining", {
            for (int i = 0; i < ITERATIONS; i++) {
                SHA256_Init(&ctx);
                SHA256_Update(&ctx, hash_buf, SHA256_DIGEST_LENGTH);
                SHA256_Final(hash_buf, &ctx);
            }
        });
    }

    // ==========================================
    // SHA-384 (Digest: 48 bytes)
    // ==========================================
    {
        SHA512_CTX ctx;
        BENCHMARK("SHA-384 Chaining", {
            for (int i = 0; i < ITERATIONS; i++) {
                SHA384_Init(&ctx);
                SHA384_Update(&ctx, hash_buf, SHA384_DIGEST_LENGTH);
                SHA384_Final(hash_buf, &ctx);
            }
        });
    }

    // ==========================================
    // SHA-512 (Digest: 64 bytes)
    // ==========================================
    {
        SHA512_CTX ctx;
        BENCHMARK("SHA-512 Chaining", {
            for (int i = 0; i < ITERATIONS; i++) {
                SHA512_Init(&ctx);
                SHA512_Update(&ctx, hash_buf, SHA512_DIGEST_LENGTH);
                SHA512_Final(hash_buf, &ctx);
            }
        });
    }

    // ==========================================
    // SM3 (Digest: 32 bytes)
    // ==========================================
#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(OPENSSL_NO_SM3)
    {
        SM3_CTX ctx;
        BENCHMARK("SM3 Chaining", {
            for (int i = 0; i < ITERATIONS; i++) {
                SM3_Init(&ctx);
                SM3_Update(&ctx, hash_buf, SM3_DIGEST_LENGTH);
                SM3_Final(hash_buf, &ctx);
            }
        });
    }
#endif

    // ==========================================
    // WHIRLPOOL (Digest: 64 bytes)
    // ==========================================
#ifndef OPENSSL_NO_WHIRLPOOL
    {
        WHIRLPOOL_CTX ctx;
        BENCHMARK("Whirlpool Chaining", {
            for (int i = 0; i < ITERATIONS; i++) {
                WHIRLPOOL_Init(&ctx);
                WHIRLPOOL_Update(&ctx, hash_buf, WHIRLPOOL_DIGEST_LENGTH);
                WHIRLPOOL_Final(hash_buf, &ctx);
            }
        });
    }
#endif

    return 0;
}
