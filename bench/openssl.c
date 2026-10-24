#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define ITERATIONS 1000000
#define DATA_SIZE 16

void run_benchmark(const char *name, const EVP_CIPHER *cipher) {
    if (cipher == NULL) {
        printf("%-20s: [Not Supported]\n", name);
        return;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32] = {0}; 
    unsigned char iv[16] = {0};  
    unsigned char in[DATA_SIZE];
    unsigned char out[DATA_SIZE + 16]; // Extra space for padding
    int len;

    // Initialize input data
    for (int i = 0; i < DATA_SIZE; i++) {
        in[i] = (unsigned char)i;
    }

    // Initialize encryption context with the cipher, key, and IV
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        unsigned long err = ERR_get_error();
        char *err_msg = ERR_error_string(err, NULL);
        printf("%-20s: [Init Failed] (Error: %s)\n", name, err_msg);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < ITERATIONS; i++) {
        // Chaining mode: we don't reset the context in each iteration.
        // This means the internal state (like IV for CBC) evolves with each call.
        EVP_EncryptUpdate(ctx, out, &len, in, DATA_SIZE);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (double)(end.tv_sec - start.tv_sec) + (double)(end.tv_nsec - start.tv_nsec) / 1e9;
    printf("%-20s: %f s\n", name, elapsed);

    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    // List of ciphers requested by the user
    const char *cipher_names[] = {
        "AES-128-CBC", 
        "ARIA-128-CBC", 
        "Camellia-128-CBC", 
        "CAST5-CBC", 
        "ChaCha20", 
        "DES-CBC", 
        "IDEA-CBC", 
        "SEED-CBC", 
        "RC2-CBC", 
        "RC4"
    };
    int num_ciphers = sizeof(cipher_names) / sizeof(cipher_names[0]);

    printf("=== OpenSSL Benchmark (Chaining Mode, %d iterations) ===\n", ITERATIONS);
    for (int i = 0; i < num_ciphers; i++) {
        run_benchmark(cipher_names[i], EVP_get_cipherbyname(cipher_names[i]));
    }

    return 0;
}
