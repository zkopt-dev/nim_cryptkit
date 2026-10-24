// Benchmark Crypto++ symmetric primitives and hash functions.
//
// Build from Cryptography/bench:
//   c++ -O3 -DNDEBUG -std=c++17 cryptopp.cpp -I../ref/cryptopp-master \
//       ../ref/cryptopp-master/libcryptopp.a -pthread -o cryptopp
//
// The benchmark intentionally uses the primitive APIs (not cipher modes,
// padding, AEAD or MAC wrappers).  Every benchmark performs 1,000,000
// operations and prints elapsed time in the same shape as the Nim examples.

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <cryptlib.h>

#include <3way.h>
#include <adler32.h>
#include <aes.h>
#include <arc4.h>
#include <aria.h>
#include <blake2.h>
#include <blowfish.h>
#include <camellia.h>
#include <cast.h>
#include <chacha.h>
#include <cham.h>
#include <crc.h>
#include <des.h>
#include <gost.h>
#include <hc128.h>
#include <hc256.h>
#include <hight.h>
#include <idea.h>
#include <kalyna.h>
#include <keccak.h>
#include <lea.h>
#include <lsh.h>
#include <mars.h>
#include <md2.h>
#include <md4.h>
#include <md5.h>
#include <panama.h>
#include <rabbit.h>
#include <rc2.h>
#include <rc5.h>
#include <rc6.h>
#include <rijndael.h>
#include <ripemd.h>
#include <safer.h>
#include <salsa.h>
#include <seal.h>
#include <seed.h>
#include <serpent.h>
#include <shacal2.h>
#include <sha.h>
#include <sha3.h>
#include <shake.h>
#include <shark.h>
#include <simeck.h>
#include <simon.h>
#include <skipjack.h>
#include <sm3.h>
#include <sm4.h>
#include <sosemanuk.h>
#include <speck.h>
#include <square.h>
#include <tea.h>
#include <threefish.h>
#include <tiger.h>
#include <twofish.h>
#include <wake.h>
#include <whrlpool.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using CryptoPP::byte;
using Clock = std::chrono::steady_clock;

#ifndef CRYPTOPP_BENCH_ITERATIONS
# define CRYPTOPP_BENCH_ITERATIONS 1'000'000
#endif

constexpr std::size_t kIterations = CRYPTOPP_BENCH_ITERATIONS;
constexpr std::size_t kMaxBlockSize = 128;  // Threefish-1024

// Keeps the final result observable so the optimizer cannot discard a chain.
volatile byte g_sink = 0;

template <class F>
void benchmark(std::string_view name, F&& code) {
    const auto start = Clock::now();
    std::forward<F>(code)();
    const auto elapsed = Clock::now() - start;
    const auto microseconds =
        std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
    const auto nanoseconds =
        std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count();

    std::cout << name << " took: " << microseconds << " μs (" << nanoseconds
              << " ns)\n";
}

template <class Cipher>
void bench_block_cipher(const char* name, std::size_t key_length = 0) {
    typename Cipher::Encryption encryptor;
    typename Cipher::Decryption decryptor;

    if (key_length == 0)
        key_length = encryptor.DefaultKeyLength();

    std::vector<byte> key(key_length, 0x42);
    std::array<byte, kMaxBlockSize> input{};
    std::array<byte, kMaxBlockSize> output{};
    const std::size_t block_size = encryptor.BlockSize();
    for (std::size_t i = 0; i < block_size; ++i)
        input[i] = static_cast<byte>(i);

    // Key schedule / context initialization.
    benchmark(std::string(name) + " Init", [&] {
        for (std::size_t i = 0; i < kIterations; ++i)
            encryptor.SetKey(key.data(), key.size());
    });

    encryptor.SetKey(key.data(), key.size());
    decryptor.SetKey(key.data(), key.size());

    byte* current = input.data();
    byte* next = output.data();
    benchmark(std::string(name) + " Encrypt", [&] {
        for (std::size_t i = 0; i < kIterations; ++i) {
            encryptor.ProcessBlock(current, next);
            std::swap(current, next);
        }
    });
    g_sink ^= current[block_size - 1];

    current = input.data();
    next = output.data();
    benchmark(std::string(name) + " Decrypt", [&] {
        for (std::size_t i = 0; i < kIterations; ++i) {
            decryptor.ProcessBlock(current, next);
            std::swap(current, next);
        }
    });
    g_sink ^= current[block_size - 1];
}

template <class Cipher>
void set_stream_key(Cipher& cipher, const byte* key, std::size_t key_length,
                    const byte* iv) {
    if (cipher.IVSize() == 0)
        cipher.SetKey(key, key_length);
    else
        cipher.SetKeyWithIV(key, key_length, iv, cipher.IVSize());
}

template <class Cipher>
void bench_stream_cipher(const char* name, std::size_t key_length = 0) {
    typename Cipher::Encryption cipher;
    if (key_length == 0)
        key_length = cipher.DefaultKeyLength();

    std::vector<byte> key(key_length, 0x42);
    std::array<byte, kMaxBlockSize> iv{};
    std::array<byte, 64> input{};
    std::array<byte, 64> output{};
    for (std::size_t i = 0; i < input.size(); ++i)
        input[i] = static_cast<byte>(i);

    // This includes nonce/IV setup for ciphers that require one.
    benchmark(std::string(name) + " Init", [&] {
        for (std::size_t i = 0; i < kIterations; ++i)
            set_stream_key(cipher, key.data(), key.size(), iv.data());
    });

    set_stream_key(cipher, key.data(), key.size(), iv.data());
    byte* current = input.data();
    byte* next = output.data();
    benchmark(std::string(name) + " Xor", [&] {
        for (std::size_t i = 0; i < kIterations; ++i) {
            cipher.ProcessData(next, current, input.size());
            std::swap(current, next);
        }
    });
    g_sink ^= current[input.size() - 1];
}

template <class Hash>
void bench_hash(const char* name, Hash hash) {
    // The digest is also the next iteration's input, matching the requested
    // Init -> Input -> Final chaining structure.
    std::vector<byte> digest(hash.DigestSize(), 0x42);

    benchmark(std::string(name) + " Benchmark", [&] {
        for (std::size_t i = 0; i < kIterations; ++i) {
            hash.Restart();
            hash.Update(digest.data(), digest.size());
            hash.Final(digest.data());
        }
    });
    g_sink ^= digest.back();
}

void bench_block_ciphers() {
    bench_block_cipher<CryptoPP::ThreeWay>("3-Way");
    bench_block_cipher<CryptoPP::AES>("AES-128", 16);
    bench_block_cipher<CryptoPP::AES>("AES-192", 24);
    bench_block_cipher<CryptoPP::AES>("AES-256", 32);
    bench_block_cipher<CryptoPP::ARIA>("ARIA-128", 16);
    bench_block_cipher<CryptoPP::ARIA>("ARIA-192", 24);
    bench_block_cipher<CryptoPP::ARIA>("ARIA-256", 32);
    bench_block_cipher<CryptoPP::Blowfish>("Blowfish");
    bench_block_cipher<CryptoPP::Camellia>("Camellia-128", 16);
    bench_block_cipher<CryptoPP::Camellia>("Camellia-192", 24);
    bench_block_cipher<CryptoPP::Camellia>("Camellia-256", 32);
    bench_block_cipher<CryptoPP::CAST128>("CAST-128");
    bench_block_cipher<CryptoPP::CAST256>("CAST-256");
    bench_block_cipher<CryptoPP::CHAM64>("CHAM-64/128");
    bench_block_cipher<CryptoPP::CHAM128>("CHAM-128/128", 16);
    bench_block_cipher<CryptoPP::CHAM128>("CHAM-128/256", 32);
    bench_block_cipher<CryptoPP::DES>("DES");
    bench_block_cipher<CryptoPP::DES_EDE2>("DES-EDE2");
    bench_block_cipher<CryptoPP::DES_EDE3>("DES-EDE3");
    bench_block_cipher<CryptoPP::DES_XEX3>("DES-XEX3");
    bench_block_cipher<CryptoPP::GOST>("GOST");
    bench_block_cipher<CryptoPP::HIGHT>("HIGHT");
    bench_block_cipher<CryptoPP::IDEA>("IDEA");
    bench_block_cipher<CryptoPP::Kalyna128>("Kalyna-128/128", 16);
    bench_block_cipher<CryptoPP::Kalyna128>("Kalyna-128/256", 32);
    bench_block_cipher<CryptoPP::Kalyna256>("Kalyna-256/256", 32);
    bench_block_cipher<CryptoPP::Kalyna256>("Kalyna-256/512", 64);
    bench_block_cipher<CryptoPP::Kalyna512>("Kalyna-512/512", 64);
    bench_block_cipher<CryptoPP::LEA>("LEA-128", 16);
    bench_block_cipher<CryptoPP::LEA>("LEA-192", 24);
    bench_block_cipher<CryptoPP::LEA>("LEA-256", 32);
    bench_block_cipher<CryptoPP::MARS>("MARS");
    bench_block_cipher<CryptoPP::RC2>("RC2");
    bench_block_cipher<CryptoPP::RC5>("RC5");
    bench_block_cipher<CryptoPP::RC6>("RC6");
    bench_block_cipher<CryptoPP::Rijndael>("Rijndael-128", 16);
    bench_block_cipher<CryptoPP::Rijndael>("Rijndael-192", 24);
    bench_block_cipher<CryptoPP::Rijndael>("Rijndael-256", 32);
    bench_block_cipher<CryptoPP::SAFER_K>("SAFER-K");
    bench_block_cipher<CryptoPP::SAFER_SK>("SAFER-SK");
    bench_block_cipher<CryptoPP::SEED>("SEED");
    bench_block_cipher<CryptoPP::Serpent>("Serpent");
    bench_block_cipher<CryptoPP::SHACAL2>("SHACAL-2");
    bench_block_cipher<CryptoPP::SHARK>("SHARK");
    bench_block_cipher<CryptoPP::SIMECK32>("SIMECK-32");
    bench_block_cipher<CryptoPP::SIMECK64>("SIMECK-64");
    bench_block_cipher<CryptoPP::SIMON64>("SIMON-64/96", 12);
    bench_block_cipher<CryptoPP::SIMON64>("SIMON-64/128", 16);
    bench_block_cipher<CryptoPP::SIMON128>("SIMON-128/128", 16);
    bench_block_cipher<CryptoPP::SIMON128>("SIMON-128/192", 24);
    bench_block_cipher<CryptoPP::SIMON128>("SIMON-128/256", 32);
    bench_block_cipher<CryptoPP::SKIPJACK>("SKIPJACK");
    bench_block_cipher<CryptoPP::SM4>("SM4");
    bench_block_cipher<CryptoPP::SPECK64>("SPECK-64/96", 12);
    bench_block_cipher<CryptoPP::SPECK64>("SPECK-64/128", 16);
    bench_block_cipher<CryptoPP::SPECK128>("SPECK-128/128", 16);
    bench_block_cipher<CryptoPP::SPECK128>("SPECK-128/192", 24);
    bench_block_cipher<CryptoPP::SPECK128>("SPECK-128/256", 32);
    bench_block_cipher<CryptoPP::Square>("Square");
    bench_block_cipher<CryptoPP::TEA>("TEA");
    bench_block_cipher<CryptoPP::Threefish256>("Threefish-256");
    bench_block_cipher<CryptoPP::Threefish512>("Threefish-512");
    bench_block_cipher<CryptoPP::Threefish1024>("Threefish-1024");
    bench_block_cipher<CryptoPP::Twofish>("Twofish");
    bench_block_cipher<CryptoPP::XTEA>("XTEA");
}

void bench_stream_ciphers() {
    bench_stream_cipher<CryptoPP::Weak::ARC4>("ARC4");
    bench_stream_cipher<CryptoPP::Weak::MARC4>("MARC4");
    bench_stream_cipher<CryptoPP::ChaCha>("ChaCha20");
    bench_stream_cipher<CryptoPP::ChaChaTLS>("ChaCha20-IETF");
    bench_stream_cipher<CryptoPP::XChaCha20>("XChaCha20");
    bench_stream_cipher<CryptoPP::HC128>("HC-128");
    bench_stream_cipher<CryptoPP::HC256>("HC-256");
    bench_stream_cipher<CryptoPP::PanamaCipher<CryptoPP::LittleEndian>>("Panama-LE");
    bench_stream_cipher<CryptoPP::PanamaCipher<CryptoPP::BigEndian>>("Panama-BE");
    bench_stream_cipher<CryptoPP::Rabbit>("Rabbit");
    bench_stream_cipher<CryptoPP::RabbitWithIV>("RabbitWithIV");
    bench_stream_cipher<CryptoPP::Salsa20>("Salsa20");
    bench_stream_cipher<CryptoPP::XSalsa20>("XSalsa20");
    bench_stream_cipher<CryptoPP::SEAL<CryptoPP::LittleEndian>>("SEAL-3.0-LE");
    bench_stream_cipher<CryptoPP::SEAL<CryptoPP::BigEndian>>("SEAL-3.0-BE");
    bench_stream_cipher<CryptoPP::Sosemanuk>("Sosemanuk");
    bench_stream_cipher<CryptoPP::WAKE_OFB<CryptoPP::LittleEndian>>("WAKE-OFB-LE");
    bench_stream_cipher<CryptoPP::WAKE_OFB<CryptoPP::BigEndian>>("WAKE-OFB-BE");
}

void bench_hashes() {
    bench_hash("Adler-32", CryptoPP::Adler32{});
    bench_hash("BLAKE2s-128", CryptoPP::BLAKE2s(false, 16));
    bench_hash("BLAKE2s-160", CryptoPP::BLAKE2s(false, 20));
    bench_hash("BLAKE2s-224", CryptoPP::BLAKE2s(false, 28));
    bench_hash("BLAKE2s-256", CryptoPP::BLAKE2s(false, 32));
    bench_hash("BLAKE2b-128", CryptoPP::BLAKE2b(false, 16));
    bench_hash("BLAKE2b-160", CryptoPP::BLAKE2b(false, 20));
    bench_hash("BLAKE2b-224", CryptoPP::BLAKE2b(false, 28));
    bench_hash("BLAKE2b-256", CryptoPP::BLAKE2b(false, 32));
    bench_hash("BLAKE2b-384", CryptoPP::BLAKE2b(false, 48));
    bench_hash("BLAKE2b-512", CryptoPP::BLAKE2b(false, 64));
    bench_hash("CRC-32", CryptoPP::CRC32{});
    bench_hash("CRC-32C", CryptoPP::CRC32C{});
    bench_hash("Keccak-224", CryptoPP::Keccak_224{});
    bench_hash("Keccak-256", CryptoPP::Keccak_256{});
    bench_hash("Keccak-384", CryptoPP::Keccak_384{});
    bench_hash("Keccak-512", CryptoPP::Keccak_512{});
    bench_hash("LSH-224", CryptoPP::LSH224{});
    bench_hash("LSH-256", CryptoPP::LSH256{});
    bench_hash("LSH-384", CryptoPP::LSH384{});
    bench_hash("LSH-512/256", CryptoPP::LSH512_256{});
    bench_hash("LSH-512", CryptoPP::LSH512{});
    bench_hash("MD2", CryptoPP::Weak::MD2{});
    bench_hash("MD4", CryptoPP::Weak::MD4{});
    bench_hash("MD5", CryptoPP::Weak::MD5{});
    bench_hash("Panama-LE", CryptoPP::Weak::PanamaHash<CryptoPP::LittleEndian>{});
    bench_hash("Panama-BE", CryptoPP::Weak::PanamaHash<CryptoPP::BigEndian>{});
    bench_hash("RIPEMD-128", CryptoPP::RIPEMD128{});
    bench_hash("RIPEMD-160", CryptoPP::RIPEMD160{});
    bench_hash("RIPEMD-256", CryptoPP::RIPEMD256{});
    bench_hash("RIPEMD-320", CryptoPP::RIPEMD320{});
    bench_hash("SHA-1", CryptoPP::SHA1{});
    bench_hash("SHA-224", CryptoPP::SHA224{});
    bench_hash("SHA-256", CryptoPP::SHA256{});
    bench_hash("SHA-384", CryptoPP::SHA384{});
    bench_hash("SHA-512", CryptoPP::SHA512{});
    bench_hash("SHA3-224", CryptoPP::SHA3_224{});
    bench_hash("SHA3-256", CryptoPP::SHA3_256{});
    bench_hash("SHA3-384", CryptoPP::SHA3_384{});
    bench_hash("SHA3-512", CryptoPP::SHA3_512{});
    bench_hash("SHAKE128-128", CryptoPP::SHAKE128{16});
    bench_hash("SHAKE256-256", CryptoPP::SHAKE256{32});
    bench_hash("SM3", CryptoPP::SM3{});
    bench_hash("Tiger", CryptoPP::Tiger{});
    bench_hash("Whirlpool", CryptoPP::Whirlpool{});
}

}  // namespace

int main() {
    std::cout << "Crypto++ primitive benchmark (" << kIterations
              << " iterations per measurement)\n";
    bench_block_ciphers();
    bench_stream_ciphers();
    bench_hashes();
    return 0;
}
