# nim_cryptkit

## nim_cryptkit : Nim's biggest cryptography library

## SUPPORTED CIPHERS

### Hash

List

- MD2, MD4, MD5

- SHA-0, SHA-1, SHA-2(224/256/384/512), RIPEMD(128/160/256/320)

- SHA-3(224/256/384/512), Keccak(224/256/384/512), Shake(128/256)

- BLAKE2S(128/160/224/256), BLAKE2B(128/160/224/256/384/512)

- GOST, Streebog(256/512), SM3, HAS-160, LSH(224/256/384/512), Kupyna(256/384/512)

- Groestl, JH, JH2, Skein, Whirlpool, CubeHash, ECHO, ESCH

### Block Cipher

List

- AES, Twofish, Serpent, ARIA, Camellia, LEA, RC6, CAST-256

- Blowfish, DES, CAST-128, RC2, RC5, IDEA, Threefish

- SM4, GOST, SEED

- HIGHT, SPECK, SIMON, TEA, XTEA, XXTEA

### Stream Cipher

List

- HC128, HC256, Rabbit, ChaCha20, WAKE, SalSa20, RC4

### KDF 

List

- Balloon, Bcrypt, Catena, LMHash, NTHash, PBKDF2, Scrypt, Yescrypt

### MAC

List

- CBC-MAC, GMAC, HMAC, CMAC, Poly1305

### Mode

List

- ECB, CBC, PCBC, CFB, OFB, CTRL

### AEAD

List

- GCM, CCM, OCB, SIV, EAX

### PubKey

List

- x25519, SM2, EC-KCDSA, Ed25519

## PLAN TO SUPPORT

List

- BLAKE1, BLAKE3, MD6

- MARS(Test and Debuggin Needs), Kuznycheik, Kalyna(Test and Debugging Needs), BELT

- Argon2(Test and Debugging Needs)

- ML-DSA, ML-KEM(Test and Debugging Needs), ECDSA, ECDH

Also : SIMD Acceleration, PipelineC Backend

- SIMD Acceleration : Will be supported soon -> Nim-SIMDLang is developing

- Nim-JS Backend : Will be not supported : JS is not good for Cryptography

- Nim-WASM Backend : All file is supported to compile to WASM

- C/C++/Rust/Go/Python/Java/.NET Wrapper : Will be supported

## Compile Option

- Default : nim c --mm:orc --threads:on --opt:speed --d:debug --stacktrace:off --debugger:off --passC:"-O3" 

- When Test : --define:test

- When Full inline Mode : --define:templateOpt

- When Size Opt : --define:sizeOpt

- When Use T-Table(AES) : --define:tableOpt

