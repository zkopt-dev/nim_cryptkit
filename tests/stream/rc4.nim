import "../../src/nim_cryptkit/stream/rc4"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

var key: array[8, uint8] = [
  0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8
]
var text: array[16, uint8]
let expectedCiphertext: array[16, uint8] = [
  0x1F'u8, 0x09'u8, 0x58'u8, 0x93'u8, 0xAB'u8, 0x0C'u8, 0xBD'u8, 0xBF'u8, 0x05'u8, 0x0E'u8, 0x56'u8, 0x38'u8, 0x1E'u8, 0xB4'u8, 0x06'u8, 0x66'u8
]
var ctx: RC4Ctx

echo "RC4 Key : ", binToHex(key)
echo "RC4 Plain Text Standard : ", binToHex(text)

# --- Correctness Verification: Encryption ---
rc4Init(ctx, key)
rc4Xor(ctx, text, text)

echo "RC4 Cipher Text : ", binToHex(text)
echo "RC4 Cipher Text Standard : ", binToHex(expectedCiphertext)

doAssert text == expectedCiphertext,
  "RC4 Ciphertext Wrong! got=" & binToHex(text) & " expected=" & binToHex(expectedCiphertext)

# --- Correctness Verification: Decryption (round-trip) ---
rc4Init(ctx, key)
rc4Xor(ctx, text, text)

echo "RC4 Plain Text : ", binToHex(text)

doAssert text == [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  "RC4 Round-trip Decryption Wrong! got=" & binToHex(text)

# --- Benchmark ---
template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("RC4 Init Benchmark"):
  for i in 1 .. 1_000_000:
    rc4Init(ctx, key)

benchmark("RC4 Xor Benchmark"):
  for i in 1 .. 1_000_000:
    rc4Xor(ctx, text, text)
