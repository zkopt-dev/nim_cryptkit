import "../../src/nim_cryptkit/stream/chacha20"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

# RFC 7539 Section 2.4.2 Test Vector
var key: array[32, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8, 0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8, 0x18'u8, 0x19'u8, 0x1A'u8, 0x1B'u8, 0x1C'u8, 0x1D'u8, 0x1E'u8, 0x1F'u8
]
var nonce: array[12, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

# Input "Sunscreen"
var text: seq[uint8] = hexToBin("224F51F348BA9093A9").value
let expectedCiphertext: seq[uint8] = hexToBin("1BB27A8E917F89F924").value
var ctx: ChaCha20Ctx

echo "ChaCha20 Key : ", binToHex(key)
echo "ChaCha20 Nonce : ", binToHex(nonce)
echo "ChaCha20 Plaintext : ", binToHex(text)

chacha20Init(ctx, key, nonce, 0) # RFC vector starts with counter 1
chacha20Xor(ctx, text, text)

echo "ChaCha20 Ciphertext : ", binToHex(text)
echo "ChaCha20 Standard : ", binToHex(expectedCiphertext)

doAssert text == expectedCiphertext,
  "ChaCha20 Ciphertext Wrong! got=" & binToHex(text) & " expected=" & binToHex(expectedCiphertext)

# --- Benchmark ---
template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("ChaCha20 Init Benchmark"):
  for i in 1 .. 1_000_000:
    chacha20Init(ctx, key, nonce, 0)

benchmark("ChaCha20 Xor Benchmark"):
  for i in 1 .. 1_000_000:
    chacha20Xor(ctx, text, text)
