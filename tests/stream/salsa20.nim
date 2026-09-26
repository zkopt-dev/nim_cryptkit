import "../../src/nim_cryptkit/stream/salsa20"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

# --- Salsa20 128-bit Correctness Verification ---
var key128: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var nonce128: array[8, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var text128: seq[uint8] = newSeq[uint8](64)
var ctx128: SalSa20Ctx

salsa20_128Init(ctx128, key128, nonce128, 0)
salsa20Xor(ctx128, text128, text128)

let expected128 = "6513ADAECFEB124C1CBE6BDAEF690B4FFB00B0FCACE33CE806792BB41480199834BFB1CFDD095802C6E95E251002989AC22AE588D32AE79320D9BD7732E00338"
let actual128 = binToHex(text128)

echo "Salsa20 128-bit Test (Set 2 Vector 0):"
echo "Key:    ", binToHex(key128)
echo "Nonce:  ", binToHex(nonce128)
echo "Result: ", actual128
echo "Expected: ", expected128

doAssert actual128 == expected128,
  "Salsa20-128 Ciphertext Wrong! got=" & actual128 & " expected=" & expected128

# --- Salsa20 256-bit Correctness Verification ---
var key256: array[32, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var nonce256: array[8, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var text256: seq[uint8] = newSeq[uint8](64)
var ctx256: SalSa20Ctx

salsa20_256Init(ctx256, key256, nonce256, 0)
salsa20Xor(ctx256, text256, text256)

let expected256 = "9A97F65B9B4C721B960A672145FCA8D4E32E67F9111EA979CE9C4826806AEEE63DE9C0DA2BD7F91EBCB2639BF989C6251B29BF38D39A9BDCE7C55F4B2AC12A39"
let actual256 = binToHex(text256)

echo "Salsa20 256-bit Test:"
echo "Key:    ", binToHex(key256)
echo "Nonce:  ", binToHex(nonce256)
echo "Result: ", actual256
echo "Expected: ", expected256

doAssert actual256 == expected256,
  "Salsa20-256 Ciphertext Wrong! got=" & actual256 & " expected=" & expected256

# --- Benchmark ---
template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("SalSa20-128 Init"):
  for i in 1 .. 1_000_000:
    salsa20_128Init(ctx128, key128, nonce128, 0)

benchmark("SalSa20-128 Xor"):
  for i in 1 .. 1_000_000:
    salsa20Xor(ctx128, text128, text128)

benchmark("SalSa20-256 Init"):
  for i in 1 .. 1_000_000:
    salsa20_256Init(ctx256, key256, nonce256, 0)

benchmark("SalSa20-256 Xor"):
  for i in 1 .. 1_000_000:
    salsa20Xor(ctx256, text256, text256)
