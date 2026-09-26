import "../../src/nim_cryptkit/block/rc5"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

# =============================================================================
# RC5-16 64-bit Key Test
# =============================================================================
var ctx64: RC5_16Ctx
var key64: array[8, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8
]
var text64: array[4, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8
]

echo "--- Test : RC5-16 64-bit Key ---"
var pt64: string = binToHex(text64)
echo "RC5-16 Key Standard : ", binToHex(key64)
echo "RC5-16 Plain Text Standard : ", pt64
rc5_16Init(ctx64, key64, 16)
rc5_16Encrypt(ctx64, text64, text64)
echo "RC5-16 Cipher Text Standard : 23A8D72E"
var ct64: string = binToHex(text64)
echo "RC5-16 Cipher Text State : ", ct64
doAssert ct64 == "23A8D72E", "RC5-16 Encrypt Wrong!"
rc5_16Decrypt(ctx64, text64, text64)
echo "RC5-16 Plain Text State : ", binToHex(text64)
doAssert pt64 == binToHex(text64), "RC5-16 Decrypt Wrong!"
echo ""

# =============================================================================
# RC5-32 128-bit Key Test 1
# =============================================================================
var ctx128_1: RC5_32Ctx
var key128_1: array[16, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
  0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8
]
var text128_1: array[8, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8
]

echo "--- Test : RC5-32 128-bit Key ---"
var pt128_1: string = binToHex(text128_1)
echo "RC5-32 Key Standard : ", binToHex(key128_1)
echo "RC5-32 Plain Text Standard : ", pt128_1
rc5_32Init(ctx128_1, key128_1, 20)
rc5_32Encrypt(ctx128_1, text128_1, text128_1)
echo "RC5-32 Cipher Text Standard : 2A0EDC0E9431FF73"
var ct128_1: string = binToHex(text128_1)
echo "RC5-32 Cipher Text State : ", ct128_1
doAssert ct128_1 == "2A0EDC0E9431FF73", "RC5-32 Encrypt Wrong!"
rc5_32Decrypt(ctx128_1, text128_1, text128_1)
echo "RC5-32 Plain Text State : ", binToHex(text128_1)
doAssert pt128_1 == binToHex(text128_1), "RC5-32 Decrypt Wrong!"
echo ""

# =============================================================================
# RC5-64 192-bit Key Test
# =============================================================================
var ctx192_64: RC5_64Ctx
var key192_64: array[24, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
  0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8
]
var text192_64: array[16, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
  0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8
]

echo "--- Test : RC5-64 192-bit Key ---"
var pt192_64: string = binToHex(text192_64)
echo "RC5-64 Key Standard : ", binToHex(key192_64)
echo "RC5-64 Plain Text Standard : ", pt192_64
rc5_64Init(ctx192_64, key192_64, 24)
rc5_64Encrypt(ctx192_64, text192_64, text192_64)
echo "RC5-64 Cipher Text Standard : A46772820EDBCE0235ABEA32AE7178DA"
var ct192_64: string = binToHex(text192_64)
echo "RC5-64 Cipher Text State : ", ct192_64
doAssert ct192_64 == "A46772820EDBCE0235ABEA32AE7178DA", "RC5-64 Encrypt Wrong!"
rc5_64Decrypt(ctx192_64, text192_64, text192_64)
echo "RC5-64 Plain Text State : ", binToHex(text192_64)
doAssert pt192_64 == binToHex(text192_64), "RC5-64 Decrypt Wrong!"
echo ""

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

# RC5-16 128-bit Benchmark
benchmark("RC5-16 64-bit Init"):
  for i in 1 .. 1_000_000:
    rc5_16Init(ctx64, key64, 16)

benchmark("RC5-16 64-bit Encrypt"):
  for i in 1 .. 1_000_000:
    rc5_16Encrypt(ctx64, text64, text64)

benchmark("RC5-16 64-bit Decrypt"):
  for i in 1 .. 1_000_000:
    rc5_16Decrypt(ctx64, text64, text64)

# RC5-32 128-bit Benchmark
benchmark("RC5-32 128-bit Init"):
  for i in 1 .. 1_000_000:
    rc5_32Init(ctx128_1, key128_1, 20)

benchmark("RC5-32 128-bit Encrypt"):
  for i in 1 .. 1_000_000:
    rc5_32Encrypt(ctx128_1, text128_1, text128_1)

benchmark("RC5-32 128-bit Decrypt"):
  for i in 1 .. 1_000_000:
    rc5_32Decrypt(ctx128_1, text128_1, text128_1)

# RC5-64 192-bit Benchmark
benchmark("RC5-64 192-bit Init"):
  for i in 1 .. 1_000_000:
    rc5_64Init(ctx192_64, key192_64, 24)

benchmark("RC5-64 192-bit Encrypt"):
  for i in 1 .. 1_000_000:
    rc5_64Encrypt(ctx192_64, text192_64, text192_64)

benchmark("RC5-64 192-bit Decrypt"):
  for i in 1 .. 1_000_000:
    rc5_64Decrypt(ctx192_64, text192_64, text192_64)
