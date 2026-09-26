import "../../src/nim_cryptkit/block/rc6"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

# =============================================================================
# RC6-16 64-bit Key Test
# =============================================================================
var ctx64: RC6_16Ctx
var key64: array[8, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8
]
var text64: array[8, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8
]

echo "--- Test : RC6-16 64-bit Key ---"
var pt64: string = binToHex(text64)
echo "RC6-16 Key Standard : ", binToHex(key64)
echo "RC6-16 Plain Text Standard : ", pt64
rc6_16Init(ctx64, key64, 16)
rc6_16Encrypt(ctx64, text64, text64)
echo "RC6-16 Cipher Text Standard : 2FF0B68EAEFFAD5B"
var ct64: string = binToHex(text64)
echo "RC6-16 Cipher Text State : ", ct64
doAssert ct64 == "2FF0B68EAEFFAD5B", "RC6-16 Encrypt Wrong!"
rc6_16Decrypt(ctx64, text64, text64)
echo "RC6-16 Plain Text State : ", binToHex(text64)
doAssert pt64 == binToHex(text64), "RC6-16 Decrypt Wrong!"
echo ""

# =============================================================================
# RC6-32 128-bit Key Test 1
# =============================================================================
var ctx128_1: RC6_32Ctx
var key128_1: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var text128_1: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

echo "--- Test : RC6-32 128-bit Key 1 ---"
var pt128_1: string = binToHex(text128_1)
echo "RC6-32 Key Standard : ", binToHex(key128_1)
echo "RC6-32 Plain Text Standard : ", pt128_1
rc6_32Init(ctx128_1, key128_1, 20)
rc6_32Encrypt(ctx128_1, text128_1, text128_1)
echo "RC6-32 Cipher Text Standard : 8FC3A53656B1F778C129DF4E9848A41E"
var ct128_1: string = binToHex(text128_1)
echo "RC6-32 Cipher Text State : ", ct128_1
doAssert ct128_1 == "8FC3A53656B1F778C129DF4E9848A41E", "RC6-32 128-bit Key 1 Encrypt Wrong!"
rc6_32Decrypt(ctx128_1, text128_1, text128_1)
echo "RC6-32 Plain Text State : ", binToHex(text128_1)
doAssert pt128_1 == binToHex(text128_1), "RC6-32 128-bit Key 1 Decrypt Wrong!"
echo ""

# =============================================================================
# RC6-32 128-bit Key Test 2
# =============================================================================
var ctx128_2: RC6_32Ctx
var key128_2: array[16, uint8] = [
  0x01'u8, 0x23'u8, 0x45'u8, 0x67'u8, 0x89'u8, 0xab'u8, 0xcd'u8, 0xef'u8,
  0x01'u8, 0x12'u8, 0x23'u8, 0x34'u8, 0x45'u8, 0x56'u8, 0x67'u8, 0x78'u8
]
var text128_2: array[16, uint8] = [
  0x02'u8, 0x13'u8, 0x24'u8, 0x35'u8, 0x46'u8, 0x57'u8, 0x68'u8, 0x79'u8,
  0x8a'u8, 0x9b'u8, 0xac'u8, 0xbd'u8, 0xce'u8, 0xdf'u8, 0xe0'u8, 0xf1'u8
]

echo "--- Test : RC6-32 128-bit Key 2 ---"
var pt128_2: string = binToHex(text128_2)
echo "RC6-32 Key Standard : ", binToHex(key128_2)
echo "RC6-32 Plain Text Standard : ", pt128_2
rc6_32Init(ctx128_2, key128_2, 20)
rc6_32Encrypt(ctx128_2, text128_2, text128_2)
echo "RC6-32 Cipher Text Standard : 524E192F4715C6231F51F6367EA43F18"
var ct128_2: string = binToHex(text128_2)
echo "RC6-32 Cipher Text State : ", ct128_2
doAssert ct128_2 == "524E192F4715C6231F51F6367EA43F18", "RC6-32 128-bit Key 2 Encrypt Wrong!"
rc6_32Decrypt(ctx128_2, text128_2, text128_2)
echo "RC6-32 Plain Text State : ", binToHex(text128_2)
doAssert pt128_2 == binToHex(text128_2), "RC6-32 128-bit Key 2 Decrypt Wrong!"
echo ""

# =============================================================================
# RC6-32 192-bit Key Test 1
# =============================================================================
var ctx192_1: RC6_32Ctx
var key192_1: array[24, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var text192_1: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

echo "--- Test : RC6-32 192-bit Key 1 ---"
var pt192_1: string = binToHex(text192_1)
echo "RC6-32 Key Standard : ", binToHex(key192_1)
echo "RC6-32 Plain Text Standard : ", pt192_1
rc6_32Init(ctx192_1, key192_1, 20)
rc6_32Encrypt(ctx192_1, text192_1, text192_1)
echo "RC6-32 Cipher Text Standard : 6CD61BCB190B30384E8A3F168690AE82"
var ct192_1: string = binToHex(text192_1)
echo "RC6-32 Cipher Text State : ", ct192_1
doAssert ct192_1 == "6CD61BCB190B30384E8A3F168690AE82", "RC6-32 192-bit Key 1 Encrypt Wrong!"
rc6_32Decrypt(ctx192_1, text192_1, text192_1)
echo "RC6-32 Plain Text State : ", binToHex(text192_1)
doAssert pt192_1 == binToHex(text192_1), "RC6-32 192-bit Key 1 Decrypt Wrong!"
echo ""

# =============================================================================
# RC6-32 192-bit Key Test 2
# =============================================================================
var ctx192_2: RC6_32Ctx
var key192_2: array[24, uint8] = [
  0x01'u8, 0x23'u8, 0x45'u8, 0x67'u8, 0x89'u8, 0xab'u8, 0xcd'u8, 0xef'u8,
  0x01'u8, 0x12'u8, 0x23'u8, 0x34'u8, 0x45'u8, 0x56'u8, 0x67'u8, 0x78'u8,
  0x89'u8, 0x9a'u8, 0xab'u8, 0xbc'u8, 0xcd'u8, 0xde'u8, 0xef'u8, 0xf0'u8
]
var text192_2: array[16, uint8] = [
  0x02'u8, 0x13'u8, 0x24'u8, 0x35'u8, 0x46'u8, 0x57'u8, 0x68'u8, 0x79'u8,
  0x8a'u8, 0x9b'u8, 0xac'u8, 0xbd'u8, 0xce'u8, 0xdf'u8, 0xe0'u8, 0xf1'u8
]

echo "--- Test : RC6-32 192-bit Key 2 ---"
var pt192_2: string = binToHex(text192_2)
echo "RC6-32 Key Standard : ", binToHex(key192_2)
echo "RC6-32 Plain Text Standard : ", pt192_2
rc6_32Init(ctx192_2, key192_2, 20)
rc6_32Encrypt(ctx192_2, text192_2, text192_2)
echo "RC6-32 Cipher Text Standard : 688329D019E505041E52E92AF95291D4"
var ct192_2: string = binToHex(text192_2)
echo "RC6-32 Cipher Text State : ", ct192_2
doAssert ct192_2 == "688329D019E505041E52E92AF95291D4", "RC6-32 192-bit Key 2 Encrypt Wrong!"
rc6_32Decrypt(ctx192_2, text192_2, text192_2)
echo "RC6-32 Plain Text State : ", binToHex(text192_2)
doAssert pt192_2 == binToHex(text192_2), "RC6-32 192-bit Key 2 Decrypt Wrong!"
echo ""

# =============================================================================
# RC6-32 256-bit Key Test 1
# =============================================================================
var ctx256_1: RC6_32Ctx
var key256_1: array[32, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var text256_1: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

echo "--- Test : RC6-32 256-bit Key 1 ---"
var pt256_1: string = binToHex(text256_1)
echo "RC6-32 Key Standard : ", binToHex(key256_1)
echo "RC6-32 Plain Text Standard : ", pt256_1
rc6_32Init(ctx256_1, key256_1, 20)
rc6_32Encrypt(ctx256_1, text256_1, text256_1)
echo "RC6-32 Cipher Text Standard : 8F5FBD0510D15FA893FA3FDA6E857EC2"
var ct256_1: string = binToHex(text256_1)
echo "RC6-32 Cipher Text State : ", ct256_1
doAssert ct256_1 == "8F5FBD0510D15FA893FA3FDA6E857EC2", "RC6-32 256-bit Key 1 Encrypt Wrong!"
rc6_32Decrypt(ctx256_1, text256_1, text256_1)
echo "RC6-32 Plain Text State : ", binToHex(text256_1)
doAssert pt256_1 == binToHex(text256_1), "RC6-32 256-bit Key 1 Decrypt Wrong!"
echo ""

# =============================================================================
# RC6-32 256-bit Key Test 2
# =============================================================================
var ctx256_2: RC6_32Ctx
var key256_2: array[32, uint8] = [
  0x01'u8, 0x23'u8, 0x45'u8, 0x67'u8, 0x89'u8, 0xab'u8, 0xcd'u8, 0xef'u8,
  0x01'u8, 0x12'u8, 0x23'u8, 0x34'u8, 0x45'u8, 0x56'u8, 0x67'u8, 0x78'u8,
  0x89'u8, 0x9a'u8, 0xab'u8, 0xbc'u8, 0xcd'u8, 0xde'u8, 0xef'u8, 0xf0'u8,
  0x10'u8, 0x32'u8, 0x54'u8, 0x76'u8, 0x98'u8, 0xba'u8, 0xdc'u8, 0xfe'u8
]
var text256_2: array[16, uint8] = [
  0x02'u8, 0x13'u8, 0x24'u8, 0x35'u8, 0x46'u8, 0x57'u8, 0x68'u8, 0x79'u8,
  0x8a'u8, 0x9b'u8, 0xac'u8, 0xbd'u8, 0xce'u8, 0xdf'u8, 0xe0'u8, 0xf1'u8
]

echo "--- Test : RC6-32 256-bit Key 2 ---"
var pt256_2: string = binToHex(text256_2)
echo "RC6-32 Key Standard : ", binToHex(key256_2)
echo "RC6-32 Plain Text Standard : ", pt256_2
rc6_32Init(ctx256_2, key256_2, 20)
rc6_32Encrypt(ctx256_2, text256_2, text256_2)
echo "RC6-32 Cipher Text Standard : C8241816F0D7E48920AD16A1674E5D48"
var ct256_2: string = binToHex(text256_2)
echo "RC6-32 Cipher Text State : ", ct256_2
doAssert ct256_2 == "C8241816F0D7E48920AD16A1674E5D48", "RC6-32 256-bit Key 2 Encrypt Wrong!"
rc6_32Decrypt(ctx256_2, text256_2, text256_2)
echo "RC6-32 Plain Text State : ", binToHex(text256_2)
doAssert pt256_2 == binToHex(text256_2), "RC6-32 256-bit Key 2 Decrypt Wrong!"
echo ""

# =============================================================================
# RC6-64 192-bit Key Test 2
# =============================================================================
var ctx192_64: RC6_64Ctx
var key192_64: array[24, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
  0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8
]
var text192_64: array[32, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
  0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8,
  0x18'u8, 0x19'u8, 0x1A'u8, 0x1B'u8, 0x1C'u8, 0x1D'u8, 0x1E'u8, 0x1F'u8
]

echo "--- Test : RC6-64 192-bit Key ---"
var pt192_64: string = binToHex(text192_64)
echo "RC6-64 Key Standard : ", binToHex(key192_64)
echo "RC6-64 Plain Text Standard : ", pt192_64
rc6_64Init(ctx192_64, key192_64, 24)
rc6_64Encrypt(ctx192_64, text192_64, text192_64)
echo "RC6-64 Cipher Text Standard : C002DE050BD55E5D36864AB9853338E6DC4A1326C6BDAAEB1BC9E4FD67886617"
var ct192_64: string = binToHex(text192_64)
echo "RC6-64 Cipher Text State : ", ct192_64
doAssert ct192_64 == "C002DE050BD55E5D36864AB9853338E6DC4A1326C6BDAAEB1BC9E4FD67886617", "RC6-64 Encrypt Wrong!"
rc6_64Decrypt(ctx192_64, text192_64, text192_64)
echo "RC6-64 Plain Text State : ", binToHex(text192_64)
doAssert pt192_64 == binToHex(text192_64), "RC6-64 Decrypt Wrong!"
echo ""

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

# RC6-16 128-bit Benchmark
benchmark("RC6-16 64-bit Init"):
  for i in 1 .. 1_000_000:
    rc6_16Init(ctx64, key64, 16)

benchmark("RC6-16 64-bit Encrypt"):
  for i in 1 .. 1_000_000:
    rc6_16Encrypt(ctx64, text64, text64)

benchmark("RC6-16 64-bit Decrypt"):
  for i in 1 .. 1_000_000:
    rc6_16Decrypt(ctx64, text64, text64)

# RC6-32 128-bit Benchmark
benchmark("RC6-32 128-bit Init"):
  for i in 1 .. 1_000_000:
    rc6_32Init(ctx128_1, key128_1, 20)

benchmark("RC6-32 128-bit Encrypt"):
  for i in 1 .. 1_000_000:
    rc6_32Encrypt(ctx128_1, text128_1, text128_1)

benchmark("RC6-32 128-bit Decrypt"):
  for i in 1 .. 1_000_000:
    rc6_32Decrypt(ctx128_1, text128_1, text128_1)

# RC6-32 192-bit Benchmark
benchmark("RC6-32 192-bit Init"):
  for i in 1 .. 1_000_000:
    rc6_32Init(ctx192_1, key192_1, 20)

benchmark("RC6-32 192-bit Encrypt"):
  for i in 1 .. 1_000_000:
    rc6_32Encrypt(ctx192_1, text192_1, text192_1)

benchmark("RC6-32 192-bit Decrypt"):
  for i in 1 .. 1_000_000:
    rc6_32Decrypt(ctx192_1, text192_1, text192_1)

# RC6-32 256-bit Benchmark
benchmark("RC6-32 256-bit Init"):
  for i in 1 .. 1_000_000:
    rc6_32Init(ctx256_1, key256_1, 20)

benchmark("RC6-32 256-bit Encrypt"):
  for i in 1 .. 1_000_000:
    rc6_32Encrypt(ctx256_1, text256_1, text256_1)

benchmark("RC6-32 256-bit Decrypt"):
  for i in 1 .. 1_000_000:
    rc6_32Decrypt(ctx256_1, text256_1, text256_1)

# RC6-64 192-bit Benchmark
benchmark("RC6-64 192-bit Init"):
  for i in 1 .. 1_000_000:
    rc6_64Init(ctx192_64, key192_64, 24)

benchmark("RC6-64 192-bit Encrypt"):
  for i in 1 .. 1_000_000:
    rc6_64Encrypt(ctx192_64, text192_64, text192_64)

benchmark("RC6-64 192-bit Decrypt"):
  for i in 1 .. 1_000_000:
    rc6_64Decrypt(ctx192_64, text192_64, text192_64)
