import "../../src/nim_cryptkit/block/twofish"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

# ============================================================
# Twofish-128 Test
# ============================================================

var ctx128: Twofish128Ctx

var key128: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

var text128: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

echo "--- Test : Twofish-128 ---"
let pt128 = binToHex(text128)
echo "Twofish-128 Key : ", binToHex(key128)
echo "Twofish-128 Plain Text Standard : ", pt128
twofish128Init(ctx128, key128)
twofish128Encrypt(ctx128, text128, text128)
echo "Twofish-128 Cipher Text Standard : 9F589F5CF6122C32B6BFEC2F2AE8C35A"
let ct128 = binToHex(text128)
echo "Twofish-128 Cipher Text State : ", ct128
doAssert ct128 == "9F589F5CF6122C32B6BFEC2F2AE8C35A", "Twofish-128 Encrypt Wrong!"
twofish128Decrypt(ctx128, text128, text128)
echo "Twofish-128 Plain Text State : ", binToHex(text128)
doAssert binToHex(text128) == pt128, "Twofish-128 Decrypt Wrong!"
echo ""


# ============================================================
# Twofish-192 Test
# ============================================================

var ctx192: Twofish192Ctx

var key192: array[24, uint8] = [
  0x01'u8, 0x23'u8, 0x45'u8, 0x67'u8, 0x89'u8, 0xAB'u8, 0xCD'u8, 0xEF'u8,
  0xFE'u8, 0xDC'u8, 0xBA'u8, 0x98'u8, 0x76'u8, 0x54'u8, 0x32'u8, 0x10'u8,
  0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8
]

var text192: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

echo "--- Test : Twofish-192 ---"
let pt192 = binToHex(text192)
echo "Twofish-192 Key : ", binToHex(key192)
echo "Twofish-192 Plain Text Standard : ", pt192
twofish192Init(ctx192, key192)
twofish192Encrypt(ctx192, text192, text192)
echo "Twofish-192 Cipher Text Standard : CFD1D2E5A9BE9CDF501F13B892BD2248"
let ct192 = binToHex(text192)
echo "Twofish-192 Cipher Text State : ", ct192
doAssert ct192 == "CFD1D2E5A9BE9CDF501F13B892BD2248", "Twofish-192 Encrypt Wrong!"
twofish192Decrypt(ctx192, text192, text192)
echo "Twofish-192 Plain Text State : ", binToHex(text192)
doAssert binToHex(text192) == pt192, "Twofish-192 Decrypt Wrong!"
echo ""


# ============================================================
# Twofish-256 Test
# ============================================================

var ctx256: Twofish256Ctx

var key256: array[32, uint8] = [
  0x01'u8, 0x23'u8, 0x45'u8, 0x67'u8, 0x89'u8, 0xAB'u8, 0xCD'u8, 0xEF'u8,
  0xFE'u8, 0xDC'u8, 0xBA'u8, 0x98'u8, 0x76'u8, 0x54'u8, 0x32'u8, 0x10'u8,
  0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8,
  0x88'u8, 0x99'u8, 0xAA'u8, 0xBB'u8, 0xCC'u8, 0xDD'u8, 0xEE'u8, 0xFF'u8
]

var text256: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

echo "--- Test : Twofish-256 ---"
let pt256 = binToHex(text256)
echo "Twofish-256 Key : ", binToHex(key256)
echo "Twofish-256 Plain Text Standard : ", pt256
twofish256Init(ctx256, key256)
twofish256Encrypt(ctx256, text256, text256)
echo "Twofish-256 Cipher Text Standard : 37527BE0052334B89F0CFCCAE87CFA20"
let ct256 = binToHex(text256)
echo "Twofish-256 Cipher Text State : ", ct256
doAssert ct256 == "37527BE0052334B89F0CFCCAE87CFA20", "Twofish-256 Encrypt Wrong!"
twofish256Decrypt(ctx256, text256, text256)
echo "Twofish-256 Plain Text State : ", binToHex(text256)
doAssert binToHex(text256) == pt256, "Twofish-256 Decrypt Wrong!"
echo ""

# ============================================================
# Benchmark
# ============================================================

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

# Twofish-128 Benchmark
benchmark("Twofish-128 Init"):
  for i in 1 .. 1_000_000:
    twofish128Init(ctx128, key128)

benchmark("Twofish-128 Encrypt"):
  for i in 1 .. 1_000_000:
    twofish128Encrypt(ctx128, text128, text128)

benchmark("Twofish-128 Decrypt"):
  for i in 1 .. 1_000_000:
    twofish128Decrypt(ctx128, text128, text128)

# Twofish-192 Benchmark
benchmark("Twofish-192 Init"):
  for i in 1 .. 1_000_000:
    twofish192Init(ctx192, key192)

benchmark("Twofish-192 Encrypt"):
  for i in 1 .. 1_000_000:
    twofish192Encrypt(ctx192, text192, text192)

benchmark("Twofish-192 Decrypt"):
  for i in 1 .. 1_000_000:
    twofish192Decrypt(ctx192, text192, text192)

# Twofish-256 Benchmark
benchmark("Twofish-256 Init"):
  for i in 1 .. 1_000_000:
    twofish256Init(ctx256, key256)

benchmark("Twofish-256 Encrypt"):
  for i in 1 .. 1_000_000:
    twofish256Encrypt(ctx256, text256, text256)

benchmark("Twofish-256 Decrypt"):
  for i in 1 .. 1_000_000:
    twofish256Decrypt(ctx256, text256, text256)
