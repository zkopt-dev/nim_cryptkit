import "../../src/nim_cryptkit/block/camellia"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

# --- Camellia-128 Test ---
var ctx128: Camellia128Ctx
var text128: array[16, uint8] = [
  0x01'u8, 0x23'u8, 0x45'u8, 0x67'u8, 0x89'u8, 0xab'u8, 0xcd'u8, 0xef'u8, 0xfe'u8, 0xdc'u8, 0xba'u8, 0x98'u8, 0x76'u8, 0x54'u8, 0x32'u8, 0x10'u8
]
var key128: array[16, uint8] = [
  0x01'u8, 0x23'u8, 0x45'u8, 0x67'u8, 0x89'u8, 0xab'u8, 0xcd'u8, 0xef'u8, 0xfe'u8, 0xdc'u8, 0xba'u8, 0x98'u8, 0x76'u8, 0x54'u8, 0x32'u8, 0x10'u8
]

echo "Camellia-128 Test"
var pt128: string = binToHex(text128)
echo "Camellia-128 Key Standard : ", binToHex(key128)
echo "Camellia-128 Plain Text Standard : ", pt128
camellia128Init(ctx128, key128)
camellia128Encrypt(ctx128, text128, text128)
echo "Camellia-128 Cipher Text Standard : 67673138549669730857065648EABE43"
var ct128: string = binToHex(text128)
echo "Camellia-128 Cipher Text State : ", ct128
doAssert ct128 == "67673138549669730857065648EABE43", "Camellia-128 Encrypt Wrong!"
camellia128Decrypt(ctx128, text128, text128)
echo "Camellia-128 Plain Text State : ", binToHex(text128)
doAssert pt128 == binToHex(text128), "Camellia-128 Decrypt Wrong!"

# --- Camellia-192 Test ---
var ctx192: Camellia192Ctx
var text192: array[16, uint8] = [
  0x01'u8, 0x23'u8, 0x45'u8, 0x67'u8, 0x89'u8, 0xab'u8, 0xcd'u8, 0xef'u8, 0xfe'u8, 0xdc'u8, 0xba'u8, 0x98'u8, 0x76'u8, 0x54'u8, 0x32'u8, 0x10'u8
]
var key192: array[24, uint8] = [
  0x01'u8, 0x23'u8, 0x45'u8, 0x67'u8, 0x89'u8, 0xab'u8, 0xcd'u8, 0xef'u8, 0xfe'u8, 0xdc'u8, 0xba'u8, 0x98'u8, 0x76'u8, 0x54'u8, 0x32'u8, 0x10'u8,
  0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8
]

echo "Camellia-192 Test"
var pt192: string = binToHex(text192)
echo "Camellia-192 Key Standard : ", binToHex(key192)
echo "Camellia-192 Plain Text Standard : ", pt192
camellia192Init(ctx192, key192)
camellia192Encrypt(ctx192, text192, text192)
echo "Camellia-192 Cipher Text Standard : B4993401B3E996F84EE5CEE7D79B09B9"
var ct192: string = binToHex(text192)
echo "Camellia-192 Cipher Text State : ", ct192
doAssert ct192 == "B4993401B3E996F84EE5CEE7D79B09B9", "Camellia-192 Encrypt Wrong!"
camellia192Decrypt(ctx192, text192, text192)
echo "Camellia-192 Plain Text State : ", binToHex(text192)
doAssert pt192 == binToHex(text192), "Camellia-192 Decrypt Wrong!"

# --- Camellia-256 Test ---
var ctx256: Camellia256Ctx
var text256: array[16, uint8] = [
  0x01'u8, 0x23'u8, 0x45'u8, 0x67'u8, 0x89'u8, 0xab'u8, 0xcd'u8, 0xef'u8, 0xfe'u8, 0xdc'u8, 0xba'u8, 0x98'u8, 0x76'u8, 0x54'u8, 0x32'u8, 0x10'u8
]
var key256: array[32, uint8] = [
  0x01'u8, 0x23'u8, 0x45'u8, 0x67'u8, 0x89'u8, 0xab'u8, 0xcd'u8, 0xef'u8, 0xfe'u8, 0xdc'u8, 0xba'u8, 0x98'u8, 0x76'u8, 0x54'u8, 0x32'u8, 0x10'u8,
  0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8, 0x88'u8, 0x99'u8, 0xaa'u8, 0xbb'u8, 0xcc'u8, 0xdd'u8, 0xee'u8, 0xff'u8
]

echo "Camellia-256 Test"
var pt256: string = binToHex(text256)
echo "Camellia-256 Key Standard : ", binToHex(key256)
echo "Camellia-256 Plain Text Standard : ", pt256
camellia256Init(ctx256, key256)
camellia256Encrypt(ctx256, text256, text256)
echo "Camellia-256 Cipher Text Standard : 9ACC237DFF16D76C20EF7C919E3A7509"
var ct256: string = binToHex(text256)
echo "Camellia-256 Cipher Text State : ", ct256
doAssert ct256 == "9ACC237DFF16D76C20EF7C919E3A7509", "Camellia-256 Encrypt Wrong!"
camellia256Decrypt(ctx256, text256, text256)
echo "Camellia-256 Plain Text State : ", binToHex(text256)
doAssert pt256 == binToHex(text256), "Camellia-256 Decrypt Wrong!"

# --- Benchmark Template ---
template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"
# --- Camellia-128 Benchmarks ---

benchmark("Camellia-128 Init"):
  for i in 1 .. 1_000_000:
    camellia128Init(ctx128, key128)

benchmark("Camellia-128 Encrypt"):
  for i in 1 .. 1_000_000:
    camellia128Encrypt(ctx128, text128, text128)

benchmark("Camellia-128 Decrypt"):
  for i in 1 .. 1_000_000:
    camellia128Decrypt(ctx128, text128, text128)

# --- Camellia-192 Benchmarks ---

benchmark("Camellia-192 Init"):
  for i in 1 .. 1_000_000:
    camellia192Init(ctx192, key192)

benchmark("Camellia-192 Encrypt"):
  for i in 1 .. 1_000_000:
    camellia192Encrypt(ctx192, text192, text192)

benchmark("Camellia-192 Decrypt"):
  for i in 1 .. 1_000_000:
    camellia192Decrypt(ctx192, text192, text192)

# --- Camellia-256 Benchmarks ---

benchmark("Camellia-256 Init"):
  for i in 1 .. 1_000_000:
    camellia256Init(ctx256, key256)

benchmark("Camellia-256 Encrypt"):
  for i in 1 .. 1_000_000:
    camellia256Encrypt(ctx256, text256, text256)

benchmark("Camellia-256 Decrypt"):
  for i in 1 .. 1_000_000:
    camellia256Decrypt(ctx256, text256, text256)
