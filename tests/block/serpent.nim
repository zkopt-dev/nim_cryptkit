import "../../src/nim_cryptkit/block/serpent"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var ctx128: Serpent128Ctx
var text128: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var key128: array[16, uint8] = [
  0x80'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

echo "--- Test : Serpent-128 ---"
var pt128: string = binToHex(text128)
echo "Serpent-128 Key Standard : ", binToHex(key128)
echo "Serpent-128 Plain Text Standard : ", pt128
serpent128Init(ctx128, key128)
serpent128Encrypt(ctx128, text128, text128)
echo "Serpent-128 Cipher Text Standard : 264E5481EFF42A4606ABDA06C0BFDA3D"
var ct128: string = binToHex(text128)
echo "Serpent-128 Cipher Text State : ", ct128
doAssert ct128 == "264E5481EFF42A4606ABDA06C0BFDA3D", "Serpent-128 Encrypt Wrong!"
serpent128Decrypt(ctx128, text128, text128)
echo "Serpent-128 Plain Text State : ", binToHex(text128)
doAssert binToHex(text128) == pt128, "Serpent-128 Decrypt Wrong!"
echo ""


var ctx192: Serpent192Ctx
var text192: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var key192: array[24, uint8] = [
  0x80'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

echo "--- Test : Serpent-192 ---"
var pt192: string = binToHex(text192)
echo "Serpent-192 Key Standard : ", binToHex(key192)
echo "Serpent-192 Plain Text Standard : ", pt192
serpent192Init(ctx192, key192)
serpent192Encrypt(ctx192, text192, text192)
echo "Serpent-192 Cipher Text Standard : 9E274EAD9B737BB21EFCFCA548602689"
var ct192: string = binToHex(text192)
echo "Serpent-192 Cipher Text State : ", ct192
doAssert ct192 == "9E274EAD9B737BB21EFCFCA548602689", "Serpent-192 Encrypt Wrong!"
serpent192Decrypt(ctx192, text192, text192)
echo "Serpent-192 Plain Text State : ", binToHex(text192)
doAssert binToHex(text192) == pt192, "Serpent-192 Decrypt Wrong!"
echo ""


var ctx256: Serpent256Ctx
var text256: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var key256: array[32, uint8] = [
  0x80'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

echo "--- Test : Serpent-256 ---"
var pt256: string = binToHex(text256)
echo "Serpent-256 Key Standard : ", binToHex(key256)
echo "Serpent-256 Plain Text Standard : ", pt256
serpent256Init(ctx256, key256)
serpent256Encrypt(ctx256, text256, text256)
echo "Serpent-256 Cipher Text Standard : A223AA1288463C0E2BE38EBD825616C0"
var ct256: string = binToHex(text256)
echo "Serpent-256 Cipher Text State : ", ct256
doAssert ct256 == "A223AA1288463C0E2BE38EBD825616C0", "Serpent-256 Encrypt Wrong!"
serpent256Decrypt(ctx256, text256, text256)
echo "Serpent-256 Plain Text State : ", binToHex(text256)
doAssert binToHex(text256) == pt256, "Serpent-256 Decrypt Wrong!"
echo ""

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("Serpent-128 Init"):
  for i in 1 .. 1_000_000:
    serpent128Init(ctx128, key128)

benchmark("Serpent-128 Encrypt"):
  for i in 1 .. 1_000_000:
    serpent128Encrypt(ctx128, text128, text128)

benchmark("Serpent-128 Decrypt"):
  for i in 1 .. 1_000_000:
    serpent128Decrypt(ctx128, text128, text128)

benchmark("Serpent-192 Init"):
  for i in 1 .. 1_000_000:
    serpent192Init(ctx192, key192)

benchmark("Serpent-192 Encrypt"):
  for i in 1 .. 1_000_000:
    serpent192Encrypt(ctx192, text192, text192)

benchmark("Serpent-192 Decrypt"):
  for i in 1 .. 1_000_000:
    serpent192Decrypt(ctx192, text192, text192)

benchmark("Serpent-256 Init"):
  for i in 1 .. 1_000_000:
    serpent256Init(ctx256, key256)

benchmark("Serpent-256 Encrypt"):
  for i in 1 .. 1_000_000:
    serpent256Encrypt(ctx256, text256, text256)

benchmark("Serpent-256 Decrypt"):
  for i in 1 .. 1_000_000:
    serpent256Decrypt(ctx256, text256, text256)
