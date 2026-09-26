import "../../src/nim_cryptkit/block/aria"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

echo "ARIA Series Test"

var ctx128: ARIA128Ctx
var key128: array[16, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8, 0x08'u8, 0x09'u8, 0x0a'u8, 0x0b'u8, 0x0c'u8, 0x0d'u8, 0x0e'u8, 0x0f'u8
]
var text128: array[16, uint8] = [
  0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8, 0x88'u8, 0x99'u8, 0xaa'u8, 0xbb'u8, 0xcc'u8, 0xdd'u8, 0xee'u8, 0xff'u8
]
var encrypt128: array[16, uint8]
var decrypt128: array[16, uint8]

aria128Init(ctx128, key128)
echo "--- Test : ARIA-128 ---"
var pt128: string = binToHex(text128)
echo "ARIA-128 Key Standard : ", binToHex(key128)
echo "ARIA-128 Plain Text Standard : ", pt128
aria128Encrypt(ctx128, text128, encrypt128)
echo "ARIA-128 Standard Cipher Text : D718FBD6AB644C739DA95F3BE6451778"
var ct128: string = binToHex(encrypt128)
echo "ARIA-128 Cipher Text State : ", ct128
doAssert ct128 == "D718FBD6AB644C739DA95F3BE6451778", "ARIA-128 Encrypt Wrong!"
aria128Decrypt(ctx128, encrypt128, decrypt128)
echo "ARIA-128 Plain Text State : ", binToHex(decrypt128)
doAssert pt128 == binToHex(decrypt128), "ARIA-128 Decrypt Wrong!"

var ctx192: ARIA192Ctx
var key192: array[24, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8, 0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8, 0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8
]
var text192: array[16, uint8] = [
  0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8, 0x88'u8, 0x99'u8, 0xaa'u8, 0xbb'u8, 0xcc'u8, 0xdd'u8, 0xee'u8, 0xff'u8
]
var encrypt192: array[16, uint8]
var decrypt192: array[16, uint8]

aria192Init(ctx192, key192)
echo "--- Test : ARIA-192 ---"
var pt192: string = binToHex(text192)
echo "ARIA-192 Key Standard : ", binToHex(key192)
echo "ARIA-192 Plain Text Standard : ", pt192
aria192Encrypt(ctx192, text192, encrypt192)
echo "ARIA-192 Standard Cipher Text : 26449C1805DBE7AA25A468CE263A9E79"
var ct192: string = binToHex(encrypt192)
echo "ARIA-192 Cipher Text State : ", ct192
doAssert ct192 == "26449C1805DBE7AA25A468CE263A9E79", "ARIA-192 Encrypt Wrong!"
aria192Decrypt(ctx192, encrypt192, decrypt192)
echo "ARIA-192 Plain Text State : ", binToHex(decrypt192)
doAssert pt192 == binToHex(decrypt192), "ARIA-192 Decrypt Wrong!"

var ctx256: ARIA256Ctx
var key256: array[32, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8, 0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8, 0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8, 0x18'u8, 0x19'u8, 0x1A'u8, 0x1B'u8, 0x1C'u8, 0x1D'u8, 0x1E'u8, 0x1F'u8
]
var text256: array[16, uint8] = [
  0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8, 0x88'u8, 0x99'u8, 0xaa'u8, 0xbb'u8, 0xcc'u8, 0xdd'u8, 0xee'u8, 0xff'u8
]
var encrypt256: array[16, uint8]
var decrypt256: array[16, uint8]

aria256Init(ctx256, key256)
echo "--- Test : ARIA-256 ---"
var pt256: string = binToHex(text256)
echo "ARIA-256 Key Standard : ", binToHex(key256)
echo "ARIA-256 Plain Text Standard : ", pt256
aria256Encrypt(ctx256, text256, encrypt256)
echo "ARIA-256 Standard Cipher Text : F92BD7C79FB72E2F2B8F80C1972D24FC"
var ct256: string = binToHex(encrypt256)
echo "ARIA-256 Cipher Text State : ", ct256
doAssert ct256 == "F92BD7C79FB72E2F2B8F80C1972D24FC", "ARIA-256 Encrypt Wrong!"
aria256Decrypt(ctx256, encrypt256, decrypt256)
echo "ARIA-256 Plain Text State : ", binToHex(decrypt256)
doAssert pt256 == binToHex(decrypt256), "ARIA-256 Decrypt Wrong!"

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("ARIA-128 Init"):
  for i in 1 .. 1_000_000:
    aria128Init(ctx128, key128)

benchmark("ARIA-128 Encrypt"):
  for i in 1 .. 1_000_000:
    aria128Encrypt(ctx128, text128, text128)

benchmark("ARIA-128 Decrypt"):
  for i in 1 .. 1_000_000:
    aria128Decrypt(ctx128, text128, text128)

benchmark("ARIA-192 Init"):
  for i in 1 .. 1_000_000:
    aria192Init(ctx192, key192)

benchmark("ARIA-192 Encrypt"):
  for i in 1 .. 1_000_000:
    aria192Encrypt(ctx192, text192, text128)

benchmark("ARIA-192 Decrypt"):
  for i in 1 .. 1_000_000:
    aria192Decrypt(ctx192, text192, text128)

benchmark("ARIA-256 Init"):
  for i in 1 .. 1_000_000:
    aria256Init(ctx256, key256)

benchmark("ARIA-256 Encrypt"):
  for i in 1 .. 1_000_000:
    aria256Encrypt(ctx256, text256, text128)

benchmark("ARIA-256 Decrypt"):
  for i in 1 .. 1_000_000:
    aria256Decrypt(ctx256, text256, text128)
