import "../../src/nim_cryptkit/block/aes"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

echo "AES Series Test"

var ctx128: AES128Ctx
var key128: array[16, uint8] = [
  0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8, 0x88'u8, 0x99'u8, 0xAA'u8, 0xBB'u8, 0xCC'u8, 0xDD'u8, 0xEE'u8, 0xFF'u8
]
var text128: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8 
]

aes128Init(ctx128, key128)
echo "---"
echo "AES-128 Test"
var pt128: string = binToHex(text128)
echo "AES-128 Key Standard : ", binToHex(key128)
echo "AES-128 Plain Text Standard : ", pt128
aes128Encrypt(ctx128, text128, text128)
echo "AES-128 Cipher Text Standard : FDE4FBAE4A09E020EFF722969F83832B"
var ct128: string = binToHex(text128)
echo "AES-128 Cipher Text State : ", ct128
doAssert ct128 == "FDE4FBAE4A09E020EFF722969F83832B", "AES-128 Encrypt Wrong!"
aes128Decrypt(ctx128, text128, text128)
echo "AES-128 Plain Text State : ", binToHex(text128)
doAssert pt128 == binToHex(text128), "AES-128 Decrypt Wrong!"


var ctx192: AES192Ctx
var key192: array[24, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
  0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8
]
var text192: array[16, uint8] = [
  0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8,
  0x88'u8, 0x99'u8, 0xAA'u8, 0xBB'u8, 0xCC'u8, 0xDD'u8, 0xEE'u8, 0xFF'u8
]
aes192Init(ctx192, key192)
echo "---"
echo "AES-192 Test"
echo "AES-192 Key Standard : ", binToHex(key192)
var pt192: string = binToHex(text192)
echo "AES-192 Plain Text Standard : ", pt192
aes192Encrypt(ctx192, text192, text192)
var ct192: string = binToHex(text192)
echo "AES-192 Cipher Text Standard : DDA97CA4864CDFE06EAF70A0EC0D7191"
echo "AES-192 Cipher Text State : ", ct192
doAssert ct192 == "DDA97CA4864CDFE06EAF70A0EC0D7191", "AES-192 Encrypt Wrong!"
aes192Decrypt(ctx192, text192, text192)
echo "AES-192 Plain Text State : ", binToHex(text192)
doAssert pt192 == binToHex(text192), "AES-192 Decrypt Wrong!"

var ctx256: AES256Ctx
var key256: array[32, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
  0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8,
  0x18'u8, 0x19'u8, 0x1A'u8, 0x1B'u8, 0x1C'u8, 0x1D'u8, 0x1E'u8, 0x1F'u8
]
var text256: array[16, uint8] = [
  0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8,
  0x88'u8, 0x99'u8, 0xAA'u8, 0xBB'u8, 0xCC'u8, 0xDD'u8, 0xEE'u8, 0xFF'u8
]
var encrypt256: array[16, uint8]
var decrypt256: array[16, uint8]

aes256Init(ctx256, key256)
echo "---"
echo "AES-256 Test"
var pt256: string = binToHex(text256)
echo "AES-256 Key Standard : ", binToHex(key256)
echo "AES-256 Plain Text Standard : ", pt256
aes256Encrypt(ctx256, text256, encrypt256)
echo "AES-256 Cipher Text Standard : 8EA2B7CA516745BFEAFC49904B496089"
var ct256: string = binToHex(encrypt256)
echo "AES-256 Cipher Text State : ", ct256
doAssert ct256 == "8EA2B7CA516745BFEAFC49904B496089", "AES-256 Encrypt Wrong!"
aes256Decrypt(ctx256, encrypt256, decrypt256)
echo "AES-256 Plain Text State : ", binToHex(decrypt256)
doAssert pt256 == binToHex(decrypt256), "AES-256 Decrypt Wrong!"
  

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("AES-128 Init"):
  for i in 1 .. 1_000_000:
    aes128Init(ctx128, key128)

benchmark("AES-128 Encrypt"):
  for i in 1 .. 1_000_000:
    aes128Encrypt(ctx128, text128, text128)

benchmark("AES-128 Decrypt"):
  for i in 1 .. 1_000_000:
    aes128Decrypt(ctx128, text128, text128)

benchmark("AES-192 Init"):
  for i in 1 .. 1_000_000:
    aes192Init(ctx192, key192)

benchmark("AES-192 Encrypt"):
  for i in 1 .. 1_000_000:
    aes192Encrypt(ctx192, text192, text192)

benchmark("AES-192 Decrypt"):
  for i in 1 .. 1_000_000:
    aes192Decrypt(ctx192, text192, text192)

benchmark("AES-256 Init"):
  for i in 1 .. 1_000_000:
    aes256Init(ctx256, key256)

benchmark("AES-256 Encrypt"):
  for i in 1 .. 1_000_000:
    aes256Encrypt(ctx256, text256, text256)

benchmark("AES-256 Decrypt"):
  for i in 1 .. 1_000_000:
    aes256Decrypt(ctx256, text256, text256)
