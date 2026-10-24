import "../../src/nim_cryptkit/block/lea"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var ctx128: LEA128Ctx
var key128: array[16, uint8] = [
  0x07'u8, 0xAB'u8, 0x63'u8, 0x05'u8, 0xB0'u8, 0x25'u8, 0xD8'u8, 0x3F'u8, 0x79'u8, 0xAD'u8, 0xDA'u8, 0xA6'u8, 0x3A'u8, 0xC8'u8, 0xAD'u8, 0x00'u8
]
var text128: array[16, uint8] = [
  0xF2'u8, 0x8A'u8, 0xE3'u8, 0x25'u8, 0x6A'u8, 0xAD'u8, 0x23'u8, 0xB4'u8, 0x15'u8, 0xE0'u8, 0x28'u8, 0x06'u8, 0x3B'u8, 0x61'u8, 0x0C'u8, 0x60'u8
]
lea128Init(ctx128, key128)
echo "--- Test : LEA-128 ---"
var pt128: string = binToHex(text128)
echo "LEA-128 Key Standard : ", binToHex(key128)
echo "LEA-128 Plain Text Standard : ", pt128
lea128Encrypt(ctx128, text128, text128)
echo "LEA-128 Cipher Text Standard : 64D908FCB7EBFEF90FD670106DE7C7C5"
var ct128: string = binToHex(text128)
echo "LEA-128 Cipher Text State : ", ct128
doAssert ct128 == "64D908FCB7EBFEF90FD670106DE7C7C5", "LEA-128 Encrypt Wrong!"
lea128Decrypt(ctx128, text128, text128)
echo "LEA-128 Plain Text State : ", binToHex(text128)
doAssert pt128 == binToHex(text128), "LEA-128 Decrypt Wrong!"

var ctx192: LEA192Ctx
var key192: array[24, uint8] = [
  0x14'u8, 0x37'u8, 0xAF'u8, 0x53'u8, 0x30'u8, 0x69'u8, 0xBD'u8, 0x75'u8, 0x25'u8, 0xC1'u8, 0x56'u8, 0x0C'u8, 0x78'u8, 0xBA'u8, 0xD2'u8, 0xA1'u8, 0xE5'u8, 0x34'u8, 0x67'u8, 0x1C'u8, 0x00'u8, 0x7E'u8, 0xF2'u8, 0x7C'u8
]
var text192: array[16, uint8] = [
  0x1C'u8, 0xB4'u8, 0xF4'u8, 0xCB'u8, 0x6C'u8, 0x4B'u8, 0xDB'u8, 0x51'u8, 0x68'u8, 0xEA'u8, 0x84'u8, 0x09'u8, 0x72'u8, 0x7B'u8, 0xFD'u8, 0x51'u8
]

lea192Init(ctx192, key192)
echo "--- Test : LEA-192 ---"
var pt192: string = binToHex(text192)
echo "LEA-192 Key Standard : ", binToHex(key192)
echo "LEA-192 Plain Text Standard : ", pt192
lea192Encrypt(ctx192, text192, text192)
echo "LEA-192 Cipher Text Standard : 69725C6DF912F8B70EB511E6663C5870"
var ct192: string = binToHex(text192)
echo "LEA-192 Cipher Text State : ", ct192
doAssert ct192 == "69725C6DF912F8B70EB511E6663C5870", "LEA-192 Encrypt Wrong!"
lea192Decrypt(ctx192, text192, text192)
echo "LEA-192 Plain Text State : ", binToHex(text192)
doAssert pt192 == binToHex(text192), "LEA-192 Decrypt Wrong!"

var ctx256: LEA256Ctx
var key256: array[32, uint8] = [
  0x4F'u8, 0x67'u8, 0x79'u8, 0xE2'u8, 0xBD'u8, 0x1E'u8, 0x93'u8, 0x19'u8, 0xC6'u8, 0x30'u8, 0x15'u8, 0xAC'u8, 0xFF'u8, 0xEF'u8, 0xD7'u8, 0xA7'u8,
  0x91'u8, 0xF0'u8, 0xED'u8, 0x59'u8, 0xDF'u8, 0x1B'u8, 0x70'u8, 0x07'u8, 0x69'u8, 0xFE'u8, 0x82'u8, 0xE2'u8, 0xF0'u8, 0x66'u8, 0x8C'u8, 0x35'u8
]
var text256: array[16, uint8] = [
  0xDC'u8, 0x31'u8, 0xCA'u8, 0xE3'u8, 0xDA'u8, 0x5E'u8, 0x0A'u8, 0x11'u8, 0xC9'u8, 0x66'u8, 0xB0'u8, 0x20'u8, 0xD7'u8, 0xCF'u8, 0xFE'u8, 0xDE'u8
]

lea256Init(ctx256, key256)
echo "--- Test : LEA-256 ---"
var pt256: string = binToHex(text256)
echo "LEA-256 Key Standard : ", binToHex(key256)
echo "LEA-256 Plain Text Standard : ", pt256
lea256Encrypt(ctx256, text256, text256)
echo "LEA-256 Cipher Text Standard : EDA2042098F667E857A02DB8CAA7DFF2"
var ct256: string = binToHex(text256)
echo "LEA-256 Cipher Text State : ", ct256
doAssert ct256 == "EDA2042098F667E857A02DB8CAA7DFF2", "LEA-256 Encrypt Wrong!"
lea256Decrypt(ctx256, text256, text256)
echo "LEA-256 Plain Text State : ", binToHex(text256)
doAssert pt256 == binToHex(text256), "LEA-256 Decrypt Wrong!"

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("LEA-128 Init"):
  for i in 1 .. 1_000_000:
    lea128Init(ctx128, key128)

benchmark("LEA-128 Encrypt"):
  for i in 1 .. 1_000_000:
    lea128Encrypt(ctx128, text128, text128)

benchmark("LEA-128 Decrypt"):
  for i in 1 .. 1_000_000:
    lea128Decrypt(ctx128, text128, text128)

benchmark("LEA-192 Init"):
  for i in 1 .. 1_000_000:
    lea192Init(ctx192, key192)

benchmark("LEA-192 Encrypt"):
  for i in 1 .. 1_000_000:
    lea192Encrypt(ctx192, text192, text192)

benchmark("LEA-192 Decrypt"):
  for i in 1 .. 1_000_000:
    lea192Decrypt(ctx192, text192, text192)

benchmark("LEA-256 Init"):
  for i in 1 .. 1_000_000:
    lea256Init(ctx256, key256)

benchmark("LEA-256 Encrypt"):
  for i in 1 .. 1_000_000:
    lea256Encrypt(ctx256, text256, text256)

benchmark("LEA-256 Decrypt"):
  for i in 1 .. 1_000_000:
    lea256Decrypt(ctx256, text256, text256)
