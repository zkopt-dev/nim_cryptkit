import "../../src/nim_cryptkit/block/gost"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var ctx: GOSTCtx
var key: array[32, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8, 0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8, 0x18'u8, 0x19'u8, 0x1A'u8, 0x1B'u8, 0x1C'u8, 0x1D'u8, 0x1E'u8, 0x1F'u8
]
var text: array[8, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

echo "--- Test : GOST ---"
var pt: string = binToHex(text)
echo "GOST Key Standard : ", binToHex(key)
echo "GOST SBox : E-Z"
echo "GOST Plain Text Standard : ", pt
gostInit(ctx, key)
gostEncrypt(ctx, text, text)
echo "GOST Cipher Text Standard : 12372CEF8D0FA429"
var ct: string = binToHex(text)
echo "GOST Cipher Text State : ", ct
doAssert ct == "12372CEF8D0FA429", "GOST Encrypt Wrong!"
gostDecrypt(ctx, text, text)
echo "GOST Plain Text State : ", binToHex(text)
doAssert pt == binToHex(text), "GOST Decrypt Wrong!"

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("GOST Init"):
  for i in 1 .. 1_000_000:
    gostInit(ctx, key)

benchmark("GOST Encrypt"):
  for i in 1 .. 1_000_000:
    gostEncrypt(ctx, text, text)

benchmark("GOST Encrypt"):
  for i in 1 .. 1_000_000:
    gostDecrypt(ctx, text, text)
