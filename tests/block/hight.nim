import "../../src/nim_cryptkit/block/hight"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var key: array[16, uint8] = [0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8]
var text: array[8, uint8] = [0x80'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8]
var ctx: HIGHTCtx

echo "--- Test : HIGHT ---"
var pt: string = binToHex(text)
echo "HIGHT Key Standard : ", binToHex(key)
echo "HIGHT Plain Text Standard : ", pt
hightInit(ctx, key)
hightEncrypt(ctx, text, text)
echo "HIGHT Cipher Text Standard : D2B366EE33648CCE"
var ct: string = binToHex(text)
echo "HIGHT Cipher Text State : ", ct
doAssert ct == "D2B366EE33648CCE", "HIGHT Encrypt Wrong!"
hightDecrypt(ctx, text, text)
echo "HIGHT Plain Text State : ", binToHex(text)
doAssert pt == binToHex(text), "HIGHT Decrypt Wrong!"

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("HIGHT Init"):
  for i in 1 .. 1_000_000:
    hightInit(ctx, key)

benchmark("HIGHT Encrypt"):
  for i in 1 .. 1_000_000:
    hightEncrypt(ctx, text, text)
benchmark("HIGHT Decrypt"):
  for i in 1 .. 1_000_000:
    hightDecrypt(ctx, text, text)
