import "../../src/nim_cryptkit/block/idea"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var key: array[16, uint8] = [
  0x00'u8, 0x01'u8, 0x00'u8, 0x02'u8, 0x00'u8, 0x03'u8, 0x00'u8, 0x04'u8,
  0x00'u8, 0x05'u8, 0x00'u8, 0x06'u8, 0x00'u8, 0x07'u8, 0x00'u8, 0x08'u8,
]

var text: array[8, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x01'u8, 0x00'u8, 0x02'u8, 0x00'u8, 0x03'u8
]

var ctx: IDEACtx
echo "--- Test : IDEA ---"
var pt: string = binToHex(text)
echo "IDEA Key Standard : ", binToHex(key)
echo "IDEA Plain Text Standard : ", pt
ideaInit(ctx, key)
ideaEncrypt(ctx, text, text)
echo "IDEA Cipher Text Standard : 11FBED2B01986DE5"
var ct: string = binToHex(text)
echo "IDEA Cipher Text State : ", ct
doAssert ct == "11FBED2B01986DE5", "IDEA Encrypt Wrong!"
ideaDecrypt(ctx, text, text)
echo "IDEA Plain Text State : ", binToHex(text)
doAssert pt == binToHex(text), "IDEA Decrypt Wrong!"

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("IDEA Init"):
  for i in 1 .. 1_000_000:
    ideaInit(ctx, key)

benchmark("IDEA Encrypt"):
  for i in 1 .. 1_000_000:
    ideaEncrypt(ctx, text, text)

benchmark("IDEA Decrypt"):
  for i in 1 .. 1_000_000:
    ideaDecrypt(ctx, text, text) 
