import "../../src/nim_cryptkit/block/des"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var ctx: DESCtx
var key: array[8, uint8] = [
  0x01'u8, 0x23'u8, 0x45'u8, 0x67'u8, 0x89'u8, 0xab'u8, 0xcd'u8, 0xef'u8
]
var text: array[8, uint8] = [
  0x4e'u8, 0x6f'u8, 0x77'u8, 0x20'u8, 0x69'u8, 0x73'u8, 0x20'u8, 0x74'u8
]

echo "--- Test : DES ---"
var pt: string = binToHex(text)
echo "DES Key Standard : ", binToHex(key)
echo "DES Plain Text Standard : ", pt
desInit(ctx, key)
desEncrypt(ctx, text, text)
echo "DES Cipher Text Standard : 3FA40E8A984D4815"
var ct: string = binToHex(text)
echo "DES Cipher Text State : ", ct
doAssert ct == "3FA40E8A984D4815", "DES Encrypt Wrong!"
desDecrypt(ctx, text, text)
echo "DES Plain Text State : ", binToHex(text)
doAssert pt == binToHex(text), "DES Decrypt Wrong!"

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("DES Init"):
  for i in 1 .. 1_000_000:
    desInit(ctx, key)

benchmark("DES Encrypt"):
  for i in 1 .. 1_000_000:
    desEncrypt(ctx, text, text)

benchmark("DES Decrypt"):
  for i in 1 .. 1_000_000:
    desDecrypt(ctx, text, text)
