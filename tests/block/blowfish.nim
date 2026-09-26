import "../../src/nim_cryptkit/block/blowfish"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]


var key: array[8, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

var text: array[8, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

var ctx: BlowfishCtx
blowfishInit(ctx, key)
echo "--- Test : Blowfish ---"
var pt: string = binToHex(text)
echo "Blowfish Key Standard : ", binToHex(key)
echo "Blowfish Plain Text Standard : ", pt
blowfishEncrypt(ctx, text, text)
echo "Blowfish Standard Cipher Text : 4EF997456198DD78"
var ct: string = binToHex(text)
echo "Blowfish Cipher Text State : ", ct
doAssert ct == "4EF997456198DD78", "Blowfish Encrypt Wrong!"
blowfishDecrypt(ctx, text, text)
echo "Blowfish Plain Text State : ", binToHex(text)
doAssert pt == binToHex(text), "Blowfish Decrypt Wrong!"

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("Blowfish Init"):
  for i in 1 .. 1_000_000:
    blowfishInit(ctx, key)

benchmark("Blowfish Encrypt"):
  for i in 1 .. 1_000_000:
    blowfishEncrypt(ctx, text, text)

benchmark("Blowfish Decrypt"):
  for i in 1 .. 1_000_000:
    blowfishDecrypt(ctx, text, text)
