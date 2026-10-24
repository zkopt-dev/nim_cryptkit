import "../../src/nim_cryptkit/block/cast128"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var ctx: CAST128Ctx
var key: array[16, uint8] = [
  0x01'u8, 0x23'u8, 0x45'u8, 0x67'u8, 0x12'u8, 0x34'u8, 0x56'u8, 0x78'u8,
  0x23'u8, 0x45'u8, 0x67'u8, 0x89'u8, 0x34'u8, 0x56'u8, 0x78'u8, 0x9a'u8
]
var text: array[8, uint8] = [
  0x01'u8, 0x23'u8, 0x45'u8, 0x67'u8, 0x89'u8, 0xab'u8, 0xcd'u8, 0xef'u8
]

echo "--- Test : CAST-128 ---"
var pt: string = binToHex(text)
echo "CAST-128 Key Standard : ", binToHex(key)
echo "CAST-128 Plain Text Standard : ", pt
cast128Init(ctx, key)
cast128Encrypt(ctx, text, text)
echo "CAST-128 Cipher Text Standard : 238B4FE5847E44B2"
var ct: string = binToHex(text)
echo "CAST-128 Cipher Text State : ", ct
doAssert ct == "238B4FE5847E44B2", "CAST-128 Encrypt Wrong!"
cast128Decrypt(ctx, text, text)
echo "CAST-128 Plain Text State : ", binToHex(text)
doAssert pt == binToHex(text), "CAST-128 Decrypt Wrong!"

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("CAST128 Init"):
  for i in 1 .. 1_000_000:
    cast128Init(ctx, key)
  
benchmark("CAST128 Encrypt"):
  for i in 1 .. 1_000_000:
    cast128Encrypt(ctx, text, text)

benchmark("CAST128 Decrypt"):
  for i in 1 .. 1_000_000:
    cast128Decrypt(ctx, text, text)
