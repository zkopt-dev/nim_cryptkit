import "../../src/nim_cryptkit/block/skipjack"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

var key: array[10, uint8] = [
  0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8, 0x88'u8,
  0x99'u8, 0x00'u8
]

var text: array[8, uint8] = [
  0xaa'u8, 0xbb'u8, 0xcc'u8, 0xdd'u8, 0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8
]

var ctx: SkipjackCtx

echo "--- Test : Skipjack ---"
let pt = binToHex(text)

echo "Skipjack Key Standard : ", binToHex(key)
echo "Skipjack Plain Text Standard : ", pt
echo "Skipjack Cipher Text Standard : 00D3127AE2CA8725"

skipjackInit(ctx, key)
skipjackEncrypt(ctx, text, text)
let ct = binToHex(text)
echo "Skipjack Cipher Text State : ", ct
doAssert ct == "00D3127AE2CA8725", "Skipjack Encrypt Wrong!"
skipjackDecrypt(ctx, text, text)
echo "Skipjack Plain Text State : ", binToHex(text)
doAssert binToHex(text) == pt, "Skipjack Decrypt Wrong!"
echo ""

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("Skipjack Init"):
  for i in 1 .. 1_000_000:
    skipjackInit(ctx, key)

benchmark("Skipjack Encrypt"):
  for i in 1 .. 1_000_000:
    skipjackEncrypt(ctx, text, text)

benchmark("Skipjack Decrypt"):
  for i in 1 .. 1_000_000:
    skipjackDecrypt(ctx, text, text)
