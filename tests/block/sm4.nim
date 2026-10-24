import "../../src/nim_cryptkit/block/sm4"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

var key: array[16, uint8] = [
  0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8,
  0x88'u8, 0x99'u8, 0xAA'u8, 0xBB'u8, 0xCC'u8, 0xDD'u8, 0xEE'u8, 0xFF'u8
]

var text: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

var ctx: SM4Ctx

echo "--- Test : SM4 ---"
let pt = binToHex(text)

echo "SM4 Key : ", binToHex(key)
echo "SM4 Plain Text Standard : ", pt
sm4Init(ctx, key)
sm4Encrypt(ctx, text, text)
echo "SM4 Cipher Text Standard : 72EBA3039947E17092E922D7CDA38EA0"
let ct = binToHex(text)
echo "SM4 Cipher Text State : ", ct
doAssert ct == "72EBA3039947E17092E922D7CDA38EA0", "SM4 Encrypt Wrong!"
sm4Decrypt(ctx, text, text)
echo "SM4 Plain Text State : ", binToHex(text)
doAssert binToHex(text) == pt, "SM4 Decrypt Wrong!"
echo ""

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("SM4 Init"):
  for i in 1 .. 1_000_000:
    sm4Init(ctx, key)

benchmark("SM4 Encrypt"):
  for i in 1 .. 1_000_000:
    sm4Encrypt(ctx, text, text)

benchmark("SM4 Decrypt"):
  for i in 1 .. 1_000_000:
    sm4Decrypt(ctx, text, text)
