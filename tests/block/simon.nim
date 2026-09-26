import "../../src/nim_cryptkit/block/simon"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

import "../../src/nim_cryptkit/block/simon"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

# ============================================================
# Simon-64/96 Test
# ============================================================

var simon64_96Ctx: Simon64_96Ctx

var key64_96: array[12, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x08'u8, 0x09'u8, 0x0a'u8, 0x0b'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8
]

var text64_96: array[8, uint8] = [
  0x63'u8, 0x6c'u8, 0x69'u8, 0x6e'u8, 0x67'u8, 0x20'u8, 0x72'u8, 0x6f'u8
]

echo "--- Test : Simon-64/96 ---"
let pt64_96 = binToHex(text64_96)
echo "Simon-64/96 Key : ", binToHex(key64_96)
echo "Simon-64/96 Plain Text Standard : ", pt64_96
simon64_96Init(simon64_96Ctx, key64_96)
simon64_96Encrypt(simon64_96Ctx, text64_96, text64_96)
echo "Simon-64/96 Cipher Text Standard : C88F1A117FE2A25C"
let ct64_96 = binToHex(text64_96)
echo "Simon-64/96 Cipher Text State : ", ct64_96
doAssert ct64_96 == "C88F1A117FE2A25C", "Simon-64/96 Encrypt Wrong!"
simon64_96Decrypt(simon64_96Ctx, text64_96, text64_96)
echo "Simon-64/96 Plain Text State : ", binToHex(text64_96)
doAssert binToHex(text64_96) == pt64_96, "Simon-64/96 Decrypt Wrong!"
echo ""


# ============================================================
# Simon-64/128 Test
# ============================================================

var simon64_128Ctx: Simon64_128Ctx

var key64_128: array[16, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x08'u8, 0x09'u8, 0x0a'u8, 0x0b'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x18'u8, 0x19'u8, 0x1a'u8, 0x1b'u8
]

var text64_128: array[8, uint8] = [
  0x75'u8, 0x6e'u8, 0x64'u8, 0x20'u8, 0x6c'u8, 0x69'u8, 0x6b'u8, 0x65'u8
]

echo "--- Test : Simon-64/128 ---"
let pt64_128 = binToHex(text64_128)
echo "Simon-64/128 Key : ", binToHex(key64_128)
echo "Simon-64/128 Plain Text Standard : ", pt64_128
simon64_128Init(simon64_128Ctx, key64_128)
simon64_128Encrypt(simon64_128Ctx, text64_128, text64_128)
echo "Simon-64/128 Cipher Text Standard : 7AA0DFB920FCC844"
let ct64_128 = binToHex(text64_128)
echo "Simon-64/128 Cipher Text State : ", ct64_128
doAssert ct64_128 == "7AA0DFB920FCC844", "Simon-64/128 Encrypt Wrong!"
simon64_128Decrypt(simon64_128Ctx, text64_128, text64_128)
echo "Simon-64/128 Plain Text State : ", binToHex(text64_128)
doAssert binToHex(text64_128) == pt64_128, "Simon-64/128 Decrypt Wrong!"
echo ""


# ============================================================
# Simon-128/128 Test
# ============================================================

var simon128_128Ctx: Simon128_128Ctx

var key128_128: array[16, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
  0x08'u8, 0x09'u8, 0x0a'u8, 0x0b'u8, 0x0c'u8, 0x0d'u8, 0x0e'u8, 0x0f'u8
]

var text128_128: array[16, uint8] = [
  0x20'u8, 0x74'u8, 0x72'u8, 0x61'u8, 0x76'u8, 0x65'u8, 0x6c'u8, 0x6c'u8,
  0x65'u8, 0x72'u8, 0x73'u8, 0x20'u8, 0x64'u8, 0x65'u8, 0x73'u8, 0x63'u8
]

echo "--- Test : Simon-128/128 ---"
let pt128_128 = binToHex(text128_128)
echo "Simon-128/128 Key : ", binToHex(key128_128)
echo "Simon-128/128 Plain Text Standard : ", pt128_128
simon128_128Init(simon128_128Ctx, key128_128)
simon128_128Encrypt(simon128_128Ctx, text128_128, text128_128)
echo "Simon-128/128 Cipher Text Standard : BC0B4EF82A83AA653FFE541E1E1B6849"
let ct128_128 = binToHex(text128_128)
echo "Simon-128/128 Cipher Text State : ", ct128_128
doAssert ct128_128 == "BC0B4EF82A83AA653FFE541E1E1B6849", "Simon-128/128 Encrypt Wrong!"
simon128_128Decrypt(simon128_128Ctx, text128_128, text128_128)
echo "Simon-128/128 Plain Text State : ", binToHex(text128_128)
doAssert binToHex(text128_128) == pt128_128, "Simon-128/128 Decrypt Wrong!"
echo ""


# ============================================================
# Simon-128/192 Test
# ============================================================

var simon128_192Ctx: Simon128_192Ctx

var keySimon128_192: array[24, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
  0x08'u8, 0x09'u8, 0x0a'u8, 0x0b'u8, 0x0c'u8, 0x0d'u8, 0x0e'u8, 0x0f'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8
]

var textSimon128_192: array[16, uint8] = [
  0x72'u8, 0x69'u8, 0x62'u8, 0x65'u8, 0x20'u8, 0x77'u8, 0x68'u8, 0x65'u8,
  0x6e'u8, 0x20'u8, 0x74'u8, 0x68'u8, 0x65'u8, 0x72'u8, 0x65'u8, 0x20'u8
]

echo "--- Test : Simon-128/192 ---"
let ptSimon128_192 = binToHex(textSimon128_192)
echo "Simon-128/192 Key : ", binToHex(keySimon128_192)
echo "Simon-128/192 Plain Text Standard : ", ptSimon128_192
simon128_192Init(simon128_192Ctx, keySimon128_192)
simon128_192Encrypt(simon128_192Ctx, textSimon128_192, textSimon128_192)
echo "Simon-128/192 Cipher Text Standard : 5BB897256E8D9C6C4F0DDCFCEF61ACC4"
let ctSimon128_192 = binToHex(textSimon128_192)
echo "Simon-128/192 Cipher Text State : ", ctSimon128_192
doAssert ctSimon128_192 == "5BB897256E8D9C6C4F0DDCFCEF61ACC4", "Simon-128/192 Encrypt Wrong!"
simon128_192Decrypt(simon128_192Ctx, textSimon128_192, textSimon128_192)
echo "Simon-128/192 Plain Text State : ", binToHex(textSimon128_192)
doAssert binToHex(textSimon128_192) == ptSimon128_192, "Simon-128/192 Decrypt Wrong!"
echo ""


# ============================================================
# Simon-128/256 Test
# ============================================================

var simon128_256Ctx: Simon128_256Ctx

var keySimon128_256: array[32, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
  0x08'u8, 0x09'u8, 0x0a'u8, 0x0b'u8, 0x0c'u8, 0x0d'u8, 0x0e'u8, 0x0f'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8,
  0x18'u8, 0x19'u8, 0x1a'u8, 0x1b'u8, 0x1c'u8, 0x1d'u8, 0x1e'u8, 0x1f'u8
]

var textSimon128_256: array[16, uint8] = [
  0x69'u8, 0x73'u8, 0x20'u8, 0x61'u8, 0x20'u8, 0x73'u8, 0x69'u8, 0x6d'u8,
  0x6f'u8, 0x6f'u8, 0x6d'u8, 0x20'u8, 0x69'u8, 0x6e'u8, 0x20'u8, 0x74'u8
]

echo "--- Test : Simon-128/256 ---"
let ptSimon128_256 = binToHex(textSimon128_256)
echo "Simon-128/256 Key : ", binToHex(keySimon128_256)
echo "Simon-128/256 Plain Text Standard : ", ptSimon128_192
simon128_256Init(simon128_256Ctx, keySimon128_256)
simon128_256Encrypt(simon128_256Ctx, textSimon128_256, textSimon128_256)
echo "Simon-128/256 Cipher Text Standard : 68B8E7EF872AF73BA0A3C8AF79552B8D"
let ctSimon128_256 = binToHex(textSimon128_256)
echo "Simon-128/256 Cipher Text State : ", ctSimon128_256
doAssert ctSimon128_256 == "68B8E7EF872AF73BA0A3C8AF79552B8D", "Simon-128/256 Encrypt Wrong!"
simon128_256Decrypt(simon128_256Ctx, textSimon128_256, textSimon128_256)
echo "Simon-128/256 Plain Text State : ", binToHex(textSimon128_256)
doAssert binToHex(textSimon128_256) == ptSimon128_256, "Simon-128/256 Decrypt Wrong!"
echo ""


# ============================================================
# Benchmark
# ============================================================

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

# Simon-64/96 Benchmark
benchmark("Simon-64/96 Init"):
  for i in 1 .. 1_000_000:
    simon64_96Init(simon64_96Ctx, key64_96)

benchmark("Simon-64/96 Encrypt"):
  for i in 1 .. 1_000_000:
    simon64_96Encrypt(simon64_96Ctx, text64_96, text64_96)

benchmark("Simon-64/96 Decrypt"):
  for i in 1 .. 1_000_000:
    simon64_96Decrypt(simon64_96Ctx, text64_96, text64_96)

# Simon-64/128 Benchmark
benchmark("Simon-64/128 Init"):
  for i in 1 .. 1_000_000:
    simon64_128Init(simon64_128Ctx, key64_128)

benchmark("Simon-64/128 Encrypt"):
  for i in 1 .. 1_000_000:
    simon64_128Encrypt(simon64_128Ctx, text64_128, text64_128)

benchmark("Simon-64/128 Decrypt"):
  for i in 1 .. 1_000_000:
    simon64_128Decrypt(simon64_128Ctx, text64_128, text64_128)

# Simon-128/128 Benchmark
benchmark("Simon-128/128 Init"):
  for i in 1 .. 1_000_000:
    simon128_128Init(simon128_128Ctx, key128_128)

benchmark("Simon-128/128 Encrypt"):
  for i in 1 .. 1_000_000:
    simon128_128Encrypt(simon128_128Ctx, text128_128, text128_128)

benchmark("Simon-128/128 Decrypt"):
  for i in 1 .. 1_000_000:
    simon128_128Decrypt(simon128_128Ctx, text128_128, text128_128)

# Simon-128/192 Benchmark
benchmark("Simon-128/192 Init"):
  for i in 1 .. 1_000_000:
    simon128_192Init(simon128_192Ctx, keySimon128_192)

benchmark("Simon-128/192 Encrypt"):
  for i in 1 .. 1_000_000:
    simon128_192Encrypt(simon128_192Ctx, textSimon128_192, textSimon128_192)

benchmark("Simon-128/192 Decrypt"):
  for i in 1 .. 1_000_000:
    simon128_192Decrypt(simon128_192Ctx, textSimon128_192, textSimon128_192)

# Simon-128/256 Benchmark
benchmark("Simon-128/256 Init"):
  for i in 1 .. 1_000_000:
    simon128_256Init(simon128_256Ctx, keySimon128_256)

benchmark("Simon-128/256 Encrypt"):
  for i in 1 .. 1_000_000:
    simon128_256Encrypt(simon128_256Ctx, textSimon128_256, textSimon128_256)

benchmark("Simon-128/256 Decrypt"):
  for i in 1 .. 1_000_000:
    simon128_256Decrypt(simon128_256Ctx, textSimon128_256, textSimon128_256)
