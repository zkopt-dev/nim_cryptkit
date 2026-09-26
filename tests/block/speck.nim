import "../../src/nim_cryptkit/block/speck"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

# ============================================================
# Speck-64/96 Test
# ============================================================

var speck64_96Ctx: Speck64_96Ctx

var keySpeck64_96: array[12, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x08'u8, 0x09'u8, 0x0a'u8, 0x0b'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8
]

var textSpeck64_96: array[8, uint8] = [
  0x65'u8, 0x61'u8, 0x6e'u8, 0x73'u8, 0x20'u8, 0x46'u8, 0x61'u8, 0x74'u8
]

echo "--- Test : Speck-64/96 ---"
let ptSpeck64_96 = binToHex(textSpeck64_96)
echo "Speck-64/96 Key : ", binToHex(keySpeck64_96)
echo "Speck-64/96 Plain Text Standard : ", ptSpeck64_96
speck64_96Init(speck64_96Ctx, keySpeck64_96)
speck64_96Encrypt(speck64_96Ctx, textSpeck64_96, textSpeck64_96)
echo "Speck-64/96 Cipher Text Standard : 6C947541EC52799F"
let ctSpeck64_96 = binToHex(textSpeck64_96)
echo "Speck-64/96 Cipher Text State : ", ctSpeck64_96
doAssert ctSpeck64_96 == "6C947541EC52799F", "Speck-64/96 Encrypt Wrong!"
speck64_96Decrypt(speck64_96Ctx, textSpeck64_96, textSpeck64_96)
echo "Speck-64/96 Plain Text State : ", binToHex(textSpeck64_96)
doAssert binToHex(textSpeck64_96) == ptSpeck64_96, "Speck-64/96 Decrypt Wrong!"
echo ""


# ============================================================
# Speck-64/128 Test
# ============================================================

var speck64_128Ctx: Speck64_128Ctx

var keySpeck64_128: array[16, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x08'u8, 0x09'u8, 0x0a'u8, 0x0b'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x18'u8, 0x19'u8, 0x1a'u8, 0x1b'u8
]

var textSpeck64_128: array[8, uint8] = [
  0x2d'u8, 0x43'u8, 0x75'u8, 0x74'u8, 0x74'u8, 0x65'u8, 0x72'u8, 0x3b'u8
]

echo "--- Test : Speck-64/128 ---"
let ptSpeck64_128 = binToHex(textSpeck64_128)
echo "Speck-64/128 Key : ", binToHex(keySpeck64_128)
echo "Speck-64/128 Plain Text Standard : ", ptSpeck64_128
speck64_128Init(speck64_128Ctx, keySpeck64_128)
speck64_128Encrypt(speck64_128Ctx, textSpeck64_128, textSpeck64_128)
echo "Speck-64/128 Cipher Text Standard : 8B024E4548A56F8C"
let ctSpeck64_128 = binToHex(textSpeck64_128)
echo "Speck-64/128 Cipher Text State : ", ctSpeck64_128
doAssert ctSpeck64_128 == "8B024E4548A56F8C", "Speck-64/128 Encrypt Wrong!"
speck64_128Decrypt(speck64_128Ctx, textSpeck64_128, textSpeck64_128)
echo "Speck-64/128 Plain Text State : ", binToHex(textSpeck64_128)
doAssert binToHex(textSpeck64_128) == ptSpeck64_128, "Speck-64/128 Decrypt Wrong!"
echo ""


# ============================================================
# Speck-128/128 Test
# ============================================================

var speck128_128Ctx: Speck128_128Ctx

var keySpeck128_128: array[16, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
  0x08'u8, 0x09'u8, 0x0a'u8, 0x0b'u8, 0x0c'u8, 0x0d'u8, 0x0e'u8, 0x0f'u8
]

var textSpeck128_128: array[16, uint8] = [
  0x20'u8, 0x6d'u8, 0x61'u8, 0x64'u8, 0x65'u8, 0x20'u8, 0x69'u8, 0x74'u8,
  0x20'u8, 0x65'u8, 0x71'u8, 0x75'u8, 0x69'u8, 0x76'u8, 0x61'u8, 0x6c'u8
]

echo "--- Test : Speck-128/128 ---"
let ptSpeck128_128 = binToHex(textSpeck128_128)
echo "Speck-128/128 Key : ", binToHex(keySpeck128_128)
echo "Speck-128/128 Plain Text Standard : ", ptSpeck128_128
speck128_128Init(speck128_128Ctx, keySpeck128_128)
speck128_128Encrypt(speck128_128Ctx, textSpeck128_128, textSpeck128_128)
echo "Speck-128/128 Cipher Text Standard : 180D575CDFFE60786532787951985DA6"
let ctSpeck128_128 = binToHex(textSpeck128_128)
echo "Speck-128/128 Cipher Text State : ", ctSpeck128_128
doAssert ctSpeck128_128 == "180D575CDFFE60786532787951985DA6", "Speck-128/128 Encrypt Wrong!"
speck128_128Decrypt(speck128_128Ctx, textSpeck128_128, textSpeck128_128)
echo "Speck-128/128 Plain Text State : ", binToHex(textSpeck128_128)
doAssert binToHex(textSpeck128_128) == ptSpeck128_128, "Speck-128/128 Decrypt Wrong!"
echo ""


# ============================================================
# Speck-128/192 Test
# ============================================================

var speck128_192Ctx: Speck128_192Ctx

var keySpeck128_192: array[24, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
  0x08'u8, 0x09'u8, 0x0a'u8, 0x0b'u8, 0x0c'u8, 0x0d'u8, 0x0e'u8, 0x0f'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8
]

var textSpeck128_192: array[16, uint8] = [
  0x65'u8, 0x6e'u8, 0x74'u8, 0x20'u8, 0x74'u8, 0x6f'u8, 0x20'u8, 0x43'u8,
  0x68'u8, 0x69'u8, 0x65'u8, 0x66'u8, 0x20'u8, 0x48'u8, 0x61'u8, 0x72'u8
]

echo "--- Test : Speck-128/192 ---"
let ptSpeck128_192 = binToHex(textSpeck128_192)
echo "Speck-128/192 Key : ", binToHex(keySpeck128_192)
echo "Speck-128/192 Plain Text Standard : ", ptSpeck128_192
speck128_192Init(speck128_192Ctx, keySpeck128_192)
speck128_192Encrypt(speck128_192Ctx, textSpeck128_192, textSpeck128_192)
echo "Speck-128/192 Cipher Text Standard : 86183CE05D18BCF9665513133ACFE41B"
let ctSpeck128_192 = binToHex(textSpeck128_192)
echo "Speck-128/192 Cipher Text State : ", ctSpeck128_192
doAssert ctSpeck128_192 == "86183CE05D18BCF9665513133ACFE41B", "Speck-128/192 Encrypt Wrong!"
speck128_192Decrypt(speck128_192Ctx, textSpeck128_192, textSpeck128_192)
echo "Speck-128/192 Plain Text State : ", binToHex(textSpeck128_192)
doAssert binToHex(textSpeck128_192) == ptSpeck128_192, "Speck-128/192 Decrypt Wrong!"
echo ""


# ============================================================
# Speck-128/256 Test
# ============================================================

var speck128_256Ctx: Speck128_256Ctx

var keySpeck128_256: array[32, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
  0x08'u8, 0x09'u8, 0x0a'u8, 0x0b'u8, 0x0c'u8, 0x0d'u8, 0x0e'u8, 0x0f'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8,
  0x18'u8, 0x19'u8, 0x1a'u8, 0x1b'u8, 0x1c'u8, 0x1d'u8, 0x1e'u8, 0x1f'u8
]

var textSpeck128_256: array[16, uint8] = [
  0x70'u8, 0x6f'u8, 0x6f'u8, 0x6e'u8, 0x65'u8, 0x72'u8, 0x2e'u8, 0x20'u8,
  0x49'u8, 0x6e'u8, 0x20'u8, 0x74'u8, 0x68'u8, 0x6f'u8, 0x73'u8, 0x65'u8
]

echo "--- Test : Speck-128/256 ---"
let ptSpeck128_256 = binToHex(textSpeck128_256)
echo "Speck-128/256 Key : ", binToHex(keySpeck128_256)
echo "Speck-128/256 Plain Text Standard : ", ptSpeck128_256
speck128_256Init(speck128_256Ctx, keySpeck128_256)
speck128_256Encrypt(speck128_256Ctx, textSpeck128_256, textSpeck128_256)
echo "Speck-128/256 Cipher Text Standard : 438F189C8DB4EE4E3EF5C00504010941"
let ctSpeck128_256 = binToHex(textSpeck128_256)
echo "Speck-128/256 Cipher Text State : ", ctSpeck128_256
doAssert ctSpeck128_256 == "438F189C8DB4EE4E3EF5C00504010941", "Speck-128/256 Encrypt Wrong!"
speck128_256Decrypt(speck128_256Ctx, textSpeck128_256, textSpeck128_256)
echo "Speck-128/256 Plain Text State : ", binToHex(textSpeck128_256)
doAssert binToHex(textSpeck128_256) == ptSpeck128_256, "Speck-128/256 Decrypt Wrong!"
echo ""


# ============================================================
# Benchmark
# ============================================================

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

# Speck-64/96 Benchmark
benchmark("Speck-64/96 Init"):
  for i in 1 .. 1_000_000:
    speck64_96Init(speck64_96Ctx, keySpeck64_96)

benchmark("Speck-64/96 Encrypt"):
  for i in 1 .. 1_000_000:
    speck64_96Encrypt(speck64_96Ctx, textSpeck64_96, textSpeck64_96)

benchmark("Speck-64/96 Decrypt"):
  for i in 1 .. 1_000_000:
    speck64_96Decrypt(speck64_96Ctx, textSpeck64_96, textSpeck64_96)

# Speck-64/128 Benchmark
benchmark("Speck-64/128 Init"):
  for i in 1 .. 1_000_000:
    speck64_128Init(speck64_128Ctx, keySpeck64_128)

benchmark("Speck-64/128 Encrypt"):
  for i in 1 .. 1_000_000:
    speck64_128Encrypt(speck64_128Ctx, textSpeck64_128, textSpeck64_128)

benchmark("Speck-64/128 Decrypt"):
  for i in 1 .. 1_000_000:
    speck64_128Decrypt(speck64_128Ctx, textSpeck64_128, textSpeck64_128)

# Speck-128/128 Benchmark
benchmark("Speck-128/128 Init"):
  for i in 1 .. 1_000_000:
    speck128_128Init(speck128_128Ctx, keySpeck128_128)

benchmark("Speck-128/128 Encrypt"):
  for i in 1 .. 1_000_000:
    speck128_128Encrypt(speck128_128Ctx, textSpeck128_128, textSpeck128_128)

benchmark("Speck-128/128 Decrypt"):
  for i in 1 .. 1_000_000:
    speck128_128Decrypt(speck128_128Ctx, textSpeck128_128, textSpeck128_128)

# Speck-128/192 Benchmark
benchmark("Speck-128/192 Init"):
  for i in 1 .. 1_000_000:
    speck128_192Init(speck128_192Ctx, keySpeck128_192)

benchmark("Speck-128/192 Encrypt"):
  for i in 1 .. 1_000_000:
    speck128_192Encrypt(speck128_192Ctx, textSpeck128_192, textSpeck128_192)

benchmark("Speck-128/192 Decrypt"):
  for i in 1 .. 1_000_000:
    speck128_192Decrypt(speck128_192Ctx, textSpeck128_192, textSpeck128_192)

# Speck-128/256 Benchmark
benchmark("Speck-128/256 Init"):
  for i in 1 .. 1_000_000:
    speck128_256Init(speck128_256Ctx, keySpeck128_256)

benchmark("Speck-128/256 Encrypt"):
  for i in 1 .. 1_000_000:
    speck128_256Encrypt(speck128_256Ctx, textSpeck128_256, textSpeck128_256)

benchmark("Speck-128/256 Decrypt"):
  for i in 1 .. 1_000_000:
    speck128_256Decrypt(speck128_256Ctx, textSpeck128_256, textSpeck128_256)
