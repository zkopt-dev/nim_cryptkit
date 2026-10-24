import "../../src/nim_cryptkit/block/seed"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

# =============================================================================
# SEED Test Vector B.1
# =============================================================================
var key1: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var text1: array[16, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
  0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8
]
var ctx1: SEEDCtx

echo "--- Test : SEED B.1 ---"
var pt1: string = binToHex(text1)
echo "SEED Key Standard : ", binToHex(key1)
echo "SEED Plain Text Standard : ", pt1
seedInit(ctx1, key1)
seedEncrypt(ctx1, text1, text1)
echo "SEED Cipher Text Standard : 5EBAC6E0054E166819AFF1CC6D346CDB"
var ct1: string = binToHex(text1)
echo "SEED Cipher Text State : ", ct1
doAssert ct1 == "5EBAC6E0054E166819AFF1CC6D346CDB", "SEED B.1 Encrypt Wrong!"
seedDecrypt(ctx1, text1, text1)
echo "SEED Plain Text State : ", binToHex(text1)
doAssert pt1 == binToHex(text1), "SEED B.1 Decrypt Wrong!"
echo ""

# =============================================================================
# SEED Test Vector B.2
# =============================================================================
var key2: array[16, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
  0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8
]
var text2: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var ctx2: SEEDCtx

echo "--- Test : SEED B.2 ---"
var pt2: string = binToHex(text2)
echo "SEED Key Standard : ", binToHex(key2)
echo "SEED Plain Text Standard : ", pt2
seedInit(ctx2, key2)
seedEncrypt(ctx2, text2, text2)
echo "SEED Cipher Text Standard : C11F22F20140505084483597E4370F43"
var ct2: string = binToHex(text2)
echo "SEED Cipher Text State : ", ct2
doAssert ct2 == "C11F22F20140505084483597E4370F43", "SEED B.2 Encrypt Wrong!"
seedDecrypt(ctx2, text2, text2)
echo "SEED Plain Text State : ", binToHex(text2)
doAssert pt2 == binToHex(text2), "SEED B.2 Decrypt Wrong!"
echo ""

# =============================================================================
# SEED Test Vector B.3
# =============================================================================
var key3: array[16, uint8] = [
  0x47'u8, 0x06'u8, 0x48'u8, 0x08'u8, 0x51'u8, 0xE6'u8, 0x1B'u8, 0xE8'u8,
  0x5D'u8, 0x74'u8, 0xBF'u8, 0xB3'u8, 0xFD'u8, 0x95'u8, 0x61'u8, 0x85'u8
]
var text3: array[16, uint8] = [
  0x83'u8, 0xA2'u8, 0xF8'u8, 0xA2'u8, 0x88'u8, 0x64'u8, 0x1F'u8, 0xB9'u8,
  0xA4'u8, 0xE9'u8, 0xA5'u8, 0xCC'u8, 0x2F'u8, 0x13'u8, 0x1C'u8, 0x7D'u8
]
var ctx3: SEEDCtx

echo "--- Test : SEED B.3 ---"
var pt3: string = binToHex(text3)
echo "SEED Key Standard : ", binToHex(key3)
echo "SEED Plain Text Standard : ", pt3
seedInit(ctx3, key3)
seedEncrypt(ctx3, text3, text3)
echo "SEED Cipher Text Standard : EE54D13EBCAE706D226BC3142CD40D4A"
var ct3: string = binToHex(text3)
echo "SEED Cipher Text State : ", ct3
doAssert ct3 == "EE54D13EBCAE706D226BC3142CD40D4A", "SEED B.3 Encrypt Wrong!"
seedDecrypt(ctx3, text3, text3)
echo "SEED Plain Text State : ", binToHex(text3)
doAssert pt3 == binToHex(text3), "SEED B.3 Decrypt Wrong!"
echo ""

# =============================================================================
# SEED Test Vector B.4
# =============================================================================
var key4: array[16, uint8] = [
  0x28'u8, 0xDB'u8, 0xC3'u8, 0xBC'u8, 0x49'u8, 0xFF'u8, 0xD8'u8, 0x7D'u8,
  0xCF'u8, 0xA5'u8, 0x09'u8, 0xB1'u8, 0x1D'u8, 0x42'u8, 0x2B'u8, 0xE7'u8
]
var text4: array[16, uint8] = [
  0xB4'u8, 0x1E'u8, 0x6B'u8, 0xE2'u8, 0xEB'u8, 0xA8'u8, 0x4A'u8, 0x14'u8,
  0x8E'u8, 0x2E'u8, 0xED'u8, 0x84'u8, 0x59'u8, 0x3C'u8, 0x5E'u8, 0xC7'u8
]
var ctx4: SEEDCtx

echo "--- Test : SEED B.4 ---"
var pt4: string = binToHex(text4)
echo "SEED Key Standard : ", binToHex(key4)
echo "SEED Plain Text Standard : ", pt4
seedInit(ctx4, key4)
seedEncrypt(ctx4, text4, text4)
echo "SEED Cipher Text Standard : 9B9B7BFCD1813CB95D0B3618F40F5122"
var ct4: string = binToHex(text4)
echo "SEED Cipher Text State : ", ct4
doAssert ct4 == "9B9B7BFCD1813CB95D0B3618F40F5122", "SEED B.4 Encrypt Wrong!"
seedDecrypt(ctx4, text4, text4)
echo "SEED Plain Text State : ", binToHex(text4)
doAssert pt4 == binToHex(text4), "SEED B.4 Decrypt Wrong!"
echo ""

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("SEED Init"):
  for i in 1 .. 1_000_000:
    seedInit(ctx1, key1)

benchmark("SEED Encrypt"):
  for i in 1 .. 1_000_000:
    seedEncrypt(ctx1, text1, text1)

benchmark("SEED Decrypt"):
  for i in 1 .. 1_000_000:
    seedDecrypt(ctx1, text1, text1)
