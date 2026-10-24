import "../../src/nim_cryptkit/block/rc2"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

var ctx1: RC2Ctx
var key1: array[8, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var text1: array[8, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

rc2Init(ctx1, key1, 63)
echo "--- Test : RC2-63 (Key 8bytes) ---"
var pt1: string = binToHex(text1)
echo "RC2-63 Key Standard : ", binToHex(key1)
echo "RC2-63 Plain Text Standard : ", pt1
rc2Encrypt(ctx1, text1, text1)
echo "RC2-63 Cipher Text Standard : EBB773F993278EFF"
var ct1: string = binToHex(text1)
echo "RC2-63 Cipher Text State : ", ct1
doAssert ct1 == "EBB773F993278EFF", "RC2-63 Encrypt Wrong!"
rc2Decrypt(ctx1, text1, text1)
echo "RC2-63 Plain Text State : ", binToHex(text1)
doAssert pt1 == binToHex(text1), "RC2-63 Decrypt Wrong!"
echo ""

var ctx2: RC2Ctx
var key2: array[16, uint8] = [
  0x88'u8, 0xBC'u8, 0xA9'u8, 0x0E'u8, 0x90'u8, 0x87'u8, 0x5A'u8, 0x7F'u8, 0x0F'u8, 0x79'u8, 0xC3'u8, 0x84'u8, 0x62'u8, 0x7B'u8, 0xAF'u8, 0xB2'u8
]
var text2: array[8, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

rc2Init(ctx2, key2, 128)
echo "--- Test : RC2-128 (Key 16bytes) ---"
var pt2: string = binToHex(text2)
echo "RC2-128 Key Standard : ", binToHex(key2)
echo "RC2-128 Plain Text Standard : ", pt2
rc2Encrypt(ctx2, text2, text2)
echo "RC2-128 Cipher Text Standard : 2269552AB0F85CA6"
var ct2: string = binToHex(text2)
echo "RC2-128 Cipher Text State : ", ct2
doAssert ct2 == "2269552AB0F85CA6", "RC2-128 Encrypt Wrong!"
rc2Decrypt(ctx2, text2, text2)
echo "RC2-128 Plain Text State : ", binToHex(text2)
doAssert pt2 == binToHex(text2), "RC2-128 Decrypt Wrong!"
echo ""

var ctx3: RC2Ctx
var key3: array[33, uint8] = [
  0x88'u8, 0xBC'u8, 0xA9'u8, 0x0E'u8, 0x90'u8, 0x87'u8, 0x5A'u8, 0x7F'u8, 0x0F'u8, 0x79'u8, 0xC3'u8, 0x84'u8, 0x62'u8, 0x7B'u8, 0xAF'u8, 0xB2'u8,
  0x16'u8, 0xF8'u8, 0x0A'u8, 0x6F'u8, 0x85'u8, 0x92'u8, 0x05'u8, 0x84'u8, 0xC4'u8, 0x2F'u8, 0xCE'u8, 0xB0'u8, 0xBE'u8, 0x25'u8, 0x5D'u8, 0xAF'u8, 0x1E'u8
]
var text3: array[8, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

rc2Init(ctx3, key3, 129)
echo "--- Test : RC2-129 (Key 33bytes) ---"
var pt3: string = binToHex(text3)
echo "RC2-129 Key Standard : ", binToHex(key3)
echo "RC2-129 Plain Text Standard : ", pt3
rc2Encrypt(ctx3, text3, text3)
echo "RC2-129 Cipher Text Standard : 5B78D3A43DFFF1F1"
var ct3: string = binToHex(text3)
echo "RC2-129 Cipher Text State : ", ct3
doAssert ct3 == "5B78D3A43DFFF1F1", "RC2-129 Encrypt Wrong!"
rc2Decrypt(ctx3, text3, text3)
echo "RC2-129 Plain Text State : ", binToHex(text3)
doAssert pt3 == binToHex(text3), "RC2-129 Decrypt Wrong!"
echo ""

var ctx4: RC2Ctx
var key4: array[1, uint8] = [0x88'u8]
var text4: array[8, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

rc2Init(ctx4, key4, 64)
echo "--- Test : RC2-64 (Short Key 1byte) ---"
var pt4: string = binToHex(text4)
echo "RC2-64 Key Standard : ", binToHex(key4)
echo "RC2-64 Plain Text Standard : ", pt4
rc2Encrypt(ctx4, text4, text4)
echo "RC2-64 Cipher Text Standard : 61A8A244ADACCCF0"
var ct4: string = binToHex(text4)
echo "RC2-64 Cipher Text State : ", ct4
doAssert ct4 == "61A8A244ADACCCF0", "RC2-64 Encrypt Wrong!"
rc2Decrypt(ctx4, text4, text4)
echo "RC2-64 Plain Text State : ", binToHex(text4)
doAssert pt4 == binToHex(text4), "RC2-64 Decrypt Wrong!"
echo ""

var ctx5: RC2Ctx
var key5: array[7, uint8] = [
  0x88'u8, 0xBC'u8, 0xA9'u8, 0x0E'u8, 0x90'u8, 0x87'u8, 0x5A'u8
]
var text5: array[8, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

rc2Init(ctx5, key5, 64)
echo "--- Test : RC2-64 (Key 7bytes) ---"
var pt5: string = binToHex(text5)
echo "RC2-64 Key Standard : ", binToHex(key5)
echo "RC2-64 Plain Text Standard : ", pt5
rc2Encrypt(ctx5, text5, text5)
echo "RC2-64 Cipher Text Standard : 6CCF4308974C267F"
var ct5: string = binToHex(text5)
echo "RC2-64 Cipher Text State : ", ct5
doAssert ct5 == "6CCF4308974C267F", "RC2-64 Encrypt Wrong!"
rc2Decrypt(ctx5, text5, text5)
echo "RC2-64 Plain Text State : ", binToHex(text5)
doAssert pt5 == binToHex(text5), "RC2-64 Decrypt Wrong!"
echo ""

var ctx6: RC2Ctx
var key6: array[16, uint8] = [
  0x88'u8, 0xBC'u8, 0xA9'u8, 0x0E'u8, 0x90'u8, 0x87'u8, 0x5A'u8, 0x7F'u8, 0x0F'u8, 0x79'u8, 0xC3'u8, 0x84'u8, 0x62'u8, 0x7B'u8, 0xAF'u8, 0xB2'u8
]
var text6: array[8, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]

rc2Init(ctx6, key6, 64)
echo "--- Test : RC2-64 (Key 16bytes) ---"
var pt6: string = binToHex(text6)
echo "RC2-64 Key Standard : ", binToHex(key6)
echo "RC2-64 Plain Text Standard : ", pt6
rc2Encrypt(ctx6, text6, text6)
echo "RC2-64 Cipher Text Standard : 1A807D272BBE5DB1"
var ct6: string = binToHex(text6)
echo "RC2-64 Cipher Text State : ", ct6
doAssert ct6 == "1A807D272BBE5DB1", "RC2-64 Encrypt Wrong!"
rc2Decrypt(ctx6, text6, text6)
echo "RC2-64 Plain Text State : ", binToHex(text6)
doAssert pt6 == binToHex(text6), "RC2-64 Decrypt Wrong!"
echo ""

var ctx7: RC2Ctx
var key7: array[8, uint8] = [
  0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8
]
var text7: array[8, uint8] = [
  0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8, 0xFF'u8
]

rc2Init(ctx7, key7, 64)
echo "--- Test : RC2-64 (All FF) ---"
var pt7: string = binToHex(text7)
echo "RC2-64 Key Standard : ", binToHex(key7)
echo "RC2-64 Plain Text Standard : ", pt7
rc2Encrypt(ctx7, text7, text7)
echo "RC2-64 Cipher Text Standard : 278B27E42E2F0D49"
var ct7: string = binToHex(text7)
echo "RC2-64 Cipher Text State : ", ct7
doAssert ct7 == "278B27E42E2F0D49", "RC2-64 Encrypt Wrong!"
rc2Decrypt(ctx7, text7, text7)
echo "RC2-64 Plain Text State : ", binToHex(text7)
doAssert pt7 == binToHex(text7), "RC2-64 Decrypt Wrong!"
echo ""

var ctx8: RC2Ctx
var key8: array[8, uint8] = [
  0x30'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var text8: array[8, uint8] = [
  0x10'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x01'u8
]

rc2Init(ctx8, key8, 64)
echo "--- Test : RC2-64 (Special Plain) ---"
var pt8: string = binToHex(text8)
echo "RC2-64 Key Standard : ", binToHex(key8)
echo "RC2-64 Plain Text Standard : ", pt8
rc2Encrypt(ctx8, text8, text8)
echo "RC2-64 Cipher Text Standard : 30649EDF9BE7D2C2"
var ct8: string = binToHex(text8)
echo "RC2-64 Cipher Text State : ", ct8
doAssert ct8 == "30649EDF9BE7D2C2", "RC2-64 Encrypt Wrong!"
rc2Decrypt(ctx8, text8, text8)
echo "RC2-64 Plain Text State : ", binToHex(text8)
doAssert pt8 == binToHex(text8), "RC2-64 Decrypt Wrong!"
echo ""

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

benchmark("RC2-64 Init"):
  for i in 1 .. 1_000_000:
    rc2Init(ctx6, key6, 64)

benchmark("RC2-64 Encrypt"):
  for i in 1 .. 1_000_000:
    rc2Encrypt(ctx6, text6, text6)

benchmark("RC2-64 Decrypt"):
  for i in 1 .. 1_000_000:
    rc2Decrypt(ctx6, text6, text6)
