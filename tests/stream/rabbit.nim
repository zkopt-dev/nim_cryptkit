import "../../src/nim_cryptkit/stream/rabbit"
import "../../src/nim_cryptkit/utils/digits"
import std/[monotimes, times]

# ==========================================================
# Test Vector 1: Zero IV (32-byte)
# ==========================================================
echo "=== Rabbit Test 1: Zero IV ==="

var key1: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var iv1: array[8, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var pt1: array[32, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var ct1_exp: array[32, uint8] = [
  0xed'u8, 0xb7'u8, 0x05'u8, 0x67'u8, 0x37'u8, 0x5d'u8, 0xcd'u8, 0x7c'u8,
  0xd8'u8, 0x95'u8, 0x54'u8, 0xf8'u8, 0x5e'u8, 0x27'u8, 0xa7'u8, 0xc6'u8,
  0x8d'u8, 0x4a'u8, 0xdc'u8, 0x70'u8, 0x32'u8, 0x29'u8, 0x8f'u8, 0x7b'u8,
  0xd4'u8, 0xef'u8, 0xf5'u8, 0x04'u8, 0xac'u8, 0xa6'u8, 0x29'u8, 0x5f'u8
]

var ctx1: RabbitCtx
rabbitInit(ctx1, key1, iv1)
var out1: array[32, uint8]
rabbitXor(ctx1, pt1, out1)
echo "Ciphertext : ", binToHex(out1)
echo "Expected   : ", binToHex(ct1_exp)
doAssert out1 == ct1_exp, "Test1 Zero IV failed!"
echo "OK Test1\n"

# ==========================================================
# Test Vector 2: IV=597e26c175f573c3 (32-byte)
# ==========================================================
echo "=== Rabbit Test 2: IV 597e... ==="

var key2: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var iv2: array[8, uint8] = [
  0x59'u8, 0x7e'u8, 0x26'u8, 0xc1'u8, 0x75'u8, 0xf5'u8, 0x73'u8, 0xc3'u8
]
var pt2: array[32, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var ct2_exp: array[32, uint8] = [
  0x6d'u8, 0x7d'u8, 0x01'u8, 0x22'u8, 0x92'u8, 0xcc'u8, 0xdc'u8, 0xe0'u8,
  0xe2'u8, 0x12'u8, 0x00'u8, 0x58'u8, 0xb9'u8, 0x4e'u8, 0xcd'u8, 0x1f'u8,
  0x2e'u8, 0x6f'u8, 0x93'u8, 0xed'u8, 0xff'u8, 0x99'u8, 0x24'u8, 0x7b'u8,
  0x01'u8, 0x25'u8, 0x21'u8, 0xd1'u8, 0x10'u8, 0x4e'u8, 0x5f'u8, 0xa7'u8
]

var ctx2: RabbitCtx
rabbitInit(ctx2, key2, iv2)
var out2: array[32, uint8]
rabbitXor(ctx2, pt2, out2)
echo "Ciphertext : ", binToHex(out2)
echo "Expected   : ", binToHex(ct2_exp)
doAssert out2 == ct2_exp, "Test2 failed!"
echo "OK Test2\n"

# ==========================================================
# Test Vector 3: IV=2717f4d21a56eba6 (32-byte)
# ==========================================================
echo "=== Rabbit Test 3: IV 2717... ==="

var key3: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var iv3: array[8, uint8] = [
  0x27'u8, 0x17'u8, 0xf4'u8, 0xd2'u8, 0x1a'u8, 0x56'u8, 0xeb'u8, 0xa6'u8
]
var pt3: array[32, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
var ct3_exp: array[32, uint8] = [
  0x4d'u8, 0x10'u8, 0x51'u8, 0xa1'u8, 0x23'u8, 0xaf'u8, 0xb6'u8, 0x70'u8,
  0xbf'u8, 0x8d'u8, 0x85'u8, 0x05'u8, 0xc8'u8, 0xd8'u8, 0x5a'u8, 0x44'u8,
  0x03'u8, 0x5b'u8, 0xc3'u8, 0xac'u8, 0xc6'u8, 0x67'u8, 0xae'u8, 0xae'u8,
  0x5b'u8, 0x2c'u8, 0xf4'u8, 0x47'u8, 0x79'u8, 0xf2'u8, 0xc8'u8, 0x96'u8
]

var ctx3: RabbitCtx
rabbitInit(ctx3, key3, iv3)
var out3: array[32, uint8]
rabbitXor(ctx3, pt3, out3)
echo "Ciphertext : ", binToHex(out3)
echo "Expected   : ", binToHex(ct3_exp)
doAssert out3 == ct3_exp, "Test3 failed!"
echo "OK Test3\n"

# ==========================================================
# Test Vector 4: 1-byte
# ==========================================================
echo "=== Rabbit Test 4: 1-byte ==="

var key4: array[16, uint8] = [
  0x29'u8, 0x23'u8, 0xbe'u8, 0x84'u8, 0xe1'u8, 0x6c'u8, 0xd6'u8, 0xae'u8,
  0x52'u8, 0x90'u8, 0x49'u8, 0xf1'u8, 0xf1'u8, 0xbb'u8, 0xe9'u8, 0xeb'u8
]
var iv4: array[8, uint8] = [
  0xb3'u8, 0xa6'u8, 0xdb'u8, 0x3c'u8, 0x87'u8, 0x0c'u8, 0x3e'u8, 0x99'u8
]
var pt4: array[1, uint8] = [0x24'u8]
var ct4_exp: array[1, uint8] = [0x66'u8]

var ctx4: RabbitCtx
rabbitInit(ctx4, key4, iv4)
var out4: array[1, uint8]
rabbitXor(ctx4, pt4, out4)
echo "Ciphertext : ", binToHex(out4)
echo "Expected   : ", binToHex(ct4_exp)
doAssert out4 == ct4_exp, "Test4 1-byte failed!"
echo "OK Test4\n"

# ==========================================================
# Test Vector 5: 2-byte
# ==========================================================
echo "=== Rabbit Test 5: 2-byte ==="

var key5: array[16, uint8] = [
  0x5e'u8, 0x0d'u8, 0x1c'u8, 0x06'u8, 0xb7'u8, 0x47'u8, 0xde'u8, 0xb3'u8,
  0x12'u8, 0x4d'u8, 0xc8'u8, 0x43'u8, 0xbb'u8, 0x8b'u8, 0xa6'u8, 0x1f'u8
]
var iv5: array[8, uint8] = [
  0x03'u8, 0x5a'u8, 0x7d'u8, 0x09'u8, 0x38'u8, 0x25'u8, 0x1f'u8, 0x5d'u8
]
var pt5: array[2, uint8] = [0xd4'u8, 0xcb'u8]
var ct5_exp: array[2, uint8] = [0xa3'u8, 0xf2'u8]

var ctx5: RabbitCtx
rabbitInit(ctx5, key5, iv5)
var out5: array[2, uint8]
rabbitXor(ctx5, pt5, out5)
echo "Ciphertext : ", binToHex(out5)
echo "Expected   : ", binToHex(ct5_exp)
doAssert out5 == ct5_exp, "Test5 2-byte failed!"
echo "OK Test5\n"

# ==========================================================
# Test Vector 6: 4-byte
# ==========================================================
echo "=== Rabbit Test 6: 4-byte ==="

var key6: array[16, uint8] = [
  0x49'u8, 0xdc'u8, 0xad'u8, 0x4f'u8, 0x14'u8, 0xf2'u8, 0x44'u8, 0x40'u8,
  0x66'u8, 0xd0'u8, 0x6b'u8, 0xc4'u8, 0x30'u8, 0xb7'u8, 0x32'u8, 0x3b'u8
]
var iv6: array[8, uint8] = [
  0xa1'u8, 0x22'u8, 0xf6'u8, 0x22'u8, 0x91'u8, 0x9d'u8, 0xe1'u8, 0x8b'u8
]
var pt6: array[4, uint8] = [0x1f'u8, 0xda'u8, 0xb0'u8, 0xca'u8]
var ct6_exp: array[4, uint8] = [0x03'u8, 0x0a'u8, 0x99'u8, 0x55'u8]

var ctx6: RabbitCtx
rabbitInit(ctx6, key6, iv6)
var out6: array[4, uint8]
rabbitXor(ctx6, pt6, out6)
echo "Ciphertext : ", binToHex(out6)
echo "Expected   : ", binToHex(ct6_exp)
doAssert out6 == ct6_exp, "Test6 4-byte failed!"
echo "OK Test6\n"

# ==========================================================
# Benchmarks
# ==========================================================
template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

var benchKey: array[16, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
  0x08'u8, 0x09'u8, 0x0a'u8, 0x0b'u8, 0x0c'u8, 0x0d'u8, 0x0e'u8, 0x0f'u8
]
var benchIv: array[8, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8
]
var benchData: array[1024, uint8]
for i in 0 ..< benchData.len:
  benchData[i] = uint8(i and 0xFF)

var ctxBench: RabbitCtx

benchmark("Rabbit Init Benchmark"):
  for i in 1 .. 1_000_000:
    rabbitInit(ctxBench, benchKey, benchIv)

benchmark("Rabbit Xor Benchmark (1KB)"):
  for i in 1 .. 100_000:
    rabbitInit(ctxBench, benchKey, benchIv)
    rabbitXor(ctxBench, benchData, benchData)
