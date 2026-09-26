import "../../src/nim_cryptkit/block/cast256"
import ../../src/nim_cryptkit/utils/digits
import std/[monotimes, times]

template benchmark(name: string, code: untyped) =
  let start = getMonoTime()
  code
  let elapsed = getMonoTime() - start
  echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

# 128-bit key
var ctx128: CAST256_128Ctx
var key128: array[16, uint8] = [
  0x23'u8, 0x42'u8, 0xbb'u8, 0x9e'u8, 0xfa'u8, 0x38'u8, 0x54'u8, 0x2c'u8, 0x0a'u8, 0xf7'u8, 0x56'u8, 0x47'u8, 0xf2'u8, 0x9f'u8, 0x61'u8, 0x5d'u8
]
var text128: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
echo "--- Test : CAST256-128 ---"
var pt128: string = binToHex(text128)
echo "CAST256-128 Key Standard : ", binToHex(key128)
echo "CAST256-128 Plain Text Standard : ", pt128
cast256_128Init(ctx128, key128)
cast256_128Encrypt(ctx128, text128, text128)
echo "CAST256-128 Cipher Text Standard : C842A08972B43D20836C91D1B7530F6B"
var ct128: string = binToHex(text128)
echo "CAST256-128 Cipher Text State : ", ct128
doAssert ct128 == "C842A08972B43D20836C91D1B7530F6B", "CAST256-128 Encrypt Wrong!"
cast256_128Decrypt(ctx128, text128, text128)
echo "CAST256-128 Plain Text State : ", binToHex(text128)
doAssert pt128 == binToHex(text128), "CAST256-128 Decrypt Wrong!"

# 192-bit key
var ctx192: CAST256_192Ctx
var key192: array[24, uint8] = [
  0x23'u8, 0x42'u8, 0xbb'u8, 0x9e'u8, 0xfa'u8, 0x38'u8, 0x54'u8, 0x2c'u8, 0xbe'u8, 0xd0'u8, 0xac'u8, 0x83'u8, 0x94'u8, 0x0a'u8, 0xc2'u8, 0x98'u8,
  0xba'u8, 0xc7'u8, 0x7a'u8, 0x77'u8, 0x17'u8, 0x94'u8, 0x28'u8, 0x63'u8
]
var text192: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
echo "--- Test : CAST256-192 ---"
var pt192: string = binToHex(text192)
echo "CAST256-192 Key Standard : ", binToHex(key192)
echo "CAST256-192 Plain Text Standard : ", pt192
cast256_192Init(ctx192, key192)
cast256_192Encrypt(ctx192, text192, text192)
echo "CAST256-192 Cipher Text Standard : 1B386C0210DCADCBDD0E41AA08A7A7E8"
var ct192: string = binToHex(text192)
echo "CAST256-192 Cipher Text State : ", ct192
doAssert ct192 == "1B386C0210DCADCBDD0E41AA08A7A7E8", "CAST256-192 Encrypt Wrong!"
cast256_192Decrypt(ctx192, text192, text192)
echo "CAST256-192 Plain Text State : ", binToHex(text192)
doAssert pt192 == binToHex(text192), "CAST256-192 Decrypt Wrong!"

# 256-bit key
var ctx256: CAST256_256Ctx
var key256: array[32, uint8] = [
  0x23'u8, 0x42'u8, 0xbb'u8, 0x9e'u8, 0xfa'u8, 0x38'u8, 0x54'u8, 0x2c'u8, 0xbe'u8, 0xd0'u8, 0xac'u8, 0x83'u8, 0x94'u8, 0x0a'u8, 0xc2'u8, 0x98'u8,
  0x8d'u8, 0x7c'u8, 0x47'u8, 0xce'u8, 0x26'u8, 0x49'u8, 0x08'u8, 0x46'u8, 0x1c'u8, 0xc1'u8, 0xb5'u8, 0x13'u8, 0x7a'u8, 0xe6'u8, 0xb6'u8, 0x04'u8
]
var text256: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
echo "--- Test : CAST256-256 ---"
var pt256: string = binToHex(text256)
echo "CAST256-256 Key Standard : ", binToHex(key256)
echo "CAST256-256 Plain Text Standard : ", pt256
cast256_256Init(ctx256, key256)
cast256_256Encrypt(ctx256, text256, text256)
echo "CAST256-256 Cipher Text Standard : 4F6A2038286897B9C9870136553317FA"
var ct256: string = binToHex(text256)
echo "CAST256-256 Cipher Text State : ", ct256
doAssert ct256 == "4F6A2038286897B9C9870136553317FA", "CAST256-256 Encrypt Wrong!"
cast256_256Decrypt(ctx256, text256, text256)
echo "CAST256-256 Plain Text State : ", binToHex(text256)
doAssert pt256 == binToHex(text256), "CAST256-256 Decrypt Wrong!"

# 160-bit key
var ctx160: CAST256_160Ctx
var key160: array[20, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8, 0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8
]
var text160: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
echo "--- Test : CAST256-160 ---"
var pt160: string = binToHex(text160)
echo "CAST256-160 Key Standard : ", binToHex(key160)
echo "CAST256-160 Plain Text Standard : ", pt160
cast256_160Init(ctx160, key160)
cast256_160Encrypt(ctx160, text160, text160)
var ct160: string = binToHex(text160)
echo "CAST256-160 Cipher Text State : ", ct160
cast256_160Decrypt(ctx160, text160, text160)
echo "CAST256-160 Plain Text State : ", binToHex(text160)
doAssert pt160 == binToHex(text160), "CAST256-160 Decrypt Wrong!"

# 224-bit key
var ctx224: CAST256_224Ctx
var key224: array[28, uint8] = [
  0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8, 0x08'u8, 0x09'u8, 0x0A'u8, 0x0B'u8, 0x0C'u8, 0x0D'u8, 0x0E'u8, 0x0F'u8,
  0x10'u8, 0x11'u8, 0x12'u8, 0x13'u8, 0x14'u8, 0x15'u8, 0x16'u8, 0x17'u8, 0x18'u8, 0x19'u8, 0x1A'u8, 0x1B'u8
]
var text224: array[16, uint8] = [
  0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
]
echo "--- Test : CAST256-224 ---"
var pt224: string = binToHex(text224)
echo "CAST256-224 Key Standard : ", binToHex(key224)
echo "CAST256-224 Plain Text Standard : ", pt224
cast256_224Init(ctx224, key224)
cast256_224Encrypt(ctx224, text224, text224)
var ct224: string = binToHex(text224)
echo "CAST256-224 Cipher Text State : ", ct224
cast256_224Decrypt(ctx224, text224, text224)
echo "CAST256-224 Plain Text State : ", binToHex(text224)
doAssert pt224 == binToHex(text224), "CAST256-224 Decrypt Wrong!"

benchmark("CAST256-128 Init"):
  for i in 1 .. 1_000_000:
    cast256_128Init(ctx128, key128)

benchmark("CAST256-128 Encrypt"):
  for i in 1 .. 1_000_000:
    cast256_128Encrypt(ctx128, text128, text128)
    
benchmark("CAST256-128 Decrypt"):
  for i in 1 .. 1_000_000:
    cast256_128Decrypt(ctx128, text128, text128)

benchmark("CAST256-160 Init"):
  for i in 1 .. 1_000_000:
    cast256_160Init(ctx160, key160)

benchmark("CAST256-160 Encrypt"):
  for i in 1 .. 1_000_000:
    cast256_160Encrypt(ctx160, text160, text160)
    
benchmark("CAST256-160 Decrypt"):
  for i in 1 .. 1_000_000:
    cast256_160Decrypt(ctx160, text160, text160)

benchmark("CAST256-192 Init"):
  for i in 1 .. 1_000_000:
    cast256_192Init(ctx192, key192)

benchmark("CAST256-192 Encrypt"):
  for i in 1 .. 1_000_000:
    cast256_192Encrypt(ctx192, text192, text192)
    
benchmark("CAST256-192 Decrypt"):
  for i in 1 .. 1_000_000:
    cast256_192Decrypt(ctx192, text192, text192)

benchmark("CAST256-224 Init"):
  for i in 1 .. 1_000_000:
    cast256_224Init(ctx224, key224)

benchmark("CAST256-224 Encrypt"):
  for i in 1 .. 1_000_000:
    cast256_224Encrypt(ctx224, text224, text224)
    
benchmark("CAST256-224 Decrypt"):
  for i in 1 .. 1_000_000:
    cast256_224Decrypt(ctx224, text224, text224)

benchmark("CAST256-256 Init"):
  for i in 1 .. 1_000_000:
    cast256_256Init(ctx256, key256)

benchmark("CAST256-256 Encrypt"):
  for i in 1 .. 1_000_000:
    cast256_256Encrypt(ctx256, text256, text256)
    
benchmark("CAST256-256 Decrypt"):
  for i in 1 .. 1_000_000:
    cast256_256Decrypt(ctx256, text256, text256)
