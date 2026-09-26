import ../utils/endian
import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils
import std/[monotimes, times]
import std/bitops
import strutils

const
  # SM4 key constants
  KC*: array[32, uint32] = [
    0x00070e15'u32, 0x1c232a31'u32, 0x383f464d'u32, 0x545b6269'u32, 0x70777e85'u32, 0x8c939aa1'u32, 0xa8afb6bd'u32, 0xc4cbd2d9'u32,
    0xe0e7eef5'u32, 0xfc030a11'u32, 0x181f262d'u32, 0x343b4249'u32, 0x50575e65'u32, 0x6c737a81'u32, 0x888f969d'u32, 0xa4abb2b9'u32,
    0xc0c7ced5'u32, 0xdce3eaf1'u32, 0xf8ff060d'u32, 0x141b2229'u32, 0x30373e45'u32, 0x4c535a61'u32, 0x686f767d'u32, 0x848b9299'u32,
    0xa0a7aeb5'u32, 0xbcc3cad1'u32, 0xd8dfe6ed'u32, 0xf4fb0209'u32, 0x10171e25'u32, 0x2c333a41'u32, 0x484f565d'u32, 0x646b7279'u32
  ]
  # Sm4 S-Box
  SBox*: array[256 , uint8] = [
    0xd6'u8, 0x90'u8, 0xe9'u8, 0xfe'u8, 0xcc'u8, 0xe1'u8, 0x3d'u8, 0xb7'u8, 0x16'u8, 0xb6'u8, 0x14'u8, 0xc2'u8, 0x28'u8, 0xfb'u8, 0x2c'u8, 0x05'u8,
    0x2b'u8, 0x67'u8, 0x9a'u8, 0x76'u8, 0x2a'u8, 0xbe'u8, 0x04'u8, 0xc3'u8, 0xaa'u8, 0x44'u8, 0x13'u8, 0x26'u8, 0x49'u8, 0x86'u8, 0x06'u8, 0x99'u8,
    0x9c'u8, 0x42'u8, 0x50'u8, 0xf4'u8, 0x91'u8, 0xef'u8, 0x98'u8, 0x7a'u8, 0x33'u8, 0x54'u8, 0x0b'u8, 0x43'u8, 0xed'u8, 0xcf'u8, 0xac'u8, 0x62'u8,
    0xe4'u8, 0xb3'u8, 0x1c'u8, 0xa9'u8, 0xc9'u8, 0x08'u8, 0xe8'u8, 0x95'u8, 0x80'u8, 0xdf'u8, 0x94'u8, 0xfa'u8, 0x75'u8, 0x8f'u8, 0x3f'u8, 0xa6'u8,
    0x47'u8, 0x07'u8, 0xa7'u8, 0xfc'u8, 0xf3'u8, 0x73'u8, 0x17'u8, 0xba'u8, 0x83'u8, 0x59'u8, 0x3c'u8, 0x19'u8, 0xe6'u8, 0x85'u8, 0x4f'u8, 0xa8'u8,
    0x68'u8, 0x6b'u8, 0x81'u8, 0xb2'u8, 0x71'u8, 0x64'u8, 0xda'u8, 0x8b'u8, 0xf8'u8, 0xeb'u8, 0x0f'u8, 0x4b'u8, 0x70'u8, 0x56'u8, 0x9d'u8, 0x35'u8,
    0x1e'u8, 0x24'u8, 0x0e'u8, 0x5e'u8, 0x63'u8, 0x58'u8, 0xd1'u8, 0xa2'u8, 0x25'u8, 0x22'u8, 0x7c'u8, 0x3b'u8, 0x01'u8, 0x21'u8, 0x78'u8, 0x87'u8,
    0xd4'u8, 0x00'u8, 0x46'u8, 0x57'u8, 0x9f'u8, 0xd3'u8, 0x27'u8, 0x52'u8, 0x4c'u8, 0x36'u8, 0x02'u8, 0xe7'u8, 0xa0'u8, 0xc4'u8, 0xc8'u8, 0x9e'u8,
    0xea'u8, 0xbf'u8, 0x8a'u8, 0xd2'u8, 0x40'u8, 0xc7'u8, 0x38'u8, 0xb5'u8, 0xa3'u8, 0xf7'u8, 0xf2'u8, 0xce'u8, 0xf9'u8, 0x61'u8, 0x15'u8, 0xa1'u8,
    0xe0'u8, 0xae'u8, 0x5d'u8, 0xa4'u8, 0x9b'u8, 0x34'u8, 0x1a'u8, 0x55'u8, 0xad'u8, 0x93'u8, 0x32'u8, 0x30'u8, 0xf5'u8, 0x8c'u8, 0xb1'u8, 0xe3'u8,
    0x1d'u8, 0xf6'u8, 0xe2'u8, 0x2e'u8, 0x82'u8, 0x66'u8, 0xca'u8, 0x60'u8, 0xc0'u8, 0x29'u8, 0x23'u8, 0xab'u8, 0x0d'u8, 0x53'u8, 0x4e'u8, 0x6f'u8,
    0xd5'u8, 0xdb'u8, 0x37'u8, 0x45'u8, 0xde'u8, 0xfd'u8, 0x8e'u8, 0x2f'u8, 0x03'u8, 0xff'u8, 0x6a'u8, 0x72'u8, 0x6d'u8, 0x6c'u8, 0x5b'u8, 0x51'u8,
    0x8d'u8, 0x1b'u8, 0xaf'u8, 0x92'u8, 0xbb'u8, 0xdd'u8, 0xbc'u8, 0x7f'u8, 0x11'u8, 0xd9'u8, 0x5c'u8, 0x41'u8, 0x1f'u8, 0x10'u8, 0x5a'u8, 0xd8'u8,
    0x0a'u8, 0xc1'u8, 0x31'u8, 0x88'u8, 0xa5'u8, 0xcd'u8, 0x7b'u8, 0xbd'u8, 0x2d'u8, 0x74'u8, 0xd0'u8, 0x12'u8, 0xb8'u8, 0xe5'u8, 0xb4'u8, 0xb0'u8,
    0x89'u8, 0x69'u8, 0x97'u8, 0x4a'u8, 0x0c'u8, 0x96'u8, 0x77'u8, 0x7e'u8, 0x65'u8, 0xb9'u8, 0xf1'u8, 0x09'u8, 0xc5'u8, 0x6e'u8, 0xc6'u8, 0x84'u8,
    0x18'u8, 0xf0'u8, 0x7d'u8, 0xec'u8, 0x3a'u8, 0xdc'u8, 0x4d'u8, 0x20'u8, 0x79'u8, 0xee'u8, 0x5f'u8, 0x3e'u8, 0xd7'u8, 0xcb'u8, 0x39'u8, 0x48'u8
  ]
  # SM4 FK
  FK*: array[4, uint32] = [0xA3B1BAC6'u32, 0x56AA3350'u32, 0x677D9197'u32, 0xB27022DC'u32]

  # SM4 information constants
  SM4_KEY_SIZE*: int = 16
  SM4_BLOCK_SIZE*: int = 16
  SM4_ROUND_NUMBER*: int = 32

type
  # SM4 context
  SM4Ctx* = object
    roundKey*: array[32, uint32]

# sm4 init core
template sm4InitC(ctx: var SM4Ctx, key: slicearray[16, uint8]): void {.autoSizeOpt.} =
  # temporal round key 
  var k: array[36, uint32]
  # decode key and xor FK
#  unroll(i, 0, 3):
#    k[i] = FK[i] xor ((uint32(key[4*i]) shl 24) or (uint32(key[4*i+1]) shl 16) or (uint32(key[4*i+2]) shl 8) or uint32(key[4*i+3]))
  decodeBE(key.toSliceArray(0, 15), k.toSliceArray(0, 3))
  unroll(i, 0, 3):
    k[i] = FK[i] xor k[i]

  var temp: uint32 = 0
  var buffer: uint32 = 0

  # generate round key
  for i in static(0 ..< 32):
    temp = k[i+1] xor k[i+2] xor k[i+3] xor KC[i]
    buffer = (uint32(SBox[int((temp shr 24) and 0xFF)]) shl 24) or
             (uint32(SBox[int((temp shr 16) and 0xFF)]) shl 16) or
             (uint32(SBox[int((temp shr 8) and 0xFF)]) shl 8) or
              uint32(SBox[int(temp and 0xFF)])
    k[i+4] = k[i] xor (buffer xor rotateLeftBits(buffer, 13) xor rotateLeftBits(buffer, 23))
    ctx.roundKey[i] = k[i+4]

# sm4 encrypt core
template sm4EncryptC(ctx: SM4Ctx, input, output: slicearray[16, uint8]): void {.autoSizeOpt.} =
  # temporal state
  var x: array[36, uint32]
  # decode input to x
  decodeBE(input, x.toSliceArray(0, 3))

  var temp: uint32 = 0
  var buffer: uint32 = 0 

  # encrypt round
  for i in static(0 ..< 32):
    temp = x[i+1] xor x[i+2] xor x[i+3] xor ctx.roundKey[i]
    buffer = (uint32(SBox[int((temp shr 24) and 0xFF)]) shl 24) or
              (uint32(SBox[int((temp shr 16) and 0xFF)]) shl 16) or
              (uint32(SBox[int((temp shr 8) and 0xFF)]) shl 8) or
              uint32(SBox[int(temp and 0xFF)])
    x[i+4] = x[i] xor (buffer xor rotateLeftBits(buffer, 2) xor rotateLeftBits(buffer, 10) xor rotateLeftBits(buffer, 18) xor rotateLeftBits(buffer, 24))
  
  # encode x to state
  when BE:
    let outputU32: ptr array[4, uint32] = cast[ptr array[4, uint32]](addr output[0])
    outputU32[0] = x[35]
    outputU32[1] = X[34]
    outputU32[2] = X[33]
    outputU32[3] = X[32]
  else:
    unroll(j, 0, 3):
      output[4*j] = uint8((x[35-j] shr 24) and 0xFF)
      output[4*j+1] = uint8((x[35-j] shr 16) and 0xFF)
      output[4*j+2] = uint8((x[35-j] shr 8) and 0xFF)
      output[4*j+3] = uint8(x[35-j] and 0xFF)

# sm4 decrytp core
template sm4DecryptC(ctx: SM4Ctx, input, output: slicearray[16, uint8]): void {.autoSizeOpt.} =
  # temporal state
  var x: array[36, uint32]
  # decode state to x
  decodeBE(input, x.toSliceArray(0, 3))
#  for j in static(0 ..< 4):
#    x[j] = (uint32(state[j*4]) shl 24) or (uint32(state[j*4+1]) shl 16) or (uint32(state[j*4+2]) shl 8) or uint32(state[j*4+3])
  
  var temp: uint32 = 0
  var buffer: uint32 = 0 

  # decrypt round
  for i in static(0 ..< 32):
    temp = x[i+1] xor x[i+2] xor x[i+3] xor ctx.roundKey[31-i]
    buffer = (uint32(SBox[int((temp shr 24) and 0xFF)]) shl 24) or
              (uint32(SBox[int((temp shr 16) and 0xFF)]) shl 16) or
              (uint32(SBox[int((temp shr 8) and 0xFF)]) shl 8) or
              uint32(SBox[int(temp and 0xFF)])
    x[i+4] = x[i] xor (buffer xor rotateLeftBits(buffer, 2) xor rotateLeftBits(buffer, 10) xor rotateLeftBits(buffer, 18) xor rotateLeftBits(buffer, 24))
  
  # encode x to state
  when BE:
    let outputU32: ptr array[4, uint32] = cast[ptr array[4, uint32]](addr output[0])
    outputU32[0] = x[35]
    outputU32[1] = X[34]
    outputU32[2] = X[33]
    outputU32[3] = X[32]
  else:
    unroll(j, 0, 3):
      output[4*j] = uint8((x[35-j] shr 24) and 0xFF)
      output[4*j+1] = uint8((x[35-j] shr 16) and 0xFF)
      output[4*j+2] = uint8((x[35-j] shr 8) and 0xFF)
      output[4*j+3] = uint8(x[35-j] and 0xFF)

# export wrappers
when defined(templateOpt):
  template sm4Init*(ctx: var SM4Ctx, key: array[16, uint8]): void =
    sm4InitC(ctx, key.toSliceArray(0, 15))
  template sm4Init*(ctx: var SM4Ctx, key: openArray[uint8]): void =
    sm4InitC(ctx, key.toSliceArray(0, 15))
  template sm4Init*(ctx: var SM4Ctx, key: slicearray[16, uint8]): void =
    sm4InitC(ctx, key)
  template sm4Init*(ctx: ptr SM4Ctx, key: ptr array[16, uint8]): void =
    sm4InitC(ctx[], key.toSliceArray(0, 15))

  template sm4Encrypt*(ctx: SM4Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    sm4EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template sm4Encrypt*(ctx: SM4Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    sm4EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template sm4Encrypt*(ctx: SM4Ctx, input, output: slicearray[16, uint8]): void =
    sm4EncryptC(ctx, input, output)
  template sm4Encrypt*(ctx: ptr SM4Ctx, input, output: ptr array[16, uint8]): void =
    sm4EncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template sm4Decrypt*(ctx: SM4Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    sm4DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template sm4Decrypt*(ctx: SM4Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    sm4DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template sm4Decrypt*(ctx: SM4Ctx, input, output: slicearray[16, uint8]): void =
    sm4DecryptC(ctx, input, output)
  template sm4Decrypt*(ctx: ptr SM4Ctx, input, output: ptr array[16, uint8]): void =
    sm4DecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))
else:
  proc sm4Init*(ctx: var SM4Ctx, key: array[16, uint8]): void =
    sm4InitC(ctx, key.toSliceArray(0, 15))
  proc sm4Init*(ctx: var SM4Ctx, key: openArray[uint8]): void =
    sm4InitC(ctx, key.toSliceArray(0, 15))
  proc sm4Init*(ctx: var SM4Ctx, key: slicearray[16, uint8]): void =
    sm4InitC(ctx, key)
  proc sm4Init*(ctx: ptr SM4Ctx, key: ptr array[16, uint8]): void {.exportc: "sm4Init", cdecl.} =
    sm4InitC(ctx[], key.toSliceArray(0, 15))

  proc sm4Encrypt*(ctx: SM4Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    sm4EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc sm4Encrypt*(ctx: SM4Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    sm4EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc sm4Encrypt*(ctx: SM4Ctx, input, output: slicearray[16, uint8]): void =
    sm4EncryptC(ctx, input, output)
  proc sm4Encrypt*(ctx: ptr SM4Ctx, input, output: ptr array[16, uint8]): void {.exportc: "sm4Encrypt", cdecl.} =
    sm4EncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc sm4Decrypt*(ctx: SM4Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    sm4DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc sm4Decrypt*(ctx: SM4Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    sm4DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc sm4Decrypt*(ctx: SM4Ctx, input, output: slicearray[16, uint8]): void =
    sm4DecryptC(ctx, input, output)
  proc sm4Decrypt*(ctx: ptr SM4Ctx, input, output: ptr array[16, uint8]): void {.exportc: "sm4Decrypt", cdecl.} =
    sm4DecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

