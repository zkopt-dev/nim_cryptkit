import ../utils/optmacro
import ../utils/bitutils
import ../utils/errorutils
import ../utils/digits
import ../utils/slicearray
import ../utils/endian
import ../utils/envconst
import ../utils/biguintBE
import std/[monotimes, times]
import std/bitops
import strutils

const
  # declare S-Box
  SBox0: array[256, uint8] = [
    0x3e'u8, 0x72'u8, 0x5b'u8, 0x47'u8, 0xca'u8, 0xe0'u8, 0x00'u8, 0x33'u8, 0x04'u8, 0xd1'u8, 0x54'u8, 0x98'u8, 0x09'u8, 0xb9'u8, 0x6d'u8, 0xcb'u8,
    0x7b'u8, 0x1b'u8, 0xf9'u8, 0x32'u8, 0xaf'u8, 0x9d'u8, 0x6a'u8, 0xa5'u8, 0xb8'u8, 0x2d'u8, 0xfc'u8, 0x1d'u8, 0x08'u8, 0x53'u8, 0x03'u8, 0x90'u8,
    0x4d'u8, 0x4e'u8, 0x84'u8, 0x99'u8, 0xe4'u8, 0xce'u8, 0xd9'u8, 0x91'u8, 0xdd'u8, 0xb6'u8, 0x85'u8, 0x48'u8, 0x8b'u8, 0x29'u8, 0x6e'u8, 0xac'u8,
    0xcd'u8, 0xc1'u8, 0xf8'u8, 0x1e'u8, 0x73'u8, 0x43'u8, 0x69'u8, 0xc6'u8, 0xb5'u8, 0xbd'u8, 0xfd'u8, 0x39'u8, 0x63'u8, 0x20'u8, 0xd4'u8, 0x38'u8,
    0x76'u8, 0x7d'u8, 0xb2'u8, 0xa7'u8, 0xcf'u8, 0xed'u8, 0x57'u8, 0xc5'u8, 0xf3'u8, 0x2c'u8, 0xbb'u8, 0x14'u8, 0x21'u8, 0x06'u8, 0x55'u8, 0x9b'u8,
    0xe3'u8, 0xef'u8, 0x5e'u8, 0x31'u8, 0x4f'u8, 0x7f'u8, 0x5a'u8, 0xa4'u8, 0x0d'u8, 0x82'u8, 0x51'u8, 0x49'u8, 0x5f'u8, 0xba'u8, 0x58'u8, 0x1c'u8,
    0x4a'u8, 0x16'u8, 0xd5'u8, 0x17'u8, 0xa8'u8, 0x92'u8, 0x24'u8, 0x1f'u8, 0x8c'u8, 0xff'u8, 0xd8'u8, 0xae'u8, 0x2e'u8, 0x01'u8, 0xd3'u8, 0xad'u8,
    0x3b'u8, 0x4b'u8, 0xda'u8, 0x46'u8, 0xeb'u8, 0xc9'u8, 0xde'u8, 0x9a'u8, 0x8f'u8, 0x87'u8, 0xd7'u8, 0x3a'u8, 0x80'u8, 0x6f'u8, 0x2f'u8, 0xc8'u8,
    0xb1'u8, 0xb4'u8, 0x37'u8, 0xf7'u8, 0x0a'u8, 0x22'u8, 0x13'u8, 0x28'u8, 0x7c'u8, 0xcc'u8, 0x3c'u8, 0x89'u8, 0xc7'u8, 0xc3'u8, 0x96'u8, 0x56'u8,
    0x07'u8, 0xbf'u8, 0x7e'u8, 0xf0'u8, 0x0b'u8, 0x2b'u8, 0x97'u8, 0x52'u8, 0x35'u8, 0x41'u8, 0x79'u8, 0x61'u8, 0xa6'u8, 0x4c'u8, 0x10'u8, 0xfe'u8,
    0xbc'u8, 0x26'u8, 0x95'u8, 0x88'u8, 0x8a'u8, 0xb0'u8, 0xa3'u8, 0xfb'u8, 0xc0'u8, 0x18'u8, 0x94'u8, 0xf2'u8, 0xe1'u8, 0xe5'u8, 0xe9'u8, 0x5d'u8,
    0xd0'u8, 0xdc'u8, 0x11'u8, 0x66'u8, 0x64'u8, 0x5c'u8, 0xec'u8, 0x59'u8, 0x42'u8, 0x75'u8, 0x12'u8, 0xf5'u8, 0x74'u8, 0x9c'u8, 0xaa'u8, 0x23'u8,
    0x0e'u8, 0x86'u8, 0xab'u8, 0xbe'u8, 0x2a'u8, 0x02'u8, 0xe7'u8, 0x67'u8, 0xe6'u8, 0x44'u8, 0xa2'u8, 0x6c'u8, 0xc2'u8, 0x93'u8, 0x9f'u8, 0xf1'u8,
    0xf6'u8, 0xfa'u8, 0x36'u8, 0xd2'u8, 0x50'u8, 0x68'u8, 0x9e'u8, 0x62'u8, 0x71'u8, 0x15'u8, 0x3d'u8, 0xd6'u8, 0x40'u8, 0xc4'u8, 0xe2'u8, 0x0f'u8,
    0x8e'u8, 0x83'u8, 0x77'u8, 0x6b'u8, 0x25'u8, 0x05'u8, 0x3f'u8, 0x0c'u8, 0x30'u8, 0xea'u8, 0x70'u8, 0xb7'u8, 0xa1'u8, 0xe8'u8, 0xa9'u8, 0x65'u8,
    0x8d'u8, 0x27'u8, 0x1a'u8, 0xdb'u8, 0x81'u8, 0xb3'u8, 0xa0'u8, 0xf4'u8, 0x45'u8, 0x7a'u8, 0x19'u8, 0xdf'u8, 0xee'u8, 0x78'u8, 0x34'u8, 0x60'u8
  ]
  SBox1: array[256, uint8] = [
    0x55'u8, 0xc2'u8, 0x63'u8, 0x71'u8, 0x3b'u8, 0xc8'u8, 0x47'u8, 0x86'u8, 0x9f'u8, 0x3c'u8, 0xda'u8, 0x5b'u8, 0x29'u8, 0xaa'u8, 0xfd'u8, 0x77'u8,
    0x8c'u8, 0xc5'u8, 0x94'u8, 0x0c'u8, 0xa6'u8, 0x1a'u8, 0x13'u8, 0x00'u8, 0xe3'u8, 0xa8'u8, 0x16'u8, 0x72'u8, 0x40'u8, 0xf9'u8, 0xf8'u8, 0x42'u8,
    0x44'u8, 0x26'u8, 0x68'u8, 0x96'u8, 0x81'u8, 0xd9'u8, 0x45'u8, 0x3e'u8, 0x10'u8, 0x76'u8, 0xc6'u8, 0xa7'u8, 0x8b'u8, 0x39'u8, 0x43'u8, 0xe1'u8,
    0x3a'u8, 0xb5'u8, 0x56'u8, 0x2a'u8, 0xc0'u8, 0x6d'u8, 0xb3'u8, 0x05'u8, 0x22'u8, 0x66'u8, 0xbf'u8, 0xdc'u8, 0x0b'u8, 0xfa'u8, 0x62'u8, 0x48'u8,
    0xdd'u8, 0x20'u8, 0x11'u8, 0x06'u8, 0x36'u8, 0xc9'u8, 0xc1'u8, 0xcf'u8, 0xf6'u8, 0x27'u8, 0x52'u8, 0xbb'u8, 0x69'u8, 0xf5'u8, 0xd4'u8, 0x87'u8,
    0x7f'u8, 0x84'u8, 0x4c'u8, 0xd2'u8, 0x9c'u8, 0x57'u8, 0xa4'u8, 0xbc'u8, 0x4f'u8, 0x9a'u8, 0xdf'u8, 0xfe'u8, 0xd6'u8, 0x8d'u8, 0x7a'u8, 0xeb'u8,
    0x2b'u8, 0x53'u8, 0xd8'u8, 0x5c'u8, 0xa1'u8, 0x14'u8, 0x17'u8, 0xfb'u8, 0x23'u8, 0xd5'u8, 0x7d'u8, 0x30'u8, 0x67'u8, 0x73'u8, 0x08'u8, 0x09'u8,
    0xee'u8, 0xb7'u8, 0x70'u8, 0x3f'u8, 0x61'u8, 0xb2'u8, 0x19'u8, 0x8e'u8, 0x4e'u8, 0xe5'u8, 0x4b'u8, 0x93'u8, 0x8f'u8, 0x5d'u8, 0xdb'u8, 0xa9'u8,
    0xad'u8, 0xf1'u8, 0xae'u8, 0x2e'u8, 0xcb'u8, 0x0d'u8, 0xfc'u8, 0xf4'u8, 0x2d'u8, 0x46'u8, 0x6e'u8, 0x1d'u8, 0x97'u8, 0xe8'u8, 0xd1'u8, 0xe9'u8,
    0x4d'u8, 0x37'u8, 0xa5'u8, 0x75'u8, 0x5e'u8, 0x83'u8, 0x9e'u8, 0xab'u8, 0x82'u8, 0x9d'u8, 0xb9'u8, 0x1c'u8, 0xe0'u8, 0xcd'u8, 0x49'u8, 0x89'u8,
    0x01'u8, 0xb6'u8, 0xbd'u8, 0x58'u8, 0x24'u8, 0xa2'u8, 0x5f'u8, 0x38'u8, 0x78'u8, 0x99'u8, 0x15'u8, 0x90'u8, 0x50'u8, 0xb8'u8, 0x95'u8, 0xe4'u8,
    0xd0'u8, 0x91'u8, 0xc7'u8, 0xce'u8, 0xed'u8, 0x0f'u8, 0xb4'u8, 0x6f'u8, 0xa0'u8, 0xcc'u8, 0xf0'u8, 0x02'u8, 0x4a'u8, 0x79'u8, 0xc3'u8, 0xde'u8,
    0xa3'u8, 0xef'u8, 0xea'u8, 0x51'u8, 0xe6'u8, 0x6b'u8, 0x18'u8, 0xec'u8, 0x1b'u8, 0x2c'u8, 0x80'u8, 0xf7'u8, 0x74'u8, 0xe7'u8, 0xff'u8, 0x21'u8,
    0x5a'u8, 0x6a'u8, 0x54'u8, 0x1e'u8, 0x41'u8, 0x31'u8, 0x92'u8, 0x35'u8, 0xc4'u8, 0x33'u8, 0x07'u8, 0x0a'u8, 0xba'u8, 0x7e'u8, 0x0e'u8, 0x34'u8,
    0x88'u8, 0xb1'u8, 0x98'u8, 0x7c'u8, 0xf3'u8, 0x3d'u8, 0x60'u8, 0x6c'u8, 0x7b'u8, 0xca'u8, 0xd3'u8, 0x1f'u8, 0x32'u8, 0x65'u8, 0x04'u8, 0x28'u8,
    0x64'u8, 0xbe'u8, 0x85'u8, 0x9b'u8, 0x2f'u8, 0x59'u8, 0x8a'u8, 0xd7'u8, 0xb0'u8, 0x25'u8, 0xac'u8, 0xaf'u8, 0x12'u8, 0x03'u8, 0xe2'u8, 0xf2'u8
  ]
  D: array[16, uint32] = [
    0x44D7'u32, 0x26BC'u32, 0x626B'u32, 0x135E'u32, 0x5789'u32, 0x35E2'u32, 0x7135'u32, 0x09AF'u32,
    0x4D78'u32, 0x2F13'u32, 0x6BC4'u32, 0x1AF1'u32, 0x5E26'u32, 0x3C4D'u32, 0x789A'u32, 0x47AC'u32
  ]

type
  # ZUC context
  ZUCCtx* = object
    state*: array[16, uint32]
    register1*: uint32
    register2*: uint32

# ZUC multiply by power of 2
template mulByPow2(x, k: uint32): uint32 =
  ((x shl k) or (x shr (31 - k))) and 0x7FFFFFFF'u32

# ZUC add module
template addModule(a, b: uint32): uint32 =
  let c: uint32 = a + b
  let d: uint32 = (c and 0x7FFFFFFF'u32) + (c shr 31)
  if d >= 0x7FFFFFFF'u32: d - 0x7FFFFFFF'u32 else: d

# ZUC LFSR initialization mode
template lfsrInitializationMode(state: var array[16, uint32], u: uint32): void =
  var f = state[0]
  f = addModule(f, mulByPow2(state[0], 8))
  f = addModule(f, mulByPow2(state[4], 20))
  f = addModule(f, mulByPow2(state[10], 21))
  f = addModule(f, mulByPow2(state[13], 17))
  f = addModule(f, mulByPow2(state[15], 15))
  f = addModule(f, u)
  
  if f == 0: f = 0x7FFFFFFF'u32

  for i in static(0 ..< 15):
    state[i] = state[i + 1]
  state[15] = f

# ZUC LFSR work mode
template lfsrWorkMode(state: var array[16, uint32]): void =
  var f = state[0]
  f = addModule(f, mulByPow2(state[0], 8))
  f = addModule(f, mulByPow2(state[4], 20))
  f = addModule(f, mulByPow2(state[10], 21))
  f = addModule(f, mulByPow2(state[13], 17))
  f = addModule(f, mulByPow2(state[15], 15))
  
  if f == 0: f = 0x7FFFFFFF'u32

  for i in static(0 ..< 15):
    state[i] = state[i + 1]
  state[15] = f

# ZUC bit reorganization
template bitReorganization(state: array[16, uint32], x: var array[4, uint32]): void =
  x[0] = ((state[15] shr 15) shl 16) or (state[14] and 0xFFFF'u32)
  x[1] = (state[11] and 0xFFFF'u32) shl 16 or (state[9] shr 15)
  x[2] = (state[7] and 0xFFFF'u32) shl 16 or (state[5] shr 15)
  x[3] = (state[2] and 0xFFFF'u32) shl 16 or (state[0] shr 15)

# ZUC L1 template
template L1(x: uint32): uint32 =
  x xor rotateLeftBits(x, 2) xor rotateLeftBits(x, 10) xor rotateLeftBits(x, 18) xor rotateLeftBits(x, 24)

# ZUC L2 template
template L2(x: uint32): uint32 =
  x xor rotateLeftBits(x, 8) xor rotateLeftBits(x, 14) xor rotateLeftBits(x, 22) xor rotateLeftBits(x, 30)

# ZUC make 32-bit integer
template makeU32(a, b, c, d: uint8): uint32 =
  (uint32(a) shl 24) or (uint32(b) shl 16) or (uint32(c) shl 8) or uint32(d)

# ZUC make 31-bit integer
template makeU31(a: uint8, b: uint32, c: uint8): uint32 =
  (uint32(a) shl 23) or (uint32(b) shl 8) or uint32(c)

# ZUC f template
template fFunction(ctx: var ZUCCtx, x: array[4, uint32]): uint32 =
  let w = (x[0] xor ctx.register1) + ctx.register2
  let w1 = ctx.register1 + x[1]
  let w2 = ctx.register2 xor x[2]
  let u = L1((w1 and 0xFFFF0000'u32) or (w2 and 0x0000FFFF'u32))
  let v = L2((w2 and 0xFFFF0000'u32) or (w1 and 0x0000FFFF'u32))
  ctx.register1 = makeU32(SBox0[int(u shr 24)], SBox1[int((u shr 16) and 0xFF'u32)], SBox0[int((u shr 8) and 0xFF'u32)], SBox1[int(u and 0xFF'u32)])
  ctx.register2 = makeU32(SBox0[int(v shr 24)], SBox1[int((v shr 16) and 0xFF'u32)], SBox0[int((v shr 8) and 0xFF'u32)], SBox1[int(v and 0xFF'u32)])
  w

# ZUC init core
template zucInitC(ctx: var ZUCCtx, key, iv: slicearray[16, uint8]): void =
  for i in static(0 ..< 16):
    ctx.state[i] = makeU31(key[i], D[i], iv[i])
  ctx.register1 = 0
  ctx.register2 = 0
  
  var x: array[4, uint32]
  for i in static(0 ..< 32):
    bitReorganization(ctx.state, x)
    let w = fFunction(ctx, x)
    lfsrInitializationMode(ctx.state, w shr 1)
  
  bitReorganization(ctx.state, x)
  discard fFunction(ctx, x)
  lfsrWorkMode(ctx.state)

# ZUC generate key stream
template zucGenerateKeyStream(ctx: var ZUCCtx, keyStream: var openArray[uint32]): void =
  let keyStreamLen: int = keyStream.len
  var x: array[4, uint32]
  for i in 0 ..< keyStreamLen:
    bitReorganization(ctx.state, x)
    keyStream[i] = fFunction(ctx, x) xor x[3]
    lfsrWorkMode(ctx.state)

# ZUC xor core
template zucXorC(ctx: var ZUCCtx, input: openArray[uint8], output: var openArray[uint8]): void =
  let inputLen: int = input.len
  var inputU32: ptr UncheckedArray[uint32] = cast[ptr UncheckedArray[uint32]](addr input[0])
  var outputU32: ptr UncheckedArray[uint32] = cast[ptr UncheckedArray[uint32]](addr output[0])
  var keyStream: seq[uint32] = newSeq[uint32](inputLen div 4)
  zucGenerateKeyStream(ctx, keyStream)
  for i in 0 ..< (inputLen div 4):
    outputU32[i] = inputU32[i] xor keyStream[i]

# export wrappers
when defined(templateOpt):
  template zucInit*(ctx: var ZUCCtx, key, iv: array[16, uint8]): void =
    zucInitC(ctx, key.toSliceArray(0, 15), iv.toSliceArray(0, 15))
  template zucInit*(ctx: var ZUCCtx, key, iv: slicearray[16, uint8]): void =
    zucInitC(ctx, key, iv)
  template zucInit*(ctx: var ZUCCtx, key, iv: openArray[uint8]): void =
    zucInitC(ctx, key.toSliceArray(0, 15), iv.toSliceArray(0, 15))
  template zucInit*(ctx: ptr ZUCCtx, key, iv: ptr array[16, uint8]): void =
    zucInitC(ctx[], key.toSliceArray(0, 15), iv.toSliceArray(0, 15))
  
  template zucXor*(ctx: var ZUCCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    zucXorC(ctx, input, output)
  template zucXor*(ctx: ptr ZUCCtx, input, output: ptr UncheckedArray[uint8], length: int): void =
    zucXorC(ctx[], input.toOpenArray(0, length - 1), output.toOpenArray(0, length - 1))
else:
  proc zucInit*(ctx: var ZUCCtx, key, iv: array[16, uint8]): void =
    zucInitC(ctx, key.toSliceArray(0, 15), iv.toSliceArray(0, 15))
  proc zucInit*(ctx: var ZUCCtx, key, iv: slicearray[16, uint8]): void =
    zucInitC(ctx, key, iv)
  proc zucInit*(ctx: var ZUCCtx, key, iv: openArray[uint8]): void =
    zucInitC(ctx, key.toSliceArray(0, 15), iv.toSliceArray(0, 15))
  proc zucInit*(ctx: ptr ZUCCtx, key, iv: ptr array[16, uint8]): void {.exportc: "zucInit".} =
    zucInitC(ctx[], key.toSliceArray(0, 15), iv.toSliceArray(0, 15))
  
  proc zucXor*(ctx: var ZUCCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    zucXorC(ctx, input, output)
  proc zucXor*(ctx: ptr ZUCCtx, input, output: ptr UncheckedArray[uint8], length: int): void {.exportc: "zucXor".} =
    zucXorC(ctx[], input.toOpenArray(0, length - 1), output.toOpenArray(0, length - 1))
