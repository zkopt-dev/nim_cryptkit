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
  # PI constant table
  PI: array[256, uint8] = [
    0xd9'u8, 0x78'u8, 0xf9'u8, 0xc4'u8, 0x19'u8, 0xdd'u8, 0xb5'u8, 0xed'u8, 0x28'u8, 0xe9'u8, 0xfd'u8, 0x79'u8, 0x4a'u8, 0xa0'u8, 0xd8'u8, 0x9d'u8,
    0xc6'u8, 0x7e'u8, 0x37'u8, 0x83'u8, 0x2b'u8, 0x76'u8, 0x53'u8, 0x8e'u8, 0x62'u8, 0x4c'u8, 0x64'u8, 0x88'u8, 0x44'u8, 0x8b'u8, 0xfb'u8, 0xa2'u8,
    0x17'u8, 0x9a'u8, 0x59'u8, 0xf5'u8, 0x87'u8, 0xb3'u8, 0x4f'u8, 0x13'u8, 0x61'u8, 0x45'u8, 0x6d'u8, 0x8d'u8, 0x09'u8, 0x81'u8, 0x7d'u8, 0x32'u8,
    0xbd'u8, 0x8f'u8, 0x40'u8, 0xeb'u8, 0x86'u8, 0xb7'u8, 0x7b'u8, 0x0b'u8, 0xf0'u8, 0x95'u8, 0x21'u8, 0x22'u8, 0x5c'u8, 0x6b'u8, 0x4e'u8, 0x82'u8,
    0x54'u8, 0xd6'u8, 0x65'u8, 0x93'u8, 0xce'u8, 0x60'u8, 0xb2'u8, 0x1c'u8, 0x73'u8, 0x56'u8, 0xc0'u8, 0x14'u8, 0xa7'u8, 0x8c'u8, 0xf1'u8, 0xdc'u8,
    0x12'u8, 0x75'u8, 0xca'u8, 0x1f'u8, 0x3b'u8, 0xbe'u8, 0xe4'u8, 0xd1'u8, 0x42'u8, 0x3d'u8, 0xd4'u8, 0x30'u8, 0xa3'u8, 0x3c'u8, 0xb6'u8, 0x26'u8,
    0x6f'u8, 0xbf'u8, 0x0e'u8, 0xda'u8, 0x46'u8, 0x69'u8, 0x07'u8, 0x57'u8, 0x27'u8, 0xf2'u8, 0x1d'u8, 0x9b'u8, 0xbc'u8, 0x94'u8, 0x43'u8, 0x03'u8,
    0xf8'u8, 0x11'u8, 0xc7'u8, 0xf6'u8, 0x90'u8, 0xef'u8, 0x3e'u8, 0xe7'u8, 0x06'u8, 0xc3'u8, 0xd5'u8, 0x2f'u8, 0xc8'u8, 0x66'u8, 0x1e'u8, 0xd7'u8,
    0x08'u8, 0xe8'u8, 0xea'u8, 0xde'u8, 0x80'u8, 0x52'u8, 0xee'u8, 0xf7'u8, 0x84'u8, 0xaa'u8, 0x72'u8, 0xac'u8, 0x35'u8, 0x4d'u8, 0x6a'u8, 0x2a'u8,
    0x96'u8, 0x1a'u8, 0xd2'u8, 0x71'u8, 0x5a'u8, 0x15'u8, 0x49'u8, 0x74'u8, 0x4b'u8, 0x9f'u8, 0xd0'u8, 0x5e'u8, 0x04'u8, 0x18'u8, 0xa4'u8, 0xec'u8,
    0xc2'u8, 0xe0'u8, 0x41'u8, 0x6e'u8, 0x0f'u8, 0x51'u8, 0xcb'u8, 0xcc'u8, 0x24'u8, 0x91'u8, 0xaf'u8, 0x50'u8, 0xa1'u8, 0xf4'u8, 0x70'u8, 0x39'u8,
    0x99'u8, 0x7c'u8, 0x3a'u8, 0x85'u8, 0x23'u8, 0xb8'u8, 0xb4'u8, 0x7a'u8, 0xfc'u8, 0x02'u8, 0x36'u8, 0x5b'u8, 0x25'u8, 0x55'u8, 0x97'u8, 0x31'u8,
    0x2d'u8, 0x5d'u8, 0xfa'u8, 0x98'u8, 0xe3'u8, 0x8a'u8, 0x92'u8, 0xae'u8, 0x05'u8, 0xdf'u8, 0x29'u8, 0x10'u8, 0x67'u8, 0x6c'u8, 0xba'u8, 0xc9'u8,
    0xd3'u8, 0x00'u8, 0xe6'u8, 0xcf'u8, 0xe1'u8, 0x9e'u8, 0xa8'u8, 0x2c'u8, 0x63'u8, 0x16'u8, 0x01'u8, 0x3f'u8, 0x58'u8, 0xe2'u8, 0x89'u8, 0xa9'u8,
    0x0d'u8, 0x38'u8, 0x34'u8, 0x1b'u8, 0xab'u8, 0x33'u8, 0xff'u8, 0xb0'u8, 0xbb'u8, 0x48'u8, 0x0c'u8, 0x5f'u8, 0xb9'u8, 0xb1'u8, 0xcd'u8, 0x2e'u8,
    0xc5'u8, 0xf3'u8, 0xdb'u8, 0x47'u8, 0xe5'u8, 0xa5'u8, 0x9c'u8, 0x77'u8, 0x0a'u8, 0xa6'u8, 0x20'u8, 0x68'u8, 0xfe'u8, 0x7f'u8, 0xc1'u8, 0xad'u8,
  ]

  # rc2 information constants
  RC2_BLOCK_SIZE*: int = 8
  RC2_MIN_KEY_SIZE*: int = 1
  RC2_MAX_KEY_SIZE*: int = 128
  RC2_ROUND_NUMBER*: int = 64

type
  # rc2 context
  RC2Ctx* = object
    roundKey*: array[64, uint16]

# rc2 init core
template rc2InitC(ctx: var RC2Ctx, key: openArray[uint8], t1: int): void =
  # declare buffer
  var buffer: array[128, uint8]

  # copy key to buffer
  for i in 0 ..< key.len:
    buffer[i] = key[i]

  # calculate security strength
  let t8: int = (t1 + 7) div 8
  let shiftValue: int = 8 + t1 - (8 * t8)
  let tm: uint8 = uint8(255 mod (1 shl shiftValue))

  # generate round key
  for i in key.len ..< 128:
    buffer[i] = PI[(buffer[i - 1] + buffer[i - key.len]).int]

  buffer[128 - t8] = PI[(buffer[128 - t8] and tm).int]

  for i in countdown(127 - t8, 0):
    buffer[i] = PI[(buffer[i + 1] xor buffer[i + t8]).int]

  # compress buffer to round key
  for i in static(0 ..< 64):
    ctx.roundKey[i] = uint16(buffer[2 * i]) or (uint16(buffer[2 * i + 1]) shl 8)

# rc2 encrypt core
template rc2EncryptC(ctx: RC2Ctx, input, output: slicearray[8, uint8]): void =
  # declare tmporal registers
  var r0, r1, r2, r3: uint16
  
  # decode state to temporal register
  when LE:
    let inputU16: ptr array[4, uint16] = cast[ptr array[4, uint16]](addr input[0])
    r0 = inputU16[0]
    r1 = inputU16[1]
    r2 = inputU16[2]
    r3 = inputU16[3]
  else:
    fromBytesLE(input.toSliceArray(0, 1), r0)
    fromBytesLE(input.toSliceArray(2, 3), r1)
    fromBytesLE(input.toSliceArray(4, 5), r2)
    fromBytesLE(input.toSliceArray(6, 7), r3)

  # unroll mixing round : 0 ~ 19
  for i in static(0 .. 4):
    r0 = rotateLeftBits(r0 + ctx.roundKey[i * 4 + 0] + (r3 and r2) + ((not r3) and r1), 1)
    r1 = rotateLeftBits(r1 + ctx.roundKey[i * 4 + 1] + (r0 and r3) + ((not r0) and r2), 2)
    r2 = rotateLeftBits(r2 + ctx.roundKey[i * 4 + 2] + (r1 and r0) + ((not r1) and r3), 3)
    r3 = rotateLeftBits(r3 + ctx.roundKey[i * 4 + 3] + (r2 and r1) + ((not r2) and r0), 5)

  # mashing
  r0 = r0 + ctx.roundKey[int(r3 and 63)]
  r1 = r1 + ctx.roundKey[int(r0 and 63)]
  r2 = r2 + ctx.roundKey[int(r1 and 63)]
  r3 = r3 + ctx.roundKey[int(r2 and 63)]
  
  # unroll mixing round : 20 ~ 43
  for i in static(5 .. 10):
    r0 = rotateLeftBits(r0 + ctx.roundKey[i * 4 + 0] + (r3 and r2) + ((not r3) and r1), 1)
    r1 = rotateLeftBits(r1 + ctx.roundKey[i * 4 + 1] + (r0 and r3) + ((not r0) and r2), 2)
    r2 = rotateLeftBits(r2 + ctx.roundKey[i * 4 + 2] + (r1 and r0) + ((not r1) and r3), 3)
    r3 = rotateLeftBits(r3 + ctx.roundKey[i * 4 + 3] + (r2 and r1) + ((not r2) and r0), 5)

  # mashing
  r0 = r0 + ctx.roundKey[int(r3 and 63)]
  r1 = r1 + ctx.roundKey[int(r0 and 63)]
  r2 = r2 + ctx.roundKey[int(r1 and 63)]
  r3 = r3 + ctx.roundKey[int(r2 and 63)]

  # unroll mixing round : 44 ~ 63
  for i in static(11 .. 15):
    r0 = rotateLeftBits(r0 + ctx.roundKey[i * 4 + 0] + (r3 and r2) + ((not r3) and r1), 1)
    r1 = rotateLeftBits(r1 + ctx.roundKey[i * 4 + 1] + (r0 and r3) + ((not r0) and r2), 2)
    r2 = rotateLeftBits(r2 + ctx.roundKey[i * 4 + 2] + (r1 and r0) + ((not r1) and r3), 3)
    r3 = rotateLeftBits(r3 + ctx.roundKey[i * 4 + 3] + (r2 and r1) + ((not r2) and r0), 5)

  # encode temporal register to state
  when LE:
    let outputU16: ptr array[4, uint16] = cast[ptr array[4, uint16]](addr output[0])
    outputU16[0] = r0
    outputU16[1] = r1
    outputU16[2] = r2
    outputU16[3] = r3
  else:
    toBytesLE(r0, output.toSliceArray(0, 1))
    toBytesLE(r1, output.toSliceArray(2, 3))
    toBytesLE(r2, output.toSliceArray(4, 5))
    toBytesLE(r3, output.toSliceArray(6, 7))

# rc2 decrypt core
template rc2DecryptC(ctx: RC2Ctx, input, output: slicearray[8, uint8]): void =
  # declare tmporal registers
  var r0, r1, r2, r3: uint16
  
  # decode state to temporal register
  when LE:
    let inputU16: ptr array[4, uint16] = cast[ptr array[4, uint16]](addr input[0])
    r0 = inputU16[0]
    r1 = inputU16[1]
    r2 = inputU16[2]
    r3 = inputU16[3]
  else:
    fromBytesLE(input.toSliceArray(0, 1), r0)
    fromBytesLE(input.toSliceArray(2, 3), r1)
    fromBytesLE(input.toSliceArray(4, 5), r2)
    fromBytesLE(input.toSliceArray(6, 7), r3)

  # unroll mixing round : 63 ~ 44
  for i in countdown(15, 11):
    r3 = rotateLeftBits(r3, 16 - 5)
    r3 = r3 - ctx.roundKey[i * 4 + 3] - (r2 and r1) - ((not r2) and r0)
    
    r2 = rotateLeftBits(r2, 16 - 3)
    r2 = r2 - ctx.roundKey[i * 4 + 2] - (r1 and r0) - ((not r1) and r3)
    
    r1 = rotateLeftBits(r1, 16 - 2)
    r1 = r1 - ctx.roundKey[i * 4 + 1] - (r0 and r3) - ((not r0) and r2)
    
    r0 = rotateLeftBits(r0, 16 - 1)
    r0 = r0 - ctx.roundKey[i * 4 + 0] - (r3 and r2) - ((not r3) and r1)

  # mashing
  r3 = r3 - ctx.roundKey[int(r2 and 63)]
  r2 = r2 - ctx.roundKey[int(r1 and 63)]
  r1 = r1 - ctx.roundKey[int(r0 and 63)]
  r0 = r0 - ctx.roundKey[int(r3 and 63)]

  # unroll mixing round : 43  ~ 20
  for i in countdown(10, 5):
    r3 = rotateLeftBits(r3, 16 - 5)
    r3 = r3 - ctx.roundKey[i * 4 + 3] - (r2 and r1) - ((not r2) and r0)
    
    r2 = rotateLeftBits(r2, 16 - 3)
    r2 = r2 - ctx.roundKey[i * 4 + 2] - (r1 and r0) - ((not r1) and r3)
    
    r1 = rotateLeftBits(r1, 16 - 2)
    r1 = r1 - ctx.roundKey[i * 4 + 1] - (r0 and r3) - ((not r0) and r2)
    
    r0 = rotateLeftBits(r0, 16 - 1)
    r0 = r0 - ctx.roundKey[i * 4 + 0] - (r3 and r2) - ((not r3) and r1)

  # mashing
  r3 = r3 - ctx.roundKey[int(r2 and 63)]
  r2 = r2 - ctx.roundKey[int(r1 and 63)]
  r1 = r1 - ctx.roundKey[int(r0 and 63)]
  r0 = r0 - ctx.roundKey[int(r3 and 63)]

  # unroll mixing round : 19 ~ 0
  for i in countdown(4, 0):
    r3 = rotateLeftBits(r3, 16 - 5)
    r3 = r3 - ctx.roundKey[i * 4 + 3] - (r2 and r1) - ((not r2) and r0)
    
    r2 = rotateLeftBits(r2, 16 - 3)
    r2 = r2 - ctx.roundKey[i * 4 + 2] - (r1 and r0) - ((not r1) and r3)
    
    r1 = rotateLeftBits(r1, 16 - 2)
    r1 = r1 - ctx.roundKey[i * 4 + 1] - (r0 and r3) - ((not r0) and r2)
    
    r0 = rotateLeftBits(r0, 16 - 1)
    r0 = r0 - ctx.roundKey[i * 4 + 0] - (r3 and r2) - ((not r3) and r1)

  # encode temporal register to state
  when LE:
    let outputU16: ptr array[4, uint16] = cast[ptr array[4, uint16]](addr output[0])
    outputU16[0] = r0
    outputU16[1] = r1
    outputU16[2] = r2
    outputU16[3] = r3
  else:
    toBytesLE(r0, output.toSliceArray(0, 1))
    toBytesLE(r1, output.toSliceArray(2, 3))
    toBytesLE(r2, output.toSliceArray(4, 5))
    toBytesLE(r3, output.toSliceArray(6, 7))

# export wrappers
when defined(templateOpt):
  template rc2Init*(ctx: var RC2Ctx, key: openArray[uint8], t1: int): void =
    rc2InitC(ctx, key, t1)
  template rc2Init*(ctx: ptr RC2Ctx, key: ptr UncheckedArray[uint8], keyLen: int, t1: int): void =
    rc2InitC(ctx, key.toOpenArray(0, keyLen - 1), t1)

  template rc2Encrypt*(ctx: RC2Ctx, input: array[8, uint8], output: var array[8, uint8]): void =
    rc2EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template rc2Encrypt*(ctx: RC2Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    rc2EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template rc2Encrypt*(ctx: RC2Ctx, input, output: slicearray[8, uint8]): void =
    rc2EncryptC(ctx, input, output)
  template rc2Encrypt*(ctx: RC2Ctx, input, output: ptr array[8, uint8]): void =
    rc2EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  template rc2Decrypt*(ctx: RC2Ctx, input: array[8, uint8], output: var array[8, uint8]): void =
    rc2DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template rc2Decrypt*(ctx: RC2Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    rc2DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template rc2Decrypt*(ctx: RC2Ctx, input, output: slicearray[8, uint8]): void =
    rc2DecryptC(ctx, input, output)
  template rc2Decrypt*(ctx: RC2Ctx, input, output: ptr array[8, uint8]): void =
    rc2DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
else:
  proc rc2Init*(ctx: var RC2Ctx, key: openArray[uint8], t1: int): void =
    rc2InitC(ctx, key, t1)
  proc rc2Init*(ctx: ptr RC2Ctx, key: ptr UncheckedArray[uint8], keyLen: int, t1: int): void =
    rc2InitC(ctx[], key.toOpenArray(0, keyLen - 1), t1)

  proc rc2Encrypt*(ctx: RC2Ctx, input: array[8, uint8], output: var array[8, uint8]): void =
    rc2EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc rc2Encrypt*(ctx: RC2Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    rc2EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc rc2Encrypt*(ctx: RC2Ctx, input, output: slicearray[8, uint8]): void =
    rc2EncryptC(ctx, input, output)
  proc rc2Encrypt*(ctx: RC2Ctx, input, output: ptr array[8, uint8]): void =
    rc2EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  proc rc2Decrypt*(ctx: RC2Ctx, input: array[8, uint8], output: var array[8, uint8]): void =
    rc2DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc rc2Decrypt*(ctx: RC2Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    rc2DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc rc2Decrypt*(ctx: RC2Ctx, input, output: slicearray[8, uint8]): void =
    rc2DecryptC(ctx, input, output)
  proc rc2Decrypt*(ctx: RC2Ctx, input, output: ptr array[8, uint8]): void =
    rc2DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))

