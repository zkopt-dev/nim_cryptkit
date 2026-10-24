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
  # delta constant
  Delta*: array[128, uint8] = [
    0x5A'u8, 0x6D'u8, 0x36'u8, 0x1B'u8, 0x0D'u8, 0x06'u8, 0x03'u8, 0x41'u8, 0x60'u8, 0x30'u8, 0x18'u8, 0x4C'u8, 0x66'u8, 0x33'u8, 0x59'u8, 0x2C'u8,
    0x56'u8, 0x2B'u8, 0x15'u8, 0x4A'u8, 0x65'u8, 0x72'u8, 0x39'u8, 0x1C'u8, 0x4E'u8, 0x67'u8, 0x73'u8, 0x79'u8, 0x3C'u8, 0x5E'u8, 0x6F'u8, 0x37'u8,
    0x5B'u8, 0x2D'u8, 0x16'u8, 0x0B'u8, 0x05'u8, 0x42'u8, 0x21'u8, 0x50'u8, 0x28'u8, 0x54'u8, 0x2A'u8, 0x55'u8, 0x6A'u8, 0x75'u8, 0x7A'u8, 0x7D'u8,
    0x3E'u8, 0x5F'u8, 0x2F'u8, 0x17'u8, 0x4B'u8, 0x25'u8, 0x52'u8, 0x29'u8, 0x14'u8, 0x0A'u8, 0x45'u8, 0x62'u8, 0x31'u8, 0x58'u8, 0x6C'u8, 0x76'u8,
    0x3B'u8, 0x1D'u8, 0x0E'u8, 0x47'u8, 0x63'u8, 0x71'u8, 0x78'u8, 0x7C'u8, 0x7E'u8, 0x7F'u8, 0x3F'u8, 0x1F'u8, 0x0F'u8, 0x07'u8, 0x43'u8, 0x61'u8,
    0x70'u8, 0x38'u8, 0x5C'u8, 0x6E'u8, 0x77'u8, 0x7B'u8, 0x3D'u8, 0x1E'u8, 0x4F'u8, 0x27'u8, 0x53'u8, 0x69'u8, 0x34'u8, 0x1A'u8, 0x4D'u8, 0x26'u8, 
    0x13'u8, 0x49'u8, 0x24'u8, 0x12'u8, 0x09'u8, 0x04'u8, 0x02'u8, 0x01'u8, 0x40'u8, 0x20'u8, 0x10'u8, 0x08'u8, 0x44'u8, 0x22'u8, 0x11'u8, 0x48'u8,
    0x64'u8, 0x32'u8, 0x19'u8, 0x0C'u8, 0x46'u8, 0x23'u8, 0x51'u8, 0x68'u8, 0x74'u8, 0x3A'u8, 0x5D'u8, 0x2E'u8, 0x57'u8, 0x6B'u8, 0x35'u8, 0x5A'u8
  ]

  # block size constant
  BLOCK_SIZE*: int = 8
  # key size constant
  KEY_SIZE*: int = 16

type
  # HIGHT context 
  HIGHTCtx* = object
    roundKey*: array[136, uint8]

# F0 template
template F0(x: uint8): uint8 =
  rotateLeftBits(x, 1) xor rotateLeftBits(x, 2) xor rotateLeftBits(x, 7)

# F1 template
template F1(x: uint8): uint8 = 
  rotateLeftBits(x, 3) xor rotateLeftBits(x, 4) xor rotateLeftBits(x, 6)

# hight init core
template hightInitC*(ctx: var HIGHTCtx, key: slicearray[16, uint8]): void {.autoSizeOpt.} =
  # init whitening keys
  ctx.roundKey[0] = key[12]
  ctx.roundKey[1] = key[13]
  ctx.roundKey[2] = key[14]
  ctx.roundKey[3] = key[15]
  ctx.roundKey[4] = key[0]
  ctx.roundKey[5] = key[1]
  ctx.roundKey[6] = key[2]
  ctx.roundKey[7] = key[3]

  # init round keys
  for i in static(0 ..< 8):
    for k in static(0 ..< 8):
      ctx.roundKey[8 + 16 * i + k + 0] = key[((k - i) and 7) + 0] + Delta[16 * i + k + 0]

    for k in static(0 ..< 8):
      ctx.roundKey[8 + 16 * i + k + 8] = key[((k - i) and 7) + 8] + Delta[16 * i + k + 8]
  
# hight encrypt core
template hightEncryptC(ctx: HIGHTCtx, input, output: slicearray[8, uint8]): void {.autoSizeOpt.} =
  # declare temporary array
  var x: array[8, uint8]

  # copy state to x
  x[0] = input[0] + ctx.roundKey[0]
  x[1] = input[1]
  x[2] = input[2] xor ctx.roundKey[1]
  x[3] = input[3]
  x[4] = input[4] + ctx.roundKey[2]
  x[5] = input[5]
  x[6] = input[6] xor ctx.roundKey[3]
  x[7] = input[7]

  # declare internal round template
  template hightRound(i: static int, r0, r1, r2, r3, r4, r5, r6, r7: static int) =
    x[r0] = x[r0] xor (F0(x[r1]) + ctx.roundKey[4*i + 3])
    x[r2] = x[r2] + (F1(x[r3]) xor ctx.roundKey[4*i + 2])
    x[r4] = x[r4] xor (F0(x[r5]) + ctx.roundKey[4*i + 1])
    x[r6] = x[r6] + (F1(x[r7]) xor ctx.roundKey[4*i + 0])

  # call round template
  hightRound(2, 7, 6, 5, 4, 3, 2, 1, 0)
  hightRound(3, 6, 5, 4, 3, 2, 1, 0, 7)
  hightRound(4, 5, 4, 3, 2, 1, 0, 7, 6)
  hightRound(5, 4, 3, 2, 1, 0, 7, 6, 5)
  hightRound(6, 3, 2, 1, 0, 7, 6, 5, 4)
  hightRound(7, 2, 1, 0, 7, 6, 5, 4, 3)
  hightRound(8, 1, 0, 7, 6, 5, 4, 3, 2)
  hightRound(9, 0, 7, 6, 5, 4, 3, 2, 1)
  hightRound(10, 7, 6, 5, 4, 3, 2, 1, 0)
  hightRound(11, 6, 5, 4, 3, 2, 1, 0, 7)
  hightRound(12, 5, 4, 3, 2, 1, 0, 7, 6)
  hightRound(13, 4, 3, 2, 1, 0, 7, 6, 5)
  hightRound(14, 3, 2, 1, 0, 7, 6, 5, 4)
  hightRound(15, 2, 1, 0, 7, 6, 5, 4, 3)
  hightRound(16, 1, 0, 7, 6, 5, 4, 3, 2)
  hightRound(17, 0, 7, 6, 5, 4, 3, 2, 1)
  hightRound(18, 7, 6, 5, 4, 3, 2, 1, 0)
  hightRound(19, 6, 5, 4, 3, 2, 1, 0, 7)
  hightRound(20, 5, 4, 3, 2, 1, 0, 7, 6)
  hightRound(21, 4, 3, 2, 1, 0, 7, 6, 5)
  hightRound(22, 3, 2, 1, 0, 7, 6, 5, 4)
  hightRound(23, 2, 1, 0, 7, 6, 5, 4, 3)
  hightRound(24, 1, 0, 7, 6, 5, 4, 3, 2)
  hightRound(25, 0, 7, 6, 5, 4, 3, 2, 1)
  hightRound(26, 7, 6, 5, 4, 3, 2, 1, 0)
  hightRound(27, 6, 5, 4, 3, 2, 1, 0, 7)
  hightRound(28, 5, 4, 3, 2, 1, 0, 7, 6)
  hightRound(29, 4, 3, 2, 1, 0, 7, 6, 5)
  hightRound(30, 3, 2, 1, 0, 7, 6, 5, 4)
  hightRound(31, 2, 1, 0, 7, 6, 5, 4, 3)
  hightRound(32, 1, 0, 7, 6, 5, 4, 3, 2)
  hightRound(33, 0, 7, 6, 5, 4, 3, 2, 1)

  # assign x to state
  output[0] = x[1] + ctx.roundKey[4]
  output[1] = x[2]
  output[2] = x[3] xor ctx.roundKey[5]
  output[3] = x[4]
  output[4] = x[5] + ctx.roundKey[6]
  output[5] = x[6]
  output[6] = x[7] xor ctx.roundKey[7]
  output[7] = x[0]

# hight decrypt core
template hightDecryptC(ctx: HIGHTCtx, input, output: slicearray[8, uint8]): void {.autoSizeOpt.} =
  # declare temporary array
  var x: array[8, uint8]
  
  # copy state to x
  x[0] = input[7]
  x[1] = input[0] - ctx.roundKey[4]
  x[2] = input[1]
  x[3] = input[2] xor ctx.roundKey[5]
  x[4] = input[3]
  x[5] = input[4] - ctx.roundKey[6]
  x[6] = input[5]
  x[7] = input[6] xor ctx.roundKey[7]

  # declare internal round template
  template hightRound(i, r0, r1, r2, r3, r4, r5, r6, r7: static int): void =
    x[r1] = x[r1] - (F1(x[r2]) xor ctx.roundKey[4*i + 2])
    x[r3] = x[r3] xor (F0(x[r4]) + ctx.roundKey[4*i + 1])
    x[r5] = x[r5] - (F1(x[r6]) xor ctx.roundKey[4*i + 0])
    x[r7] = x[r7] xor (F0(x[r0]) + ctx.roundKey[4*i + 3])
  
  # call round template
  hightRound(33, 7, 6, 5, 4, 3, 2, 1, 0)
  hightRound(32, 0, 7, 6, 5, 4, 3, 2, 1)
  hightRound(31, 1, 0, 7, 6, 5, 4, 3, 2)
  hightRound(30, 2, 1, 0, 7, 6, 5, 4, 3)
  hightRound(29, 3, 2, 1, 0, 7, 6, 5, 4)
  hightRound(28, 4, 3, 2, 1, 0, 7, 6, 5)
  hightRound(27, 5, 4, 3, 2, 1, 0, 7, 6)
  hightRound(26, 6, 5, 4, 3, 2, 1, 0, 7)
  hightRound(25, 7, 6, 5, 4, 3, 2, 1, 0)
  hightRound(24, 0, 7, 6, 5, 4, 3, 2, 1)
  hightRound(23, 1, 0, 7, 6, 5, 4, 3, 2)
  hightRound(22, 2, 1, 0, 7, 6, 5, 4, 3)
  hightRound(21, 3, 2, 1, 0, 7, 6, 5, 4)
  hightRound(20, 4, 3, 2, 1, 0, 7, 6, 5)
  hightRound(19, 5, 4, 3, 2, 1, 0, 7, 6)
  hightRound(18, 6, 5, 4, 3, 2, 1, 0, 7)
  hightRound(17, 7, 6, 5, 4, 3, 2, 1, 0)
  hightRound(16, 0, 7, 6, 5, 4, 3, 2, 1)
  hightRound(15, 1, 0, 7, 6, 5, 4, 3, 2)
  hightRound(14, 2, 1, 0, 7, 6, 5, 4, 3)
  hightRound(13, 3, 2, 1, 0, 7, 6, 5, 4)
  hightRound(12, 4, 3, 2, 1, 0, 7, 6, 5)
  hightRound(11, 5, 4, 3, 2, 1, 0, 7, 6)
  hightRound(10, 6, 5, 4, 3, 2, 1, 0, 7)
  hightRound(9, 7, 6, 5, 4, 3, 2, 1, 0)
  hightRound(8, 0, 7, 6, 5, 4, 3, 2, 1)
  hightRound(7, 1, 0, 7, 6, 5, 4, 3, 2)
  hightRound(6, 2, 1, 0, 7, 6, 5, 4, 3)
  hightRound(5, 3, 2, 1, 0, 7, 6, 5, 4)
  hightRound(4, 4, 3, 2, 1, 0, 7, 6, 5)
  hightRound(3, 5, 4, 3, 2, 1, 0, 7, 6)
  hightRound(2, 6, 5, 4, 3, 2, 1, 0, 7)

  # assign x to state
  output[0] = x[0] - ctx.roundKey[0]
  output[1] = x[1]
  output[2] = x[2] xor ctx.roundKey[1]
  output[3] = x[3]
  output[4] = x[4] - ctx.roundKey[2]
  output[5] = x[5]
  output[6] = x[6] xor ctx.roundKey[3]
  output[7] = x[7]

# export wrappers
when defined(templateOpt):
  template hightInit*(ctx: var HIGHTCtx, key: array[16, uint8]): void =
    hightInitC(ctx, key.toSliceArray(0, 15))
  template hightInit*(ctx: var HIGHTCtx, key: openArray[uint8]): void =
    hightInitC(ctx, key.toSliceArray(0, 15))
  template hightInit*(ctx: var HIGHTCtx, key: slicearray[16, uint8]): void =
    hightInitC(ctx, key)
  template hightInit*(ctx: ptr HIGHTCtx, key: ptr array[16, uint8]): void =
    hightInitC(ctx, key.toSliceArray(0, 15))

  template hightEncrypt*(ctx: HIGHTCtx, input: array[8, uint8], output: var array[8, uint8]): void =
    hightEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template hightEncrypt*(ctx: HIGHTCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    hightEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template hightEncrypt*(ctx: HIGHTCtx, input, output: slicearray[8, uint8]): void =
    hightEncryptC(ctx, input, output)
  template hightEncrypt*(ctx: HIGHTCtx, input, output: ptr array[8, uint8]): void =
    hightEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
 
  template hightDecrypt*(ctx: HIGHTCtx, input: array[8, uint8], output: var array[8, uint8]): void =
    hightDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template hightDecrypt*(ctx: HIGHTCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    hightDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template hightDecrypt*(ctx: HIGHTCtx, input, output: slicearray[8, uint8]): void =
    hightDecryptC(ctx, input, output)
  template hightDecrypt*(ctx: HIGHTCtx, input, output: ptr array[8, uint8]): void =
    hightDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
else:
  proc hightInit*(ctx: var HIGHTCtx, key: array[16, uint8]): void =
    hightInitC(ctx, key.toSliceArray(0, 15))
  proc hightInit*(ctx: var HIGHTCtx, key: openArray[uint8]): void =
    hightInitC(ctx, key.toSliceArray(0, 15))
  proc hightInit*(ctx: var HIGHTCtx, key: slicearray[16, uint8]): void =
    hightInitC(ctx, key)
  proc hightInit*(ctx: ptr HIGHTCtx, key: ptr array[16, uint8]): void {.exportc: "hightInit", cdecl.} =
    hightInitC(ctx[], key.toSliceArray(0, 15))

  proc hightEncrypt*(ctx: HIGHTCtx, input: array[8, uint8], output: var array[8, uint8]): void =
    hightEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc hightEncrypt*(ctx: HIGHTCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    hightEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc hightEncrypt*(ctx: HIGHTCtx, input, output: slicearray[8, uint8]): void =
    hightEncryptC(ctx, input, output)
  proc hightEncrypt*(ctx: HIGHTCtx, input, output: ptr array[8, uint8]): void {.exportc: "hightEncrypt", cdecl.} =
    hightEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
 
  proc hightDecrypt*(ctx: HIGHTCtx, input: array[8, uint8], output: var array[8, uint8]): void =
    hightDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc hightDecrypt*(ctx: HIGHTCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    hightDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc hightDecrypt*(ctx: HIGHTCtx, input, output: slicearray[8, uint8]): void =
    hightDecryptC(ctx, input, output)
  proc hightDecrypt*(ctx: HIGHTCtx, input, output: ptr array[8, uint8]): void {.exportc: "hightDecrypt", cdecl.} =
    hightDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
