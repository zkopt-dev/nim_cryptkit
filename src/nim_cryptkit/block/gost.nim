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

#[
const SBox: array[8, array[16, uint8]] = [
  [4'u8, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
  [14'u8, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
  [5'u8, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
  [7'u8, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
  [6'u8, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
  [4'u8, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
  [13'u8, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
  [1'u8, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]
]
]#
const SBox: array[8, array[16, uint8]] = [
  [12'u8, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
  [6'u8, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
  [11'u8, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
  [12'u8, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
  [7'u8, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
  [5'u8, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
  [8'u8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
  [1'u8, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2]
]

template genTable(table: array[4, array[256, uint32]]): void =
  for i in static(0 ..< 4):
    for j in static(0 ..< 256):
      let temp = uint32(SBox[2 * i][j mod 16]) or (uint32(SBox[2 * i + 1][j div 16]) shl 4)
      table[i][j] = rotateLeftBits(temp, (11 + 8 * i) mod 32)

type
  GOSTCtx* = object
    table*: array[4, array[256, uint32]]
    roundKey*: array[8, uint32]

template getByte(x: uint32; y: int): uint32 =
  (x shr (8 * y)) and 0xff'u32

template F(table: array[4, array[256, uint32]], x: uint32): uint32 =
  table[3][int((x shr 24) and 0xFF'u32)] xor table[2][int((x shr 16) and 0xFF'u32)] xor
  table[1][int((x shr  8) and 0xFF'u32)] xor table[0][int((x shr  0) and 0xFF'u32)]

template gostInitC*(ctx: var GOSTCtx, key: slicearray[32, uint8]): void =
  genTable(ctx.table)
  decodeLE(key, ctx.roundKey.toSliceArray(0, 7))

template gostEncryptC*(ctx: GOSTCtx, input, output: slicearray[8, uint8]): void =
  var x, y: uint32
  fromBytesLE(input.toSliceArray(0, 3), x)
  fromBytesLE(input.toSliceArray(4, 7), y)

  for _ in static(0 .. 2):
    y = y xor F(ctx.table, x + ctx.roundKey[0])
    x = x xor F(ctx.table, y + ctx.roundKey[1])
    y = y xor F(ctx.table, x + ctx.roundKey[2])
    x = x xor F(ctx.table, y + ctx.roundKey[3])
    y = y xor F(ctx.table, x + ctx.roundKey[4])
    x = x xor F(ctx.table, y + ctx.roundKey[5])
    y = y xor F(ctx.table, x + ctx.roundKey[6])
    x = x xor F(ctx.table, y + ctx.roundKey[7])

  y = y xor F(ctx.table, x + ctx.roundKey[7])
  x = x xor F(ctx.table, y + ctx.roundKey[6])
  y = y xor F(ctx.table, x + ctx.roundKey[5])
  x = x xor F(ctx.table, y + ctx.roundKey[4])
  y = y xor F(ctx.table, x + ctx.roundKey[3])
  x = x xor F(ctx.table, y + ctx.roundKey[2])
  y = y xor F(ctx.table, x + ctx.roundKey[1])
  x = x xor F(ctx.table, y + ctx.roundKey[0])

  toBytesLE(y, output.toSliceArray(0, 3))
  toBytesLE(x, output.toSliceArray(4, 7))

template gostDecryptC*(ctx: GOSTCtx; input, output: slicearray[8, uint8]): void =
  var x, y: uint32
  fromBytesLE(input.toSliceArray(0, 3), x)
  fromBytesLE(input.toSliceArray(4, 7), y)

  y = y xor F(ctx.table, x + ctx.roundKey[0])
  x = x xor F(ctx.table, y + ctx.roundKey[1])
  y = y xor F(ctx.table, x + ctx.roundKey[2])
  x = x xor F(ctx.table, y + ctx.roundKey[3])
  y = y xor F(ctx.table, x + ctx.roundKey[4])
  x = x xor F(ctx.table, y + ctx.roundKey[5])
  y = y xor F(ctx.table, x + ctx.roundKey[6])
  x = x xor F(ctx.table, y + ctx.roundKey[7])

  for _ in static(0 .. 2):
    y = y xor F(ctx.table, x + ctx.roundKey[7])
    x = x xor F(ctx.table, y + ctx.roundKey[6])
    y = y xor F(ctx.table, x + ctx.roundKey[5])
    x = x xor F(ctx.table, y + ctx.roundKey[4])
    y = y xor F(ctx.table, x + ctx.roundKey[3])
    x = x xor F(ctx.table, y + ctx.roundKey[2])
    y = y xor F(ctx.table, x + ctx.roundKey[1])
    x = x xor F(ctx.table, y + ctx.roundKey[0])

  toBytesLE(y, output.toSliceArray(0, 3))
  toBytesLE(x, output.toSliceArray(4, 7))

when defined(templateOpt):
  template gostInit*(ctx: var GOSTCtx, key: array[32, uint8]): void = gostInitC(ctx, key.toSliceArray(0, 31))
  template gostInit*(ctx: var GOSTCtx, key: openArray[uint8]): void = gostInitC(ctx, key.toSliceArray(0, 31))
  template gostInit*(ctx: var GOSTCtx, key: slicearray[32, uint8]): void = gostInitC(ctx, key)
  template gostInit*(ctx: ptr GOSTCtx, key: ptr array[32, uint8]): void = gostInitC(ctx, key.toSliceArray(0, 31))

  template gostEncrypt*(ctx: GOSTCtx, input: array[8, uint8], output: var array[8, uint8]): void = gostEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template gostEncrypt*(ctx: GOSTCtx, input: openArray[uint8], output: var openArray[uint8]): void = gostEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template gostEncrypt*(ctx: GOSTCtx, input, output: slicearray[8, uint8]): void = gostEncryptC(ctx, input, output)
  template gostEncrypt*(ctx: ptr GOSTCtx, input, output: ptr array[8, uint8]): void = gostEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  template gostDecrypt*(ctx: GOSTCtx, input: array[8, uint8], output: var array[8, uint8]): void = gostDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template gostDecrypt*(ctx: GOSTCtx, input: openArray[uint8], output: var openArray[uint8]): void = gostDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template gostDecrypt*(ctx: GOSTCtx, input, output: slicearray[8, uint8]): void = gostDecryptC(ctx, input, output)
  template gostDecrypt*(ctx: ptr GOSTCtx, input, output: ptr array[8, uint8]): void = gostDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
else:
  proc gostInit*(ctx: var GOSTCtx, key: array[32, uint8]): void = gostInitC(ctx, key.toSliceArray(0, 31))
  proc gostInit*(ctx: var GOSTCtx, key: openArray[uint8]): void = gostInitC(ctx, key.toSliceArray(0, 31))
  proc gostInit*(ctx: var GOSTCtx, key: slicearray[32, uint8]): void = gostInitC(ctx, key)
  proc gostInit*(ctx: ptr GOSTCtx, key: ptr array[32, uint8]): void = gostInitC(ctx[], key.toSliceArray(0, 31))

  proc gostEncrypt*(ctx: GOSTCtx, input: array[8, uint8], output: var array[8, uint8]): void = gostEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc gostEncrypt*(ctx: GOSTCtx, input: openArray[uint8], output: var openArray[uint8]): void = gostEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc gostEncrypt*(ctx: GOSTCtx, input, output: slicearray[8, uint8]): void = gostEncryptC(ctx, input, output)
  proc gostEncrypt*(ctx: ptr GOSTCtx, input, output: ptr array[8, uint8]): void = gostEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  proc gostDecrypt*(ctx: GOSTCtx, input: array[8, uint8], output: var array[8, uint8]): void = gostDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc gostDecrypt*(ctx: GOSTCtx, input: openArray[uint8], output: var openArray[uint8]): void = gostDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc gostDecrypt*(ctx: GOSTCtx, input, output: slicearray[8, uint8]): void = gostDecryptC(ctx, input, output)
  proc gostDecrypt*(ctx: ptr GOSTCtx, input, output: ptr array[8, uint8]): void = gostDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))


