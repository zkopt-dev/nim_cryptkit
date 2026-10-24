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

const TT: array[8, uint32] = [
  0x726a8f3b'u32, 0xe69a3b5c'u32, 0xd3c71fe5'u32, 0xab3c73d2'u32,
  0x4d3a8eb3'u32, 0x0396d6e8'u32, 0x3d4c2f7a'u32, 0x9ee27cf3'u32
]

type
  WakeCtx* = object
    table*: array[257, uint32]
    r3*, r4*, r5*, r6*: uint32

template M(ctx: WakeCtx, x, y: uint32): uint32 =
  let w = x + y
  (w shr 8) xor ctx.table[int(w and 0xff)]

template genKey(ctx: var WakeCtx, k0, k1, k2, k3: uint32): void =
  var x, z: uint32
  ctx.table[0] = k0
  ctx.table[1] = k1
  ctx.table[2] = k2
  ctx.table[3] = k3
  for p in static(4 ..< 256):
    let sum = ctx.table[p - 4] + ctx.table[p - 1]
    let xs = cast[int32](sum)
    ctx.table[p] = cast[uint32](xs shr 3) xor TT[int(sum and 7)]
  for p in static(0 .. 22):
    ctx.table[p] = ctx.table[p] + ctx.table[p+89]
  x = ctx.table[33]
  z = (ctx.table[59] or 0x01000001'u32) and 0xff7fffff'u32
  for p in static(0 ..< 256):
    x = (x and 0xff7fffff'u32) + z
    ctx.table[p] = (ctx.table[p] and 0x00ffffff'u32) xor x
  ctx.table[256] = ctx.table[0]
  var y = uint8(x)
  for p in static(0 .. 255):
    y = uint8(ctx.table[p xor int(y)] xor uint32(y))
    ctx.table[p] = ctx.table[int(y)]
    ctx.table[int(y)] = ctx.table[p + 1]

template wakeInitC*(ctx: var WakeCtx, key: slicearray[32, uint8]): void =
  fromBytesBE(key.toSliceArray(0, 3), ctx.r3)
  fromBytesBE(key.toSliceArray(4, 7), ctx.r4)
  fromBytesBE(key.toSliceArray(8, 11), ctx.r5)
  fromBytesBE(key.toSliceArray(12, 15), ctx.r6)
  var k0, k1, k2, k3: uint32
  fromBytesBE(key.toSliceArray(16, 19), k0)
  fromBytesBE(key.toSliceArray(20, 23), k1)
  fromBytesBE(key.toSliceArray(24, 27), k2)
  fromBytesBE(key.toSliceArray(28, 31), k3)
  genKey(ctx, k0, k1, k2, k3)

template wakeXorC*(ctx: var WakeCtx, input: openArray[uint8], output: var openArray[uint8]): void =
  let length: int = min(input.len, output.len)
  var i: int = 0

  while i < length:
    var temp: array[4, uint8]
    toBytesBE(ctx.r6, temp)

    let remain: int = min(4, length - i)
    for j in 0 ..< remain:
      output[i + j] = input[i + j] xor temp[j]

    ctx.r3 = M(ctx, ctx.r3, ctx.r6)
    ctx.r4 = M(ctx, ctx.r4, ctx.r3)
    ctx.r5 = M(ctx, ctx.r5, ctx.r4)
    ctx.r6 = M(ctx, ctx.r6, ctx.r5)

    i += 4

when defined(templateOpt):
  template wakeInit*(ctx: var WakeCtx, key: array[32, uint8]): void =
    wakeInitC(ctx, key.toSliceArray(0, 31))
  template wakeXor*(ctx: var WakeCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    wakeXorC(ctx, input, output)

  template wakeInit*(ctx: ptr WakeCtx, key: ptr array[32, uint8]): void =
    wakeInitC(ctx[], key.toSliceArray(0, 31))
  template wakeXor*(ctx: ptr WakeCtx, input, output: ptr UncheckedArray[uint8], length: int): void =
    wakeXorC(ctx[], input.toOpenArray(0, length - 1), output.toOpenArray(0, length - 1))
else:
  proc wakeInit*(ctx: var WakeCtx, key: array[32, uint8]): void =
    wakeInitC(ctx, key.toSliceArray(0, 31))
  proc wakeXor*(ctx: var WakeCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    wakeXorC(ctx, input, output)

  proc wakeInit*(ctx: ptr WakeCtx, key: ptr array[32, uint8]): void {.exportc: "wakeInit".} =
    wakeInitC(ctx[], key.toSliceArray(0, 31))
  proc wakeXor*(ctx: ptr WakeCtx, input, output: ptr UncheckedArray[uint8], length: int): void {.exportc: "wakeXor".} =
    wakeXorC(ctx[], input.toOpenArray(0, length - 1), output.toOpenArray(0, length - 1))
