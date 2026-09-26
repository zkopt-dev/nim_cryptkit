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

type
  HC128Ctx* = object
    table*: array[1024, uint32]
    x*: array[16, uint32]
    y*: array[16, uint32]
    key*: array[8, uint32]
    iv*: array[8, uint32]
    counter*: int

template f1(x: uint32): uint32 =
  rotateRightBits(x, 7) xor rotateRightBits(x, 18) xor (x shr 3)

template f2(x: uint32): uint32 =
  rotateRightBits(x, 17) xor rotateRightBits(x, 19) xor (x shr 10)

template h1(ctx: var HC128Ctx, x: uint32, y: var uint32): void =
  let a: uint8 = cast[uint8](x)
  let c: uint8 = cast[uint8](x shr 16)
  y = ctx.table[512 + a.int] + ctx.table[512 + 256 + c.int]

template h2(ctx: var HC128Ctx, x: uint32, y: var uint32): void =
  let a: uint8 = cast[uint8](x)
  let c: uint8 = cast[uint8](x shr 16)
  y = ctx.table[a.int] + ctx.table[256 + c.int]

template roundP(ctx: var HC128Ctx, u, v, a, b, c, d: int, n: var uint32): void =
  var temp0, temp1, temp2, temp3: uint32
  h1(ctx, ctx.x[d], temp3)
  temp0 = rotateRightBits(ctx.table[v], 23)
  temp1 = rotateRightBits(ctx.x[c], 10)
  temp2 = rotateRightBits(ctx.x[b], 8)
  ctx.table[u] += temp2 + (temp0 xor temp1)
  ctx.x[a] = ctx.table[u]
  n = temp3 xor ctx.table[u]

template roundQ(ctx: var HC128Ctx, u, v, a, b, c, d: int, n: var uint32): void =
  var temp0, temp1, temp2, temp3: uint32
  h2(ctx, ctx.y[d], temp3)
  temp0 = rotateRightBits(ctx.table[v], 32 - 23)
  temp1 = rotateRightBits(ctx.y[c], 32 - 10)
  temp2 = rotateRightBits(ctx.y[b], 32 - 8)
  ctx.table[u] += temp2 + (temp0 xor temp1)
  ctx.y[a] = ctx.table[u]
  n = temp3 xor ctx.table[u]

template updateP(ctx: var HC128Ctx, u, v, a, b, c, d: int): void =
  var temp0, temp1, temp2, temp3: uint32
  temp0 = rotateRightBits(ctx.table[v], 23)
  temp1 = rotateRightBits(ctx.x[c], 10)
  temp2 = rotateRightBits(ctx.x[b], 8)
  h1(ctx, ctx.x[d], temp3)
  ctx.table[u] = (ctx.table[u] + temp2 + (temp0 xor temp1)) xor temp3
  ctx.x[a] = ctx.table[u]

template updateQ(ctx: var HC128Ctx, u, v, a, b, c, d: int): void =
  var temp0, temp1, temp2, temp3: uint32
  temp0 = rotateRightBits(ctx.table[v], 32 - 23)
  temp1 = rotateRightBits(ctx.y[c], 32 - 10)
  temp2 = rotateRightBits(ctx.y[b], 32 - 8)
  h2(ctx, ctx.y[d], temp3)
  ctx.table[u] = (ctx.table[u] + temp2 + (temp0 xor temp1)) xor temp3
  ctx.y[a] = ctx.table[u]

template generateKeystream*(ctx: var HC128Ctx, keystream: var array[16, uint32]) =
  let cc = ctx.counter and 0x1ff
  let dd = (cc + 16) and 0x1ff

  if ctx.counter < 512:
    ctx.counter = (ctx.counter + 16) and 0x3ff
    roundP(ctx, cc + 0, cc + 1, 0, 6, 13, 4, keystream[0])
    roundP(ctx, cc + 1, cc + 2, 1, 7, 14, 5, keystream[1])
    roundP(ctx, cc + 2, cc + 3, 2, 8, 15, 6, keystream[2])
    roundP(ctx, cc + 3, cc + 4, 3, 9, 0, 7, keystream[3])
    roundP(ctx, cc + 4, cc + 5, 4, 10, 1, 8, keystream[4])
    roundP(ctx, cc + 5, cc + 6, 5, 11, 2, 9, keystream[5])
    roundP(ctx, cc + 6, cc + 7, 6, 12, 3, 10, keystream[6])
    roundP(ctx, cc + 7, cc + 8, 7, 13, 4, 11, keystream[7])
    roundP(ctx, cc + 8, cc + 9, 8, 14, 5, 12, keystream[8])
    roundP(ctx, cc + 9, cc + 10, 9, 15, 6, 13, keystream[9])
    roundP(ctx, cc + 10, cc + 11, 10, 0, 7, 14, keystream[10])
    roundP(ctx, cc + 11, cc + 12, 11, 1, 8, 15, keystream[11])
    roundP(ctx, cc + 12, cc + 13, 12, 2, 9, 0, keystream[12])
    roundP(ctx, cc + 13, cc + 14, 13, 3, 10, 1, keystream[13])
    roundP(ctx, cc + 14, cc + 15, 14, 4, 11, 2, keystream[14])
    roundP(ctx, cc + 15, dd + 0, 15, 5, 12, 3, keystream[15])
  else:
    ctx.counter = (ctx.counter + 16) and 0x3ff
    roundQ(ctx, 512 + cc + 0, 512 + cc + 1, 0, 6, 13, 4, keystream[0])
    roundQ(ctx, 512 + cc + 1, 512 + cc + 2, 1, 7, 14, 5, keystream[1])
    roundQ(ctx, 512 + cc + 2, 512 + cc + 3, 2, 8, 15, 6, keystream[2])
    roundQ(ctx, 512 + cc + 3, 512 + cc + 4, 3, 9, 0, 7, keystream[3])
    roundQ(ctx, 512 + cc + 4, 512 + cc + 5, 4, 10, 1, 8, keystream[4])
    roundQ(ctx, 512 + cc + 5, 512 + cc + 6, 5, 11, 2, 9, keystream[5])
    roundQ(ctx, 512 + cc + 6, 512 + cc + 7, 6, 12, 3, 10, keystream[6])
    roundQ(ctx, 512 + cc + 7, 512 + cc + 8, 7, 13, 4, 11, keystream[7])
    roundQ(ctx, 512 + cc + 8, 512 + cc + 9, 8, 14, 5, 12, keystream[8])
    roundQ(ctx, 512 + cc + 9, 512 + cc + 10, 9, 15, 6, 13, keystream[9])
    roundQ(ctx, 512 + cc + 10, 512 + cc + 11, 10, 0, 7, 14, keystream[10])
    roundQ(ctx, 512 + cc + 11, 512 + cc + 12, 11, 1, 8, 15, keystream[11])
    roundQ(ctx, 512 + cc + 12, 512 + cc + 13, 12, 2, 9, 0, keystream[12])
    roundQ(ctx, 512 + cc + 13, 512 + cc + 14, 13, 3, 10, 1, keystream[13])
    roundQ(ctx, 512 + cc + 14, 512 + cc + 15, 14, 4, 11, 2, keystream[14])
    roundQ(ctx, 512 + cc + 15, 512 + dd + 0, 15, 5, 12, 3, keystream[15])

template setupUpdate(ctx: var HC128Ctx): void =
  let cc = ctx.counter and 0x1ff
  let dd = (cc + 16) and 0x1ff

  if ctx.counter < 512:
    ctx.counter = (ctx.counter + 16) and 0x3ff
    updateP(ctx, cc + 0, cc + 1, 0, 6, 13, 4)
    updateP(ctx, cc + 1, cc + 2, 1, 7, 14, 5)
    updateP(ctx, cc + 2, cc + 3, 2, 8, 15, 6)
    updateP(ctx, cc + 3, cc + 4, 3, 9, 0, 7)
    updateP(ctx, cc + 4, cc + 5, 4, 10, 1, 8)
    updateP(ctx, cc + 5, cc + 6, 5, 11, 2, 9)
    updateP(ctx, cc + 6, cc + 7, 6, 12, 3, 10)
    updateP(ctx, cc + 7, cc + 8, 7, 13, 4, 11)
    updateP(ctx, cc + 8, cc + 9, 8, 14, 5, 12)
    updateP(ctx, cc + 9, cc + 10, 9, 15, 6, 13)
    updateP(ctx, cc + 10, cc + 11, 10, 0, 7, 14)
    updateP(ctx, cc + 11, cc + 12, 11, 1, 8, 15)
    updateP(ctx, cc + 12, cc + 13, 12, 2, 9, 0)
    updateP(ctx, cc + 13, cc + 14, 13, 3, 10, 1)
    updateP(ctx, cc + 14, cc + 15, 14, 4, 11, 2)
    updateP(ctx, cc + 15, dd + 0, 15, 5, 12, 3)
  else:
    ctx.counter = (ctx.counter + 16) and 0x3ff
    updateQ(ctx, 512 + cc + 0, 512 + cc + 1, 0, 6, 13, 4)
    updateQ(ctx, 512 + cc + 1, 512 + cc + 2, 1, 7, 14, 5)
    updateQ(ctx, 512 + cc + 2, 512 + cc + 3, 2, 8, 15, 6)
    updateQ(ctx, 512 + cc + 3, 512 + cc + 4, 3, 9, 0, 7)
    updateQ(ctx, 512 + cc + 4, 512 + cc + 5, 4, 10, 1, 8)
    updateQ(ctx, 512 + cc + 5, 512 + cc + 6, 5, 11, 2, 9)
    updateQ(ctx, 512 + cc + 6, 512 + cc + 7, 6, 12, 3, 10)
    updateQ(ctx, 512 + cc + 7, 512 + cc + 8, 7, 13, 4, 11)
    updateQ(ctx, 512 + cc + 8, 512 + cc + 9, 8, 14, 5, 12)
    updateQ(ctx, 512 + cc + 9, 512 + cc + 10, 9, 15, 6, 13)
    updateQ(ctx, 512 + cc + 10, 512 + cc + 11, 10, 0, 7, 14)
    updateQ(ctx, 512 + cc + 11, 512 + cc + 12, 11, 1, 8, 15)
    updateQ(ctx, 512 + cc + 12, 512 + cc + 13, 12, 2, 9, 0)
    updateQ(ctx, 512 + cc + 13, 512 + cc + 14, 13, 3, 10, 1)
    updateQ(ctx, 512 + cc + 14, 512 + cc + 15, 14, 4, 11, 2)
    updateQ(ctx, 512 + cc + 15, 512 + dd + 0, 15, 5, 12, 3)

template hc128InitC(ctx: var HC128Ctx, userKey, userIv: slicearray[16, uint8]): void =
  decodeLE(userKey, ctx.key.toSliceArray(0, 3))
  copyMem(addr ctx.key[4], addr ctx.key[0], 16)

  decodeLE(userIv, ctx.iv.toSliceArray(0, 3))
  copyMem(addr ctx.iv[4], addr ctx.iv[0], 16)

  for i in static(0 ..< 8):
    ctx.table[i] = ctx.key[i]
  for i in static(8 ..< 16):
    ctx.table[i] = ctx.iv[i - 8]

  for i in static(16 ..< (256 + 16)):
    ctx.table[i] = f2(ctx.table[i - 2]) + ctx.table[i - 7] + f1(ctx.table[i - 15]) + ctx.table[i - 16] + i.uint32

  for i in static(0 ..< 16):
    ctx.table[i] = ctx.table[256 + i]

  for i in static(16 ..< 1024):
    ctx.table[i] = f2(ctx.table[i - 2]) + ctx.table[i - 7] + f1(ctx.table[i - 15]) + ctx.table[i - 16] + 256'u32 + i.uint32

  ctx.counter = 0
  for i in static(0 ..< 16):
    ctx.x[i] = ctx.table[512 - 16 + i]
  for i in static(0 ..< 16):
    ctx.y[i] = ctx.table[512 + 512 - 16 + i]

  for i in static(0 ..< 64):
    ctx.setupUpdate()

template hc128XorC(ctx: var HC128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
  let length: int = min(output.len, input.len)
  let totalBlocks: int = length div 64
  let left: int = length - (totalBlocks * 64)

  var keystream: array[16, uint32]
  var inBuffer, outBuffer: array[16, uint32]

  for i in 0 ..< totalBlocks:
    generateKeystream(ctx, keystream)

    when LE:
      copyMem(addr inBuffer[0], addr input[i * 64], 64)
    else:
      decodeLE(input.toSliceArray(i * 64, i * 64 + 63, 64), inBuffer.toSliceArray(0, 15))

    for j in static(0 ..< 16):
      outBuffer[j] = inBuffer[j] xor keyStream[j]

    when LE:
      copyMem(addr output[i * 64], addr outBuffer[0], 64)
    else:
      encodeLE(outBuffer.toSliceArray(0, 15), output.toSliceArray(i * 64, i * 64 + 63, 64))

  if left > 0:
    generateKeystream(ctx, keystream)

    var buffer: array[64, uint8]

    when LE:
      copyMem(addr buffer[0], addr keystream[0], 64)
    else:
      encodeLE(keystream, buffer)

    for i in 0 ..< left:
      output[totalBlocks * 64 + i] = input[totalBlocks * 64 + i] xor buffer[i]

when defined(templateOpt):
  template hc128Init*(ctx: var HC128Ctx, key: array[16, uint8], iv: array[16, uint8]): void =
    hc128InitC(ctx, key.toSliceArray(0, 15), iv.toSliceArray(0, 15))
  template hc128Init*(ctx: ptr HC128Ctx, key: ptr array[16, uint8], iv: ptr array[16, uint8]): void =
    hc128InitC(ctx[], key[].toSliceArray(0, 15), iv[].toSliceArray(0, 15))

  template hc128Xor*(ctx: var HC128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    hc128XorC(ctx, input, output)
  template hc128Xor*(ctx: ptr HC128Ctx, input, output: ptr UncheckedArray[uint8], length: int): void =
    hc128XorC(ctx[], input.toOpenArray(0, length - 1), output.toOpenArray(0, length - 1))
else:
  proc hc128Init*(ctx: var HC128Ctx, key: array[16, uint8], iv: array[16, uint8]): void =
    hc128InitC(ctx, key.toSliceArray(0, 15), iv.toSliceArray(0, 15))
  proc hc128Init*(ctx: ptr HC128Ctx, key: ptr array[16, uint8], iv: ptr array[16, uint8]): void {.exportc: "hc128Init".} =
    hc128InitC(ctx[], key[].toSliceArray(0, 15), iv[].toSliceArray(0, 15))

  proc hc128Xor*(ctx: var HC128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    hc128XorC(ctx, input, output)
  proc hc128Xor*(ctx: ptr HC128Ctx, input, output: ptr UncheckedArray[uint8], length: int): void {.exportc: "hc128Xor".} =
    hc128XorC(ctx[], input.toOpenArray(0, length - 1), output.toOpenArray(0, length - 1))
