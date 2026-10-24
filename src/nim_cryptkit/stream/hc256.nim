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

import std/bitops

type
  HC256Ctx* = object
    key*: array[8, uint32]
    iv*: array[8, uint32]
    p*: array[1024, uint32]
    q*: array[1024, uint32]
    counter*: uint32

proc F1(x: uint32): uint32 =
  rotateRightBits(x, 7) xor rotateRightBits(x, 18) xor (x shr 3)

proc F2(x: uint32): uint32 =
  rotateRightBits(x, 17) xor rotateRightBits(x, 19) xor (x shr 10)

template packKeyWords(output: var array[8, uint32], input: array[32, uint8]) =
  for i in static(0 ..< 8):
    output[i] = 0
  for i in static(0 ..< 32):
    output[i shr 2] = output[i shr 2] or uint32(input[i])
    output[i shr 2] = rotateLeftBits(output[i shr 2], 8)

template H1(ctx: HC256Ctx, u: uint32): uint32 =
  let
    a: int = int(u and 0xff)
    b: int = int((u shr 8) and 0xff)
    c: int = int((u shr 16) and 0xff)
    d: int = int((u shr 24) and 0xff)
  ctx.q[a] + ctx.q[256 + b] + ctx.q[512 + c] + ctx.q[768 + d]

template H2(ctx: HC256Ctx, u: uint32): uint32 =
  let
    a: int = int(u and 0xff)
    b: int = int((u shr 8) and 0xff)
    c: int = int((u shr 16) and 0xff)
    d: int = int((u shr 24) and 0xff)
  ctx.p[a] + ctx.p[256 + b] + ctx.p[512 + c] + ctx.p[768 + d]

template generate(ctx: var HC256Ctx): uint32 =
  let
    i = int(ctx.counter and 0x3ff)
    i3 = (i - 3) and 0x3ff
    i10 = (i - 10) and 0x3ff
    i12 = (i - 12) and 0x3ff
    i1023 = (i - 1023) and 0x3ff
  var output: uint32
  if ctx.counter < 1024:
    ctx.p[i] = ctx.p[i] + ctx.p[i10] +
      (rotateRightBits(ctx.p[i3], 10) xor rotateRightBits(ctx.p[i1023], 23)) +
      ctx.q[int((ctx.p[i3] xor ctx.p[i1023]) and 0x3ff)]
    output = H1(ctx, ctx.p[i12]) xor ctx.p[i]
  else:
    ctx.q[i] = ctx.q[i] + ctx.q[i10] +
      (rotateRightBits(ctx.q[i3], 10) xor rotateRightBits(ctx.q[i1023], 23)) +
      ctx.p[int((ctx.q[i3] xor ctx.q[i1023]) and 0x3ff)]
    output = H2(ctx, ctx.q[i12]) xor ctx.q[i]
  ctx.counter = (ctx.counter + 1) and 0x7ff
  output

template hc256InitC*(ctx: var HC256Ctx, userKey: array[32, uint8], nonce: array[32, uint8]): void =
  zeroMem(addr ctx, sizeof(ctx))
  packKeyWords(ctx.key, userKey)
  packKeyWords(ctx.iv, nonce)
  var w: array[2560, uint32]
  copyMem(addr w[0], addr ctx.key[0], 32)
  copyMem(addr w[8], addr ctx.iv[0], 32)
  for i in static(16 ..< 2560):
    w[i] = F2(w[i - 2]) + w[i - 7] + F1(w[i - 15]) + w[i - 16] + uint32(i)
  copyMem(addr ctx.p[0], addr w[512], 4096)
  copyMem(addr ctx.q[0], addr w[1536], 4096)
  ctx.counter = 0
  for i in static(0 ..< 4096):
    discard generate(ctx)

template hc256XorC*(ctx: var HC256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
  let length: int = min(input.len, output.len)
  let totalBlocks: int = length div 16
  let left: int = length - (totalBlocks * 16)

  var keyStream: array[4, uint32]
  var inBuffer, outBuffer: array[4, uint32]

  # Process complete 16-byte blocks
  for i in 0 ..< totalBlocks:
    keyStream[0] = generate(ctx)
    keyStream[1] = generate(ctx)
    keyStream[2] = generate(ctx)
    keyStream[3] = generate(ctx)

    when LE:
      copyMem(addr inBuffer[0], addr input[i * 16], 16)
    else:
      decodeLE(input.toSliceArray(i * 16, i * 16 + 15, 16), inBuffer.toSliceArray(0, 3))

    for j in static(0 ..< 4):
      outBuffer[j] = inBuffer[j] xor keyStream[j]

    when LE:
      copyMem(addr output[i * 16], addr outBuffer[0], 16)
    else:
      encodeLE(outBuffer.toSliceArray(0, 3), output.toSliceArray(i * 16, i * 16 + 15, 16))

  # Process remaining bytes (< 16)
  if left > 0:
    keyStream[0] = generate(ctx)
    keyStream[1] = generate(ctx)
    keyStream[2] = generate(ctx)
    keyStream[3] = generate(ctx)

    var buffer: array[16, uint8]

    when LE:
      copyMem(addr buffer[0], addr keyStream[0], 16)
    else:
      encodeLE(keyStream, buffer)

    for i in 0 ..< left:
      output[totalBlocks * 16 + i] = input[totalBlocks * 16 + i] xor buffer[i]

when defined(templateOpt):
  template hc256Init*(ctx: var HC256Ctx, key: array[32, uint8], nonce: array[32, uint8]): void =
    hc256InitC(ctx, key, nonce)
  template hc256Xor*(ctx: var HC256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    hc256XorC(ctx, input, output)

  template hc256Init*(ctx: ptr HC256Ctx, key: ptr array[32, uint8], nonce: ptr array[32, uint8]): void =
    hc256InitC(ctx[], key[], nonce[])
  template hc256Xor*(ctx: ptr HC256Ctx, input, output: ptr UncheckedArray[uint8], length: int): void =
    hc256XorC(ctx[], input.toOpenArray(0, length - 1), output.toOpenArray(0, length - 1))
else:
  proc hc256Init*(ctx: var HC256Ctx, key: array[32, uint8], nonce: array[32, uint8]): void =
    hc256InitC(ctx, key, nonce)
  proc hc256Xor*(ctx: var HC256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    hc256XorC(ctx, input, output)

  proc hc256Init*(ctx: ptr HC256Ctx, key: ptr array[32, uint8], nonce: ptr array[32, uint8]): void {.exportc: "hc256Init".} =
    hc256InitC(ctx[], key[], nonce[])
  proc hc256Xor*(ctx: ptr HC256Ctx, input, output: ptr UncheckedArray[uint8], length: int): void {.exportc: "hc256Xor".} =
    hc256XorC(ctx[], input.toOpenArray(0, length - 1), output.toOpenArray(0, length - 1))
