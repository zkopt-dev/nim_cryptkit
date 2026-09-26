import ../utils/endian
import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils
import ../utils/vectorop
import std/[monotimes, times]
import std/bitops

type Poly1305Ctx* = object
  r0, r1, r2, r3, r4: uint64
  s1, s2, s3, s4: uint64
  h0, h1, h2, h3, h4: uint64
  pad0, pad1, pad2, pad3: uint32
  buffer: array[16, uint8]
  index: int

template poly1305Transform(ctx: var Poly1305Ctx, chunk: slicearray[16, uint8], isFinal: static bool): void =
  var t0, t1, t2, t3: uint32
  fromBytesLE(chunk.toSliceArray(0, 3), t0)
  fromBytesLE(chunk.toSliceArray(4, 7), t1)
  fromBytesLE(chunk.toSliceArray(8, 11), t2)
  fromBytesLE(chunk.toSliceArray(12, 15), t3)

  const hibit: uint64 = when isFinal: 0'u64 else: 1'u64 shl 24
  ctx.h0 += t0 and 0x3ffffff'u64
  ctx.h1 += ((t0 shr 26) or (t1 shl 6)) and 0x3ffffff'u64
  ctx.h2 += ((t1 shr 20) or (t2 shl 12)) and 0x3ffffff'u64
  ctx.h3 += ((t2 shr 14) or (t3 shl 18)) and 0x3ffffff'u64
  ctx.h4 += (t3 shr 8) or hibit

  let d0: uint64 = ctx.h0 * ctx.r0 + ctx.h1 * ctx.s4 + ctx.h2 * ctx.s3 + ctx.h3 * ctx.s2 + ctx.h4 * ctx.s1
  let d1: uint64 = ctx.h0 * ctx.r1 + ctx.h1 * ctx.r0 + ctx.h2 * ctx.s4 + ctx.h3 * ctx.s3 + ctx.h4 * ctx.s2
  let d2: uint64 = ctx.h0 * ctx.r2 + ctx.h1 * ctx.r1 + ctx.h2 * ctx.r0 + ctx.h3 * ctx.s4 + ctx.h4 * ctx.s3
  let d3: uint64 = ctx.h0 * ctx.r3 + ctx.h1 * ctx.r2 + ctx.h2 * ctx.r1 + ctx.h3 * ctx.r0 + ctx.h4 * ctx.s4
  let d4: uint64 = ctx.h0 * ctx.r4 + ctx.h1 * ctx.r3 + ctx.h2 * ctx.r2 + ctx.h3 * ctx.r1 + ctx.h4 * ctx.r0
  var carry: uint64
  ctx.h0 = d0 and 0x3ffffff'u64; carry = d0 shr 26
  ctx.h1 = (d1 + carry) and 0x3ffffff'u64; carry = (d1 + carry) shr 26
  ctx.h2 = (d2 + carry) and 0x3ffffff'u64; carry = (d2 + carry) shr 26
  ctx.h3 = (d3 + carry) and 0x3ffffff'u64; carry = (d3 + carry) shr 26
  ctx.h4 = (d4 + carry) and 0x3ffffff'u64; carry = (d4 + carry) shr 26
  ctx.h0 += carry * 5
  carry = ctx.h0 shr 26
  ctx.h0 = ctx.h0 and 0x3ffffff'u64
  ctx.h1 += carry

template poly1305Init*(ctx: var Poly1305Ctx, key: array[32, uint8]): void =
  var t0, t1, t2, t3: uint32
  fromBytesLE(key.toSliceArray(0, 3), t0)
  fromBytesLE(key.toSliceArray(4, 7), t1)
  fromBytesLE(key.toSliceArray(8, 11), t2)
  fromBytesLE(key.toSliceArray(12, 15), t3)
  fromBytesLE(key.toSliceArray(16, 19), ctx.pad0)
  fromBytesLE(key.toSliceArray(20, 23), ctx.pad1)
  fromBytesLE(key.toSliceArray(24, 27), ctx.pad2)
  fromBytesLE(key.toSliceArray(28, 31), ctx.pad3)
  ctx.r0 = t0 and 0x3ffffff'u64
  ctx.r1 = ((t0 shr 26) or (t1 shl 6)) and 0x3ffff03'u64
  ctx.r2 = ((t1 shr 20) or (t2 shl 12)) and 0x3ffc0ff'u64
  ctx.r3 = ((t2 shr 14) or (t3 shl 18)) and 0x3f03fff'u64
  ctx.r4 = (t3 shr 8) and 0x00fffff'u64
  ctx.s1 = ctx.r1 * 5; ctx.s2 = ctx.r2 * 5
  ctx.s3 = ctx.r3 * 5; ctx.s4 = ctx.r4 * 5

template poly1305Input*(ctx: var Poly1305Ctx, input: openArray[uint8]): void =
  var check: bool = true

  let inputLen: int = input.len
  fromBytesLE(key.toSliceArray(16, 19), ctx.pad0)
  fromBytesLE(key.toSliceArray(20, 23), ctx.pad1)
  fromBytesLE(key.toSliceArray(24, 27), ctx.pad2)
  fromBytesLE(key.toSliceArray(28, 31), ctx.pad3)

  if inputLen <= 0: check = false

  if check:
    var index: int = ctx.index
    let left: int = 16 - index
    var position: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      poly1305Transform(ctx, ctx.buffer.toSliceArray(0, 15), false)
      position = left
      index = 0

      while position + 16 <= inputLen:
        poly1305Transform(ctx, input.toSliceArray(position, position + 15, 16), false)
        position += 16

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

template poly1305Final*(ctx: var Poly1305Ctx): array[16, uint8] =
  var output: array[16, uint8]

  var index: int = ctx.index

  if index != 0:
    ctx.buffer[index] = 1
    index += 1
    zeroMem(addr ctx.buffer[index], 16 - index)
    poly1305Transform(ctx, ctx.buffer.toSliceArray(0, 15), true)

  var carry: uint64 = ctx.h1 shr 26; ctx.h1 = ctx.h1 and 0x3ffffff'u64; ctx.h2 += carry
  carry = ctx.h2 shr 26; ctx.h2 = ctx.h2 and 0x3ffffff'u64; ctx.h3 += carry
  carry = ctx.h3 shr 26; ctx.h3 = ctx.h3 and 0x3ffffff'u64; ctx.h4 += carry
  carry = ctx.h4 shr 26; ctx.h4 = ctx.h4 and 0x3ffffff'u64; ctx.h0 += carry * 5
  carry = ctx.h0 shr 26; ctx.h0 = ctx.h0 and 0x3ffffff'u64; ctx.h1 += carry

  var g0: uint64 = ctx.h0 + 5
  carry = g0 shr 26; g0 = g0 and 0x3ffffff'u64
  var g1: uint64 = ctx.h1 + carry; carry = g1 shr 26; g1 = g1 and 0x3ffffff'u64
  var g2: uint64 = ctx.h2 + carry; carry = g2 shr 26; g2 = g2 and 0x3ffffff'u64
  var g3: uint64 = ctx.h3 + carry; carry = g3 shr 26; g3 = g3 and 0x3ffffff'u64
  let g4: uint64 = ctx.h4 + carry - (1'u64 shl 26)
  let mask = (g4 shr 63) - 1
  let keepH = not mask
  ctx.h0 = (ctx.h0 and keepH) or (g0 and mask)
  ctx.h1 = (ctx.h1 and keepH) or (g1 and mask)
  ctx.h2 = (ctx.h2 and keepH) or (g2 and mask)
  ctx.h3 = (ctx.h3 and keepH) or (g3 and mask)
  ctx.h4 = (ctx.h4 and keepH) or (g4 and mask)

  var f0 = ((ctx.h0 or (ctx.h1 shl 26)) and 0xffffffff'u64) + uint64(ctx.pad0)
  var f1 = (((ctx.h1 shr 6) or (ctx.h2 shl 20)) and 0xffffffff'u64) + uint64(ctx.pad1) + (f0 shr 32)
  var f2 = (((ctx.h2 shr 12) or (ctx.h3 shl 14)) and 0xffffffff'u64) + uint64(ctx.pad2) + (f1 shr 32)
  var f3 = (((ctx.h3 shr 18) or (ctx.h4 shl 8)) and 0xffffffff'u64) + uint64(ctx.pad3) + (f2 shr 32)
  f0 = f0 and 0xffffffff'u64; f1 = f1 and 0xffffffff'u64
  f2 = f2 and 0xffffffff'u64; f3 = f3 and 0xffffffff'u64
  unroll(i, 0, 3):
    output[i] = uint8(f0 shr (8 * i))
    output[4 + i] = uint8(f1 shr (8 * i))
    output[8 + i] = uint8(f2 shr (8 * i))
    output[12 + i] = uint8(f3 shr (8 * i))

  output

template poly1305One*(key: array[32, uint8], input: openArray[uint8]): array[16, uint8] =
  var ctx: Poly1305Ctx
  poly1305Init(ctx, key)
  poly1305Input(ctx, input)
  poly1305Final(ctx)
