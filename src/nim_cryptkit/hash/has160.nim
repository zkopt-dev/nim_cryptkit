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
  # HAS-160 block size(byte)
  HAS160_BLOCK_SIZE*: int = 64
  # HAS-160 hash size(byte)
  HAS160_HASH_SIZE*: int = 20

when CPUBits == 64:
  # HAS-160 context for 64bits
  type
    HAS160Ctx* = object
      buffer*: array[HAS160_BLOCK_SIZE, uint8]
      length*: uint64
      state*: array[5, uint32]
      index*: int
elif CPUBits == 32: # Bits == 32:
  # HAS-160 context for 32bits
  type
    HAS160Ctx* = object
      buffer*: array[HAS160_BLOCK_SIZE, uint8]
      length*: array[2, uint32]
      state*: array[5, uint32]
      index*: int

# FF round template
template FF(a: uint32, b: var uint32, c, d: uint32, e: var uint32, x: uint32, rot: static[int]): void =
  e = e + rotateLeftBits(a, rot) + (d xor (b and (c xor d))) + x
  b = rotateLeftBits(b, 10)

# GG round template
template GG(a: uint32, b: var uint32, c, d: uint32, e: var uint32, x: uint32, rot: static[int]): void =
  e = e + rotateLeftBits(a, rot) + (b xor c xor d) + x + 0x5A827999'u32
  b = rotateLeftBits(b, 17)

# HH round template
template HH(a: uint32, b: var uint32, c, d: uint32, e: var uint32, x: uint32, rot: static[int]): void =
  e = e + rotateLeftBits(a, rot) + (c xor (b or (not d))) + x + 0x6ED9EBA1'u32
  b = rotateLeftBits(b, 25)

# II round template
template II(a: uint32, b: var uint32, c, d: uint32, e: var uint32, x: uint32, rot: static[int]): void =
  e = e + rotateLeftBits(a, rot) + (b xor c xor d) + x + 0x8F1BBCDC'u32
  b = rotateLeftBits(b, 30)

## don't use leftRotate/rightRotate, use rotateLeftBits/rotateRightBits

autoMemOpt:
  # has160 transform template
  template has160Transform(state: var array[5, uint32], input: slicearray[64, uint8]): void {.autoSizeOpt.} =
    # declare block
    var x: array[32, uint32]
    # decode input to x
    decodeLE(input, x.toSliceArray(0, 15))

    # extend block
    x[16] = x[0] xor x[1] xor x[2] xor x[3]
    x[17] = x[4] xor x[5] xor x[6] xor x[7]
    x[18] = x[8] xor x[9] xor x[10] xor x[11]
    x[19] = x[12] xor x[13] xor x[14] xor x[15]
    x[20] = x[3] xor x[6] xor x[9] xor x[12]
    x[21] = x[2] xor x[5] xor x[8] xor x[15]
    x[22] = x[1] xor x[4] xor x[11] xor x[14]
    x[23] = x[0] xor x[7] xor x[10] xor x[13]
    x[24] = x[5] xor x[7] xor x[12] xor x[14]
    x[25] = x[0] xor x[2] xor x[9] xor x[11]
    x[26] = x[4] xor x[6] xor x[13] xor x[15]
    x[27] = x[1] xor x[3] xor x[8] xor x[10]
    x[28] = x[2] xor x[7] xor x[8] xor x[13]
    x[29] = x[3] xor x[4] xor x[9] xor x[14]
    x[30] = x[0] xor x[5] xor x[10] xor x[15]
    x[31] = x[1] xor x[6] xor x[11] xor x[12]

    # declare temporary variable and initialize to ctx
    var
      a = state[0]
      b = state[1]
      c = state[2]
      d = state[3]
      e = state[4]

    # call FF round template
    FF(a, b, c, d, e, x[18], 5)
    FF(e, a, b, c, d, x[0], 11)
    FF(d, e, a, b, c, x[1], 7)
    FF(c, d, e, a, b, x[2], 15)
    FF(b, c, d, e, a, x[3], 6)
    FF(a, b, c, d, e, x[19], 13)
    FF(e, a, b, c, d, x[4], 8)
    FF(d, e, a, b, c, x[5], 14)
    FF(c, d, e, a, b, x[6], 7)
    FF(b, c, d, e, a, x[7], 12)
    FF(a, b, c, d, e, x[16], 9)
    FF(e, a, b, c, d, x[8], 11)
    FF(d, e, a, b, c, x[9], 8)
    FF(c, d, e, a, b, x[10], 15)
    FF(b, c, d, e, a, x[11], 6)
    FF(a, b, c, d, e, x[17], 12)
    FF(e, a, b, c, d, x[12], 9)
    FF(d, e, a, b, c, x[13], 14)
    FF(c, d, e, a, b, x[14], 5)
    FF(b, c, d, e, a, x[15], 13)

    # call GG round template
    GG(a, b, c, d, e, x[22], 5)
    GG(e, a, b, c, d, x[3], 11)
    GG(d, e, a, b, c, x[6], 7)
    GG(c, d, e, a, b, x[9], 15)
    GG(b, c, d, e, a, x[12], 6)
    GG(a, b, c, d, e, x[23], 13)
    GG(e, a, b, c, d, x[15], 8)
    GG(d, e, a, b, c, x[2], 14)
    GG(c, d, e, a, b, x[5], 7)
    GG(b, c, d, e, a, x[8], 12)
    GG(a, b, c, d, e, x[20], 9)
    GG(e, a, b, c, d, x[11], 11)
    GG(d, e, a, b, c, x[14], 8)
    GG(c, d, e, a, b, x[1], 15)
    GG(b, c, d, e, a, x[4], 6)
    GG(a, b, c, d, e, x[21], 12)
    GG(e, a, b, c, d, x[7], 9)
    GG(d, e, a, b, c, x[10], 14)
    GG(c, d, e, a, b, x[13], 5)
    GG(b, c, d, e, a, x[0], 13)

    # call HH round template
    HH(a, b, c, d, e, x[26], 5)
    HH(e, a, b, c, d, x[12], 11)
    HH(d, e, a, b, c, x[5], 7)
    HH(c, d, e, a, b, x[14], 15)
    HH(b, c, d, e, a, x[7], 6)
    HH(a, b, c, d, e, x[27], 13)
    HH(e, a, b, c, d, x[0], 8)
    HH(d, e, a, b, c, x[9], 14)
    HH(c, d, e, a, b, x[2], 7)
    HH(b, c, d, e, a, x[11], 12)
    HH(a, b, c, d, e, x[24], 9)
    HH(e, a, b, c, d, x[4], 11)
    HH(d, e, a, b, c, x[13], 8)
    HH(c, d, e, a, b, x[6], 15)
    HH(b, c, d, e, a, x[15], 6)
    HH(a, b, c, d, e, x[25], 12)
    HH(e, a, b, c, d, x[8], 9)
    HH(d, e, a, b, c, x[1], 14)
    HH(c, d, e, a, b, x[10], 5)
    HH(b, c, d, e, a, x[3], 13)

    # call II round template
    II(a, b, c, d, e, x[30], 5)
    II(e, a, b, c, d, x[7], 11)
    II(d, e, a, b, c, x[2], 7)
    II(c, d, e, a, b, x[13], 15)
    II(b, c, d, e, a, x[8], 6)
    II(a, b, c, d, e, x[31], 13)
    II(e, a, b, c, d, x[3], 8)
    II(d, e, a, b, c, x[14], 14)
    II(c, d, e, a, b, x[9], 7)
    II(b, c, d, e, a, x[4], 12)
    II(a, b, c, d, e, x[28], 9)
    II(e, a, b, c, d, x[15], 11)
    II(d, e, a, b, c, x[10], 8)
    II(c, d, e, a, b, x[5], 15)
    II(b, c, d, e, a, x[0], 6)
    II(a, b, c, d, e, x[29], 12)
    II(e, a, b, c, d, x[11], 9)
    II(d, e, a, b, c, x[6], 14)
    II(c, d, e, a, b, x[1], 5)
    II(b, c, d, e, a, x[12], 13)

    # add and assign temporary variables to state
    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e

  # has160 init core
  template has160InitC(ctx: var HAS160Ctx): void =
    # initialize ctx's length
    when CPUBits == 64:
      ctx.length = 0x00'u64
    elif CPUBits == 32:
      ctx.length[0] = 0x00'u32
      ctx.length[1] = 0x00'u32
    ctx.index = 0

    # initialize ctx's state to initialize vector
    ctx.state[0] = 0x67452301'u32
    ctx.state[1] = 0xEFCDAB89'u32
    ctx.state[2] = 0x98BADCFE'u32
    ctx.state[3] = 0x10325476'u32
    ctx.state[4] = 0xC3D2E1F0'u32

  # has160 input core
  template has160InputC(ctx: var HAS160Ctx, input: openArray[uint8]): void {.autoSizeOpt.} =
    # declare check variables
    var check: bool = true
    # set input length
    let inputLen: int = input.len

    # check input length is not zero
    if inputLen <= 0: check = false

    if check:
      # set index and add input length to ctx's length
      when CPUBits == 64:
        ctx.length += uint64(inputLen)
      elif CPUBits == 32:
        let oldLength: uint32 = ctx.length[0]
        ctx.length[0] += uint32(inputLen)
        if ctx.length[0] < oldLength:
          ctx.length[1] += 1

      var index: int = ctx.index
      let left: int = 64 - index
      var position: int = 0

      if inputLen >= left:
        if left > 0:
          copyMem(addr ctx.buffer[index], addr input[0], left)
        has160Transform(ctx.state, ctx.buffer.toSliceArray(0, 63))
        position = left
        index = 0

        while position + 64 <= inputLen:
          has160Transform(ctx.state, input.toSliceArray(position, position + 63, 64))
          position += 64

      let remain: int = inputLen - position
      if remain > 0:
        copyMem(addr ctx.buffer[index], addr input[position], remain)
        index += remain

      ctx.index = index

  # has160 final core
  template has160FinalC(ctx: var HAS160Ctx): array[HAS160_HASH_SIZE, uint8] {.autoSizeOpt.} =
    # declare output
    var output: array[20, uint8]
    # set bitLength and index
    var index: int = ctx.index

    # set buffer as pointer of ctx.buffer
    # add padding
    ctx.buffer[index] = 0x80'u8
    # increase index
    index.inc

    let padLen: int = if index <= 56: 56 - index else: 64 - index

    if index <= 56:
      zeroMem(addr ctx.buffer[index], padLen)
    else:
      if padLen > 0:
        zeroMem(addr ctx.buffer[index], padLen)
      has160Transform(ctx.state, ctx.buffer.toSliceArray(0, 63))
      zeroMem(addr ctx.buffer[0], 56)
      index = 0

    # multiple 8 to ctx.length and copy to ctx.buffer
    when CPUBits == 64:
      ctx.length = ctx.length shl 3
      toBytesLE(ctx.length, ctx.buffer.toSliceArray(56, 63))
    elif CPUBits == 32:
      ctx.length[1] = (ctx.length[0] shr 29) or (ctx.length[1] shl 3)
      ctx.length[0] = ctx.length[0] shl 3
      encodeLE(ctx.length.toSliceArray(0, 1), ctx.buffer.toSliceArray(56, 63))


    # call transform template
    has160Transform(ctx.state, ctx.buffer.toSliceArray(0, 63))

    # encode state to output
    encodeLE(ctx.state, output)

    # declare output
    output

# export wrappers
when defined(templateOpt):
  template has160Init*(ctx: var HAS160Ctx): void = has160InitC(ctx)
  template has160Input*(ctx: var HAS160Ctx, input: openArray[uint8]): void = has160InputC(ctx, input)
  template has160Final*(ctx: var HAS160Ctx): array[20, uint8] = has160FinalC(ctx)

  when Native:
    template has160Init*(ctx: ptr HAS160Ctx): void = has160InitC(ctx[])
    template has160Input*(ctx: ptr HAS160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = has160InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template has160Final*(ctx: ptr HAS160Ctx, output: ptr array[20, uint8]): void = output[] = has160FinalC(ctx[])
else:
  when Native:
    proc has160Init*(ctx: var HAS160Ctx): void = has160InitC(ctx)
    proc has160Input*(ctx: var HAS160Ctx, input: openArray[uint8]): void = has160InputC(ctx, input)
    proc has160Final*(ctx: var HAS160Ctx): array[20, uint8] = has160FinalC(ctx)

  when defined(c) or defined(objc):
    proc has160Init*(ctx: ptr HAS160Ctx): void {.exportc: "has160Init".} = has160InitC(ctx[])
    proc has160Input*(ctx: ptr HAS160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "has160Input".} = has160InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc has160Final*(ctx: ptr HAS160Ctx, output: ptr array[20, uint8]): void {.exportc: "has160Final".} = output[] = has160FinalC(ctx[])
  elif defined(cpp):
    proc has160Init*(ctx: ptr HAS160Ctx): void {.exportcpp: "has160Init".} = has160InitC(ctx[])
    proc has160Input*(ctx: ptr HAS160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "has160Input".} = has160InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc has160Final*(ctx: ptr HAS160Ctx, output: ptr array[20, uint8]): void {.exportcpp: "has160Final".} = output[] = has160FinalC(ctx[])
