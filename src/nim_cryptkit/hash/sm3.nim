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

type
  # SM3 context
  SM3Ctx* = object
    state*: array[8, uint32]
    index*: int
    buffer*: array[64, uint8]
    blockNumber*: int

const
  # sm3 information constant
  SM3_HASH_SIZE*: int = 32
  SM3_BLOCK_SIZE*: int = 64

# sm3 init core
template sm3InitC(ctx: var SM3Ctx): void =
  ctx.state[0] = 0x7380166F'u32
  ctx.state[1] = 0x4914B2B9'u32
  ctx.state[2] = 0x172442D7'u32
  ctx.state[3] = 0xDA8A0600'u32
  ctx.state[4] = 0xA96F30BC'u32
  ctx.state[5] = 0x163138AA'u32
  ctx.state[6] = 0xE38DEE4D'u32
  ctx.state[7] = 0xB0FB0E4E'u32

  ctx.blockNumber = 0
  ctx.index = 0

# P0 template
template P0(x: uint32): uint32 = 
  x xor rotateLeftBits(x, 9) xor rotateLeftBits(x, 17)

# P1 template
template P1(x: uint32): uint32 =
  x xor rotateLeftBits(x, 15) xor rotateLeftBits(x, 23)

# FF0 template
template FF0(x, y, z: uint32): uint32 = 
  x xor y xor z

# FF1 template
template FF1(x, y, z: uint32): uint32 =
  (x and y) or (x and z) or (y and z)

# GG0 template
template GG0(x, y, z: uint32): uint32 =
  x xor y xor z

# GG1 template
template GG1(x, y, z: uint32): uint32 =
  (x and y) or (not x and z)

# sm3 Round template
template sm3Round(a, b, c, d, e, f, g, h: var uint32, w: array[16, uint32], i: static int): void =
  let T = if i < 16: 0x79CC4519'u32 else: 0x7A879D8A'u32
  let SS1 = rotateLeftBits((rotateLeftBits(a, 12) + e + rotateLeftBits(T, i mod 32)), 7)

  let w_prime = w[i and 15] xor w[(i + 4) and 15]
  
  let SS2 = SS1 xor rotateLeftBits(a, 12)
  let TT1 = (when i < 16: FF0(a, b, c) else: FF1(a, b, c)) + d + SS2 + w_prime
  let TT2 = (when i < 16: GG0(e, f, g) else: GG1(e, f, g)) + h + SS1 + w[i and 15]
  d = c
  c = rotateLeftBits(b, 9)
  b = a
  a = TT1
  h = g
  g = rotateLeftBits(f, 19)
  f = e
  e = P0(TT2)
  
# sm3 expand template
template sm3Expand(w: var array[16, uint32], i: static int): void =
  let next_w = P1(w[(i - 16) and 15] xor w[(i - 9) and 15] xor rotateLeftBits(w[(i - 3) and 15], 15)) xor 
               rotateLeftBits(w[(i - 13) and 15], 7) xor w[(i - 6) and 15]
  w[i and 15] = next_w

when defined(sizeOpt):
  # sm3 transform for sizeOpt : don't use static/template
  proc sm3Transform(state: var array[8, uint32], buffer: slicearray[64, uint8]): void =
    var W: array[68, uint32]
    var W1: array[64, uint32]

    var a: uint32 = state[0]
    var b: uint32 = state[1]
    var c: uint32 = state[2]
    var d: uint32 = state[3]
    var e: uint32 = state[4]
    var f: uint32 = state[5]
    var g: uint32 = state[6]
    var h: uint32 = state[7]

    var SS1, SS2, TT1, TT2: uint32

    decodeBE(buffer, W.toSliceArray(0, 15))

    for i in 16 ..< 68:
      W[i] = P1(W[i - 16] xor W[i - 9] xor rotateLeftBits(W[i - 3], 15)) xor rotateLeftBits(W[i - 13], 7) xor W[i - 6]

    for i in 0 ..< 64:
      W1[i] = W[i] xor W[i + 4]

    for i in 0 ..< 16:
      let T = 0x79CC4519'u32
      SS1 = rotateLeftBits((rotateLeftBits(a, 12) + e + rotateLeftBits(T, i mod 32)), 7)
      SS2 = SS1 xor rotateLeftBits(a, 12)
      TT1 = FF0(a, b, c) + d + SS2 + W1[i]
      TT2 = GG0(e, f, g) + h + SS1 + W[i]
      d = c
      c = rotateLeftBits(b, 9)
      b = a
      a = TT1
      h = g
      g = rotateLeftBits(f, 19)
      f = e
      e = P0(TT2)

    for i in 16 ..< 64:
      let T = 0x7A879D8A'u32
      SS1 = rotateLeftBits((rotateLeftBits(a, 12) + e + rotateLeftBits(T, i mod 32)), 7)
      SS2 = SS1 xor rotateLeftBits(a, 12)
      TT1 = FF1(a, b, c) + d + SS2 + W1[i]
      TT2 = GG1(e, f, g) + h + SS1 + W[i]
      d = c
      c = rotateLeftBits(b, 9)
      b = a
      a = TT1
      h = g
      g = rotateLeftBits(f, 19)
      f = e
      e = P0(TT2)

    state[0] = state[0] xor a
    state[1] = state[1] xor b
    state[2] = state[2] xor c
    state[3] = state[3] xor d
    state[4] = state[4] xor e
    state[5] = state[5] xor f
    state[6] = state[6] xor g
    state[7] = state[7] xor h
else:
  # sm3 transform template for default
  template sm3Transform(state: var array[8, uint32], buffer: slicearray[64, uint8]): void =
    var w: array[16, uint32]

    var a: uint32 = state[0]
    var b: uint32 = state[1]
    var c: uint32 = state[2]
    var d: uint32 = state[3]
    var e: uint32 = state[4]
    var f: uint32 = state[5]
    var g: uint32 = state[6]
    var h: uint32 = state[7]

    decodeBE(buffer, w.toSliceArray(0, 15))

    # Rounds 0-11
    sm3Round(a, b, c, d, e, f, g, h, w, 0); sm3Round(a, b, c, d, e, f, g, h, w, 1)
    sm3Round(a, b, c, d, e, f, g, h, w, 2); sm3Round(a, b, c, d, e, f, g, h, w, 3)
    sm3Round(a, b, c, d, e, f, g, h, w, 4); sm3Round(a, b, c, d, e, f, g, h, w, 5)
    sm3Round(a, b, c, d, e, f, g, h, w, 6); sm3Round(a, b, c, d, e, f, g, h, w, 7)
    sm3Round(a, b, c, d, e, f, g, h, w, 8); sm3Round(a, b, c, d, e, f, g, h, w, 9)
    sm3Round(a, b, c, d, e, f, g, h, w, 10); sm3Round(a, b, c, d, e, f, g, h, w, 11)

    # Rounds 12-15
    sm3Expand(w, 16); sm3Round(a, b, c, d, e, f, g, h, w, 12)
    sm3Expand(w, 17); sm3Round(a, b, c, d, e, f, g, h, w, 13)
    sm3Expand(w, 18); sm3Round(a, b, c, d, e, f, g, h, w, 14)
    sm3Expand(w, 19); sm3Round(a, b, c, d, e, f, g, h, w, 15)

    # Rounds 16-63
    template roundExp(idx: static int) =
      sm3Expand(w, idx + 4)
      sm3Round(a, b, c, d, e, f, g, h, w, idx)

    # sm3 round for 16 ~ 63
    roundExp(16); roundExp(17); roundExp(18); roundExp(19)
    roundExp(20); roundExp(21); roundExp(22); roundExp(23)
    roundExp(24); roundExp(25); roundExp(26); roundExp(27)
    roundExp(28); roundExp(29); roundExp(30); roundExp(31)
    roundExp(32); roundExp(33); roundExp(34); roundExp(35)
    roundExp(36); roundExp(37); roundExp(38); roundExp(39)
    roundExp(40); roundExp(41); roundExp(42); roundExp(43)
    roundExp(44); roundExp(45); roundExp(46); roundExp(47)
    roundExp(48); roundExp(49); roundExp(50); roundExp(51)
    roundExp(52); roundExp(53); roundExp(54); roundExp(55)
    roundExp(56); roundExp(57); roundExp(58); roundExp(59)
    roundExp(60); roundExp(61); roundExp(62); roundExp(63)

    # xor and assign temporary variables to state
    state[0] = state[0] xor a
    state[1] = state[1] xor b
    state[2] = state[2] xor c
    state[3] = state[3] xor d
    state[4] = state[4] xor e
    state[5] = state[5] xor f
    state[6] = state[6] xor g
    state[7] = state[7] xor h

# sm3 input core
template sm3InputC(ctx: var SM3Ctx, input: openArray[uint8]): void =
  var check: bool = true
  let inputLen: int = input.len

  if inputLen == 0:
    check = false

  if check:
    var index: int = ctx.index
    let left: int = SM3_BLOCK_SIZE - index
    var position: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      sm3Transform(ctx.state, ctx.buffer.toSliceArray(0, 63))
      ctx.blockNumber += 1
      position = left
      index = 0

      while position + SM3_BLOCK_SIZE <= inputLen:
        sm3Transform(ctx.state, input.toSliceArray(position, position + 63, 64))
        ctx.blockNumber += 1
        position += SM3_BLOCK_SIZE

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

# sm3 final core
template sm3FinalC(ctx: var SM3Ctx): array[32, uint8] =
  # declare output
  var output: array[32, uint8]
  var index: int = ctx.index

  # calculate bit length
  let totalBits: uint64 = ((ctx.blockNumber.uint64 shl 6) + ctx.index.uint64) shl 3 

  # padding
  ctx.buffer[index] = 0x80'u8
  index += 1

  let padLen: int = if index <= SM3_BLOCK_SIZE - 8: SM3_BLOCK_SIZE - 8 - index else: SM3_BLOCK_SIZE - index

  # check left space is bigger than length size
  if index <= SM3_BLOCK_SIZE - 8:
    # zerofill left space
    zeroMem(addr ctx.buffer[index], padLen)
  else:
    if padLen > 0:
      # zerofill space and transform
      zeroMem(addr ctx.buffer[index], padLen)
    sm3Transform(ctx.state, ctx.buffer.toSliceArray(0, 63))
    # zerofill before blocksize - 8
    zeroMem(addr ctx.buffer, SM3_BLOCK_SIZE - 8)

  # decode bit length
  toBytesBE(totalBits, ctx.buffer.toSliceArray(56, 63))

  # transform state
  sm3Transform(ctx.state, ctx.buffer.toSliceArray(0, 63))

  # encode state to output
  encodeBE(ctx.state, output)

  output

# export wrappers
when defined(templateOpt):
  template sm3Init*(ctx: var SM3Ctx): void = sm3InitC(ctx)
  template sm3Init*(ctx: ptr SM3Ctx): void = sm3InitC(ctx[])

  template sm3Input*(ctx: var SM3Ctx, input: openArray[uint8]): void = sm3InputC(ctx, input)
  template sm3Input*(ctx: ptr SM3Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sm3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
  
  template sm3Final*(ctx: var SM3Ctx): array[32, uint8] = sm3FinalC(ctx)
  template sm3Final*(ctx: ptr SM3Ctx, output: ptr array[32, uint8]): void = output[] = sm3FinalC(ctx[])
else:
  proc sm3Init*(ctx: var SM3Ctx): void = sm3InitC(ctx)
  proc sm3Init*(ctx: ptr SM3Ctx): void {.exportc: "sm3Init".} = sm3InitC(ctx[])

  proc sm3Input*(ctx: var SM3Ctx, input: openArray[uint8]): void = sm3InputC(ctx, input)
  proc sm3Input*(ctx: ptr SM3Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sm3Input".} = sm3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
  
  proc sm3Final*(ctx: var SM3Ctx): array[32, uint8] = sm3FinalC(ctx)
  proc sm3Final*(ctx: ptr SM3Ctx, output: ptr array[32, uint8]): void {.exportc: "sm3Final".} = output[] = sm3FinalC(ctx[])
