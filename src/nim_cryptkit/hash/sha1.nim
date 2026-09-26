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

when CPUBits == 64:
  # SHA-1 context for 64 bits
  type
    SHA1Ctx* = object
      state*: array[5, uint32]
      length*: uint64
      index*: int
      buffer*: array[64, uint8]
elif CPUBits == 32:
  # SHA-1 context for 32/lower bits
  type
    SHA1Ctx* = object
      state*: array[5, uint32]
      length*: array[2, uint32]
      index*: int
      buffer*: array[64, uint8]

# extend chunk
template extend(chunk: var array[16, uint32], i: int): uint32 =
  let index = i and 15
  chunk[index] = rotateLeftBits(chunk[(index + 13) and 15] xor chunk[(index + 8) and 15] xor chunk[(index + 2) and 15] xor chunk[index], 1)
  chunk[index]

# round 0 template : with out chunk extend
template round0(a, b, c, d, e: var uint32, x: var array[16, uint32], i: int): void =
  e += ((b and (c xor d)) xor d) + x[i] + 0x5A827999'u32 + rotateLeftBits(a, 5)
  b = rotateLeftBits(b, 30)

# round 1 template : include chunk extend
template round1(a, b, c, d, e: var uint32, x: var array[16, uint32], i: int): void =
  e += ((b and (c xor d)) xor d) + extend(x, i) + 0x5A827999'u32 + rotateLeftBits(a, 5)
  b = rotateLeftBits(b, 30)

# round 2 template
template round2(a, b, c, d, e: var uint32, x: var array[16, uint32], i: int): void =
  e += (b xor c xor d) + extend(x, i) + 0x6ED9EBA1'u32 + rotateLeftBits(a, 5)
  b = rotateLeftBits(b, 30)

# round 3 template
template round3(a, b, c, d, e: var uint32, x: var array[16, uint32], i: int): void =
  e += (((b or c) and d) or (b and c)) + extend(x, i) + 0x8F1BBCDC'u32 + rotateLeftBits(a, 5)
  b = rotateLeftBits(b, 30)

# round 4 template
template round4(a, b, c, d, e: var uint32, x: var array[16, uint32], i: int): void =
  e += (b xor c xor d) + extend(x, i) + 0xCA62C1D6'u32 + rotateLeftBits(a, 5)
  b = rotateLeftBits(b, 30)

# common sha1 operating process template
template sha1Transform(state: var array[5, uint32], input: slicearray[64, uint8]): void =
  # declare and initialize temporary variables
  var a: uint32 = state[0]
  var b: uint32 = state[1]
  var c: uint32 = state[2]
  var d: uint32 = state[3]
  var e: uint32 = state[4]

  # declare extended chunk
  var chunk: array[16, uint32]

  # decode chunk to extended chunk(w)
  decodeBE(input, chunk.toSliceArray(0, 15))

  # call round template
  round0(a, b, c, d, e, chunk, 0)
  round0(e, a, b, c, d, chunk, 1)
  round0(d, e, a, b, c, chunk, 2)
  round0(c, d, e, a, b, chunk, 3)
  round0(b, c, d, e, a, chunk, 4)
  round0(a, b, c, d, e, chunk, 5)
  round0(e, a, b, c, d, chunk, 6)
  round0(d, e, a, b, c, chunk, 7)
  round0(c, d, e, a, b, chunk, 8)
  round0(b, c, d, e, a, chunk, 9)
  round0(a, b, c, d, e, chunk, 10)
  round0(e, a, b, c, d, chunk, 11)
  round0(d, e, a, b, c, chunk, 12)
  round0(c, d, e, a, b, chunk, 13)
  round0(b, c, d, e, a, chunk, 14)
  round0(a, b, c, d, e, chunk, 15)
  round1(e, a, b, c, d, chunk, 16)
  round1(d, e, a, b, c, chunk, 17)
  round1(c, d, e, a, b, chunk, 18)
  round1(b, c, d, e, a, chunk, 19)
  round2(a, b, c, d, e, chunk, 20)
  round2(e, a, b, c, d, chunk, 21)
  round2(d, e, a, b, c, chunk, 22)
  round2(c, d, e, a, b, chunk, 23)
  round2(b, c, d, e, a, chunk, 24)
  round2(a, b, c, d, e, chunk, 25)
  round2(e, a, b, c, d, chunk, 26)
  round2(d, e, a, b, c, chunk, 27)
  round2(c, d, e, a, b, chunk, 28)
  round2(b, c, d, e, a, chunk, 29)
  round2(a, b, c, d, e, chunk, 30)
  round2(e, a, b, c, d, chunk, 31)
  round2(d, e, a, b, c, chunk, 32)
  round2(c, d, e, a, b, chunk, 33)
  round2(b, c, d, e, a, chunk, 34)
  round2(a, b, c, d, e, chunk, 35)
  round2(e, a, b, c, d, chunk, 36)
  round2(d, e, a, b, c, chunk, 37)
  round2(c, d, e, a, b, chunk, 38)
  round2(b, c, d, e, a, chunk, 39)
  round3(a, b, c, d, e, chunk, 40)
  round3(e, a, b, c, d, chunk, 41)
  round3(d, e, a, b, c, chunk, 42)
  round3(c, d, e, a, b, chunk, 43)
  round3(b, c, d, e, a, chunk, 44)
  round3(a, b, c, d, e, chunk, 45)
  round3(e, a, b, c, d, chunk, 46)
  round3(d, e, a, b, c, chunk, 47)
  round3(c, d, e, a, b, chunk, 48)
  round3(b, c, d, e, a, chunk, 49)
  round3(a, b, c, d, e, chunk, 50)
  round3(e, a, b, c, d, chunk, 51)
  round3(d, e, a, b, c, chunk, 52)
  round3(c, d, e, a, b, chunk, 53)
  round3(b, c, d, e, a, chunk, 54)
  round3(a, b, c, d, e, chunk, 55)
  round3(e, a, b, c, d, chunk, 56)
  round3(d, e, a, b, c, chunk, 57)
  round3(c, d, e, a, b, chunk, 58)
  round3(b, c, d, e, a, chunk, 59)
  round4(a, b, c, d, e, chunk, 60)
  round4(e, a, b, c, d, chunk, 61)
  round4(d, e, a, b, c, chunk, 62)
  round4(c, d, e, a, b, chunk, 63)
  round4(b, c, d, e, a, chunk, 64)
  round4(a, b, c, d, e, chunk, 65)
  round4(e, a, b, c, d, chunk, 66)
  round4(d, e, a, b, c, chunk, 67)
  round4(c, d, e, a, b, chunk, 68)
  round4(b, c, d, e, a, chunk, 69)
  round4(a, b, c, d, e, chunk, 70)
  round4(e, a, b, c, d, chunk, 71)
  round4(d, e, a, b, c, chunk, 72)
  round4(c, d, e, a, b, chunk, 73)
  round4(b, c, d, e, a, chunk, 74)
  round4(a, b, c, d, e, chunk, 75)
  round4(e, a, b, c, d, chunk, 76)
  round4(d, e, a, b, c, chunk, 77)
  round4(c, d, e, a, b, chunk, 78)
  round4(b, c, d, e, a, chunk, 79)

  # assign and add temporary variables to state
  state[0] += a
  state[1] += b
  state[2] += c
  state[3] += d
  state[4] += e

# initialize sha1 context
template sha1InitC(ctx: var SHA1Ctx): void =
  when CPUBits == 64:
    ctx.length = 0x00'u64
  elif CPUBits == 32:
    ctx.length[0] = 0x00'u32
    ctx.length[1] = 0x00'u32

  ctx.state[0] = 0x67452301'u32
  ctx.state[1] = 0xEFCDAB89'u32
  ctx.state[2] = 0x98BADCFE'u32
  ctx.state[3] = 0x10325476'u32
  ctx.state[4] = 0xC3D2E1F0'u32

  ctx.index = 0

  zeroMem(addr ctx.buffer[0], 64)

# one-shot sha1 core
template sha1OneC(input: openArray[uint8]): array[20, uint8] =
  # declare output
  var output: array[20, uint8]
  # declare buffer
  let totalLen = ((input.len + 9 + 63) div 64) * 64
  var buffer: seq[uint8] = newSeq[uint8](totalLen)
  # declare and initialize index
  var index: int = input.len
  # copy input to buffer
  copyMem(addr buffer[0], addr input[0], input.len)
  # declare and initialize state
  var state: array[5, uint32] = [0x67452301'u32, 0xefcdab89'u32, 0x98badcfe'u32, 0x10325476'u32, 0xC3D2E1F0'u32]

  # append '1' bit -> 0x80
  buffer[index] = 0x80'u8
  index += 1

  let padLen: int = totalLen - index - 8
  zeroMem(addr buffer[index], padLen)
  index += padLen

  let bitLen: uint64 = uint64(input.len) shl 3
  toBytesBE(bitLen, buffer.toSliceArray(index, index + 7, 8))

  var position = 0
  # break chunk 512bits
  while position + 63 < totalLen:
    sha1Transform(state, buffer.toSliceArray(position, position + 63, 64))
    position += 64

  # encode state to output
  encodeBE(state, output)

  output

# sha1 input core
template sha1InputC(ctx: var SHA1Ctx, input: openArray[uint8]): void =
  # declare check variables
  var check: bool = true
  let inputLen: int = input.len
  
  if inputLen <= 0: check = false

  if check:
    var index: int = ctx.index
    # add input bit length to ctx.bitLength
    # 64 bits version
    when CPUBits == 64:
      ctx.length += uint64(inputLen)
    # 32/lower bits version
    elif CPUBits == 32:
      let oldLength: uint32 = ctx.length[0]
      ctx.length[0] += uint32(inputLen)
      if ctx.length[0] < oldLength:
        ctx.length[1] += 1

    let left: int = 64 - index
    var position: int = 0
    
    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[position], left)
      sha1Transform(ctx.state, ctx.buffer.toSliceArray(0, 63))
      position = left
      index = 0

      while position + 64 <= inputLen:
        sha1Transform(ctx.state, input.toSliceArray(position, position + 63, 64))
        position += 64
      
    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain
      
    ctx.index = index

# sha1 finalize core
template sha1FinalC(ctx: var SHA1Ctx): array[20, uint8] =
  var output: array[20, uint8]
  var index: int = ctx.index

  # do padding(add 0x80 and zero)
  ctx.buffer[index] = 0x80
  index += 1

  let padLen = if index <= 56: 56 - index else: 64 - index

  if index <= 56:
    zeroMem(addr ctx.buffer[index], padLen)
  else:
    if padLen > 0:
      zeroMem(addr ctx.buffer[index], padLen)
    sha1Transform(ctx.state, ctx.buffer.toSliceArray(0, 63))
    zeroMem(addr ctx.buffer[0], 56)

  when CPUBits == 64:
    ctx.length = ctx.length shl 3
    toBytesBE(ctx.length, ctx.buffer.toSliceArray(56, 63))
  else:
    ctx.length[1] = (ctx.length[1] shl 3) or (ctx.length[0] shr 29)
    ctx.length[0] = ctx.length[0] shl 3
    encodeBE(ctx.length.toSliceArray(0, 1), ctx.buffer.toSliceArray(56, 63))

  sha1Transform(ctx.state, ctx.buffer.toSliceArray(0, 63))

  encodeBE(ctx.state, output)

  output

# export wrappers
when defined(templateOpt):
  template sha1Init*(ctx: var SHA1Ctx): void = sha1InitC(ctx)
  template sha1Input*(ctx: var SHA1Ctx, input: openArray[uint8]): void = sha1InputC(ctx, input)
  template sha1Final*(ctx: var SHA1Ctx): array[20, uint8] = sha1FinalC(ctx)
  template sha1One*(input: openArray[uint8]): array[20, uint8] = sha1OneC(input)

  when Native:
    template sha1Init*(ctx: ptr SHA1Ctx): void = sha1InitC(ctx[])
    template sha1Input*(ctx: ptr SHA1Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha1InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template sha1Final*(ctx: ptr SHA1Ctx, output: ptr array[20, uint8]): void = output[] = sha1FinalC(ctx[])
    template sha1One*(output: ptr array[20, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void = output[] = sha1OneC(input.toOpenArray(0, inputLen - 1))
else:
  when Native:
    proc sha1Init*(ctx: var SHA1Ctx): void = sha1InitC(ctx)
    proc sha1Input*(ctx: var SHA1Ctx, input: openArray[uint8]): void = sha1InputC(ctx, input)
    proc sha1Final*(ctx: var SHA1Ctx): array[20, uint8] = sha1FinalC(ctx)
    proc sha1One*(input: openArray[uint8]): array[20, uint8] = sha1OneC(input)

  when defined(c) or defined(objc):
    proc sha1Init*(ctx: ptr SHA1Ctx): void {.exportc: "sha1Init".} = sha1InitC(ctx[])
    proc sha1Input*(ctx: ptr SHA1Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha1Input".} = sha1InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha1Final*(ctx: ptr SHA1Ctx, output: ptr array[20, uint8]): void {.exportc: "sha1Final".} = output[] = sha1FinalC(ctx[])
    proc sha1One*(output: ptr array[20, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha1One".} = output[] = sha1OneC(input.toOpenArray(0, inputLen - 1))
  elif defined(cpp):
    proc sha1Init*(ctx: ptr SHA1Ctx): void {.exportcpp: "sha1Init".} = sha1InitC(ctx[])
    proc sha1Input*(ctx: ptr SHA1Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha1Input".} = sha1InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha1Final*(ctx: ptr SHA1Ctx, output: ptr array[20, uint8]): void {.exportcpp: "sha1Final".} = output[] = sha1FinalC(ctx[])
    proc sha1One*(output: ptr array[20, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha1One".} = output[] = sha1OneC(input.toOpenArray(0, inputLen - 1))
