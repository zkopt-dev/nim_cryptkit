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

# Padding : precalculated padding list
# block makes constant in compile time
const
  # padding constant
  MD5_PADDING: array[64, uint8] = [
    0x80'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  ]


# md5 oneshot core
template md5OneC(msg: lent openArray[uint8]): array[16, uint8] =
  # declaring output
  var output: array[16, uint8]

  # declare and initialise state
  var state: array[4, uint32] = [0x67452301'u32, 0xefcdab89'u32, 0x98badcfe'u32, 0x10325476'u32]

  # set bit length
  let bitLen: uint64 = uint64(msg.len) * 8

  # declare buffer
  var buffer: array[64, uint8]

  # declare index and check variables
  var msgIndex: int = 0
  var paddingStarted = false
  var lengthAppended = false

  # while length is not end: loop
  while not lengthAppended:
    var bufferIndex: int = 0
    for i in 0 ..< 64: buffer[i] = 0
    while bufferIndex < 64:
      if msgIndex < msg.len:
        buffer[bufferIndex] = msg[msgIndex]
        msgIndex.inc
        bufferIndex.inc
      elif not paddingStarted:
        buffer[bufferIndex] = 0x80'u8
        paddingStarted = true
        bufferIndex.inc
      elif not lengthAppended:
        if bufferIndex <= 56:
          if bufferIndex == 56:
            for i in static(0 ..< 8):
              buffer[bufferIndex + i] = uint8((bitLen shr (8 * i)) and 0xFF'u64)
            lengthAppended = true
            bufferIndex = 64
          else:
            buffer[bufferIndex] = 0x00'u8
            bufferIndex.inc
      else:
        bufferIndex.inc

    var chunk: array[16, uint32]
    decodeLE(buffer, chunk)

    var a: uint32 = state[0]
    var b: uint32 = state[1]
    var c: uint32 = state[2]
    var d: uint32 = state[3]

    # FF round : 1 ~ 16
    FF(a, b, c, d, chunk[ 0], 7, 0xd76aa478'u32)
    FF(d, a, b, c, chunk[ 1], 12, 0xe8c7b756'u32)
    FF(c, d, a, b, chunk[ 2], 17, 0x242070db'u32)
    FF(b, c, d, a, chunk[ 3], 22, 0xc1bdceee'u32)
    FF(a, b, c, d, chunk[ 4], 7, 0xf57c0faf'u32)
    FF(d, a, b, c, chunk[ 5], 12, 0x4787c62a'u32)
    FF(c, d, a, b, chunk[ 6], 17, 0xa8304613'u32)
    FF(b, c, d, a, chunk[ 7], 22, 0xfd469501'u32)
    FF(a, b, c, d, chunk[ 8], 7, 0x698098d8'u32)
    FF(d, a, b, c, chunk[ 9], 12, 0x8b44f7af'u32)
    FF(c, d, a, b, chunk[10], 17, 0xffff5bb1'u32)
    FF(b, c, d, a, chunk[11], 22, 0x895cd7be'u32)
    FF(a, b, c, d, chunk[12], 7, 0x6b901122'u32)
    FF(d, a, b, c, chunk[13], 12, 0xfd987193'u32)
    FF(c, d, a, b, chunk[14], 17, 0xa679438e'u32)
    FF(b, c, d, a, chunk[15], 22, 0x49b40821'u32)

    # GG round : 17 ~ 32
    GG(a, b, c, d, chunk[ 1], 5, 0xf61e2562'u32)
    GG(d, a, b, c, chunk[ 6], 9, 0xc040b340'u32)
    GG(c, d, a, b, chunk[11], 14, 0x265e5a51'u32)
    GG(b, c, d, a, chunk[ 0], 20, 0xe9b6c7aa'u32)
    GG(a, b, c, d, chunk[ 5], 5, 0xd62f105d'u32)
    GG(d, a, b, c, chunk[10], 9, 0x02441453'u32)
    GG(c, d, a, b, chunk[15], 14, 0xd8a1e681'u32)
    GG(b, c, d, a, chunk[ 4], 20, 0xe7d3fbc8'u32)
    GG(a, b, c, d, chunk[ 9], 5, 0x21e1cde6'u32)
    GG(d, a, b, c, chunk[14], 9, 0xc33707d6'u32)
    GG(c, d, a, b, chunk[ 3], 14, 0xf4d50d87'u32)
    GG(b, c, d, a, chunk[ 8], 20, 0x455a14ed'u32)
    GG(a, b, c, d, chunk[13], 5, 0xa9e3e905'u32)
    GG(d, a, b, c, chunk[ 2], 9, 0xfcefa3f8'u32)
    GG(c, d, a, b, chunk[ 7], 14, 0x676f02d9'u32)
    GG(b, c, d, a, chunk[12], 20, 0x8d2a4c8a'u32)

    # HH round : 33 ~ 48
    HH(a, b, c, d, chunk[ 5], 4, 0xfffa3942'u32)
    HH(d, a, b, c, chunk[ 8], 11, 0x8771f681'u32)
    HH(c, d, a, b, chunk[11], 16, 0x6d9d6122'u32)
    HH(b, c, d, a, chunk[14], 23, 0xfde5380c'u32)
    HH(a, b, c, d, chunk[ 1], 4, 0xa4beea44'u32)
    HH(d, a, b, c, chunk[ 4], 11, 0x4bdecfa9'u32)
    HH(c, d, a, b, chunk[ 7], 16, 0xf6bb4b60'u32)
    HH(b, c, d, a, chunk[10], 23, 0xbebfbc70'u32)
    HH(a, b, c, d, chunk[13], 4, 0x289b7ec6'u32)
    HH(d, a, b, c, chunk[ 0], 11, 0xeaa127fa'u32)
    HH(c, d, a, b, chunk[ 3], 16, 0xd4ef3085'u32)
    HH(b, c, d, a, chunk[ 6], 23, 0x04881d05'u32)
    HH(a, b, c, d, chunk[ 9], 4, 0xd9d4d039'u32)
    HH(d, a, b, c, chunk[12], 11, 0xe6db99e5'u32)
    HH(c, d, a, b, chunk[15], 16, 0x1fa27cf8'u32)
    HH(b, c, d, a, chunk[ 2], 23, 0xc4ac5665'u32)

    # II round : 49 ~ 64
    II(a, b, c, d, chunk[ 0], 6, 0xf4292244'u32)
    II(d, a, b, c, chunk[ 7], 10, 0x432aff97'u32)
    II(c, d, a, b, chunk[14], 15, 0xab9423a7'u32)
    II(b, c, d, a, chunk[ 5], 21, 0xfc93a039'u32)
    II(a, b, c, d, chunk[12], 6, 0x655b59c3'u32)
    II(d, a, b, c, chunk[ 3], 10, 0x8f0ccc92'u32)
    II(c, d, a, b, chunk[10], 15, 0xffeff47d'u32)
    II(b, c, d, a, chunk[ 1], 21, 0x85845dd1'u32)
    II(a, b, c, d, chunk[ 8], 6, 0x6fa87e4f'u32)
    II(d, a, b, c, chunk[15], 10, 0xfe2ce6e0'u32)
    II(c, d, a, b, chunk[ 6], 15, 0xa3014314'u32)
    II(b, c, d, a, chunk[13], 21, 0x4e0811a1'u32)
    II(a, b, c, d, chunk[ 4], 6, 0xf7537e82'u32)
    II(d, a, b, c, chunk[11], 10, 0xbd3af235'u32)
    II(c, d, a, b, chunk[ 2], 15, 0x2ad7d2bb'u32)
    II(b, c, d, a, chunk[ 9], 21, 0xeb86d391'u32)

    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d


  encodeLE(state, output)

  output

# set CPU' bits to constant
const
  Bits*: int = sizeof(int) * 8

# MD5 context for 64bits
when Bits == 64:
  type
    MD5Ctx* = object
      state*: array[4, uint32]
      length*: uint64
      buffer*: array[64, uint8]
      index*: int
# MD5 context for 32bits
elif Bits == 32:
  type
    MD5Ctx* = object
      state*: array[4, uint32]
      length*: array[2, uint32]
      buffer*: array[64, uint8]
      index*: int

# F operation template
template F(x, y, z: uint32): uint32 =
  (x and y) or ((not x) and z)

# G operation template
template G(x, y, z: uint32): uint32 =
  (x and z) or (y and (not z))

# H operation template
template H(x, y, z: uint32): uint32 =
  x xor y xor z

# I operation template
template I(x, y, z: uint32): uint32 =
  y xor (x or (not z))

# FF round template
template FF(a: var uint32, b, c, d, x: uint32, s: static int, ac: uint32): void =
  a += F(b, c, d) + x + ac
  a = rotateLeftBits(a, s)
  a += b

# GG round template
template GG(a: var uint32, b, c, d, x: uint32, s: static int, ac: uint32): void =
  a += G(b, c, d) + x + ac
  a = rotateLeftBits(a, s)
  a += b

# HH round template
template HH(a: var uint32, b, c, d, x: uint32, s: static int, ac: uint32): void =
  a += H(b, c, d) + x + ac
  a = rotateLeftBits(a, s)
  a += b

# II roundt template
template II(a: var uint32, b, c, d, x: uint32, s: static int, ac: uint32): void =
  a += I(b, c, d) + x + ac
  a = rotateLeftBits(a, s)
  a += b

# md5 transform template
template md5Transform(state: var array[4, uint32], input: slicearray[64, uint8]): void =
  # decode input to chunk
  var chunk: array[16, uint32]
  decodeLE(input, chunk.toSliceArray(0, 15))

  # declare and initialise temporary variables
  var a: uint32 = state[0]
  var b: uint32 = state[1]
  var c: uint32 = state[2]
  var d: uint32 = state[3]

  # FF round : 1 ~ 16
  FF(a, b, c, d, chunk[ 0], 7, 0xd76aa478'u32)
  FF(d, a, b, c, chunk[ 1], 12, 0xe8c7b756'u32)
  FF(c, d, a, b, chunk[ 2], 17, 0x242070db'u32)
  FF(b, c, d, a, chunk[ 3], 22, 0xc1bdceee'u32)
  FF(a, b, c, d, chunk[ 4], 7, 0xf57c0faf'u32)
  FF(d, a, b, c, chunk[ 5], 12, 0x4787c62a'u32)
  FF(c, d, a, b, chunk[ 6], 17, 0xa8304613'u32)
  FF(b, c, d, a, chunk[ 7], 22, 0xfd469501'u32)
  FF(a, b, c, d, chunk[ 8], 7, 0x698098d8'u32)
  FF(d, a, b, c, chunk[ 9], 12, 0x8b44f7af'u32)
  FF(c, d, a, b, chunk[10], 17, 0xffff5bb1'u32)
  FF(b, c, d, a, chunk[11], 22, 0x895cd7be'u32)
  FF(a, b, c, d, chunk[12], 7, 0x6b901122'u32)
  FF(d, a, b, c, chunk[13], 12, 0xfd987193'u32)
  FF(c, d, a, b, chunk[14], 17, 0xa679438e'u32)
  FF(b, c, d, a, chunk[15], 22, 0x49b40821'u32)

  # GG round : 17 ~ 32
  GG(a, b, c, d, chunk[ 1], 5, 0xf61e2562'u32)
  GG(d, a, b, c, chunk[ 6], 9, 0xc040b340'u32)
  GG(c, d, a, b, chunk[11], 14, 0x265e5a51'u32)
  GG(b, c, d, a, chunk[ 0], 20, 0xe9b6c7aa'u32)
  GG(a, b, c, d, chunk[ 5], 5, 0xd62f105d'u32)
  GG(d, a, b, c, chunk[10], 9, 0x02441453'u32)
  GG(c, d, a, b, chunk[15], 14, 0xd8a1e681'u32)
  GG(b, c, d, a, chunk[ 4], 20, 0xe7d3fbc8'u32)
  GG(a, b, c, d, chunk[ 9], 5, 0x21e1cde6'u32)
  GG(d, a, b, c, chunk[14], 9, 0xc33707d6'u32)
  GG(c, d, a, b, chunk[ 3], 14, 0xf4d50d87'u32)
  GG(b, c, d, a, chunk[ 8], 20, 0x455a14ed'u32)
  GG(a, b, c, d, chunk[13], 5, 0xa9e3e905'u32)
  GG(d, a, b, c, chunk[ 2], 9, 0xfcefa3f8'u32)
  GG(c, d, a, b, chunk[ 7], 14, 0x676f02d9'u32)
  GG(b, c, d, a, chunk[12], 20, 0x8d2a4c8a'u32)

  # HH round : 33 ~ 48
  HH(a, b, c, d, chunk[ 5], 4, 0xfffa3942'u32)
  HH(d, a, b, c, chunk[ 8], 11, 0x8771f681'u32)
  HH(c, d, a, b, chunk[11], 16, 0x6d9d6122'u32)
  HH(b, c, d, a, chunk[14], 23, 0xfde5380c'u32)
  HH(a, b, c, d, chunk[ 1], 4, 0xa4beea44'u32)
  HH(d, a, b, c, chunk[ 4], 11, 0x4bdecfa9'u32)
  HH(c, d, a, b, chunk[ 7], 16, 0xf6bb4b60'u32)
  HH(b, c, d, a, chunk[10], 23, 0xbebfbc70'u32)
  HH(a, b, c, d, chunk[13], 4, 0x289b7ec6'u32)
  HH(d, a, b, c, chunk[ 0], 11, 0xeaa127fa'u32)
  HH(c, d, a, b, chunk[ 3], 16, 0xd4ef3085'u32)
  HH(b, c, d, a, chunk[ 6], 23, 0x04881d05'u32)
  HH(a, b, c, d, chunk[ 9], 4, 0xd9d4d039'u32)
  HH(d, a, b, c, chunk[12], 11, 0xe6db99e5'u32)
  HH(c, d, a, b, chunk[15], 16, 0x1fa27cf8'u32)
  HH(b, c, d, a, chunk[ 2], 23, 0xc4ac5665'u32)

  # II round : 49 ~ 64
  II(a, b, c, d, chunk[ 0], 6, 0xf4292244'u32)
  II(d, a, b, c, chunk[ 7], 10, 0x432aff97'u32)
  II(c, d, a, b, chunk[14], 15, 0xab9423a7'u32)
  II(b, c, d, a, chunk[ 5], 21, 0xfc93a039'u32)
  II(a, b, c, d, chunk[12], 6, 0x655b59c3'u32)
  II(d, a, b, c, chunk[ 3], 10, 0x8f0ccc92'u32)
  II(c, d, a, b, chunk[10], 15, 0xffeff47d'u32)
  II(b, c, d, a, chunk[ 1], 21, 0x85845dd1'u32)
  II(a, b, c, d, chunk[ 8], 6, 0x6fa87e4f'u32)
  II(d, a, b, c, chunk[15], 10, 0xfe2ce6e0'u32)
  II(c, d, a, b, chunk[ 6], 15, 0xa3014314'u32)
  II(b, c, d, a, chunk[13], 21, 0x4e0811a1'u32)
  II(a, b, c, d, chunk[ 4], 6, 0xf7537e82'u32)
  II(d, a, b, c, chunk[11], 10, 0xbd3af235'u32)
  II(c, d, a, b, chunk[ 2], 15, 0x2ad7d2bb'u32)
  II(b, c, d, a, chunk[ 9], 21, 0xeb86d391'u32)

  # add and assign temporary variables to state
  state[0] += a
  state[1] += b
  state[2] += c
  state[3] += d

# md5 init core
template md5InitC(ctx: var MD5Ctx): void =
  # initialise ctx.length
  when Bits == 64:
    ctx.length = 0'u64
  else:
    ctx.length[0] = 0'u32
    ctx.length[1] = 0'u32

  ctx.index = 0
  # initialise state by initialise vector
  ctx.state[0] = 0x67452301'u32
  ctx.state[1] = 0xefcdab89'u32
  ctx.state[2] = 0x98badcfe'u32
  ctx.state[3] = 0x10325476'u32
  # zerofill ctx.buffer
  zeroMem(addr ctx.buffer[0], 64)

# md5 input core
template md5InputC(ctx: var MD5Ctx, input: openArray[uint8]): void =
  # set inputLen
  let inputLen: int = input.len

  var check: bool = true

  if inputLen <= 0: check = false

  if check:
    # set index and add length
    var index: int = ctx.index
    when Bits == 64:
      ctx.length += uint64(inputLen)
    else:
      let oldLength: uint32 = ctx.length[0]
      ctx.length[0] += uint32(inputLen)
      if ctx.length[0] < oldLength:
        ctx.length[1] += 1

    let left: int = 64 - index
    var position: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      md5Transform(ctx.state, ctx.buffer.toSliceArray(0, 63))
      position = left
      index = 0

      while position + 64 <= inputLen:
        md5Transform(ctx.state, input.toSliceArray(position, position + 63, 64))
        position += 64

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

template md5FinalC(ctx: var MD5Ctx): array[16, uint8] =
  # delcare output
  var output: array[16, uint8]

  # set idnex
  var index: int = ctx.index

  # add padding
  ctx.buffer[index] = 0x80'u8
  index.inc

  # set padLen
  let padLen = if index <= 56: 56 - index else: 64 - index

  # if index is smaller then 56
  if index <= 56:
    # zerofill until 56
    zeroMem(addr ctx.buffer[index], padLen)
  else:
    if padLen > 0:
      # zerofill until 64
      zeroMem(addr ctx.buffer[index], padLen)
    # call md5 transform template
    md5Transform(ctx.state, ctx.buffer.toSliceArray(0, 63))
    # zerofill until 56
    zeroMem(addr ctx.buffer[0], 56)

  # mulitple 8(bit) to ctx.length and copy to ctx.buffer
  when Bits == 64:
    ctx.length = ctx.length shl 3
    toBytesLE(ctx.length, ctx.buffer.toSliceArray(56, 63))
  elif Bits == 32:
    ctx.length[1] = (ctx.length[1] shl 3) or (ctx.length[0] shr 29)
    ctx.length[0] = ctx.length[0] shl 3
    encodeLE(ctx.length.toSliceArray(0, 1), ctx.buffer.toSliceArray(56, 63))

  # call md5 transform template
  md5Transform(ctx.state, ctx.buffer.toSliceArray(0, 63))

  # encode ctx.state to output by little endian
  encodeLE(ctx.state, output)

  # return
  output

# export wrappers
when defined(templateOpt):
  template md5Init*(ctx: var MD5Ctx): void = md5InitC(ctx)
  template md5Input*(ctx: var MD5Ctx, input: openArray[uint8]): void = md5InputC(ctx, input)
  template md5Final*(ctx: var MD5Ctx): array[16, uint8] = md5FinalC(ctx)
  template md5One*(input: openArray[uint8]): array[16, uint8] = md5OneC(input)

  when Native:
    template md5Init*(ctx: ptr MD5Ctx): void = md5InitC(ctx[])
    template md5Input*(ctx: ptr MD5Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = md5InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template md5Final*(ctx: ptr MD5Ctx, output: ptr array[16, uint8]): void = output[] = md5FinalC(ctx[])
    template md5One*(output: ptr array[16, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void = output[] = md5OneC(input.toOpenArray(0, inputLen - 1))
else:
  when Native:
    proc md5Init*(ctx: var MD5Ctx): void = md5InitC(ctx)
    proc md5Input*(ctx: var MD5Ctx, input: openArray[uint8]): void = md5InputC(ctx, input)
    proc md5Final*(ctx: var MD5Ctx): array[16, uint8] = md5FinalC(ctx)
    proc md5One*(input: openArray[uint8]): array[16, uint8] = md5OneC(input)

  when defined(c) or defined(objc):
    proc md5Init*(ctx: ptr MD5Ctx): void {.exportc: "md5Init".} = md5InitC(ctx[])
    proc md5Input*(ctx: ptr MD5Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "md5Input".} = md5InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc md5Final*(ctx: ptr MD5Ctx, output: ptr array[16, uint8]): void {.exportc: "md5Final".} = output[] = md5FinalC(ctx[])
    proc md5One*(output: ptr array[16, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "md5One".} = output[] = md5OneC(input.toOpenArray(0, inputLen - 1))
  elif defined(cpp):
    proc md5Init*(ctx: ptr MD5Ctx): void {.exportcpp: "md5Init".} = md5InitC(ctx[])
    proc md5Input*(ctx: ptr MD5Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "md5Input".} = md5InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc md5Final*(ctx: ptr MD5Ctx, output: ptr array[16, uint8]): void {.exportcpp: "md5Final".} = output[] = md5FinalC(ctx[])
    proc md5One*(output: ptr array[16, uint8], input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "md5One".} = output[] = md5OneC(input.toOpenArray(0, inputLen - 1))
