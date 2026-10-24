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
  Blake256Sigma: array[16, array[16, uint8]] = [
    [0'u8, 1'u8, 2'u8, 3'u8, 4'u8, 5'u8, 6'u8, 7'u8, 8'u8, 9'u8, 10'u8, 11'u8, 12'u8, 13'u8, 14'u8, 15'u8],
    [14'u8, 10'u8, 4'u8, 8'u8, 9'u8, 15'u8, 13'u8, 6'u8, 1'u8, 12'u8, 0'u8, 2'u8, 11'u8, 7'u8, 5'u8, 3'u8],
    [11'u8, 8'u8, 12'u8, 0'u8, 5'u8, 2'u8, 15'u8, 13'u8, 10'u8, 14'u8, 3'u8, 6'u8, 7'u8, 1'u8, 9'u8, 4'u8],
    [7'u8, 9'u8, 3'u8, 1'u8, 13'u8, 12'u8, 11'u8, 14'u8, 2'u8, 6'u8, 5'u8, 10'u8, 4'u8, 0'u8, 15'u8, 8'u8],
    [9'u8, 0'u8, 5'u8, 7'u8, 2'u8, 4'u8, 10'u8, 15'u8, 14'u8, 1'u8, 11'u8, 12'u8, 6'u8, 8'u8, 3'u8, 13'u8],
    [2'u8, 12'u8, 6'u8, 10'u8, 0'u8, 11'u8, 8'u8, 3'u8, 4'u8, 13'u8, 7'u8, 5'u8, 15'u8, 14'u8, 1'u8, 9'u8],
    [12'u8, 5'u8, 1'u8, 15'u8, 14'u8, 13'u8, 4'u8, 10'u8, 0'u8, 7'u8, 6'u8, 3'u8, 9'u8, 2'u8, 8'u8, 11'u8],
    [13'u8, 11'u8, 7'u8, 14'u8, 12'u8, 1'u8, 3'u8, 9'u8, 5'u8, 0'u8, 15'u8, 4'u8, 8'u8, 6'u8, 2'u8, 10'u8],
    [6'u8, 15'u8, 14'u8, 9'u8, 11'u8, 3'u8, 0'u8, 8'u8, 12'u8, 2'u8, 13'u8, 7'u8, 1'u8, 4'u8, 10'u8, 5'u8],
    [10'u8, 2'u8, 8'u8, 4'u8, 7'u8, 6'u8, 1'u8, 5'u8, 15'u8, 11'u8, 9'u8, 14'u8, 3'u8, 12'u8, 13'u8, 0'u8],
    [0'u8, 1'u8, 2'u8, 3'u8, 4'u8, 5'u8, 6'u8, 7'u8, 8'u8, 9'u8, 10'u8, 11'u8, 12'u8, 13'u8, 14'u8, 15'u8],
    [14'u8, 10'u8, 4'u8, 8'u8, 9'u8, 15'u8, 13'u8, 6'u8, 1'u8, 12'u8, 0'u8, 2'u8, 11'u8, 7'u8, 5'u8, 3'u8],
    [11'u8, 8'u8, 12'u8, 0'u8, 5'u8, 2'u8, 15'u8, 13'u8, 10'u8, 14'u8, 3'u8, 6'u8, 7'u8, 1'u8, 9'u8, 4'u8],
    [7'u8, 9'u8, 3'u8, 1'u8, 13'u8, 12'u8, 11'u8, 14'u8, 2'u8, 6'u8, 5'u8, 10'u8, 4'u8, 0'u8, 15'u8, 8'u8],
    [9'u8, 0'u8, 5'u8, 7'u8, 2'u8, 4'u8, 10'u8, 15'u8, 14'u8, 1'u8, 11'u8, 12'u8, 6'u8, 8'u8, 3'u8, 13'u8],
    [2'u8, 12'u8, 6'u8, 10'u8, 0'u8, 11'u8, 8'u8, 3'u8, 4'u8, 13'u8, 7'u8, 5'u8, 15'u8, 14'u8, 1'u8, 9'u8]
  ]

  Blake256U: array[16, uint32] = [
    0x243f6a88'u32, 0x85a308d3'u32, 0x13198a2e'u32, 0x03707344'u32,
    0xa4093822'u32, 0x299f31d0'u32, 0x082efa98'u32, 0xec4e6c89'u32,
    0x452821e6'u32, 0x38d01377'u32, 0xbe5466cf'u32, 0x34e90c6c'u32,
    0xc0ac29b7'u32, 0xc97c50dd'u32, 0x3f84d5b5'u32, 0xb5470917'u32
  ]

  Blake256IV: array[8, uint32] = [
    0x6A09E667'u32, 0xBB67AE85'u32, 0x3C6EF372'u32, 0xA54FF53A'u32,
    0x510E527F'u32, 0x9B05688C'u32, 0x1F83D9AB'u32, 0x5BE0CD19'u32
  ]

  Blake224Iv: array[8, uint32] = [
    0xC1059ED8'u32, 0x367CD507'u32, 0x3070DD17'u32, 0xF70E5939'u32,
    0xFFC00B31'u32, 0x68581511'u32, 0x64F98FA7'u32, 0xBEFA4FA4'u32
  ]
  Salt256: array[16, uint8] = [
    0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
    0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
  ]

type
  Blake256Ctx*[hashSize: static int, blockSize: static int] = object
    salt*: array[4, uint32]
    buffer*: array[blockSize, uint8]
    index*: int
    length*: uint64
    state*: array[8, uint32]
    nullt*: bool

template blake256G(v: var array[16, uint32], m: array[16, uint32], index: int, a, b, c, d, e: int) =
  let s0: int = int(Blake256Sigma[index][e + 0])
  let s1: int = int(Blake256Sigma[index][e + 1])
  v[a] = v[a] + (m[s0] xor Blake256U[s1]) + v[b]
  v[d] = rotateRightBits(v[d] xor v[a], 16)
  v[c] = v[c] + v[d]
  v[b] = rotateRightBits(v[b] xor v[c], 12)
  v[a] = v[a] + (m[s1] xor Blake256U[s0]) + v[b]
  v[d] = rotateRightBits(v[d] xor v[a], 8)
  v[c] = v[c] + v[d]
  v[b] = rotateRightBits(v[b] xor v[c], 7)

template blake256Transform[K, B: static int](ctx: var Blake256Ctx[K, B], chunk: slicearray[64, uint8]) =
  var vector: array[16, uint32]
  var message: array[16, uint32]

  decodeLE(chunk, message.toSliceArray(0, 15))

  copyMem(addr vector[0], addr state[0], 32)

  v[8] = ctx.salt[0] xor blake256U[0]
  v[9] = ctx.salt[1] xor blake256U[1]
  v[10] = ctx.salt[2] xor blake256U[2]
  v[11] = ctx.salt[3] xor blake256U[3]
  v[12] = blake256U[4]
  v[13] = blake256U[5]
  v[14] = blake256U[6]
  v[15] = blake256U[7]

  if not ctx.nullt:
    vector[12] = vector[12] xor uint32(ctx.length)
    vector[13] = vector[13] xor uint32(ctx.length)
    vector[14] = vector[14] xor uint32(ctx.length shr 32)
    vector[15] = vector[15] xor uint32(ctx.length shr 32)

  for i in static(0 ..< 14):
    blake256G(vector, message, i, 0, 4, 8, 12, 0)
    blake256G(vector, message, i, 1, 5, 9, 13, 2)
    blake256G(vector, message, i, 2, 6, 10, 14, 4)
    blake256G(vector, message, i, 3, 7, 11, 15, 6)
    blake256G(vector, message, i, 0, 5, 10, 15, 8)
    blake256G(vector, message, i, 1, 6, 11, 12, 10)
    blake256G(vector, message, i, 2, 7, 8, 13, 12)
    blake256G(vector, message, i, 3, 4, 9, 14, 14)

  for i in static(0 ..< 16):
    ctx.state[i mod 8] = ctx.state[i mod 8] xor vector[i]

  for i in static(0 ..< 8):
    ctx.state[i] = ctx.state[i] xor ctx.salt[i mod 4]

template blake256InitC[K, B: static int](ctx: var Blake256Ctx[K, B], saltInput: array[16, uint8] = Salt256): void =
  zeroMem(addr ctx.buffer, B)
  ctx.index = 0
  ctx.length = 0'u64
  ctx.nullt = false
  decodeBE(saltInput, ctx.salt)

  when K == 28:
    ctx.state = Blake224IV
  elif K == 32:
    ctx.state = Blake256IV

template blake256InputC[K, B: static int](ctx: var Blake256Ctx[K, B], input: openArray[uint8]): void =
  var check: bool = true
  let inputLen: int = input.len

  if inputLen <= 0: check = false

  if check:
    var index: int = ctx.index

    let left: int = 64 - index
    var position: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[position], left)
      ctx.length += 512'u64
      blake256Transform(ctx, ctx.buffer.toSliceArray(0, 63))
      position = left
      index = 0

      while position + 64 <= inputLen:
        ctx.length += 512'u64
        blake256Transform(ctx, ctx.buffer.toSliceArray(0, 63))
        position += 64

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

template blake256FinalC[K, B: static int](ctx: var Blake256Ctx[K, B]): array[K, uint8] =
  var index: int = ctx.index
  ctx.length += uint64(ctx.index) shl 3

  when K == 28:
    ctx.buffer[index] = 0x80'u8
  elif K == 32:
    ctx.buffer[index] = 0x81'u8

  index.inc

  let padLen: int = if index <= 55: 55 - index else: 64 - index

  if index <= 55:
    zeroMem(addr ctx.buffer[index], padLen)
    ctx.buffer[55] = when K == 28: 0x00'u8 else: 0x01'u8
  else:
    zeroMem(addr ctx.buffer[index], padLen)
    blake256Transform(ctx, ctx.buffer.toSliceArray(0, 63))
    zeroMem(addr ctx.buffer[0], 55)
    ctx.buffer[55] = when K == 28: 0x00'u8 else: 0x01'u8
    ctx.nullt = true

  toBytesBE(ctx.length, ctx.buffer.toSliceArray(56, 63))

  blake256Transform(ctx, ctx.buffer.toSliceArray(0, 63))

  var output: array[K, uint8]
  decodeLE(ctx.state.toSliceArray(0, K div 4 - 1), output.toSliceArray(0, K - 1))

  output


type
  Blake512Ctx*[hashSize: static int, blockSize: static int] = object
    salt*: array[4, uint64]
    buffer*: array[blockSize, uint8]
    index*: int
    length*: uint64
    state*: array[8, uint64]
    counter*: array[2, uint64]

const
  Blake512Sigma: array[16, array[16, uint8]] = [
    [0'u8, 1'u8, 2'u8, 3'u8, 4'u8, 5'u8, 6'u8, 7'u8, 8'u8, 9'u8, 10'u8, 11'u8, 12'u8, 13'u8, 14'u8, 15'u8],
    [14'u8, 10'u8, 4'u8, 8'u8, 9'u8, 15'u8, 13'u8, 6'u8, 1'u8, 12'u8, 0'u8, 2'u8, 11'u8, 7'u8, 5'u8, 3'u8],
    [11'u8, 8'u8, 12'u8, 0'u8, 5'u8, 2'u8, 15'u8, 13'u8, 10'u8, 14'u8, 3'u8, 6'u8, 7'u8, 1'u8, 9'u8, 4'u8],
    [7'u8, 9'u8, 3'u8, 1'u8, 13'u8, 12'u8, 11'u8, 14'u8, 2'u8, 6'u8, 5'u8, 10'u8, 4'u8, 0'u8, 15'u8, 8'u8],
    [9'u8, 0'u8, 5'u8, 7'u8, 2'u8, 4'u8, 10'u8, 15'u8, 14'u8, 1'u8, 11'u8, 12'u8, 6'u8, 8'u8, 3'u8, 13'u8],
    [2'u8, 12'u8, 6'u8, 10'u8, 0'u8, 11'u8, 8'u8, 3'u8, 4'u8, 13'u8, 7'u8, 5'u8, 15'u8, 14'u8, 1'u8, 9'u8],
    [12'u8, 5'u8, 1'u8, 15'u8, 14'u8, 13'u8, 4'u8, 10'u8, 0'u8, 7'u8, 6'u8, 3'u8, 9'u8, 2'u8, 8'u8, 11'u8],
    [13'u8, 11'u8, 7'u8, 14'u8, 12'u8, 1'u8, 3'u8, 9'u8, 5'u8, 0'u8, 15'u8, 4'u8, 8'u8, 6'u8, 2'u8, 10'u8],
    [6'u8, 15'u8, 14'u8, 9'u8, 11'u8, 3'u8, 0'u8, 8'u8, 12'u8, 2'u8, 13'u8, 7'u8, 1'u8, 4'u8, 10'u8, 5'u8],
    [10'u8, 2'u8, 8'u8, 4'u8, 7'u8, 6'u8, 1'u8, 5'u8, 15'u8, 11'u8, 9'u8, 14'u8, 3'u8, 12'u8, 13'u8, 0'u8],
    [0'u8, 1'u8, 2'u8, 3'u8, 4'u8, 5'u8, 6'u8, 7'u8, 8'u8, 9'u8, 10'u8, 11'u8, 12'u8, 13'u8, 14'u8, 15'u8],
    [14'u8, 10'u8, 4'u8, 8'u8, 9'u8, 15'u8, 13'u8, 6'u8, 1'u8, 12'u8, 0'u8, 2'u8, 11'u8, 7'u8, 5'u8, 3'u8],
    [11'u8, 8'u8, 12'u8, 0'u8, 5'u8, 2'u8, 15'u8, 13'u8, 10'u8, 14'u8, 3'u8, 6'u8, 7'u8, 1'u8, 9'u8, 4'u8],
    [7'u8, 9'u8, 3'u8, 1'u8, 13'u8, 12'u8, 11'u8, 14'u8, 2'u8, 6'u8, 5'u8, 10'u8, 4'u8, 0'u8, 15'u8, 8'u8],
    [9'u8, 0'u8, 5'u8, 7'u8, 2'u8, 4'u8, 10'u8, 15'u8, 14'u8, 1'u8, 11'u8, 12'u8, 6'u8, 8'u8, 3'u8, 13'u8],
    [2'u8, 12'u8, 6'u8, 10'u8, 0'u8, 11'u8, 8'u8, 3'u8, 4'u8, 13'u8, 7'u8, 5'u8, 15'u8, 14'u8, 1'u8, 9'u8]
  ]

  Blake512U: array[16, uint64] = [
    0x243F6A8885A308D3'u64, 0x13198A2E03707344'u64,
    0xA4093822299F31D0'u64, 0x082EFA98EC4E6C89'u64,
    0x452821E638D01377'u64, 0xBE5466CF34E90C6C'u64,
    0xC0AC29B7C97C50DD'u64, 0x3F84D5B5B5470917'u64,
    0x9216D5D98979FB1B'u64, 0xD1310BA698DFB5AC'u64,
    0x2FFD72DBD01ADFB7'u64, 0xB8E1AFED6A267E96'u64,
    0xBA7C9045F12C7F99'u64, 0x24A19947B3916CF7'u64,
    0x0801F2E2858EFC16'u64, 0x636920D871574E69'u64]

  Blake512IV: array[8, uint64] = [
    0x6A09E667F3BCC908'u64, 0xBB67AE8584CAA73B'u64,
    0x3C6EF372FE94F82B'u64, 0xA54FF53A5F1D36F1'u64,
    0x510E527FADE682D1'u64, 0x9B05688C2B3E6C1F'u64,
    0x1F83D9ABFB41BD6B'u64, 0x5BE0CD19137E2179'u64]

  Blake384IV: array[8, uint64] = [
    0xCBBB9D5DC1059ED8'u64, 0x629A292A367CD507'u64,
    0x9159015A3070DD17'u64, 0x152FECD8F70E5939'u64,
    0x67332667FFC00B31'u64, 0x8EB44A8768581511'u64,
    0xDB0C2E0D64F98FA7'u64, 0x47B5481DBEFA4FA4'u64]

  Salt512: array[32, uint8] = [
    0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
    0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
    0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
    0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
  ]

template blake512Load64Be(data: openArray[uint8], offset: int): uint64 =
  (uint64(data[offset]) shl 56) or
    (uint64(data[offset + 1]) shl 48) or
    (uint64(data[offset + 2]) shl 40) or
    (uint64(data[offset + 3]) shl 32) or
    (uint64(data[offset + 4]) shl 24) or
    (uint64(data[offset + 5]) shl 16) or
    (uint64(data[offset + 6]) shl 8) or
    uint64(data[offset + 7])

template blake512Store64Be(dst: var openArray[uint8], offset: int,
    value: uint64) =
  dst[offset] = uint8((value shr 56) and 0xff'u64)
  dst[offset + 1] = uint8((value shr 48) and 0xff'u64)
  dst[offset + 2] = uint8((value shr 40) and 0xff'u64)
  dst[offset + 3] = uint8((value shr 32) and 0xff'u64)
  dst[offset + 4] = uint8((value shr 24) and 0xff'u64)
  dst[offset + 5] = uint8((value shr 16) and 0xff'u64)
  dst[offset + 6] = uint8((value shr 8) and 0xff'u64)
  dst[offset + 7] = uint8(value and 0xff'u64)

template blake512G(vector: var array[16, uint64], message: array[16, uint64], index: int, a, b, c, d, e: static int) =
  let s0: int = int(Blake512Sigma[index][e])
  let s1: int = int(Blake512Sigma[index][e + 1])
  vector[a] = vector[a] + vector[b] + (message[s0] xor Blake512U[s1])
  vector[d] = roateRightBits(vector[d] xor vector[a], 32)
  vector[c] = vector[c] + vector[d]
  vector[b] = roateRightBits(vector[b] xor vector[c], 25)
  vector[a] = vector[a] + vector[b] + (message[s1] xor Blake512U[s0])
  vector[d] = roateRightBits(vector[d] xor vector[a], 16)
  vector[c] = vector[c] + vector[d]
  vector[b] = roateRightBits(vector[b] xor vector[c], 11)

template blake512Transform[K, B: static int](ctx: var Blake512Ctx[K, B], chunk: slicearray[128, uint8]): void =
  var vector: array[16, uint64]
  var message: array[16, uint64]

  decodeBE(chunk, message.toSliceArray(0, 7))

  copyMem(addr vector[0], addr ctx.state[0], 64)

  const zero: uint64 = 0'u64

  vector[8] = ctx.salt[0] xor Blake512U[0]
  vector[9] = ctx.salt[1] xor Blake512U[1]
  vector[10] = ctx.salt[2] xor Blake512U[2]
  vector[11] = ctx.salt[3] xor Blake512U[3]
  vector[12] = ctx.length xor Blake512U[4]
  vector[13] = ctx.length xor Blake512U[5]
  vector[14] = zero xor Blake512U[6]
  vector[15] = zero xor Blake512U[7]

  for r in static(0 ..< 16):
    blake512G(vector, message, r, 0, 4, 8, 12, 0)
    blake512G(vector, message, r, 1, 5, 9, 13, 2)
    blake512G(vector, message, r, 2, 6, 10, 14, 4)
    blake512G(vector, message, r, 3, 7, 11, 15, 6)
    blake512G(vector, message, r, 0, 5, 10, 15, 8)
    blake512G(vector, message, r, 1, 6, 11, 12, 10)
    blake512G(vector, message, r, 2, 7, 8, 13, 12)
    blake512G(vector, message, r, 3, 4, 9, 14, 14)

  for i in 0 ..< 8:
    ctx.state[i] = ctx.state[i] xor ctx.salt[i mod 4] xor vector[i] xor vector[i + 8]

template blake512InitC[K, B: static int](ctx: var Blake512Ctx[K, B], salt: array[32, uint8] = Salt512): void =
  decodeBE(salt, ctx.salt)
  zeroMem(addr ctx.buffer, B)
  ctx.index = 0
  ctx.length = 0'u64
  when K == 48:
    ctx.state = Blake384IV
  elif K == 64:
    ctx.state = Blake512IV
  ctx.counter = default(array[2, uint64])

template blake512InputC[K, B: static int](ctx: var Blake512Ctx[K, B], input: openArray[uint8]): void =
  var check: bool = true
  let inputLen: int = input.len

  if inputLen <= 0: check = false

  if check:
    var index: int = ctx.index
    let left: int = B - index
    var position: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      ctx.length += B shl 3
      blake512Transform(ctx.state, ctx.buffer.toSliceArray(0, B - 1))
      position = left
      index = 0

      while position + B <= inputLen:
        ctx.length += B shl 3
        blake512Transform(ctx.state, ctx.buffer.toSliceArray(position, position + B - 1, B))
        position += B

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

template blake512FinalC[K, B: static int](ctx: var Blake512Ctx[K, B]): array[K, uint8] =
  var d = ctx
  let used = d.bufferIndex
  let bitLen = uint64(used) shl 3
  let th = d.counter[1]
  let tl = d.counter[0] + bitLen
  var tmpBuf: array[128, uint8]

  tmpBuf[used] = 0x80'u8
  if used == 0:
    d.counter[0] = 0xFFFFFFFFFFFFFC00'u64
    d.counter[1] = 0xFFFFFFFFFFFFFFFF'u64
  elif d.counter[0] == 0'u64:
    d.counter[0] = 0xFFFFFFFFFFFFFC00'u64 + bitLen
    d.counter[1] = d.counter[1] - 1'u64
  else:
    d.counter[0] = d.counter[0] - (1024'u64 - bitLen)

  if used < 112:
    if K == 64:
      tmpBuf[111] = tmpBuf[111] or 0x01'u8
    blake512Store64Be(tmpBuf, 112, th)
    blake512Store64Be(tmpBuf, 120, tl)
    blake512InputImpl(d, tmpBuf.toOpenArray(used, 127))
  else:
    blake512InputImpl(d, tmpBuf.toOpenArray(used, 127))

    d.counter[0] = 0xFFFFFFFFFFFFFC00'u64
    d.counter[1] = 0xFFFFFFFFFFFFFFFF'u64
    tmpBuf = default(array[128, uint8])
    if K == 64:
      tmpBuf[111] = 0x01'u8
    blake512Store64Be(tmpBuf, 112, th)
    blake512Store64Be(tmpBuf, 120, tl)
    blake512InputImpl(d, tmpBuf)

  for i in 0 ..< (K div 8):
    blake512Store64Be(result, i * 8, d.state[i])
