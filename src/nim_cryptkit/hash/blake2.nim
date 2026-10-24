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
  # declare blake2b generic context
  Blake2bCtx*[bits: static int] = object
    buffer*: array[128, uint8]
    state*: array[8, uint64]
    length*: array[2, uint64]
    index*: int

  # declare blake2s generic context
  Blake2sCtx*[bits: static int] = object
    buffer*: array[64, uint8]
    state*: array[8, uint32]
    length*: array[2, uint32]
    index*: int

  # declare blake2 context type
  Blake2Ctx* = Blake2sCtx | Blake2bCtx

  # declare blake2s 128/160/224/256 context
  Blake2s_128Ctx* = Blake2sCtx[128]
  Blake2s_160Ctx* = Blake2sCtx[160]
  Blake2s_224Ctx* = Blake2sCtx[224]
  Blake2s_256Ctx* = Blake2sCtx[256]

  # declare blake2b 128/160/224/256/384/512 context
  Blake2b_128Ctx* = Blake2bCtx[128]
  Blake2b_160Ctx* = Blake2bCtx[160]
  Blake2b_224Ctx* = Blake2bCtx[224]
  Blake2b_256Ctx* = Blake2bCtx[256]
  Blake2b_384Ctx* = Blake2bCtx[384]
  Blake2b_512Ctx* = Blake2bCtx[512]

# calculate hash size
template hashSize*(ctx: Blake2Ctx): int =
  (ctx.bits div 8)

# calculate block size
template blockSize*(ctx: Blake2Ctx): int =
  when ctx is Blake2sCtx:
    64
  else:
    128

const
  # blake2b initialise vector
  B2BIV = [
    0x6A09E667F3BCC908'u64, 0xBB67AE8584CAA73B'u64,
    0x3C6EF372FE94F82B'u64, 0xA54FF53A5F1D36F1'u64,
    0x510E527FADE682D1'u64, 0x9B05688C2B3E6C1F'u64,
    0x1F83D9ABFB41BD6B'u64, 0x5BE0CD19137E2179'u64
  ]

  # blake2s initialise vector
  B2SIV = [
    0x6A09E667'u32, 0xBB67AE85'u32, 0x3C6EF372'u32, 0xA54FF53A'u32,
    0x510E527F'u32, 0x9B05688C'u32, 0x1F83D9AB'u32, 0x5BE0CD19'u32
  ]

# blake2b mix g template
template blake2bMixG(vector: var array[16, uint64], a, b, c, d: static int, x, y: uint64): void {.autoSizeOpt.} =
  vector[a] = vector[a] + vector[b] + x
  vector[d] = rotateRightBits(vector[d] xor vector[a], 32)
  vector[c] = vector[c] + vector[d]
  vector[b] = rotateRightBits(vector[b] xor vector[c], 24)
  vector[a] = vector[a] + vector[b] + y
  vector[d] = rotateRightBits(vector[d] xor vector[a], 16)
  vector[c] = vector[c] + vector[d]
  vector[b] = rotateRightBits(vector[b] xor vector[c], 63)

# blake2s mix g template
template blake2sMixG(vector: var array[16, uint32], a, b, c, d: static int, x, y: uint32): void {.autoSizeOpt.} =
  vector[a] = vector[a] + vector[b] + x
  vector[d] = rotateRightBits(vector[d] xor vector[a], 16)
  vector[c] = vector[c] + vector[d]
  vector[b] = rotateRightBits(vector[b] xor vector[c], 12)
  vector[a] = vector[a] + vector[b] + y
  vector[d] = rotateRightBits(vector[d] xor vector[a], 8)
  vector[c] = vector[c] + vector[d]
  vector[b] = rotateRightBits(vector[b] xor vector[c], 7)

# blake2b rounds
template blake2bRounds(vector: var array[16, uint64], chunk: array[16, uint64]): void {.autoSizeOpt.} =
  # round 0
  blake2bMixG(vector, 0, 4,  8, 12, chunk[ 0], chunk[ 1])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 2], chunk[ 3])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[ 4], chunk[ 5])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[ 6], chunk[ 7])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[ 8], chunk[ 9])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[10], chunk[11])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[12], chunk[13])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[14], chunk[15])

  # round 1
  blake2bMixG(vector, 0, 4,  8, 12, chunk[14], chunk[10])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 4], chunk[ 8])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[ 9], chunk[15])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[13], chunk[ 6])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[ 1], chunk[12])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[ 0], chunk[ 2])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[11], chunk[ 7])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[ 5], chunk[ 3])

  # round 2
  blake2bMixG(vector, 0, 4,  8, 12, chunk[11], chunk[ 8])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[12], chunk[ 0])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[ 5], chunk[ 2])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[15], chunk[13])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[10], chunk[14])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[ 3], chunk[ 6])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[ 7], chunk[ 1])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[ 9], chunk[ 4])

  # round 3
  blake2bMixG(vector, 0, 4,  8, 12, chunk[ 7], chunk[ 9])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 3], chunk[ 1])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[13], chunk[12])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[11], chunk[14])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[ 2], chunk[ 6])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[ 5], chunk[10])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[ 4], chunk[ 0])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[15], chunk[ 8])

  # round 4
  blake2bMixG(vector, 0, 4,  8, 12, chunk[ 9], chunk[ 0])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 5], chunk[ 7])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[ 2], chunk[ 4])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[10], chunk[15])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[14], chunk[ 1])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[11], chunk[12])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[ 6], chunk[ 8])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[ 3], chunk[13])

  # round 5
  blake2bMixG(vector, 0, 4,  8, 12, chunk[ 2], chunk[12])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 6], chunk[10])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[ 0], chunk[11])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[ 8], chunk[ 3])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[ 4], chunk[13])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[ 7], chunk[ 5])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[15], chunk[14])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[ 1], chunk[ 9])

  # round 6
  blake2bMixG(vector, 0, 4,  8, 12, chunk[12], chunk[ 5])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 1], chunk[15])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[14], chunk[13])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[ 4], chunk[10])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[ 0], chunk[ 7])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[ 6], chunk[ 3])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[ 9], chunk[ 2])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[ 8], chunk[11])

  # round 7
  blake2bMixG(vector, 0, 4,  8, 12, chunk[13], chunk[11])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 7], chunk[14])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[12], chunk[ 1])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[ 3], chunk[ 9])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[ 5], chunk[ 0])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[15], chunk[ 4])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[ 8], chunk[ 6])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[ 2], chunk[10])

  # round 8
  blake2bMixG(vector, 0, 4,  8, 12, chunk[ 6], chunk[15])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[14], chunk[ 9])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[11], chunk[ 3])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[ 0], chunk[ 8])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[12], chunk[ 2])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[13], chunk[ 7])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[ 1], chunk[ 4])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[10], chunk[ 5])

  # round 9
  blake2bMixG(vector, 0, 4,  8, 12, chunk[10], chunk[ 2])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 8], chunk[ 4])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[ 7], chunk[ 6])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[ 1], chunk[ 5])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[15], chunk[11])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[ 9], chunk[14])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[ 3], chunk[12])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[13], chunk[ 0])

  # round 10
  blake2bMixG(vector, 0, 4,  8, 12, chunk[ 0], chunk[ 1])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 2], chunk[ 3])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[ 4], chunk[ 5])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[ 6], chunk[ 7])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[ 8], chunk[ 9])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[10], chunk[11])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[12], chunk[13])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[14], chunk[15])

  # round 11
  blake2bMixG(vector, 0, 4,  8, 12, chunk[14], chunk[10])
  blake2bMixG(vector, 1, 5,  9, 13, chunk[ 4], chunk[ 8])
  blake2bMixG(vector, 2, 6, 10, 14, chunk[ 9], chunk[15])
  blake2bMixG(vector, 3, 7, 11, 15, chunk[13], chunk[ 6])
  blake2bMixG(vector, 0, 5, 10, 15, chunk[ 1], chunk[12])
  blake2bMixG(vector, 1, 6, 11, 12, chunk[ 0], chunk[ 2])
  blake2bMixG(vector, 2, 7,  8, 13, chunk[11], chunk[ 7])
  blake2bMixG(vector, 3, 4,  9, 14, chunk[ 5], chunk[ 3])

# blake2s rounds
template blake2sRounds(vector: var array[16, uint32], chunk: array[16, uint32]): void {.autoSizeOpt.} =
  # round 0
  blake2sMixG(vector, 0, 4,  8, 12, chunk[ 0], chunk[ 1])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[ 2], chunk[ 3])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[ 4], chunk[ 5])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[ 6], chunk[ 7])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[ 8], chunk[ 9])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[10], chunk[11])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[12], chunk[13])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[14], chunk[15])

  # round 1
  blake2sMixG(vector, 0, 4,  8, 12, chunk[14], chunk[10])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[ 4], chunk[ 8])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[ 9], chunk[15])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[13], chunk[ 6])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[ 1], chunk[12])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[ 0], chunk[ 2])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[11], chunk[ 7])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[ 5], chunk[ 3])

  # round 2
  blake2sMixG(vector, 0, 4,  8, 12, chunk[11], chunk[ 8])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[12], chunk[ 0])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[ 5], chunk[ 2])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[15], chunk[13])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[10], chunk[14])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[ 3], chunk[ 6])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[ 7], chunk[ 1])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[ 9], chunk[ 4])

  # round 3
  blake2sMixG(vector, 0, 4,  8, 12, chunk[ 7], chunk[ 9])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[ 3], chunk[ 1])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[13], chunk[12])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[11], chunk[14])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[ 2], chunk[ 6])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[ 5], chunk[10])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[ 4], chunk[ 0])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[15], chunk[ 8])

  # round 4
  blake2sMixG(vector, 0, 4,  8, 12, chunk[ 9], chunk[ 0])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[ 5], chunk[ 7])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[ 2], chunk[ 4])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[10], chunk[15])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[14], chunk[ 1])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[11], chunk[12])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[ 6], chunk[ 8])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[ 3], chunk[13])

  # round 5
  blake2sMixG(vector, 0, 4,  8, 12, chunk[ 2], chunk[12])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[ 6], chunk[10])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[ 0], chunk[11])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[ 8], chunk[ 3])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[ 4], chunk[13])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[ 7], chunk[ 5])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[15], chunk[14])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[ 1], chunk[ 9])

  # round 6
  blake2sMixG(vector, 0, 4,  8, 12, chunk[12], chunk[ 5])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[ 1], chunk[15])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[14], chunk[13])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[ 4], chunk[10])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[ 0], chunk[ 7])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[ 6], chunk[ 3])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[ 9], chunk[ 2])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[ 8], chunk[11])

  # round 7
  blake2sMixG(vector, 0, 4,  8, 12, chunk[13], chunk[11])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[ 7], chunk[14])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[12], chunk[ 1])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[ 3], chunk[ 9])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[ 5], chunk[ 0])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[15], chunk[ 4])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[ 8], chunk[ 6])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[ 2], chunk[10])

  # round 8
  blake2sMixG(vector, 0, 4,  8, 12, chunk[ 6], chunk[15])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[14], chunk[ 9])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[11], chunk[ 3])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[ 0], chunk[ 8])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[12], chunk[ 2])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[13], chunk[ 7])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[ 1], chunk[ 4])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[10], chunk[ 5])

  # round 9
  blake2sMixG(vector, 0, 4,  8, 12, chunk[10], chunk[ 2])
  blake2sMixG(vector, 1, 5,  9, 13, chunk[ 8], chunk[ 4])
  blake2sMixG(vector, 2, 6, 10, 14, chunk[ 7], chunk[ 6])
  blake2sMixG(vector, 3, 7, 11, 15, chunk[ 1], chunk[ 5])
  blake2sMixG(vector, 0, 5, 10, 15, chunk[15], chunk[11])
  blake2sMixG(vector, 1, 6, 11, 12, chunk[ 9], chunk[14])
  blake2sMixG(vector, 2, 7,  8, 13, chunk[ 3], chunk[12])
  blake2sMixG(vector, 3, 4,  9, 14, chunk[13], chunk[ 0])

# blake2 trnasform
template blake2Transform(ctx: var Blake2Ctx, final: bool): void {.autoSizeOpt.} =
  # set Word and IV for blake2 context type
  when ctx is Blake2sCtx:
    type Word = uint32
    const IV = B2SIV
  else:
    type Word = uint64
    const IV = B2BIV

  # declare value and message
  var value: array[16, Word]
  var message: array[16, Word]

  # copy ctx.state and IV to value
  copyMem(addr value[0], addr ctx.state[0], 64)
  copyMem(addr value[8], addr IV[0], 64)

  # xor value with length
  value[12] = value[12] xor ctx.length[0]
  value[13] = value[13] xor ctx.length[1]

  # when final
  if final:
    value[14] = not value[14]

  # decode ctx.buffer to message
  decodeLE(ctx.buffer, message, 16)

  # call rounds for each context
  when ctx is Blake2sCtx:
    blake2sRounds(value, message)
  else:
    blake2bRounds(value, message)

  # update ctx.state by xor with value
  unroll(i, 0, 7):
    ctx.state[i] = ctx.state[i] xor (value[i] xor value[i + 8])

# blake2 input core
template blake2InputC*(ctx: var Blake2Ctx, input: openArray[uint8]): void {.autoSizeOpt.} =
  let inputLen = input.len
  if inputLen > 0:
    var index: int = ctx.index
    const maxBlock: int = when ctx is Blake2sCtx: 64 else: 128
    when ctx is Blake2sCtx:
      type LengthWord = uint32
    else:
      type LengthWord = uint64
    var i = 0

    if index > 0:
      let left: int = maxBlock - index
      let fill = min(left, inputLen)

      when nimvm:
        for j in 0 ..< fill: ctx.buffer[index + j] = input[j]
      else:
        copyMem(addr ctx.buffer[index], addr input[0], fill)

      i += fill
      index += fill

      # Keep the last complete block buffered: BLAKE2 must mark it final.
      if index == maxBlock and i < inputLen:
        let oldLen = ctx.length[0]
        ctx.length[0] += LengthWord(maxBlock)
        if ctx.length[0] < oldLen: ctx.length[1] += 1
        ctx.blake2Transform(false)
        index = 0

    while inputLen - i > maxBlock:
      when nimvm:
        for j in 0 ..< maxBlock: ctx.buffer[j] = input[i + j]
      else:
        copyMem(addr ctx.buffer[0], addr input[i], maxBlock)

      let oldLen = ctx.length[0]
      ctx.length[0] += LengthWord(maxBlock)
      if ctx.length[0] < oldLen: ctx.length[1] += 1
      ctx.blake2Transform(false)
      i += maxBlock

    let remain = inputLen - i
    if remain > 0:
      when nimvm:
        for j in 0 ..< remain: ctx.buffer[j] = input[i + j]
      else:
        copyMem(addr ctx.buffer[0], addr input[i], remain)
      index = remain

    ctx.index = index


# blake2 init core
template blake2InitC(ctx: var Blake2Ctx, key: openArray[uint8] = []): void {.autoSizeOpt.} =
  # declare block size, iv, word, paramBlock for each context
  when ctx is Blake2sCtx:
    const MaxBlock = 64
    const IV = B2SIV
    type Word = uint32
    let paramBlock = (Word(0x01010000'u32)) xor
                     (Word(key.len) shl 8) xor
                     (Word(ctx.bits div 8))
  else:
    const MaxBlock = 128
    const IV = B2BIV
    type Word = uint64
    let paramBlock = (Word(0x01010000'u64)) xor
                     (Word(key.len) shl 8) xor
                     (Word(ctx.bits div 8))

  # when nim vm
  when nimvm:
    for i in 0 ..< MaxBlock: ctx.buffer[i] = 0x00'u8
    for i in 0 ..< 8: ctx.state[i] = IV[i]
  else:
    # zerofill ctx.buffer
    zeroMem(addr ctx.buffer[0], MaxBlock)
    # set ctx.state to initialise vector
    ctx.state = IV

  # set index and length to 0
  ctx.length[0] = 0
  ctx.length[1] = 0
  ctx.index = 0

  # xor paramBLock with state[0]
  ctx.state[0] = ctx.state[0] xor paramBlock

  # if key exists, call input
  if key.len > 0:
    blake2InputC(ctx, key)
    ctx.index = MaxBlock
  # copy length/index to temporary length/index

# blake2s final core
template blake2FinalC*[B: static int](ctx: var Blake2sCtx[B]): array[B div 8, uint8] {.autoSizeOpt.} =
  # declare output
  var output: array[ctx.bits div 8, uint8]

  # set final length
  ctx.length[0] = ctx.length[0] + ctx.index.uint32
  if ctx.length[0] < ctx.index.uint32:
    ctx.length[1] = ctx.length[1] + 1'u32

  # pad buffer with 0x00
  if ctx.index < ctx.blockSize:
    when nimvm:
      for i in ctx.index ..< ctx.blockSize: ctx.buffer[i] = 0x00'u8
    else:
      zeroMem(addr ctx.buffer[ctx.index], ctx.blockSize - ctx.index)

  # call blake2Transform with final
  blake2Transform(ctx, true)

  # if cpu endian is little endian -> copy
  when LE:
    copyMem(addr output[0], addr ctx.state[0], ctx.bits div 8)
  # else -> encode state to output by little endian
  else:
    when ctx.bits == 128:
      encodeLE(ctx.state.toSliceArray(0, 3), output.toSliceArray(0, 15))
    elif ctx.bits == 160:
      encdoeLE(ctx.state.toSliceArray(0, 4), output.toSliceArray(0, 19))
    elif ctx.bits == 224:
      encodeLE(ctx.state.toSliceArray(0, 6), output.toSliceArray(0, 27))
    elif ctx.bits == 256:
      encodeLE(ctx.state.toSliceArray(0, 7), output.toSliceArray(0, 31))

  # return output
  output

# blake2b final core
template blake2FinalC*[B: static int](ctx: var Blake2bCtx[B]): array[B div 8, uint8] {.autoSizeOpt.} =
  # declare output
  var output: array[ctx.bits div 8, uint8]

  # set final length
  ctx.length[0] = ctx.length[0] + ctx.index.uint64
  if ctx.length[0] < ctx.index.uint64:
    ctx.length[1] = ctx.length[1] + 1'u64

  # pad buffer with 0x00
  if ctx.index < ctx.blockSize:
    when nimvm:
      for i in ctx.index ..< ctx.blockSize: ctx.buffer[i] = 0x00'u8
    else:
      zeroMem(addr ctx.buffer[ctx.index], ctx.blockSize - ctx.index)

  # call blake2Transform with final
  blake2Transform(ctx, true)

  # when cpu endian is little endian -> copy
  when LE:
    copyMem(addr output[0], addr ctx.state[0], ctx.bits div 8)
  # else -> encode state to output by little endian
  else:
    when ctx.bits == 128:
      encodeLE(ctx.state.toSliceArray(0, 1), output.toSliceArray(0, 15))
    elif ctx.bits == 160:
      var temp: array[24, uint8]
      encodeLE(ctx.state.toSliceArray(0, 2), temp.toSliceArray(0, 23))
      copyMem(addr output[0], addr temp[0], 20)
    elif ctx.bits == 224:
      var temp: array[32, uint8]
      encodeLE(ctx.state.toSliceArray(0, 3), temp.toSliceArray(0, 31))
      copyMem(addr output[0], addr temp[0], 28)
    elif ctx.bits == 256:
      encodeLE(ctx.state.toSliceArray(0, 3), output.toSliceArray(0, 31))
    elif ctx.bits == 384:
      encodeLE(ctx.state.toSliceArray(0, 5), output.toSliceArray(0, 47))
    elif ctx.bits == 512:
      encodeLE(ctx.state.toSliceArray(0, 7), output.toSliceArray(0, 63))

  # return output
  output

# export wrappers
when defined(templateOpt):
  # Blake2s-128
  template blake2s_128Init*(ctx: var Blake2s_128Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2s_128Input*(ctx: var Blake2s_128Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2s_128Final*(ctx: var Blake2s_128Ctx): array[16, uint8] = blake2FinalC(ctx)

  # Blake2s-160
  template blake2s_160Init*(ctx: var Blake2s_160Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2s_160Input*(ctx: var Blake2s_160Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2s_160Final*(ctx: var Blake2s_160Ctx): array[20, uint8] = blake2FinalC(ctx)

  # Blake2s-224
  template blake2s_224Init*(ctx: var Blake2s_224Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2s_224Input*(ctx: var Blake2s_224Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2s_224Final*(ctx: var Blake2s_224Ctx): array[28, uint8] = blake2FinalC(ctx)

  # Blake2s-256
  template blake2s_256Init*(ctx: var Blake2s_256Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2s_256Input*(ctx: var Blake2s_256Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2s_256Final*(ctx: var Blake2s_256Ctx): array[32, uint8] = blake2FinalC(ctx)

  # Blake2b-128
  template blake2b_128Init*(ctx: var Blake2b_128Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2b_128Input*(ctx: var Blake2b_128Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2b_128Final*(ctx: var Blake2b_128Ctx): array[16, uint8] = blake2FinalC(ctx)

  # Blake2b-160
  template blake2b_160Init*(ctx: var Blake2b_160Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2b_160Input*(ctx: var Blake2b_160Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2b_160Final*(ctx: var Blake2b_160Ctx): array[20, uint8] = blake2FinalC(ctx)

  # Blake2b-224
  template blake2b_224Init*(ctx: var Blake2b_224Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2b_224Input*(ctx: var Blake2b_224Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2b_224Final*(ctx: var Blake2b_224Ctx): array[28, uint8] = blake2FinalC(ctx)

  # Blake2b-256
  template blake2b_256Init*(ctx: var Blake2b_256Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2b_256Input*(ctx: var Blake2b_256Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2b_256Final*(ctx: var Blake2b_256Ctx): array[32, uint8] = blake2FinalC(ctx)

  # Blake2b-384
  template blake2b_384Init*(ctx: var Blake2b_384Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2b_384Input*(ctx: var Blake2b_384Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2b_384Final*(ctx: var Blake2b_384Ctx): array[48, uint8] = blake2FinalC(ctx)

  # Blake2b-512
  template blake2b_512Init*(ctx: var Blake2b_512Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
  template blake2b_512Input*(ctx: var Blake2b_512Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
  template blake2b_512Final*(ctx: var Blake2b_512Ctx): array[64, uint8] = blake2FinalC(ctx)

  when Native:
    template blake2s_128Init*(ctx: ptr Blake2s_128Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    template blake2s_128Input*(ctx: ptr Blake2s_128Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template blake2s_128Final*(ctx: ptr Blake2s_128Ctx, output: ptr array[16, uint8]): void = output[] = blake2FinalC(ctx[])

    template blake2s_160Init*(ctx: ptr Blake2s_160Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    template blake2s_160Input*(ctx: ptr Blake2s_160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template blake2s_160Final*(ctx: ptr Blake2s_160Ctx, output: ptr array[20, uint8]): void = output[] = blake2FinalC(ctx[])

    template blake2s_224Init*(ctx: ptr Blake2s_224Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    template blake2s_224Input*(ctx: ptr Blake2s_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template blake2s_224Final*(ctx: ptr Blake2s_224Ctx, output: ptr array[28, uint8]): void = output[] = blake2FinalC(ctx[])

    template blake2s_256Init*(ctx: ptr Blake2s_256Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    template blake2s_256Input*(ctx: ptr Blake2s_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template blake2s_256Final*(ctx: ptr Blake2s_256Ctx, output: ptr array[32, uint8]): void = output[] = blake2FinalC(ctx[])

    template blake2b_128Init*(ctx: ptr Blake2b_128Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    template blake2b_128Input*(ctx: ptr Blake2b_128Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template blake2b_128Final*(ctx: ptr Blake2b_128Ctx, output: ptr array[16, uint8]): void = output[] = blake2FinalC(ctx[])

    template blake2b_160Init*(ctx: ptr Blake2b_160Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    template blake2b_160Input*(ctx: ptr Blake2b_160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template blake2b_160Final*(ctx: ptr Blake2b_160Ctx, output: ptr array[20, uint8]): void = output[] = blake2FinalC(ctx[])

    template blake2b_224Init*(ctx: ptr Blake2b_224Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    template blake2b_224Input*(ctx: ptr Blake2b_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template blake2b_224Final*(ctx: ptr Blake2b_224Ctx, output: ptr array[28, uint8]): void = output[] = blake2FinalC(ctx[])

    template blake2b_256Init*(ctx: ptr Blake2b_256Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    template blake2b_256Input*(ctx: ptr Blake2b_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template blake2b_256Final*(ctx: ptr Blake2b_256Ctx, output: ptr array[32, uint8]): void = output[] = blake2FinalC(ctx[])

    template blake2b_384Init*(ctx: ptr Blake2b_384Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    template blake2b_384Input*(ctx: ptr Blake2b_384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template blake2b_384Final*(ctx: ptr Blake2b_384Ctx, output: ptr array[48, uint8]): void = output[] = blake2FinalC(ctx[])

    template blake2b_512Init*(ctx: ptr Blake2b_512Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    template blake2b_512Input*(ctx: ptr Blake2b_512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template blake2b_512Final*(ctx: ptr Blake2b_512Ctx, output: ptr array[64, uint8]): void = output[] = blake2FinalC(ctx[])

else:
  when Native:
    proc blake2s_128Init*(ctx: var Blake2s_128Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
    proc blake2s_128Input*(ctx: var Blake2s_128Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
    proc blake2s_128Final*(ctx: var Blake2s_128Ctx): array[16, uint8] = blake2FinalC(ctx)

    proc blake2s_160Init*(ctx: var Blake2s_160Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
    proc blake2s_160Input*(ctx: var Blake2s_160Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
    proc blake2s_160Final*(ctx: var Blake2s_160Ctx): array[20, uint8] = blake2FinalC(ctx)

    proc blake2s_224Init*(ctx: var Blake2s_224Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
    proc blake2s_224Input*(ctx: var Blake2s_224Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
    proc blake2s_224Final*(ctx: var Blake2s_224Ctx): array[28, uint8] = blake2FinalC(ctx)

    proc blake2s_256Init*(ctx: var Blake2s_256Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
    proc blake2s_256Input*(ctx: var Blake2s_256Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
    proc blake2s_256Final*(ctx: var Blake2s_256Ctx): array[32, uint8] = blake2FinalC(ctx)

    proc blake2b_128Init*(ctx: var Blake2b_128Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
    proc blake2b_128Input*(ctx: var Blake2b_128Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
    proc blake2b_128Final*(ctx: var Blake2b_128Ctx): array[16, uint8] = blake2FinalC(ctx)

    proc blake2b_160Init*(ctx: var Blake2b_160Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
    proc blake2b_160Input*(ctx: var Blake2b_160Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
    proc blake2b_160Final*(ctx: var Blake2b_160Ctx): array[20, uint8] = blake2FinalC(ctx)

    proc blake2b_224Init*(ctx: var Blake2b_224Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
    proc blake2b_224Input*(ctx: var Blake2b_224Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
    proc blake2b_224Final*(ctx: var Blake2b_224Ctx): array[28, uint8] = blake2FinalC(ctx)

    proc blake2b_256Init*(ctx: var Blake2b_256Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
    proc blake2b_256Input*(ctx: var Blake2b_256Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
    proc blake2b_256Final*(ctx: var Blake2b_256Ctx): array[32, uint8] = blake2FinalC(ctx)

    proc blake2b_384Init*(ctx: var Blake2b_384Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
    proc blake2b_384Input*(ctx: var Blake2b_384Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
    proc blake2b_384Final*(ctx: var Blake2b_384Ctx): array[48, uint8] = blake2FinalC(ctx)

    proc blake2b_512Init*(ctx: var Blake2b_512Ctx, key: openArray[uint8] = []): void = blake2InitC(ctx, key)
    proc blake2b_512Input*(ctx: var Blake2b_512Ctx, input: openArray[uint8]): void = blake2InputC(ctx, input)
    proc blake2b_512Final*(ctx: var Blake2b_512Ctx): array[64, uint8] = blake2FinalC(ctx)

  when defined(c) or defined(objc):
    proc blake2s_128Init*(ctx: ptr Blake2s_128Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportc: "blake2s_128Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2s_128Input*(ctx: ptr Blake2s_128Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "blake2s_128Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2s_128Final*(ctx: ptr Blake2s_128Ctx, output: ptr array[16, uint8]): void {.exportc: "blake2s_128Final".} = output[] = blake2FinalC(ctx[])

    proc blake2s_160Init*(ctx: ptr Blake2s_160Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportc: "blake2s_160Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2s_160Input*(ctx: ptr Blake2s_160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "blake2s_160Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2s_160Final*(ctx: ptr Blake2s_160Ctx, output: ptr array[20, uint8]): void {.exportc: "blake2s_160Final".} = output[] = blake2FinalC(ctx[])

    proc blake2s_224Init*(ctx: ptr Blake2s_224Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportc: "blake2s_224Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2s_224Input*(ctx: ptr Blake2s_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "blake2s_224Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2s_224Final*(ctx: ptr Blake2s_224Ctx, output: ptr array[28, uint8]): void {.exportc: "blake2s_224Final".} = output[] = blake2FinalC(ctx[])

    proc blake2s_256Init*(ctx: ptr Blake2s_256Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportc: "blake2s_256Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2s_256Input*(ctx: ptr Blake2s_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "blake2s_256Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2s_256Final*(ctx: ptr Blake2s_256Ctx, output: ptr array[32, uint8]): void {.exportc: "blake2s_256Final".} = output[] = blake2FinalC(ctx[])

    proc blake2b_128Init*(ctx: ptr Blake2b_128Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportc: "blake2b_128Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2b_128Input*(ctx: ptr Blake2b_128Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "blake2b_128Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2b_128Final*(ctx: ptr Blake2b_128Ctx, output: ptr array[16, uint8]): void {.exportc: "blake2b_128Final".} = output[] = blake2FinalC(ctx[])

    proc blake2b_160Init*(ctx: ptr Blake2b_160Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportc: "blake2b_160Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2b_160Input*(ctx: ptr Blake2b_160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "blake2b_160Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2b_160Final*(ctx: ptr Blake2b_160Ctx, output: ptr array[20, uint8]): void {.exportc: "blake2b_160Final".} = output[] = blake2FinalC(ctx[])

    proc blake2b_224Init*(ctx: ptr Blake2b_224Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportc: "blake2b_224Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2b_224Input*(ctx: ptr Blake2b_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "blake2b_224Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2b_224Final*(ctx: ptr Blake2b_224Ctx, output: ptr array[28, uint8]): void {.exportc: "blake2b_224Final".} = output[] = blake2FinalC(ctx[])

    proc blake2b_256Init*(ctx: ptr Blake2b_256Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportc: "blake2b_256Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2b_256Input*(ctx: ptr Blake2b_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "blake2b_256Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2b_256Final*(ctx: ptr Blake2b_256Ctx, output: ptr array[32, uint8]): void {.exportc: "blake2b_256Final".} = output[] = blake2FinalC(ctx[])

    proc blake2b_384Init*(ctx: ptr Blake2b_384Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportc: "blake2b_384Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2b_384Input*(ctx: ptr Blake2b_384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "blake2b_384Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2b_384Final*(ctx: ptr Blake2b_384Ctx, output: ptr array[48, uint8]): void {.exportc: "blake2b_384Final".} = output[] = blake2FinalC(ctx[])

    proc blake2b_512Init*(ctx: ptr Blake2b_512Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportc: "blake2b_512Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2b_512Input*(ctx: ptr Blake2b_512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "blake2b_512Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2b_512Final*(ctx: ptr Blake2b_512Ctx, output: ptr array[64, uint8]): void {.exportc: "blake2b_512Final".} = output[] = blake2FinalC(ctx[])

  elif defined(cpp):
    proc blake2s_128Init*(ctx: ptr Blake2s_128Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportcpp: "blake2s_128Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2s_128Input*(ctx: ptr Blake2s_128Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "blake2s_128Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2s_128Final*(ctx: ptr Blake2s_128Ctx, output: ptr array[16, uint8]): void {.exportcpp: "blake2s_128Final".} = output[] = blake2FinalC(ctx[])

    proc blake2s_160Init*(ctx: ptr Blake2s_160Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportcpp: "blake2s_160Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2s_160Input*(ctx: ptr Blake2s_160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "blake2s_160Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2s_160Final*(ctx: ptr Blake2s_160Ctx, output: ptr array[20, uint8]): void {.exportcpp: "blake2s_160Final".} = output[] = blake2FinalC(ctx[])

    proc blake2s_224Init*(ctx: ptr Blake2s_224Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportcpp: "blake2s_224Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2s_224Input*(ctx: ptr Blake2s_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "blake2s_224Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2s_224Final*(ctx: ptr Blake2s_224Ctx, output: ptr array[28, uint8]): void {.exportcpp: "blake2s_224Final".} = output[] = blake2FinalC(ctx[])

    proc blake2s_256Init*(ctx: ptr Blake2s_256Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportcpp: "blake2s_256Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2s_256Input*(ctx: ptr Blake2s_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "blake2s_256Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2s_256Final*(ctx: ptr Blake2s_256Ctx, output: ptr array[32, uint8]): void {.exportcpp: "blake2s_256Final".} = output[] = blake2FinalC(ctx[])

    proc blake2b_128Init*(ctx: ptr Blake2b_128Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportcpp: "blake2b_128Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2b_128Input*(ctx: ptr Blake2b_128Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "blake2b_128Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2b_128Final*(ctx: ptr Blake2b_128Ctx, output: ptr array[16, uint8]): void {.exportcpp: "blake2b_128Final".} = output[] = blake2FinalC(ctx[])

    proc blake2b_160Init*(ctx: ptr Blake2b_160Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportcpp: "blake2b_160Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2b_160Input*(ctx: ptr Blake2b_160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "blake2b_160Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2b_160Final*(ctx: ptr Blake2b_160Ctx, output: ptr array[20, uint8]): void {.exportcpp: "blake2b_160Final".} = output[] = blake2FinalC(ctx[])

    proc blake2b_224Init*(ctx: ptr Blake2b_224Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportcpp: "blake2b_224Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2b_224Input*(ctx: ptr Blake2b_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "blake2b_224Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2b_224Final*(ctx: ptr Blake2b_224Ctx, output: ptr array[28, uint8]): void {.exportcpp: "blake2b_224Final".} = output[] = blake2FinalC(ctx[])

    proc blake2b_256Init*(ctx: ptr Blake2b_256Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportcpp: "blake2b_256Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2b_256Input*(ctx: ptr Blake2b_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "blake2b_256Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2b_256Final*(ctx: ptr Blake2b_256Ctx, output: ptr array[32, uint8]): void {.exportcpp: "blake2b_256Final".} = output[] = blake2FinalC(ctx[])

    proc blake2b_384Init*(ctx: ptr Blake2b_384Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportcpp: "blake2b_384Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2b_384Input*(ctx: ptr Blake2b_384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "blake2b_384Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2b_384Final*(ctx: ptr Blake2b_384Ctx, output: ptr array[48, uint8]): void {.exportcpp: "blake2b_384Final".} = output[] = blake2FinalC(ctx[])

    proc blake2b_512Init*(ctx: ptr Blake2b_512Ctx, key: ptr UncheckedArray[uint8] = nil, keyLen: int = 0): void {.exportcpp: "blake2b_512Init".} = blake2InitC(ctx[], key.toOpenArray(0, keyLen - 1))
    proc blake2b_512Input*(ctx: ptr Blake2b_512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "blake2b_512Input".} = blake2InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc blake2b_512Final*(ctx: ptr Blake2b_512Ctx, output: ptr array[64, uint8]): void {.exportcpp: "blake2b_512Final".} = output[] = blake2FinalC(ctx[])
