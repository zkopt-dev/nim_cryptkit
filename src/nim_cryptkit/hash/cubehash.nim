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
  CubeHashCtx*[hashSize: static int, blockSize: static int] = object
    state*: array[32, uint32]
    buffer*: array[blockSize, uint8]
    index*: int
    length*: uint64
    roundsPerBlock*: int
    initRounds*: int
    finalRounds*: int

const
  CubeHashHS128_HASH_SIZE*: int = 16
  CubeHashHS160_HASH_SIZE*: int = 20
  CubeHashHS192_HASH_SIZE*: int = 24
  CubeHashHS224_HASH_SIZE*: int = 28
  CubeHashHS256_HASH_SIZE*: int = 32
  CubeHashHS384_HASH_SIZE*: int = 48
  CubeHashHS512_HASH_SIZE*: int = 64

  CubeHashSH128_HASH_SIZE*: int = 16
  CubeHashSH160_HASH_SIZE*: int = 20
  CubeHashSH192_HASH_SIZE*: int = 24
  CubeHashSH224_HASH_SIZE*: int = 28
  CubeHashSH256_HASH_SIZE*: int = 32
  CubeHashSH384_HASH_SIZE*: int = 48
  CubeHashSH512_HASH_SIZE*: int = 64

  CubeHashHS128_BLOCK_SIZE*: int = 32
  CubeHashHS160_BLOCK_SIZE*: int = 32
  CubeHashHS192_BLOCK_SIZE*: int = 32
  CubeHashHS224_BLOCK_SIZE*: int = 32
  CubeHashHS256_BLOCK_SIZE*: int = 32
  CubeHashHS384_BLOCK_SIZE*: int = 32
  CubeHashHS512_BLOCK_SIZE*: int = 32

  CubeHashSH128_BLOCK_SIZE*: int = 32
  CubeHashSH160_BLOCK_SIZE*: int = 32
  CubeHashSH192_BLOCK_SIZE*: int = 32
  CubeHashSH224_BLOCK_SIZE*: int = 32
  CubeHashSH256_BLOCK_SIZE*: int = 32
  CubeHashSH384_BLOCK_SIZE*: int = 32
  CubeHashSH512_BLOCK_SIZE*: int = 32

  CubeHashHS_ROUND_PER_BLOCK*: int = 16
  CubeHashHS_INIT_ROUND*: int = 16
  CubeHashHS_FINAL_ROUND*: int = 32

  CubeHashSH_ROUND_PER_BLOCK*: int = 16
  CubeHashSH_INIT_ROUND*: int = 160
  CubeHashSH_FINAL_ROUND*: int = 160

type
  CubeHashHS128Ctx* = CubeHashCtx[CubeHashHS128_HASH_SIZE, CubeHashHS128_BLOCK_SIZE]
  CubeHashHS160Ctx* = CubeHashCtx[CubeHashHS160_HASH_SIZE, CubeHashHS160_BLOCK_SIZE]
  CubeHashHS192Ctx* = CubeHashCtx[CubeHashHS192_HASH_SIZE, CubeHashHS192_BLOCK_SIZE]
  CubeHashHS224Ctx* = CubeHashCtx[CubeHashHS224_HASH_SIZE, CubeHashHS224_BLOCK_SIZE]
  CubeHashHS256Ctx* = CubeHashCtx[CubeHashHS256_HASH_SIZE, CubeHashHS256_BLOCK_SIZE]
  CubeHashHS384Ctx* = CubeHashCtx[CubeHashHS384_HASH_SIZE, CubeHashHS384_BLOCK_SIZE]
  CubeHashHS512Ctx* = CubeHashCtx[CubeHashHS512_HASH_SIZE, CubeHashHS512_BLOCK_SIZE]

  CubeHashSH128Ctx* = CubeHashCtx[CubeHashSH128_HASH_SIZE, CubeHashSH128_BLOCK_SIZE]
  CubeHashSH160Ctx* = CubeHashCtx[CubeHashSH160_HASH_SIZE, CubeHashSH160_BLOCK_SIZE]
  CubeHashSH192Ctx* = CubeHashCtx[CubeHashSH192_HASH_SIZE, CubeHashSH192_BLOCK_SIZE]
  CubeHashSH224Ctx* = CubeHashCtx[CubeHashSH224_HASH_SIZE, CubeHashSH224_BLOCK_SIZE]
  CubeHashSH256Ctx* = CubeHashCtx[CubeHashSH256_HASH_SIZE, CubeHashSH256_BLOCK_SIZE]
  CubeHashSH384Ctx* = CubeHashCtx[CubeHashSH384_HASH_SIZE, CubeHashSH384_BLOCK_SIZE]
  CubeHashSH512Ctx* = CubeHashCtx[CubeHashSH512_HASH_SIZE, CubeHashSH512_BLOCK_SIZE]

template cubehashTransform(x: var array[32, uint32]): void =
  for n in static(0 ..< 16):
    x[n + 16] = x[n + 16] + x[n]
    x[n] = rotateLeftBits(x[n], 7)

  swap(x[0], x[8])
  swap(x[1], x[9])
  swap(x[2], x[10])
  swap(x[3], x[11])
  swap(x[4], x[12])
  swap(x[5], x[13])
  swap(x[6], x[14])
  swap(x[7], x[15])

  for n in static(0 ..< 16):
    x[n] = x[n] xor x[n + 16]

  swap(x[16], x[18])
  swap(x[17], x[19])
  swap(x[20], x[22])
  swap(x[21], x[23])
  swap(x[24], x[26])
  swap(x[25], x[27])
  swap(x[28], x[30])
  swap(x[29], x[31])

  for n in static(0 ..< 16):
    x[n + 16] = x[n + 16] + x[n]
    x[n] = rotateLeftBits(x[n], 11)

  swap(x[0], x[4])
  swap(x[1], x[5])
  swap(x[2], x[6])
  swap(x[3], x[7])
  swap(x[8], x[12])
  swap(x[9], x[13])
  swap(x[10], x[14])
  swap(x[11], x[15])

  for n in static(0 ..< 16):
    x[n] = x[n] xor x[n + 16]

  swap(x[16], x[17])
  swap(x[18], x[19])
  swap(x[20], x[21])
  swap(x[22], x[23])
  swap(x[24], x[25])
  swap(x[26], x[27])
  swap(x[28], x[29])
  swap(x[30], x[31])

template cubehashIngest[K, B: static int](ctx: var CubeHashCtx[K, B], chunk: slicearray[B, uint8]): void =
  for n in static(0 ..< (B div 4)):
    ctx.state[n] = ctx.state[n] xor fromBytesLE[uint32, 4](chunk.toSliceArray(n * 4, n * 4 + 3, 4))
  for _ in 0 ..< ctx.roundsPerBlock:
    cubehashTransform(ctx.state)

template cubehashInitC[K, B: static int](ctx: var CubeHashCtx[K, B], a: int, b: int, c: int): void =
  zeroMem(addr ctx.state[0], 32 * 4)
  zeroMem(addr ctx.buffer[0], B)
  ctx.index = 0
  ctx.length = 0'u64
  ctx.roundsPerBlock = a
  ctx.initRounds = b
  ctx.finalRounds = c
  ctx.state[0] = uint32(K)
  ctx.state[1] = uint32(B)
  ctx.state[2] = uint32(a)
  for i in 0 ..< b:
    cubehashTransform(ctx.state)

template cubehashInputC[K, B: static int](ctx: var CubeHashCtx[K, B], input: openArray[uint8]): void =
  let inputLen: int = input.len
  var check: bool = true

  if inputLen <= 0: check = false

  if check:
    var index: int = ctx.index
    ctx.length += uint64(input.len)
    let left: int = B - index
    var position: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[position], left)
      cubeHashIngest(ctx, ctx.buffer.toSliceArray(0, B - 1))
      position = left
      index = 0

      while position + B <= inputLen:
        cubeHashIngest(ctx, input.toSliceArray(position, position + B - 1, B))
        position += B

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

template cubehashFinalC[K, B: static int](ctx: var CubeHashCtx[K, B]): array[K, uint8] =
  var output: array[K, uint8]
  var x = ctx.state
  var pad: array[B, uint8]
  var index: int = ctx.index

  copyMem(addr pad[0], addr ctx.buffer[0], index)
  pad[index] = 0x80'u8

  for n in static(0 ..< (B div 4)):
    x[n] = x[n] xor fromBytesLE[uint32, 4](pad.toSliceArray(n * 4, n * 4 + 3, 4))
  for _ in 0 ..< ctx.roundsPerBlock:
    cubehashTransform(x)

  x[31] = x[31] xor 1'u32
  for n in 0 ..< ctx.finalRounds:
    cubehashTransform(x)

  when LE:
    copyMem(addr output[0], addr x[0], K)
  else:
    encodeLE(x.toSliceArray(0, K div 4 - 1), output.toSliceArray(0, K - 1))

  output

# export wrappers
when defined(templateOpt):
  # ==========================================
  # 1. CubeHashHS (Init: 16, Block: 16, Final: 32)
  # ==========================================
  template cubeHashHS128Init*(ctx: var CubeHashHS128Ctx): void = cubeHashInitC(ctx, CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
  template cubeHashHS128Input*(ctx: var CubeHashHS128Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
  template cubeHashHS128Final*(ctx: var CubeHashHS128Ctx): array[CubeHashHS128_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

  template cubeHashHS160Init*(ctx: var CubeHashHS160Ctx): void = cubeHashInitC(ctx, CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
  template cubeHashHS160Input*(ctx: var CubeHashHS160Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
  template cubeHashHS160Final*(ctx: var CubeHashHS160Ctx): array[CubeHashHS160_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

  template cubeHashHS192Init*(ctx: var CubeHashHS192Ctx): void = cubeHashInitC(ctx, CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
  template cubeHashHS192Input*(ctx: var CubeHashHS192Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
  template cubeHashHS192Final*(ctx: var CubeHashHS192Ctx): array[CubeHashHS192_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

  template cubeHashHS224Init*(ctx: var CubeHashHS224Ctx): void = cubeHashInitC(ctx, CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
  template cubeHashHS224Input*(ctx: var CubeHashHS224Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
  template cubeHashHS224Final*(ctx: var CubeHashHS224Ctx): array[CubeHashHS224_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

  template cubeHashHS256Init*(ctx: var CubeHashHS256Ctx): void = cubeHashInitC(ctx, CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
  template cubeHashHS256Input*(ctx: var CubeHashHS256Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
  template cubeHashHS256Final*(ctx: var CubeHashHS256Ctx): array[CubeHashHS256_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

  template cubeHashHS384Init*(ctx: var CubeHashHS384Ctx): void = cubeHashInitC(ctx, CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
  template cubeHashHS384Input*(ctx: var CubeHashHS384Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
  template cubeHashHS384Final*(ctx: var CubeHashHS384Ctx): array[CubeHashHS384_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

  template cubeHashHS512Init*(ctx: var CubeHashHS512Ctx): void = cubeHashInitC(ctx, CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
  template cubeHashHS512Input*(ctx: var CubeHashHS512Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
  template cubeHashHS512Final*(ctx: var CubeHashHS512Ctx): array[CubeHashHS512_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

  # ==========================================
  # 2. CubeHashSH (Init: 160, Block: 16, Final: 160)
  # ==========================================
  template cubeHashSH128Init*(ctx: var CubeHashSH128Ctx): void = cubeHashInitC(ctx, CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
  template cubeHashSH128Input*(ctx: var CubeHashSH128Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
  template cubeHashSH128Final*(ctx: var CubeHashSH128Ctx): array[CubeHashSH128_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

  template cubeHashSH160Init*(ctx: var CubeHashSH160Ctx): void = cubeHashInitC(ctx, CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
  template cubeHashSH160Input*(ctx: var CubeHashSH160Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
  template cubeHashSH160Final*(ctx: var CubeHashSH160Ctx): array[CubeHashSH160_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

  template cubeHashSH192Init*(ctx: var CubeHashSH192Ctx): void = cubeHashInitC(ctx, CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
  template cubeHashSH192Input*(ctx: var CubeHashSH192Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
  template cubeHashSH192Final*(ctx: var CubeHashSH192Ctx): array[CubeHashSH192_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

  template cubeHashSH224Init*(ctx: var CubeHashSH224Ctx): void = cubeHashInitC(ctx, CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
  template cubeHashSH224Input*(ctx: var CubeHashSH224Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
  template cubeHashSH224Final*(ctx: var CubeHashSH224Ctx): array[CubeHashSH224_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

  template cubeHashSH256Init*(ctx: var CubeHashSH256Ctx): void = cubeHashInitC(ctx, CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
  template cubeHashSH256Input*(ctx: var CubeHashSH256Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
  template cubeHashSH256Final*(ctx: var CubeHashSH256Ctx): array[CubeHashSH256_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

  template cubeHashSH384Init*(ctx: var CubeHashSH384Ctx): void = cubeHashInitC(ctx, CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
  template cubeHashSH384Input*(ctx: var CubeHashSH384Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
  template cubeHashSH384Final*(ctx: var CubeHashSH384Ctx): array[CubeHashSH384_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

  template cubeHashSH512Init*(ctx: var CubeHashSH512Ctx): void = cubeHashInitC(ctx, CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
  template cubeHashSH512Input*(ctx: var CubeHashSH512Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
  template cubeHashSH512Final*(ctx: var CubeHashSH512Ctx): array[CubeHashSH512_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

  when Native:
    # --- HS ptr templates ---
    template cubeHashHS128Init*(ctx: ptr CubeHashHS128Ctx): void = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    template cubeHashHS128Input*(ctx: ptr CubeHashHS128Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template cubeHashHS128Final*(ctx: ptr CubeHashHS128Ctx, output: ptr array[CubeHashHS128_HASH_SIZE, uint8]): void = output[] = cubeHashFinalC(ctx[])

    template cubeHashHS160Init*(ctx: ptr CubeHashHS160Ctx): void = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    template cubeHashHS160Input*(ctx: ptr CubeHashHS160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template cubeHashHS160Final*(ctx: ptr CubeHashHS160Ctx, output: ptr array[CubeHashHS160_HASH_SIZE, uint8]): void = output[] = cubeHashFinalC(ctx[])

    template cubeHashHS192Init*(ctx: ptr CubeHashHS192Ctx): void = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    template cubeHashHS192Input*(ctx: ptr CubeHashHS192Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template cubeHashHS192Final*(ctx: ptr CubeHashHS192Ctx, output: ptr array[CubeHashHS192_HASH_SIZE, uint8]): void = output[] = cubeHashFinalC(ctx[])

    template cubeHashHS224Init*(ctx: ptr CubeHashHS224Ctx): void = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    template cubeHashHS224Input*(ctx: ptr CubeHashHS224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template cubeHashHS224Final*(ctx: ptr CubeHashHS224Ctx, output: ptr array[CubeHashHS224_HASH_SIZE, uint8]): void = output[] = cubeHashFinalC(ctx[])

    template cubeHashHS256Init*(ctx: ptr CubeHashHS256Ctx): void = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    template cubeHashHS256Input*(ctx: ptr CubeHashHS256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template cubeHashHS256Final*(ctx: ptr CubeHashHS256Ctx, output: ptr array[CubeHashHS256_HASH_SIZE, uint8]): void = output[] = cubeHashFinalC(ctx[])

    template cubeHashHS384Init*(ctx: ptr CubeHashHS384Ctx): void = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    template cubeHashHS384Input*(ctx: ptr CubeHashHS384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template cubeHashHS384Final*(ctx: ptr CubeHashHS384Ctx, output: ptr array[CubeHashHS384_HASH_SIZE, uint8]): void = output[] = cubeHashFinalC(ctx[])

    template cubeHashHS512Init*(ctx: ptr CubeHashHS512Ctx): void = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    template cubeHashHS512Input*(ctx: ptr CubeHashHS512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template cubeHashHS512Final*(ctx: ptr CubeHashHS512Ctx, output: ptr array[CubeHashHS512_HASH_SIZE, uint8]): void = output[] = cubeHashFinalC(ctx[])

    # --- SH ptr templates ---
    template cubeHashSH128Init*(ctx: ptr CubeHashSH128Ctx): void = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    template cubeHashSH128Input*(ctx: ptr CubeHashSH128Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template cubeHashSH128Final*(ctx: ptr CubeHashSH128Ctx, output: ptr array[CubeHashSH128_HASH_SIZE, uint8]): void = output[] = cubeHashFinalC(ctx[])

    template cubeHashSH160Init*(ctx: ptr CubeHashSH160Ctx): void = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    template cubeHashSH160Input*(ctx: ptr CubeHashSH160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template cubeHashSH160Final*(ctx: ptr CubeHashSH160Ctx, output: ptr array[CubeHashSH160_HASH_SIZE, uint8]): void = output[] = cubeHashFinalC(ctx[])

    template cubeHashSH192Init*(ctx: ptr CubeHashSH192Ctx): void = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    template cubeHashSH192Input*(ctx: ptr CubeHashSH192Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template cubeHashSH192Final*(ctx: ptr CubeHashSH192Ctx, output: ptr array[CubeHashSH192_HASH_SIZE, uint8]): void = output[] = cubeHashFinalC(ctx[])

    template cubeHashSH224Init*(ctx: ptr CubeHashSH224Ctx): void = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    template cubeHashSH224Input*(ctx: ptr CubeHashSH224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template cubeHashSH224Final*(ctx: ptr CubeHashSH224Ctx, output: ptr array[CubeHashSH224_HASH_SIZE, uint8]): void = output[] = cubeHashFinalC(ctx[])

    template cubeHashSH256Init*(ctx: ptr CubeHashSH256Ctx): void = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    template cubeHashSH256Input*(ctx: ptr CubeHashSH256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template cubeHashSH256Final*(ctx: ptr CubeHashSH256Ctx, output: ptr array[CubeHashSH256_HASH_SIZE, uint8]): void = output[] = cubeHashFinalC(ctx[])

    template cubeHashSH384Init*(ctx: ptr CubeHashSH384Ctx): void = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    template cubeHashSH384Input*(ctx: ptr CubeHashSH384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template cubeHashSH384Final*(ctx: ptr CubeHashSH384Ctx, output: ptr array[CubeHashSH384_HASH_SIZE, uint8]): void = output[] = cubeHashFinalC(ctx[])

    template cubeHashSH512Init*(ctx: ptr CubeHashSH512Ctx): void = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    template cubeHashSH512Input*(ctx: ptr CubeHashSH512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template cubeHashSH512Final*(ctx: ptr CubeHashSH512Ctx, output: ptr array[CubeHashSH512_HASH_SIZE, uint8]): void = output[] = cubeHashFinalC(ctx[])
else:
  when Native:
    # --- HS var procs ---
    proc cubeHashHS128Init*(ctx: var CubeHashHS128Ctx): void = cubeHashInitC(ctx, CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS128Input*(ctx: var CubeHashHS128Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
    proc cubeHashHS128Final*(ctx: var CubeHashHS128Ctx): array[CubeHashHS128_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

    proc cubeHashHS160Init*(ctx: var CubeHashHS160Ctx): void = cubeHashInitC(ctx, CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS160Input*(ctx: var CubeHashHS160Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
    proc cubeHashHS160Final*(ctx: var CubeHashHS160Ctx): array[CubeHashHS160_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

    proc cubeHashHS192Init*(ctx: var CubeHashHS192Ctx): void = cubeHashInitC(ctx, CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS192Input*(ctx: var CubeHashHS192Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
    proc cubeHashHS192Final*(ctx: var CubeHashHS192Ctx): array[CubeHashHS192_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

    proc cubeHashHS224Init*(ctx: var CubeHashHS224Ctx): void = cubeHashInitC(ctx, CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS224Input*(ctx: var CubeHashHS224Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
    proc cubeHashHS224Final*(ctx: var CubeHashHS224Ctx): array[CubeHashHS224_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

    proc cubeHashHS256Init*(ctx: var CubeHashHS256Ctx): void = cubeHashInitC(ctx, CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS256Input*(ctx: var CubeHashHS256Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
    proc cubeHashHS256Final*(ctx: var CubeHashHS256Ctx): array[CubeHashHS256_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

    proc cubeHashHS384Init*(ctx: var CubeHashHS384Ctx): void = cubeHashInitC(ctx, CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS384Input*(ctx: var CubeHashHS384Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
    proc cubeHashHS384Final*(ctx: var CubeHashHS384Ctx): array[CubeHashHS384_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

    proc cubeHashHS512Init*(ctx: var CubeHashHS512Ctx): void = cubeHashInitC(ctx, CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS512Input*(ctx: var CubeHashHS512Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
    proc cubeHashHS512Final*(ctx: var CubeHashHS512Ctx): array[CubeHashHS512_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

    # --- SH var procs ---
    proc cubeHashSH128Init*(ctx: var CubeHashSH128Ctx): void = cubeHashInitC(ctx, CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH128Input*(ctx: var CubeHashSH128Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
    proc cubeHashSH128Final*(ctx: var CubeHashSH128Ctx): array[CubeHashSH128_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

    proc cubeHashSH160Init*(ctx: var CubeHashSH160Ctx): void = cubeHashInitC(ctx, CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH160Input*(ctx: var CubeHashSH160Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
    proc cubeHashSH160Final*(ctx: var CubeHashSH160Ctx): array[CubeHashSH160_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

    proc cubeHashSH192Init*(ctx: var CubeHashSH192Ctx): void = cubeHashInitC(ctx, CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH192Input*(ctx: var CubeHashSH192Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
    proc cubeHashSH192Final*(ctx: var CubeHashSH192Ctx): array[CubeHashSH192_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

    proc cubeHashSH224Init*(ctx: var CubeHashSH224Ctx): void = cubeHashInitC(ctx, CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH224Input*(ctx: var CubeHashSH224Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
    proc cubeHashSH224Final*(ctx: var CubeHashSH224Ctx): array[CubeHashSH224_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

    proc cubeHashSH256Init*(ctx: var CubeHashSH256Ctx): void = cubeHashInitC(ctx, CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH256Input*(ctx: var CubeHashSH256Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
    proc cubeHashSH256Final*(ctx: var CubeHashSH256Ctx): array[CubeHashSH256_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

    proc cubeHashSH384Init*(ctx: var CubeHashSH384Ctx): void = cubeHashInitC(ctx, CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH384Input*(ctx: var CubeHashSH384Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
    proc cubeHashSH384Final*(ctx: var CubeHashSH384Ctx): array[CubeHashSH384_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

    proc cubeHashSH512Init*(ctx: var CubeHashSH512Ctx): void = cubeHashInitC(ctx, CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH512Input*(ctx: var CubeHashSH512Ctx, input: openArray[uint8]): void = cubeHashInputC(ctx, input)
    proc cubeHashSH512Final*(ctx: var CubeHashSH512Ctx): array[CubeHashSH512_HASH_SIZE, uint8] = cubeHashFinalC(ctx)

  when defined(c) or defined(objc):
    # --- HS ptr procs (C) ---
    proc cubeHashHS128Init*(ctx: ptr CubeHashHS128Ctx): void {.exportc: "cubeHashHS128Init".} = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS128Input*(ctx: ptr CubeHashHS128Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "cubeHashHS128Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashHS128Final*(ctx: ptr CubeHashHS128Ctx, output: ptr array[CubeHashHS128_HASH_SIZE, uint8]): void {.exportc: "cubeHashHS128Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashHS160Init*(ctx: ptr CubeHashHS160Ctx): void {.exportc: "cubeHashHS160Init".} = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS160Input*(ctx: ptr CubeHashHS160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "cubeHashHS160Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashHS160Final*(ctx: ptr CubeHashHS160Ctx, output: ptr array[CubeHashHS160_HASH_SIZE, uint8]): void {.exportc: "cubeHashHS160Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashHS192Init*(ctx: ptr CubeHashHS192Ctx): void {.exportc: "cubeHashHS192Init".} = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS192Input*(ctx: ptr CubeHashHS192Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "cubeHashHS192Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashHS192Final*(ctx: ptr CubeHashHS192Ctx, output: ptr array[CubeHashHS192_HASH_SIZE, uint8]): void {.exportc: "cubeHashHS192Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashHS224Init*(ctx: ptr CubeHashHS224Ctx): void {.exportc: "cubeHashHS224Init".} = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS224Input*(ctx: ptr CubeHashHS224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "cubeHashHS224Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashHS224Final*(ctx: ptr CubeHashHS224Ctx, output: ptr array[CubeHashHS224_HASH_SIZE, uint8]): void {.exportc: "cubeHashHS224Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashHS256Init*(ctx: ptr CubeHashHS256Ctx): void {.exportc: "cubeHashHS256Init".} = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS256Input*(ctx: ptr CubeHashHS256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "cubeHashHS256Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashHS256Final*(ctx: ptr CubeHashHS256Ctx, output: ptr array[CubeHashHS256_HASH_SIZE, uint8]): void {.exportc: "cubeHashHS256Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashHS384Init*(ctx: ptr CubeHashHS384Ctx): void {.exportc: "cubeHashHS384Init".} = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS384Input*(ctx: ptr CubeHashHS384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "cubeHashHS384Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashHS384Final*(ctx: ptr CubeHashHS384Ctx, output: ptr array[CubeHashHS384_HASH_SIZE, uint8]): void {.exportc: "cubeHashHS384Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashHS512Init*(ctx: ptr CubeHashHS512Ctx): void {.exportc: "cubeHashHS512Init".} = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS512Input*(ctx: ptr CubeHashHS512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "cubeHashHS512Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashHS512Final*(ctx: ptr CubeHashHS512Ctx, output: ptr array[CubeHashHS512_HASH_SIZE, uint8]): void {.exportc: "cubeHashHS512Final".} = output[] = cubeHashFinalC(ctx[])

    # --- SH ptr procs (C) ---
    proc cubeHashSH128Init*(ctx: ptr CubeHashSH128Ctx): void {.exportc: "cubeHashSH128Init".} = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH128Input*(ctx: ptr CubeHashSH128Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "cubeHashSH128Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashSH128Final*(ctx: ptr CubeHashSH128Ctx, output: ptr array[CubeHashSH128_HASH_SIZE, uint8]): void {.exportc: "cubeHashSH128Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashSH160Init*(ctx: ptr CubeHashSH160Ctx): void {.exportc: "cubeHashSH160Init".} = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH160Input*(ctx: ptr CubeHashSH160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "cubeHashSH160Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashSH160Final*(ctx: ptr CubeHashSH160Ctx, output: ptr array[CubeHashSH160_HASH_SIZE, uint8]): void {.exportc: "cubeHashSH160Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashSH192Init*(ctx: ptr CubeHashSH192Ctx): void {.exportc: "cubeHashSH192Init".} = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH192Input*(ctx: ptr CubeHashSH192Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "cubeHashSH192Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashSH192Final*(ctx: ptr CubeHashSH192Ctx, output: ptr array[CubeHashSH192_HASH_SIZE, uint8]): void {.exportc: "cubeHashSH192Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashSH224Init*(ctx: ptr CubeHashSH224Ctx): void {.exportc: "cubeHashSH224Init".} = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH224Input*(ctx: ptr CubeHashSH224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "cubeHashSH224Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashSH224Final*(ctx: ptr CubeHashSH224Ctx, output: ptr array[CubeHashSH224_HASH_SIZE, uint8]): void {.exportc: "cubeHashSH224Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashSH256Init*(ctx: ptr CubeHashSH256Ctx): void {.exportc: "cubeHashSH256Init".} = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH256Input*(ctx: ptr CubeHashSH256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "cubeHashSH256Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashSH256Final*(ctx: ptr CubeHashSH256Ctx, output: ptr array[CubeHashSH256_HASH_SIZE, uint8]): void {.exportc: "cubeHashSH256Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashSH384Init*(ctx: ptr CubeHashSH384Ctx): void {.exportc: "cubeHashSH384Init".} = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH384Input*(ctx: ptr CubeHashSH384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "cubeHashSH384Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashSH384Final*(ctx: ptr CubeHashSH384Ctx, output: ptr array[CubeHashSH384_HASH_SIZE, uint8]): void {.exportc: "cubeHashSH384Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashSH512Init*(ctx: ptr CubeHashSH512Ctx): void {.exportc: "cubeHashSH512Init".} = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH512Input*(ctx: ptr CubeHashSH512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "cubeHashSH512Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashSH512Final*(ctx: ptr CubeHashSH512Ctx, output: ptr array[CubeHashSH512_HASH_SIZE, uint8]): void {.exportc: "cubeHashSH512Final".} = output[] = cubeHashFinalC(ctx[])
  elif defined(cpp):
    # --- HS ptr procs (C++) ---
    proc cubeHashHS128Init*(ctx: ptr CubeHashHS128Ctx): void {.exportcpp: "cubeHashHS128Init".} = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS128Input*(ctx: ptr CubeHashHS128Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "cubeHashHS128Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashHS128Final*(ctx: ptr CubeHashHS128Ctx, output: ptr array[CubeHashHS128_HASH_SIZE, uint8]): void {.exportcpp: "cubeHashHS128Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashHS160Init*(ctx: ptr CubeHashHS160Ctx): void {.exportcpp: "cubeHashHS160Init".} = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS160Input*(ctx: ptr CubeHashHS160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "cubeHashHS160Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashHS160Final*(ctx: ptr CubeHashHS160Ctx, output: ptr array[CubeHashHS160_HASH_SIZE, uint8]): void {.exportcpp: "cubeHashHS160Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashHS192Init*(ctx: ptr CubeHashHS192Ctx): void {.exportcpp: "cubeHashHS192Init".} = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS192Input*(ctx: ptr CubeHashHS192Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "cubeHashHS192Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashHS192Final*(ctx: ptr CubeHashHS192Ctx, output: ptr array[CubeHashHS192_HASH_SIZE, uint8]): void {.exportcpp: "cubeHashHS192Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashHS224Init*(ctx: ptr CubeHashHS224Ctx): void {.exportcpp: "cubeHashHS224Init".} = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS224Input*(ctx: ptr CubeHashHS224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "cubeHashHS224Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashHS224Final*(ctx: ptr CubeHashHS224Ctx, output: ptr array[CubeHashHS224_HASH_SIZE, uint8]): void {.exportcpp: "cubeHashHS224Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashHS256Init*(ctx: ptr CubeHashHS256Ctx): void {.exportcpp: "cubeHashHS256Init".} = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS256Input*(ctx: ptr CubeHashHS256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "cubeHashHS256Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashHS256Final*(ctx: ptr CubeHashHS256Ctx, output: ptr array[CubeHashHS256_HASH_SIZE, uint8]): void {.exportcpp: "cubeHashHS256Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashHS384Init*(ctx: ptr CubeHashHS384Ctx): void {.exportcpp: "cubeHashHS384Init".} = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS384Input*(ctx: ptr CubeHashHS384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "cubeHashHS384Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashHS384Final*(ctx: ptr CubeHashHS384Ctx, output: ptr array[CubeHashHS384_HASH_SIZE, uint8]): void {.exportcpp: "cubeHashHS384Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashHS512Init*(ctx: ptr CubeHashHS512Ctx): void {.exportcpp: "cubeHashHS512Init".} = cubeHashInitC(ctx[], CubeHashHS_ROUND_PER_BLOCK, CubeHashHS_INIT_ROUND, CubeHashHS_FINAL_ROUND)
    proc cubeHashHS512Input*(ctx: ptr CubeHashHS512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "cubeHashHS512Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashHS512Final*(ctx: ptr CubeHashHS512Ctx, output: ptr array[CubeHashHS512_HASH_SIZE, uint8]): void {.exportcpp: "cubeHashHS512Final".} = output[] = cubeHashFinalC(ctx[])

    # --- SH ptr procs (C++) ---
    proc cubeHashSH128Init*(ctx: ptr CubeHashSH128Ctx): void {.exportcpp: "cubeHashSH128Init".} = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH128Input*(ctx: ptr CubeHashSH128Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "cubeHashSH128Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashSH128Final*(ctx: ptr CubeHashSH128Ctx, output: ptr array[CubeHashSH128_HASH_SIZE, uint8]): void {.exportcpp: "cubeHashSH128Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashSH160Init*(ctx: ptr CubeHashSH160Ctx): void {.exportcpp: "cubeHashSH160Init".} = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH160Input*(ctx: ptr CubeHashSH160Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "cubeHashSH160Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashSH160Final*(ctx: ptr CubeHashSH160Ctx, output: ptr array[CubeHashSH160_HASH_SIZE, uint8]): void {.exportcpp: "cubeHashSH160Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashSH192Init*(ctx: ptr CubeHashSH192Ctx): void {.exportcpp: "cubeHashSH192Init".} = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH192Input*(ctx: ptr CubeHashSH192Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "cubeHashSH192Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashSH192Final*(ctx: ptr CubeHashSH192Ctx, output: ptr array[CubeHashSH192_HASH_SIZE, uint8]): void {.exportcpp: "cubeHashSH192Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashSH224Init*(ctx: ptr CubeHashSH224Ctx): void {.exportcpp: "cubeHashSH224Init".} = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH224Input*(ctx: ptr CubeHashSH224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "cubeHashSH224Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashSH224Final*(ctx: ptr CubeHashSH224Ctx, output: ptr array[CubeHashSH224_HASH_SIZE, uint8]): void {.exportcpp: "cubeHashSH224Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashSH256Init*(ctx: ptr CubeHashSH256Ctx): void {.exportcpp: "cubeHashSH256Init".} = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH256Input*(ctx: ptr CubeHashSH256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "cubeHashSH256Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashSH256Final*(ctx: ptr CubeHashSH256Ctx, output: ptr array[CubeHashSH256_HASH_SIZE, uint8]): void {.exportcpp: "cubeHashSH256Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashSH384Init*(ctx: ptr CubeHashSH384Ctx): void {.exportcpp: "cubeHashSH384Init".} = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH384Input*(ctx: ptr CubeHashSH384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "cubeHashSH384Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashSH384Final*(ctx: ptr CubeHashSH384Ctx, output: ptr array[CubeHashSH384_HASH_SIZE, uint8]): void {.exportcpp: "cubeHashSH384Final".} = output[] = cubeHashFinalC(ctx[])

    proc cubeHashSH512Init*(ctx: ptr CubeHashSH512Ctx): void {.exportcpp: "cubeHashSH512Init".} = cubeHashInitC(ctx[], CubeHashSH_ROUND_PER_BLOCK, CubeHashSH_INIT_ROUND, CubeHashSH_FINAL_ROUND)
    proc cubeHashSH512Input*(ctx: ptr CubeHashSH512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "cubeHashSH512Input".} = cubeHashInputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc cubeHashSH512Final*(ctx: ptr CubeHashSH512Ctx, output: ptr array[CubeHashSH512_HASH_SIZE, uint8]): void {.exportcpp: "cubeHashSH512Final".} = output[] = cubeHashFinalC(ctx[])
