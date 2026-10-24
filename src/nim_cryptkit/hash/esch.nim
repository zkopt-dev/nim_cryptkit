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
  ESCHCtx*[hashSize: static int, blockSize: static int] = object
    state*: array[16, uint32]
    buffer*: array[128, uint8]
    index*: int
    length*: uint64

    blockSizeBytes*: int

  ESCH224Ctx* = ESCHCtx[28, 16]
  ESCH256Ctx* = ESCHCtx[32, 16]
  ESCH384Ctx* = ESCHCtx[48, 16]
  ESCH512Ctx* = ESCHCtx[64, 16]

const
  RC: array[8, uint32] = [
    0xb7e15162'u32, 0xbf715880'u32, 0x38b4da56'u32, 0x324e7738'u32,
    0xbb1185eb'u32, 0x4f7c7b57'u32, 0xcfbfa1c8'u32, 0xc2b3293d'u32]

template eschEll(x: uint32): uint32 =
  rotateRightBits(x xor (x shl 16), 16)

template eschSparkle(state: var array[16, uint32], rounds: static int, steps: static int): void =
  for step in static(0 ..< steps):
    state[1] = state[1] xor RC[step mod 8]
    state[3] = state[3] xor uint32(step)

    var px = 0
    var py = 1
    for j in static(0 ..< rounds):
      state[px] = state[px] + rotateRightBits(state[py], 31)
      state[py] = state[py] xor rotateRightBits(state[px], 24)
      state[px] = state[px] xor RC[j]
      state[px] = state[px] + rotateRightBits(state[py], 17)
      state[py] = state[py] xor rotateRightBits(state[px], 17)
      state[px] = state[px] xor RC[j]
      state[px] = state[px] + state[py]
      state[py] = state[py] xor rotateRightBits(state[px], 31)
      state[px] = state[px] xor RC[j]
      state[px] = state[px] + rotateRightBits(state[py], 24)
      state[py] = state[py] xor rotateRightBits(state[px], 16)
      state[px] = state[px] xor RC[j]
      px += 2
      py += 2

    var x = state[0] xor state[2] xor state[4]
    var y = state[1] xor state[3] xor state[5]
    when rounds > 6:
      x = x xor state[6]
      y = y xor state[7]

    x = eschEll(x)
    y = eschEll(y)

    var j = rounds
    var i = 0
    while i < rounds:
      state[j] = state[j] xor state[i] xor y
      state[j + 1] = state[j + 1] xor state[i + 1] xor x
      j += 2
      i += 2

    x = state[rounds]
    y = state[rounds + 1]
    for k in static(0 ..< (rounds - 2)):
      state[k + rounds] = state[k]
      state[k] = state[k + rounds + 2]
    state[rounds * 2 - 2] = state[rounds - 2]
    state[rounds * 2 - 1] = state[rounds - 1]
    state[rounds - 2] = x
    state[rounds - 1] = y

template eschTransform[K, B: static int](ctx: var EschCtx[K, B], chunk: slicearray[B, uint8], lastBlock: static bool): void =
  var message: array[4, uint32]
  decodeLE(chunk.toSliceArray(0, B - 1), message.toSliceArray(0, 3))

  var x = message[0] xor message[2]
  var y = message[1] xor message[3]
  x = eschEll(x)
  y = eschEll(y)

  ctx.state[0] = ctx.state[0] xor message[0] xor y
  ctx.state[1] = ctx.state[1] xor message[1] xor x
  ctx.state[2] = ctx.state[2] xor message[2] xor y
  ctx.state[3] = ctx.state[3] xor message[3] xor x
  ctx.state[4] = ctx.state[4] xor y
  ctx.state[5] = ctx.state[5] xor x
  if K > 32:
    ctx.state[6] = ctx.state[6] xor y
    ctx.state[7] = ctx.state[7] xor x

  when lastBlock:
    const steps: int = when K > 32: 12 else: 11
  else:
    const steps: int = when K > 32: 8 else: 7
  const rounds = when K > 32: 8 else: 6
  eschSparkle(ctx.state, rounds, steps)

template eschInitC[K, B: static int](ctx: var ESCHCtx[K, B]): void =
  zeroMem(addr ctx.state, 64)
  zeroMem(addr ctx.buffer, 128)
  ctx.index = 0
  ctx.length = 0'u64
  ctx.blockSizeBytes = 128

template eschInputC[K, B: static int](ctx: var EschCtx[K, B], input: openArray[uint8]): void =
  let inputLen: int = input.len
  var check: bool = true

  if inputLen <= 0: check = false

  if check:
    var index: int = ctx.index
    ctx.length += inputLen.uint64

    let left: int = B - index
    var position: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      eschTransform(ctx, ctx.buffer.toSliceArray(0, 15), false)
      position = left
      index = 0

      while position + B < inputLen:
        eschTransform(ctx, input.toSliceArray(position, position + B - 1, B), false)
        position += B

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

template eschFinalC[K, B: static int](ctx: var EschCtx[K, B]): array[K, uint8] =
  var output: array[K, uint8]

  var index: int = ctx.index

  if index < 16:
    ctx.buffer[index] = 0x80'u8
    zeroMem(addr ctx.buffer[index + 1], 128 - index)
    const point: int = (K * 8 + 128) div 64 - 1
    ctx.state[point] = ctx.state[point] xor 0x1000000'u32
  else:
    const point: int = (K * 8 + 128) div 64 - 1
    ctx.state[point] = ctx.state[point] xor 0x2000000'u32

  eschTransform(ctx, ctx.buffer.toSliceArray(0, 15), true)

  var processed: int = 0
  while processed < K:
    if ctx.length == 0'u64:
      const rounds: int = when K > 32: 8 else: 6
      const steps: int = when K > 32: 8 else: 7
      eschSparkle(ctx.state, rounds, steps)

    let take: int = min(K - processed, 16)
    var temp: array[64, uint8]
    encodeLE(ctx.state.toSliceArray(0, 15), temp.toSliceArray(0, 63))
    copyMem(addr output[processed], addr temp[0], take)
    processed += take
    ctx.length = 0'u64

  output

# export wrappers
when defined(templateOpt):
  # === ESCH 224 ===
  template esch224Init*(ctx: var ESCH224Ctx): void = eschInitC(ctx)
  template esch224Input*(ctx: var ESCH224Ctx, init: openArray[uint8]): void = eschInputC(ctx, init)
  template esch224Final*(ctx: var ESCH224Ctx): array[28, uint8] = eschFinalC(ctx)

  # === ESCH 256 ===
  template esch256Init*(ctx: var ESCH256Ctx): void = eschInitC(ctx)
  template esch256Input*(ctx: var ESCH256Ctx, init: openArray[uint8]): void = eschInputC(ctx, init)
  template esch256Final*(ctx: var ESCH256Ctx): array[32, uint8] = eschFinalC(ctx)

  # === ESCH 384 ===
  template esch384Init*(ctx: var ESCH384Ctx): void = eschInitC(ctx)
  template esch384Input*(ctx: var ESCH384Ctx, init: openArray[uint8]): void = eschInputC(ctx, init)
  template esch384Final*(ctx: var ESCH384Ctx): array[48, uint8] = eschFinalC(ctx)

  # === ESCH 512 ===
  template esch512Init*(ctx: var ESCH512Ctx): void = eschInitC(ctx)
  template esch512Input*(ctx: var ESCH512Ctx, init: openArray[uint8]): void = eschInputC(ctx, init)
  template esch512Final*(ctx: var ESCH512Ctx): array[64, uint8] = eschFinalC(ctx)

  when Native:
    template esch224Init*(ctx: ptr ESCH224Ctx): void = eschInitC(ctx[])
    template esch224Input*(ctx: ptr ESCH224Ctx, init: ptr UncheckedArray[uint8], inputLen: int): void = eschInputC(ctx[], init.toOpenArray(0, inputLen - 1))
    template esch224Final*(ctx: ptr ESCH224Ctx, output: ptr array[28, uint8]): void = output[] = eschFinalC(ctx[])

    template esch256Init*(ctx: ptr ESCH256Ctx): void = eschInitC(ctx[])
    template esch256Input*(ctx: ptr ESCH256Ctx, init: ptr UncheckedArray[uint8], inputLen: int): void = eschInputC(ctx[], init.toOpenArray(0, inputLen - 1))
    template esch256Final*(ctx: ptr ESCH256Ctx, output: ptr array[32, uint8]): void = output[] = eschFinalC(ctx[])

    template esch384Init*(ctx: ptr ESCH384Ctx): void = eschInitC(ctx[])
    template esch384Input*(ctx: ptr ESCH384Ctx, init: ptr UncheckedArray[uint8], inputLen: int): void = eschInputC(ctx[], init.toOpenArray(0, inputLen - 1))
    template esch384Final*(ctx: ptr ESCH384Ctx, output: ptr array[48, uint8]): void = output[] = eschFinalC(ctx[])

    template esch512Init*(ctx: ptr ESCH512Ctx): void = eschInitC(ctx[])
    template esch512Input*(ctx: ptr ESCH512Ctx, init: ptr UncheckedArray[uint8], inputLen: int): void = eschInputC(ctx[], init.toOpenArray(0, inputLen - 1))
    template esch512Final*(ctx: ptr ESCH512Ctx, output: ptr array[64, uint8]): void = output[] = eschFinalC(ctx[])

else:
  when Native:
    proc esch224Init*(ctx: var ESCH224Ctx): void = eschInitC(ctx)
    proc esch224Input*(ctx: var ESCH224Ctx, init: openArray[uint8]): void = eschInputC(ctx, init)
    proc esch224Final*(ctx: var ESCH224Ctx): array[28, uint8] = eschFinalC(ctx)

    proc esch256Init*(ctx: var ESCH256Ctx): void = eschInitC(ctx)
    proc esch256Input*(ctx: var ESCH256Ctx, init: openArray[uint8]): void = eschInputC(ctx, init)
    proc esch256Final*(ctx: var ESCH256Ctx): array[32, uint8] = eschFinalC(ctx)

    proc esch384Init*(ctx: var ESCH384Ctx): void = eschInitC(ctx)
    proc esch384Input*(ctx: var ESCH384Ctx, init: openArray[uint8]): void = eschInputC(ctx, init)
    proc esch384Final*(ctx: var ESCH384Ctx): array[48, uint8] = eschFinalC(ctx)

    proc esch512Init*(ctx: var ESCH512Ctx): void = eschInitC(ctx)
    proc esch512Input*(ctx: var ESCH512Ctx, init: openArray[uint8]): void = eschInputC(ctx, init)
    proc esch512Final*(ctx: var ESCH512Ctx): array[64, uint8] = eschFinalC(ctx)

  when defined(c) or defined(objc):
    proc esch224Init*(ctx: ptr ESCH224Ctx): void {.exportc: "esch224Init".} = eschInitC(ctx[])
    proc esch224Input*(ctx: ptr ESCH224Ctx, init: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "esch224Input".} = eschInputC(ctx[], init.toOpenArray(0, inputLen - 1))
    proc esch224Final*(ctx: ptr ESCH224Ctx, output: ptr array[28, uint8]): void {.exportc: "esch224Final".} = output[] = eschFinalC(ctx[])

    proc esch256Init*(ctx: ptr ESCH256Ctx): void {.exportc: "esch256Init".} = eschInitC(ctx[])
    proc esch256Input*(ctx: ptr ESCH256Ctx, init: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "esch256Input".} = eschInputC(ctx[], init.toOpenArray(0, inputLen - 1))
    proc esch256Final*(ctx: ptr ESCH256Ctx, output: ptr array[32, uint8]): void {.exportc: "esch256Final".} = output[] = eschFinalC(ctx[])

    proc esch384Init*(ctx: ptr ESCH384Ctx): void {.exportc: "esch384Init".} = eschInitC(ctx[])
    proc esch384Input*(ctx: ptr ESCH384Ctx, init: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "esch384Input".} = eschInputC(ctx[], init.toOpenArray(0, inputLen - 1))
    proc esch384Final*(ctx: ptr ESCH384Ctx, output: ptr array[48, uint8]): void {.exportc: "esch384Final".} = output[] = eschFinalC(ctx[])

    proc esch512Init*(ctx: ptr ESCH512Ctx): void {.exportc: "esch512Init".} = eschInitC(ctx[])
    proc esch512Input*(ctx: ptr ESCH512Ctx, init: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "esch512Input".} = eschInputC(ctx[], init.toOpenArray(0, inputLen - 1))
    proc esch512Final*(ctx: ptr ESCH512Ctx, output: ptr array[64, uint8]): void {.exportc: "esch512Final".} = output[] = eschFinalC(ctx[])

  elif defined(cpp):
    proc esch224Init*(ctx: ptr ESCH224Ctx): void {.exportcpp: "esch224Init".} = eschInitC(ctx[])
    proc esch224Input*(ctx: ptr ESCH224Ctx, init: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "esch224Input".} = eschInputC(ctx[], init.toOpenArray(0, inputLen - 1))
    proc esch224Final*(ctx: ptr ESCH224Ctx, output: ptr array[28, uint8]): void {.exportcpp: "esch224Final".} = output[] = eschFinalC(ctx[])

    proc esch256Init*(ctx: ptr ESCH256Ctx): void {.exportcpp: "esch256Init".} = eschInitC(ctx[])
    proc esch256Input*(ctx: ptr ESCH256Ctx, init: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "esch256Input".} = eschInputC(ctx[], init.toOpenArray(0, inputLen - 1))
    proc esch256Final*(ctx: ptr ESCH256Ctx, output: ptr array[32, uint8]): void {.exportcpp: "esch256Final".} = output[] = eschFinalC(ctx[])

    proc esch384Init*(ctx: ptr ESCH384Ctx): void {.exportcpp: "esch384Init".} = eschInitC(ctx[])
    proc esch384Input*(ctx: ptr ESCH384Ctx, init: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "esch384Input".} = eschInputC(ctx[], init.toOpenArray(0, inputLen - 1))
    proc esch384Final*(ctx: ptr ESCH384Ctx, output: ptr array[48, uint8]): void {.exportcpp: "esch384Final".} = output[] = eschFinalC(ctx[])

    proc esch512Init*(ctx: ptr ESCH512Ctx): void {.exportcpp: "esch512Init".} = eschInitC(ctx[])
    proc esch512Input*(ctx: ptr ESCH512Ctx, init: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "esch512Input".} = eschInputC(ctx[], init.toOpenArray(0, inputLen - 1))
    proc esch512Final*(ctx: ptr ESCH512Ctx, output: ptr array[64, uint8]): void {.exportcpp: "esch512Final".} = output[] = eschFinalC(ctx[])
