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

# declare keccak types
type
  # keccak kind enum
  KeccakKind* = enum
    SHA3
    Keccak
    Shake

  # keccak general context
  KeccakCtx*[bits: static[int], kind: static[KeccakKind]] = object
    state*: array[200, uint8] # 200 bytes, 1600 bits
    pt*: int

  # Keccak/SHA-3/Shake context
  Keccak224Ctx* = KeccakCtx[224, Keccak]
  Keccak256Ctx* = KeccakCtx[256, Keccak]
  Keccak384Ctx* = KeccakCtx[384, Keccak]
  Keccak512Ctx* = KeccakCtx[512, Keccak]
  SHA3_224Ctx* = KeccakCtx[224, SHA3]
  SHA3_256Ctx* = KeccakCtx[256, SHA3]
  SHA3_384Ctx* = KeccakCtx[384, SHA3]
  SHA3_512Ctx* = KeccakCtx[512, SHA3]
  Shake128Ctx* = KeccakCtx[128, Shake]
  Shake256Ctx* = KeccakCtx[256, Shake]

  # concept of Keccak and SHA-3 List
  KeccakList* = Keccak224Ctx | Keccak256Ctx | Keccak384Ctx | Keccak512Ctx | SHA3_224Ctx | SHA3_256Ctx | SHA3_384Ctx | SHA3_512Ctx

# declare constant
const
  RNDC = [
    0x0000000000000001'u64, 0x0000000000008082'u64, 0x800000000000808A'u64,
    0x8000000080008000'u64, 0x000000000000808B'u64, 0x0000000080000001'u64,
    0x8000000080008081'u64, 0x8000000000008009'u64, 0x000000000000008A'u64,
    0x0000000000000088'u64, 0x0000000080008009'u64, 0x000000008000000A'u64,
    0x000000008000808B'u64, 0x800000000000008B'u64, 0x8000000000008089'u64,
    0x8000000000008003'u64, 0x8000000000008002'u64, 0x8000000000000080'u64,
    0x000000000000800A'u64, 0x800000008000000A'u64, 0x8000000080008081'u64,
    0x8000000000008080'u64, 0x0000000080000001'u64, 0x8000000080008008'u64
  ]

# calculate column's parity by xor each column's 5 data
template theta1(a: var array[5, uint64], b: array[25, uint64], c: int): void {.autoSizeOpt.} =
  a[c] = b[c] xor b[c + 5] xor b[c + 10] xor b[c + 15] xor b[c + 20]

# mix current column with left/right side column's data
template theta2(a: var uint64, b: array[5, uint64], c: int): void =
  a = b[(c + 4) mod 5] xor rotateLeftBits(uint64(b[(c + 1) mod 5]), 1)

# update value by applying calculated parity to state's row
template theta3(a: var array[25, uint64], b: int, c: uint64): void =
  a[b] = a[b] xor c
  a[b + 5] = a[b + 5] xor c
  a[b + 10] = a[b + 10] xor c
  a[b + 15] = a[b + 15] xor c
  a[b + 20] = a[b + 20] xor c

# left rotate each lane's bits as specific ount
# replace each lane's location under 5 x 5 matrix
template rhopi(a: var openArray[uint64], b: var openArray[uint64], c: var uint64, d, e: int): void {.autoSizeOpt.} =
  a[0] = b[d]
  b[d] = rotateLeftBits(c, e)
  c = a[0]

# inject non-linearity
template chi(a: var array[5, uint64], b: var array[25, uint64], c: int): void {.autoSizeOpt.} =
  a[0] = b[c]
  a[1] = b[c + 1]
  a[2] = b[c + 2]
  a[3] = b[c + 3]
  a[4] = b[c + 4]
  b[c] = b[c] xor (not(a[1]) and a[2])
  b[c + 1] = b[c + 1] xor (not(a[2]) and a[3])
  b[c + 2] = b[c + 2] xor (not(a[3]) and a[4])
  b[c + 3] = b[c + 3] xor (not(a[4]) and a[0])
  b[c + 4] = b[c + 4] xor (not(a[0]) and a[1])

# round template for keccak
template keccakRound(a: var array[25, uint64], b: var array[5, uint64], c: var uint64, r: int): void {.autoSizeOpt.} =
  theta1(b, a, 0)
  theta1(b, a, 1)
  theta1(b, a, 2)
  theta1(b, a, 3)
  theta1(b, a, 4)

  theta2(c, b, 0)
  theta3(a, 0, c)
  theta2(c, b, 1)
  theta3(a, 1, c)
  theta2(c, b, 2)
  theta3(a, 2, c)
  theta2(c, b, 3)
  theta3(a, 3, c)
  theta2(c, b, 4)
  theta3(a, 4, c)

  c = a[1]
  rhopi(b, a, c, 10, 1)
  rhopi(b, a, c, 7, 3)
  rhopi(b, a, c, 11, 6)
  rhopi(b, a, c, 17, 10)
  rhopi(b, a, c, 18, 15)
  rhopi(b, a, c, 3, 21)
  rhopi(b, a, c, 5, 28)
  rhopi(b, a, c, 16, 36)
  rhopi(b, a, c, 8, 45)
  rhopi(b, a, c, 21, 55)
  rhopi(b, a, c, 24, 2)
  rhopi(b, a, c, 4, 14)
  rhopi(b, a, c, 15, 27)
  rhopi(b, a, c, 23, 41)
  rhopi(b, a, c, 19, 56)
  rhopi(b, a, c, 13, 8)
  rhopi(b, a, c, 12, 25)
  rhopi(b, a, c, 2, 43)
  rhopi(b, a, c, 20, 62)
  rhopi(b, a, c, 14, 18)
  rhopi(b, a, c, 22, 39)
  rhopi(b, a, c, 9, 61)
  rhopi(b, a, c, 6, 20)
  rhopi(b, a, c, 1, 44)

  chi(b, a, 0)
  chi(b, a, 5)
  chi(b, a, 10)
  chi(b, a, 15)
  chi(b, a, 20)

  a[0] = a[0] xor RNDC[r]

# keccak transform part
template keccakTransform(input: var array[200, uint8]): void {.autoSizeOpt.} =
  # declare variables
  var bc: array[5, uint64]
  var state: array[25, uint64]
  var t: uint64

  # decode state to data
  decodeLE(input, state)

  # call keccak round template
  for i in static(0 .. 23):
    keccakRound(state, bc, t, i)

  encodeLE(state, input)

# get size of block
template sizeBlock*(ctx: KeccakCtx): uint =
  (200)

# get size of r
template rsize(ctx: KeccakCtx): int =
  200 - 2 * (ctx.bits div 8)

# get size of digest
template sizeDigest*(r: typedesc[KeccakList | Shake128Ctx | Shake256Ctx]): int =
  when r is Shake128:
    (16)
  elif r is Keccak224 or r is SHA3_224:
    (28)
  elif r is Keccak256 or r is SHA3_256 or r is Shake256:
    (32)
  elif r is Keccak384 or r is SHA3_384:
    (48)
  elif r is Keccak512 or r is SHA3_512:
    (64)

# sha3 init core
template sha3InitC[bits: static[int], kind: static[KeccakKind]](ctx: var KeccakCtx[bits, kind]): void {.autoSizeOpt.} =
  # initialize state
  for i in static(0 ..< 200):
    ctx.state[i] = 0x00'u8
  # initialize index
  ctx.pt = 0

# sha3 input core
template sha3InputC[bits: static[int], kind: static[KeccakKind]](ctx: var KeccakCtx[bits, kind], input: openArray[uint8]): void {.autoSizeOpt.} =
  # set context state index
  var j = ctx.pt
  # check inputLen is not zero
  if input.len > 0:
    # set variables
    var position: int = 0
    # set inputLen
    let inputLen: int = input.len
    
    # loop while inputLen
    while position < inputLen:
      # set left : left index of state
      # set take : index to process in one time
      let left: int = ctx.rsize - j
      let take: int = min(left, inputLen - position)
      
      # block internal processing
      for k in 0 ..< take:
        ctx.state[j] = ctx.state[j] xor input[position + k]
        j.inc

      # call when block is full
      if j >= ctx.rsize:
        keccakTransform(ctx.state)
        j = 0

      # add take
      position += take

    # set index
    ctx.pt = j

# sha3 final core
template sha3FinalC[bits: static int, kind: static KeccakKind](ctx: var KeccakCtx[bits, kind]): array[bits div 8, uint8] {.autoSizeOpt.} =
  # declare output
  var output: array[bits div 8, uint8]
  # add kind padding
  when kind == SHA3:
    ctx.state[ctx.pt] = ctx.state[ctx.pt] xor 0x06'u8
  else:
    ctx.state[ctx.pt] = ctx.state[ctx.pt] xor 0x01'u8

  # add padding
  ctx.state[ctx.rsize - 1] = ctx.state[ctx.rsize - 1] xor 0x80'u8

  # call keccak transform
  keccakTransform(ctx.state)

  # copy state to output
  copyMem(addr output, addr ctx.state, bits div 8)

  output

# shake xof core
template shakeXofC[bits: static int, kind: static KeccakKind](ctx: var KeccakCtx[bits, kind]): void {.autoSizeOpt.} =
  # check ctx kind in compile time
  static:
    doAssert kind == Shake, "xof's ctx must be shake"

  # add pading
  ctx.state[ctx.pt] = ctx.state[ctx.pt] xor 0x1F'u8
  ctx.state[ctx.rsize - 1] = ctx.state[ctx.rsize - 1] xor 0x80'u8

  # call keccak transform template
  keccakTransform(ctx.state)

  # set index to zero
  ctx.pt = 0

template shakeFinalC*[bits: static int, kind: static KeccakKind](ctx: var KeccakCtx[bits, kind], output: var openArray[uint8]): void {.autoSizeOpt.} =
  # check ctx kind in compile time
  static:
    doAssert kind == Shake, "xof's ctx must be shake"

  var j = ctx.pt
  for i in 0 ..< output.len:
    if j >= ctx.rsize:
      # call keccak transform template
      keccakTransform(ctx.state)
      j = 0

    # copy state to output
    output[i] = ctx.state[j]
    j.inc

  # set index to j
  ctx.pt = j

# export wrappers
when defined(templateOpt):
  # Keccak
  template keccak224Init*(ctx: var Keccak224Ctx): void = sha3InitC(ctx)
  template keccak224Input*(ctx: var Keccak224Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  template keccak224Final*(ctx: var Keccak224Ctx): array[28, uint8] = sha3FinalC(ctx)

  template keccak256Init*(ctx: var Keccak256Ctx): void = sha3InitC(ctx)
  template keccak256Input*(ctx: var Keccak256Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  template keccak256Final*(ctx: var Keccak256Ctx): array[32, uint8] = sha3FinalC(ctx)

  template keccak384Init*(ctx: var Keccak384Ctx): void = sha3InitC(ctx)
  template keccak384Input*(ctx: var Keccak384Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  template keccak384Final*(ctx: var Keccak384Ctx): array[48, uint8] = sha3FinalC(ctx)

  template keccak512Init*(ctx: var Keccak512Ctx): void = sha3InitC(ctx)
  template keccak512Input*(ctx: var Keccak512Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  template keccak512Final*(ctx: var Keccak512Ctx): array[64, uint8] = sha3FinalC(ctx)

  # SHA3
  template sha3_224Init*(ctx: var SHA3_224Ctx): void = sha3InitC(ctx)
  template sha3_224Input*(ctx: var SHA3_224Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  template sha3_224Final*(ctx: var SHA3_224Ctx): array[28, uint8] = sha3FinalC(ctx)

  template sha3_256Init*(ctx: var SHA3_256Ctx): void = sha3InitC(ctx)
  template sha3_256Input*(ctx: var SHA3_256Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  template sha3_256Final*(ctx: var SHA3_256Ctx): array[32, uint8] = sha3FinalC(ctx)

  template sha3_384Init*(ctx: var SHA3_384Ctx): void = sha3InitC(ctx)
  template sha3_384Input*(ctx: var SHA3_384Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  template sha3_384Final*(ctx: var SHA3_384Ctx): array[48, uint8] = sha3FinalC(ctx)

  template sha3_512Init*(ctx: var SHA3_512Ctx): void = sha3InitC(ctx)
  template sha3_512Input*(ctx: var SHA3_512Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  template sha3_512Final*(ctx: var SHA3_512Ctx): array[64, uint8] = sha3FinalC(ctx)

  # Shake
  template shake128Init*(ctx: var Shake128Ctx): void = sha3InitC(ctx)
  template shake128Input*(ctx: var Shake128Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  template shake128Xof*(ctx: var Shake128Ctx): void = shakeXofC(ctx)
  template shake128Final*(ctx: var Shake128Ctx, output: var openArray[uint8]): void = shakeFinalC(ctx, output)

  template shake256Init*(ctx: var Shake256Ctx): void = sha3InitC(ctx)
  template shake256Input*(ctx: var Shake256Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
  template shake256Xof*(ctx: var Shake256Ctx): void = shakeXofC(ctx)
  template shake256Final*(ctx: var Shake256Ctx, output: var openArray[uint8]): void = shakeFinalC(ctx, output)

  when Native:
    # Keccak
    template keccak224Init*(ctx: ptr Keccak224Ctx): void = sha3InitC(ctx[])
    template keccak224Input*(ctx: ptr Keccak224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template keccak224Final*(ctx: ptr Keccak224Ctx, output: ptr array[28, uint8]): void = output[] = sha3FinalC(ctx[])

    template keccak256Init*(ctx: ptr Keccak256Ctx): void = sha3InitC(ctx[])
    template keccak256Input*(ctx: ptr Keccak256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template keccak256Final*(ctx: ptr Keccak256Ctx, output: ptr array[32, uint8]): void = output[] = sha3FinalC(ctx[])

    template keccak384Init*(ctx: ptr Keccak384Ctx): void = sha3InitC(ctx[])
    template keccak384Input*(ctx: ptr Keccak384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template keccak384Final*(ctx: ptr Keccak384Ctx, output: ptr array[48, uint8]): void = output[] = sha3FinalC(ctx[])

    template keccak512Init*(ctx: ptr Keccak512Ctx): void = sha3InitC(ctx[])
    template keccak512Input*(ctx: ptr Keccak512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template keccak512Final*(ctx: ptr Keccak512Ctx, output: ptr array[64, uint8]): void = output[] = sha3FinalC(ctx[])

    # SHA3
    template sha3_224Init*(ctx: ptr SHA3_224Ctx): void = sha3InitC(ctx[])
    template sha3_224Input*(ctx: ptr SHA3_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template sha3_224Final*(ctx: ptr SHA3_224Ctx, output: ptr array[28, uint8]): void = output[] = sha3FinalC(ctx[])

    template sha3_256Init*(ctx: ptr SHA3_256Ctx): void = sha3InitC(ctx[])
    template sha3_256Input*(ctx: ptr SHA3_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template sha3_256Final*(ctx: ptr SHA3_256Ctx, output: ptr array[32, uint8]): void = output[] = sha3FinalC(ctx[])

    template sha3_384Init*(ctx: ptr SHA3_384Ctx): void = sha3InitC(ctx[])
    template sha3_384Input*(ctx: ptr SHA3_384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template sha3_384Final*(ctx: ptr SHA3_384Ctx, output: ptr array[48, uint8]): void = output[] = sha3FinalC(ctx[])

    template sha3_512Init*(ctx: ptr SHA3_512Ctx): void = sha3InitC(ctx[])
    template sha3_512Input*(ctx: ptr SHA3_512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template sha3_512Final*(ctx: ptr SHA3_512Ctx, output: ptr array[64, uint8]): void = output[] = sha3FinalC(ctx[])

    # Shake
    template shake128Init*(ctx: ptr Shake128Ctx): void = sha3InitC(ctx[])
    template shake128Input*(ctx: ptr Shake128Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template shake128Xof*(ctx: ptr Shake128Ctx): void = shakeXofC(ctx[])
    template shake128Final*(ctx: ptr Shake128Ctx, output: ptr UncheckedArray[uint8], outputLen: int): void = shakeFinalC(ctx[], output.toOpenArray(0, outputLen - 1))

    template shake256Init*(ctx: ptr Shake256Ctx): void = sha3InitC(ctx[])
    template shake256Input*(ctx: ptr Shake256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    template shake256Xof*(ctx: ptr Shake256Ctx): void = shakeXofC(ctx[])
    template shake256Final*(ctx: ptr Shake256Ctx, output: ptr UncheckedArray[uint8], outputLen: int): void = shakeFinalC(ctx[], output.toOpenArray(0, outputLen - 1))

else:
  when Native:
    # Keccak
    proc keccak224Init*(ctx: var Keccak224Ctx): void = sha3InitC(ctx)
    proc keccak224Input*(ctx: var Keccak224Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
    proc keccak224Final*(ctx: var Keccak224Ctx): array[28, uint8] = sha3FinalC(ctx)

    proc keccak256Init*(ctx: var Keccak256Ctx): void = sha3InitC(ctx)
    proc keccak256Input*(ctx: var Keccak256Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
    proc keccak256Final*(ctx: var Keccak256Ctx): array[32, uint8] = sha3FinalC(ctx)

    proc keccak384Init*(ctx: var Keccak384Ctx): void = sha3InitC(ctx)
    proc keccak384Input*(ctx: var Keccak384Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
    proc keccak384Final*(ctx: var Keccak384Ctx): array[48, uint8] = sha3FinalC(ctx)

    proc keccak512Init*(ctx: var Keccak512Ctx): void = sha3InitC(ctx)
    proc keccak512Input*(ctx: var Keccak512Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
    proc keccak512Final*(ctx: var Keccak512Ctx): array[64, uint8] = sha3FinalC(ctx)

    # SHA3
    proc sha3_224Init*(ctx: var SHA3_224Ctx): void = sha3InitC(ctx)
    proc sha3_224Input*(ctx: var SHA3_224Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
    proc sha3_224Final*(ctx: var SHA3_224Ctx): array[28, uint8] = sha3FinalC(ctx)

    proc sha3_256Init*(ctx: var SHA3_256Ctx): void = sha3InitC(ctx)
    proc sha3_256Input*(ctx: var SHA3_256Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
    proc sha3_256Final*(ctx: var SHA3_256Ctx): array[32, uint8] = sha3FinalC(ctx)

    proc sha3_384Init*(ctx: var SHA3_384Ctx): void = sha3InitC(ctx)
    proc sha3_384Input*(ctx: var SHA3_384Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
    proc sha3_384Final*(ctx: var SHA3_384Ctx): array[48, uint8] = sha3FinalC(ctx)

    proc sha3_512Init*(ctx: var SHA3_512Ctx): void = sha3InitC(ctx)
    proc sha3_512Input*(ctx: var SHA3_512Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
    proc sha3_512Final*(ctx: var SHA3_512Ctx): array[64, uint8] = sha3FinalC(ctx)

    # Shake
    proc shake128Init*(ctx: var Shake128Ctx): void = sha3InitC(ctx)
    proc shake128Input*(ctx: var Shake128Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
    proc shake128Xof*(ctx: var Shake128Ctx): void = shakeXofC(ctx)
    proc shake128Final*(ctx: var Shake128Ctx, output: var openArray[uint8]): void = shakeFinalC(ctx, output)

    proc shake256Init*(ctx: var Shake256Ctx): void = sha3InitC(ctx)
    proc shake256Input*(ctx: var Shake256Ctx, input: openArray[uint8]): void = sha3InputC(ctx, input)
    proc shake256Xof*(ctx: var Shake256Ctx): void = shakeXofC(ctx)
    proc shake256Final*(ctx: var Shake256Ctx, output: var openArray[uint8]): void = shakeFinalC(ctx, output)

  when defined(c) or defined(objc):
    # Keccak
    proc keccak224Init*(ctx: ptr Keccak224Ctx): void {.exportc: "keccak224Init".} = sha3InitC(ctx[])
    proc keccak224Input*(ctx: ptr Keccak224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "keccak224Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc keccak224Final*(ctx: ptr Keccak224Ctx, output: ptr array[28, uint8]): void {.exportc: "keccak224Final".} = output[] = sha3FinalC(ctx[])

    proc keccak256Init*(ctx: ptr Keccak256Ctx): void {.exportc: "keccak256Init".} = sha3InitC(ctx[])
    proc keccak256Input*(ctx: ptr Keccak256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "keccak256Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc keccak256Final*(ctx: ptr Keccak256Ctx, output: ptr array[32, uint8]): void {.exportc: "keccak256Final".} = output[] = sha3FinalC(ctx[])

    proc keccak384Init*(ctx: ptr Keccak384Ctx): void {.exportc: "keccak384Init".} = sha3InitC(ctx[])
    proc keccak384Input*(ctx: ptr Keccak384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "keccak384Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc keccak384Final*(ctx: ptr Keccak384Ctx, output: ptr array[48, uint8]): void {.exportc: "keccak384Final".} = output[] = sha3FinalC(ctx[])

    proc keccak512Init*(ctx: ptr Keccak512Ctx): void {.exportc: "keccak512Init".} = sha3InitC(ctx[])
    proc keccak512Input*(ctx: ptr Keccak512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "keccak512Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc keccak512Final*(ctx: ptr Keccak512Ctx, output: ptr array[64, uint8]): void {.exportc: "keccak512Final".} = output[] = sha3FinalC(ctx[])

    # SHA3
    proc sha3_224Init*(ctx: ptr SHA3_224Ctx): void {.exportc: "sha3_224Init".} = sha3InitC(ctx[])
    proc sha3_224Input*(ctx: ptr SHA3_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha3_224Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha3_224Final*(ctx: ptr SHA3_224Ctx, output: ptr array[28, uint8]): void {.exportc: "sha3_224Final".} = output[] = sha3FinalC(ctx[])

    proc sha3_256Init*(ctx: ptr SHA3_256Ctx): void {.exportc: "sha3_256Init".} = sha3InitC(ctx[])
    proc sha3_256Input*(ctx: ptr SHA3_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha3_256Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha3_256Final*(ctx: ptr SHA3_256Ctx, output: ptr array[32, uint8]): void {.exportc: "sha3_256Final".} = output[] = sha3FinalC(ctx[])

    proc sha3_384Init*(ctx: ptr SHA3_384Ctx): void {.exportc: "sha3_384Init".} = sha3InitC(ctx[])
    proc sha3_384Input*(ctx: ptr SHA3_384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha3_384Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha3_384Final*(ctx: ptr SHA3_384Ctx, output: ptr array[48, uint8]): void {.exportc: "sha3_384Final".} = output[] = sha3FinalC(ctx[])

    proc sha3_512Init*(ctx: ptr SHA3_512Ctx): void {.exportc: "sha3_512Init".} = sha3InitC(ctx[])
    proc sha3_512Input*(ctx: ptr SHA3_512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "sha3_512Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha3_512Final*(ctx: ptr SHA3_512Ctx, output: ptr array[64, uint8]): void {.exportc: "sha3_512Final".} = output[] = sha3FinalC(ctx[])

    # Shake
    proc shake128Init*(ctx: ptr Shake128Ctx): void {.exportc: "shake128Init".} = sha3InitC(ctx[])
    proc shake128Input*(ctx: ptr Shake128Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "shake128Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc shake128Xof*(ctx: ptr Shake128Ctx): void {.exportc: "shake128Xof".} = shakeXofC(ctx[])
    proc shake128Final*(ctx: ptr Shake128Ctx, output: ptr UncheckedArray[uint8], outputLen: int): void {.exportc: "shake128Final".} = shakeFinalC(ctx[], output.toOpenArray(0, outputLen - 1))

    proc shake256Init*(ctx: ptr Shake256Ctx): void {.exportc: "shake256Init".} = sha3InitC(ctx[])
    proc shake256Input*(ctx: ptr Shake256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "shake256Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc shake256Xof*(ctx: ptr Shake256Ctx): void {.exportc: "shake256Xof".} = shakeXofC(ctx[])
    proc shake256Final*(ctx: ptr Shake256Ctx, output: ptr UncheckedArray[uint8], outputLen: int): void {.exportc: "shake256Final".} = shakeFinalC(ctx[], output.toOpenArray(0, outputLen - 1))

  elif defined(cpp):
    # Keccak
    proc keccak224Init*(ctx: ptr Keccak224Ctx): void {.exportcpp: "keccak224Init".} = sha3InitC(ctx[])
    proc keccak224Input*(ctx: ptr Keccak224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "keccak224Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc keccak224Final*(ctx: ptr Keccak224Ctx, output: ptr array[28, uint8]): void {.exportcpp: "keccak224Final".} = output[] = sha3FinalC(ctx[])

    proc keccak256Init*(ctx: ptr Keccak256Ctx): void {.exportcpp: "keccak256Init".} = sha3InitC(ctx[])
    proc keccak256Input*(ctx: ptr Keccak256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "keccak256Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc keccak256Final*(ctx: ptr Keccak256Ctx, output: ptr array[32, uint8]): void {.exportcpp: "keccak256Final".} = output[] = sha3FinalC(ctx[])

    proc keccak384Init*(ctx: ptr Keccak384Ctx): void {.exportcpp: "keccak384Init".} = sha3InitC(ctx[])
    proc keccak384Input*(ctx: ptr Keccak384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "keccak384Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc keccak384Final*(ctx: ptr Keccak384Ctx, output: ptr array[48, uint8]): void {.exportcpp: "keccak384Final".} = output[] = sha3FinalC(ctx[])

    proc keccak512Init*(ctx: ptr Keccak512Ctx): void {.exportcpp: "keccak512Init".} = sha3InitC(ctx[])
    proc keccak512Input*(ctx: ptr Keccak512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "keccak512Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc keccak512Final*(ctx: ptr Keccak512Ctx, output: ptr array[64, uint8]): void {.exportcpp: "keccak512Final".} = output[] = sha3FinalC(ctx[])

    # SHA3
    proc sha3_224Init*(ctx: ptr SHA3_224Ctx): void {.exportcpp: "sha3_224Init".} = sha3InitC(ctx[])
    proc sha3_224Input*(ctx: ptr SHA3_224Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha3_224Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha3_224Final*(ctx: ptr SHA3_224Ctx, output: ptr array[28, uint8]): void {.exportcpp: "sha3_224Final".} = output[] = sha3FinalC(ctx[])

    proc sha3_256Init*(ctx: ptr SHA3_256Ctx): void {.exportcpp: "sha3_256Init".} = sha3InitC(ctx[])
    proc sha3_256Input*(ctx: ptr SHA3_256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha3_256Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha3_256Final*(ctx: ptr SHA3_256Ctx, output: ptr array[32, uint8]): void {.exportcpp: "sha3_256Final".} = output[] = sha3FinalC(ctx[])

    proc sha3_384Init*(ctx: ptr SHA3_384Ctx): void {.exportcpp: "sha3_384Init".} = sha3InitC(ctx[])
    proc sha3_384Input*(ctx: ptr SHA3_384Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha3_384Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha3_384Final*(ctx: ptr SHA3_384Ctx, output: ptr array[48, uint8]): void {.exportcpp: "sha3_384Final".} = output[] = sha3FinalC(ctx[])

    proc sha3_512Init*(ctx: ptr SHA3_512Ctx): void {.exportcpp: "sha3_512Init".} = sha3InitC(ctx[])
    proc sha3_512Input*(ctx: ptr SHA3_512Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "sha3_512Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc sha3_512Final*(ctx: ptr SHA3_512Ctx, output: ptr array[64, uint8]): void {.exportcpp: "sha3_512Final".} = output[] = sha3FinalC(ctx[])

    # Shake
    proc shake128Init*(ctx: ptr Shake128Ctx): void {.exportcpp: "shake128Init".} = sha3InitC(ctx[])
    proc shake128Input*(ctx: ptr Shake128Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "shake128Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc shake128Xof*(ctx: ptr Shake128Ctx): void {.exportcpp: "shake128Xof".} = shakeXofC(ctx[])
    proc shake128Final*(ctx: ptr Shake128Ctx, output: ptr UncheckedArray[uint8], outputLen: int): void {.exportcpp: "shake128Final".} = shakeFinalC(ctx[], output.toOpenArray(0, outputLen - 1))

    proc shake256Init*(ctx: ptr Shake256Ctx): void {.exportcpp: "shake256Init".} = sha3InitC(ctx[])
    proc shake256Input*(ctx: ptr Shake256Ctx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportcpp: "shake256Input".} = sha3InputC(ctx[], input.toOpenArray(0, inputLen - 1))
    proc shake256Xof*(ctx: ptr Shake256Ctx): void {.exportcpp: "shake256Xof".} = shakeXofC(ctx[])
    proc shake256Final*(ctx: ptr Shake256Ctx, output: ptr UncheckedArray[uint8], outputLen: int): void {.exportcpp: "shake256Final".} = shakeFinalC(ctx[], output.toOpenArray(0, outputLen - 1))
