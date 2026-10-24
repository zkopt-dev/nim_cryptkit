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
  ROTATE256: array[8, array[2, int]] = [
    [14, 16],
    [52, 57],
    [23, 40],
    [ 5, 37],
    [25, 33],
    [46, 12],
    [58, 22],
    [32, 32]
  ]
  ROTATE512: array[8, array[4, int]] = [
    [46, 36, 19, 37],
    [33, 27, 14, 42],
    [17, 49, 36, 39],
    [44,  9, 54, 56],
    [39, 30, 34, 24],
    [13, 50, 10, 17],
    [25, 29, 39, 43],
    [ 8, 35, 56, 22],
  ]
  ROTATE1024: array[8, array[8, int]] = [
    [24, 13,  8, 47,  8, 17, 22, 37],
    [38, 19, 10, 55, 49, 18, 23, 52],
    [33,  4, 51, 13, 34, 41, 59, 17],
    [ 5, 20, 48, 41, 47, 28, 16, 25],
    [41,  9, 37, 31, 12, 47, 44, 30],
    [16, 34, 56, 51,  4, 53, 42, 41],
    [31, 44, 47, 46, 19, 42, 44, 25],
    [ 9, 48, 35, 52, 23, 31, 37, 20],
  ]

  PERMUTE256: array[4, int] = [0, 3, 2, 1]
  PERMUTE512: array[8, int] = [6, 1, 0, 7, 2, 5, 4, 3]
  PERMUTE1024: array[16, int] = [0, 15, 2, 11, 6, 13, 4, 9, 14, 1, 8, 5, 10, 3, 12, 7]

  C240: uint64 = 0x1BD11BDAA9FC1A22'u64

type
  ThreefishCtx*[rounds, nw: static int] = object
    roundKey*: array[(rounds div 4 + 1) * nw, uint64]
    tweak*: array[3, uint64]

  Threefish256Ctx* = ThreefishCtx[72, 4]
  Threefish512Ctx* = ThreefishCtx[72, 8]
  Threefish1024Ctx* = ThreefishCtx[80, 16]

template mix(r: int, x0, x1: var uint64): void =
  x0 = x0 + x1
  x1 = rotateLeftBits(x1, r) xor x0

template invMix(r: int, y0, y1: var uint64): void =
  let x1: uint64 = rotateRightBits(y0 xor y1, r)
  y0 = y0 - x1
  y1 = x1

template threefishInitC[rounds, nw, N: static int](ctx: var ThreefishCtx[rounds, nw], key: slicearray[N, uint8], nounce: slicearray[2, uint64]): void =
  static: doAssert N == 32 or N == 64 or N == 128, "Key size must be 32, 64, or 128 bytes."

  const expectedNw = N div 8
  const expectedRounds = when N == 32: 72 elif N == 64: 72 else: 80
  static: doAssert nw == expectedNw and rounds == expectedRounds, "Context type mismatch with key size."

  when LE:
    var keyU64 = key.castTo(uint64)
  else:
    var keyU64: array[N div 8, uint64]
    decodeLE(key, keyU64.toSliceArray(0, N div 8 - 1))

  var k: array[nw + 1, uint64]
  var parity = C240
  for i in static(0 ..< nw):
    k[i] = keyU64[i]
    parity = parity xor keyU64[i]
  k[nw] = parity

  ctx.tweak[0] = nounce[0]
  ctx.tweak[1] = nounce[1]
  ctx.tweak[2] = nounce[0] xor nounce[1]

  const numSubkeys: int = (rounds div 4) + 1

  template initRound(s: static int): void =
    unroll(i, 0, nw - 1):
      ctx.roundKey[s * nw + i] = k[(s + i) mod (nw + 1)]

    ctx.roundKey[s * nw + nw - 3] += ctx.tweak[s mod 3]
    ctx.roundKey[s * nw + nw - 2] += ctx.tweak[(s + 1) mod 3]
    ctx.roundKey[s * nw + nw - 1] += uint64(s)

  unroll(i, 0, numSubkeys - 1):
    initRound(i)

template threefishEncryptC*[rounds, nw, N: static int](ctx: ThreefishCtx[rounds, nw], input, output: slicearray[N, uint8]): void =
  static: doAssert N == 32 or N == 64 or N == 128
  static: doAssert nw == N div 8

  when LE:
    output[] = input
    var state = output.castTo(uint64)
  else:
    var state: array[N div 8, uint64]
    decodeLE(input, state.toSliceArray(0, N div 8 - 1))

  const rot = when N == 32: ROTATE256 elif N == 64: ROTATE512 else: ROTATE1024
  const perm = when N == 32: PERMUTE256 elif N == 64: PERMUTE512 else: PERMUTE1024

  template encryptRound(d: static int): void =
    when d mod 4 == 0:
      const index: int = (d div 4) * nw
      unroll(i, 0, nw - 1):
        state[i] = state[i] + ctx.roundKey[index + i]

    var blockPrev: array[nw, uint64]
    copyMem(addr blockPrev[0], addr state[0], nw * 8)

    var w0, w1: uint64
    unroll(i, 0, (nw div 2) - 1):
      w0 = blockPrev[2 * i + 0]
      w1 = blockPrev[2 * i + 1]
      mix(rot[d mod 8][i], w0, w1)

      state[perm[2 * i + 0]] = w0
      state[perm[2 * i + 1]] = w1

  unroll(d, 0, rounds - 1):
    encryptRound(d)

  const finalIndex: int = (rounds div 4) * nw
  for i in static(0 ..< nw):
    state[i] = state[i] + ctx.roundKey[finalIndex + i]

  when not LE:
    encodeLE(state.toSliceArray(0, N div 8 - 1), output)

template threefishDecryptC*[rounds, nw, N: static int](ctx: ThreefishCtx[rounds, nw], input, output: slicearray[N, uint8]): void =
  static: doAssert N == 32 or N == 64 or N == 128
  static: doAssert nw == N div 8

  when LE:
    output[] = input
    var state = output.castTo(uint64)
  else:
    var state: array[N div 8, uint64]
    decodeLE(input, state.toSliceArray(0, N div 8 - 1))

  const rot = when N == 32: ROTATE256 elif N == 64: ROTATE512 else: ROTATE1024
  const perm = when N == 32: PERMUTE256 elif N == 64: PERMUTE512 else: PERMUTE1024

  const finalIndex: int = (rounds div 4) * nw
  unroll(i, 0, nw - 1):
    state[i] = state[i] - ctx.roundKey[finalIndex + i]

  template decryptRound(d: static int): void =
    var blockPrev: array[nw, uint64]
    copyMem(addr blockPrev[0], addr state[0], nw * 8)

    var w0, w1: uint64
    unroll(i, 0, (nw div 2) - 1):
      w0 = blockPrev[perm[2 * i + 0]]
      w1 = blockPrev[perm[2 * i + 1]]

      invMix(rot[d mod 8][i], w0, w1)

      state[2 * i + 0] = w0
      state[2 * i + 1] = w1

    when d mod 4 == 0:
      const index: int = (d div 4) * nw
      unroll(i, 0, nw - 1):
        state[i] = state[i] - ctx.roundKey[index + i]

  unroll(d, rounds - 1, 0):
    decryptRound(d)

  when not LE:
    encodeLE(state.toSliceArray(0, N div 8 - 1), output)

when defined(templateOpt):
  # ==========================================
  # Threefish-256 (32 Bytes Block) Templates
  # ==========================================
  template threefish256Init*(ctx: var Threefish256Ctx, key: array[32, uint8], tweak: array[2, uint64]): void =
    threefishInitC(ctx, key.toSliceArray(0, 31), tweak.toSliceArray(0, 1))
  template threefish256Init*(ctx: var Threefish256Ctx, key: openArray[uint8], tweak: openArray[uint64]): void =
    threefishInitC(ctx, key.toSliceArray(0, 31, 32), tweak.toSliceArray(0, 1, 2))
  template threefish256Init*(ctx: var Threefish256Ctx, key: slicearray[32, uint8], tweak: slicearray[2, uint64]): void =
    threefishInitC(ctx, key, tweak)
  template threefish256Init*(ctx: ptr Threefish256Ctx, key: ptr array[32, uint8], tweak: ptr array[2, uint64]): void =
    threefishInitC(ctx[], key.toSliceArray(0, 31), tweak.toSliceArray(0, 1))

  template threefish256Encrypt*(ctx: Threefish256Ctx, input: array[32, uint8], output: var array[32, uint8]): void =
    threefishEncryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))
  template threefish256Encrypt*(ctx: Threefish256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    threefishEncryptC(ctx, input.toSliceArray(0, 31, 32), output.toSliceArray(0, 31, 32))
  template threefish256Encrypt*(ctx: Threefish256Ctx, input, output: slicearray[32, uint8]): void =
    threefishEncryptC(ctx, input, output)
  template threefish256Encrypt*(ctx: Threefish256Ctx, input, output: ptr array[32, uint8]): void =
    threefishEncryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))

  template threefish256Decrypt*(ctx: Threefish256Ctx, input: array[32, uint8], output: var array[32, uint8]): void =
    threefishDecryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))
  template threefish256Decrypt*(ctx: Threefish256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    threefishDecryptC(ctx, input.toSliceArray(0, 31, 32), output.toSliceArray(0, 31, 32))
  template threefish256Decrypt*(ctx: Threefish256Ctx, input, output: slicearray[32, uint8]): void =
    threefishDecryptC(ctx, input, output)
  template threefish256Decrypt*(ctx: Threefish256Ctx, input, output: ptr array[32, uint8]): void =
    threefishDecryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))

  # ==========================================
  # Threefish-512 (64 Bytes Block) Templates
  # ==========================================
  template threefish512Init*(ctx: var Threefish512Ctx, key: array[64, uint8], tweak: array[2, uint64]): void =
    threefishInitC(ctx, key.toSliceArray(0, 63), tweak.toSliceArray(0, 1))
  template threefish512Init*(ctx: var Threefish512Ctx, key: openArray[uint8], tweak: openArray[uint64]): void =
    threefishInitC(ctx, key.toSliceArray(0, 63, 64), tweak.toSliceArray(0, 1, 2))
  template threefish512Init*(ctx: var Threefish512Ctx, key: slicearray[64, uint8], tweak: slicearray[2, uint64]): void =
    threefishInitC(ctx, key, tweak)
  template threefish512Init*(ctx: ptr Threefish512Ctx, key: ptr array[64, uint8], tweak: ptr array[2, uint64]): void =
    threefishInitC(ctx[], key.toSliceArray(0, 63), tweak.toSliceArray(0, 1))

  template threefish512Encrypt*(ctx: Threefish512Ctx, input: array[64, uint8], output: var array[64, uint8]): void =
    threefishEncryptC(ctx, input.toSliceArray(0, 63), output.toSliceArray(0, 63))
  template threefish512Encrypt*(ctx: Threefish512Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    threefishEncryptC(ctx, input.toSliceArray(0, 63, 64), output.toSliceArray(0, 63, 64))
  template threefish512Encrypt*(ctx: Threefish512Ctx, input, output: slicearray[64, uint8]): void =
    threefishEncryptC(ctx, input, output)
  template threefish512Encrypt*(ctx: Threefish512Ctx, input, output: ptr array[64, uint8]): void =
    threefishEncryptC(ctx, input.toSliceArray(0, 63), output.toSliceArray(0, 63))

  template threefish512Decrypt*(ctx: Threefish512Ctx, input: array[64, uint8], output: var array[64, uint8]): void =
    threefishDecryptC(ctx, input.toSliceArray(0, 63), output.toSliceArray(0, 63))
  template threefish512Decrypt*(ctx: Threefish512Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    threefishDecryptC(ctx, input.toSliceArray(0, 63, 64), output.toSliceArray(0, 63, 64))
  template threefish512Decrypt*(ctx: Threefish512Ctx, input, output: slicearray[64, uint8]): void =
    threefishDecryptC(ctx, input, output)
  template threefish512Decrypt*(ctx: Threefish512Ctx, input, output: ptr array[64, uint8]): void =
    threefishDecryptC(ctx, input.toSliceArray(0, 63), output.toSliceArray(0, 63))

  # ==========================================
  # Threefish-1024 (128 Bytes Block) Templates
  # ==========================================
  template threefish1024Init*(ctx: var Threefish1024Ctx, key: array[128, uint8], tweak: array[2, uint64]): void =
    threefishInitC(ctx, key.toSliceArray(0, 127), tweak.toSliceArray(0, 1))
  template threefish1024Init*(ctx: var Threefish1024Ctx, key: openArray[uint8], tweak: openArray[uint64]): void =
    threefishInitC(ctx, key.toSliceArray(0, 127, 128), tweak.toSliceArray(0, 1, 2))
  template threefish1024Init*(ctx: var Threefish1024Ctx, key: slicearray[128, uint8], tweak: slicearray[2, uint64]): void =
    threefishInitC(ctx, key, tweak)
  template threefish1024Init*(ctx: ptr Threefish1024Ctx, key: ptr array[128, uint8], tweak: ptr array[2, uint64]): void =
    threefishInitC(ctx[], key.toSliceArray(0, 127), tweak.toSliceArray(0, 1))

  template threefish1024Encrypt*(ctx: Threefish1024Ctx, input: array[128, uint8], output: var array[128, uint8]): void =
    threefishEncryptC(ctx, input.toSliceArray(0, 127), output.toSliceArray(0, 127))
  template threefish1024Encrypt*(ctx: Threefish1024Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    threefishEncryptC(ctx, input.toSliceArray(0, 127, 128), output.toSliceArray(0, 127, 128))
  template threefish1024Encrypt*(ctx: Threefish1024Ctx, input, output: slicearray[128, uint8]): void =
    threefishEncryptC(ctx, input, output)
  template threefish1024Encrypt*(ctx: Threefish1024Ctx, input, output: ptr array[128, uint8]): void =
    threefishEncryptC(ctx, input.toSliceArray(0, 127), output.toSliceArray(0, 127))

  template threefish1024Decrypt*(ctx: Threefish1024Ctx, input: array[128, uint8], output: var array[128, uint8]): void =
    threefishDecryptC(ctx, input.toSliceArray(0, 127), output.toSliceArray(0, 127))
  template threefish1024Decrypt*(ctx: Threefish1024Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    threefishDecryptC(ctx, input.toSliceArray(0, 127, 128), output.toSliceArray(0, 127, 128))
  template threefish1024Decrypt*(ctx: Threefish1024Ctx, input, output: slicearray[128, uint8]): void =
    threefishDecryptC(ctx, input, output)
  template threefish1024Decrypt*(ctx: Threefish1024Ctx, input, output: ptr array[128, uint8]): void =
    threefishDecryptC(ctx, input.toSliceArray(0, 127), output.toSliceArray(0, 127))

else:
  # ==========================================
  # Threefish-256 (32 Bytes Block) Procs
  # ==========================================
  proc threefish256Init*(ctx: var Threefish256Ctx, key: array[32, uint8], tweak: array[2, uint64]): void =
    threefishInitC(ctx, key.toSliceArray(0, 31), tweak.toSliceArray(0, 1))
  proc threefish256Init*(ctx: var Threefish256Ctx, key: openArray[uint8], tweak: openArray[uint64]): void =
    threefishInitC(ctx, key.toSliceArray(0, 31), tweak.toSliceArray(0, 1))
  proc threefish256Init*(ctx: var Threefish256Ctx, key: slicearray[32, uint8], tweak: slicearray[2, uint64]): void =
    threefishInitC(ctx, key, tweak)
  proc threefish256Init*(ctx: ptr Threefish256Ctx, key: ptr array[32, uint8], tweak: ptr array[2, uint64]): void {.importc: "threefish256Init", cdecl.} =
    threefishInitC(ctx[], key.toSliceArray(0, 31), tweak.toSliceArray(0, 1))

  proc threefish256Encrypt*(ctx: Threefish256Ctx, input: array[32, uint8], output: var array[32, uint8]): void =
    threefishEncryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))
  proc threefish256Encrypt*(ctx: Threefish256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    threefishEncryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))
  proc threefish256Encrypt*(ctx: Threefish256Ctx, input, output: slicearray[32, uint8]): void =
    threefishEncryptC(ctx, input, output)
  proc threefish256Encrypt*(ctx: Threefish256Ctx, input, output: ptr array[32, uint8]): void {.importc: "threefish256Encrypt", cdecl.} =
    threefishEncryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))

  proc threefish256Decrypt*(ctx: Threefish256Ctx, input: array[32, uint8], output: var array[32, uint8]): void =
    threefishDecryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))
  proc threefish256Decrypt*(ctx: Threefish256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    threefishDecryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))
  proc threefish256Decrypt*(ctx: Threefish256Ctx, input, output: slicearray[32, uint8]): void =
    threefishDecryptC(ctx, input, output)
  proc threefish256Decrypt*(ctx: Threefish256Ctx, input, output: ptr array[32, uint8]): void {.importc: "threefish256Decrypt", cdecl.} =
    threefishDecryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))

  # ==========================================
  # Threefish-512 (64 Bytes Block) Procs
  # ==========================================
  proc threefish512Init*(ctx: var Threefish512Ctx, key: array[64, uint8], tweak: array[2, uint64]): void =
    threefishInitC(ctx, key.toSliceArray(0, 63), tweak.toSliceArray(0, 1))
  proc threefish512Init*(ctx: var Threefish512Ctx, key: openArray[uint8], tweak: openArray[uint64]): void =
    threefishInitC(ctx, key.toSliceArray(0, 63), tweak.toSliceArray(0, 1))
  proc threefish512Init*(ctx: var Threefish512Ctx, key: slicearray[64, uint8], tweak: slicearray[2, uint64]): void =
    threefishInitC(ctx, key, tweak)
  proc threefish512Init*(ctx: ptr Threefish512Ctx, key: ptr array[64, uint8], tweak: ptr array[2, uint64]): void {.importc: "threefish512Init", cdecl.} =
    threefishInitC(ctx[], key.toSliceArray(0, 63), tweak.toSliceArray(0, 1))

  proc threefish512Encrypt*(ctx: Threefish512Ctx, input: array[64, uint8], output: var array[64, uint8]): void =
    threefishEncryptC(ctx, input.toSliceArray(0, 63), output.toSliceArray(0, 63))
  proc threefish512Encrypt*(ctx: Threefish512Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    threefishEncryptC(ctx, input.toSliceArray(0, 63), output.toSliceArray(0, 63))
  proc threefish512Encrypt*(ctx: Threefish512Ctx, input, output: slicearray[64, uint8]): void =
    threefishEncryptC(ctx, input, output)
  proc threefish512Encrypt*(ctx: Threefish512Ctx, input, output: ptr array[64, uint8]): void {.importc: "threefish512Encrypt", cdecl.} =
    threefishEncryptC(ctx, input.toSliceArray(0, 63), output.toSliceArray(0, 63))

  proc threefish512Decrypt*(ctx: Threefish512Ctx, input: array[64, uint8], output: var array[64, uint8]): void =
    threefishDecryptC(ctx, input.toSliceArray(0, 63), output.toSliceArray(0, 63))
  proc threefish512Decrypt*(ctx: Threefish512Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    threefishDecryptC(ctx, input.toSliceArray(0, 63), output.toSliceArray(0, 63))
  proc threefish512Decrypt*(ctx: Threefish512Ctx, input, output: slicearray[64, uint8]): void =
    threefishDecryptC(ctx, input, output)
  proc threefish512Decrypt*(ctx: Threefish512Ctx, input, output: ptr array[64, uint8]): void {.importc: "threefish512Decrypt", cdecl.} =
    threefishDecryptC(ctx, input.toSliceArray(0, 63), output.toSliceArray(0, 63))

  # ==========================================
  # Threefish-1024 (128 Bytes Block) Procs
  # ==========================================
  proc threefish1024Init*(ctx: var Threefish1024Ctx, key: array[128, uint8], tweak: array[2, uint64]): void =
    threefishInitC(ctx, key.toSliceArray(0, 127), tweak.toSliceArray(0, 1))
  proc threefish1024Init*(ctx: var Threefish1024Ctx, key: openArray[uint8], tweak: openArray[uint64]): void =
    threefishInitC(ctx, key.toSliceArray(0, 127), tweak.toSliceArray(0, 1))
  proc threefish1024Init*(ctx: var Threefish1024Ctx, key: slicearray[128, uint8], tweak: slicearray[2, uint64]): void =
    threefishInitC(ctx, key, tweak)
  proc threefish1024Init*(ctx: ptr Threefish1024Ctx, key: ptr array[128, uint8], tweak: ptr array[2, uint64]): void {.importc: "threefish1024Init", cdecl.} =
    threefishInitC(ctx[], key.toSliceArray(0, 127), tweak.toSliceArray(0, 1))

  proc threefish1024Encrypt*(ctx: Threefish1024Ctx, input: array[128, uint8], output: var array[128, uint8]): void =
    threefishEncryptC(ctx, input.toSliceArray(0, 127), output.toSliceArray(0, 127))
  proc threefish1024Encrypt*(ctx: Threefish1024Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    threefishEncryptC(ctx, input.toSliceArray(0, 127), output.toSliceArray(0, 127))
  proc threefish1024Encrypt*(ctx: Threefish1024Ctx, input, output: slicearray[128, uint8]): void =
    threefishEncryptC(ctx, input, output)
  proc threefish1024Encrypt*(ctx: Threefish1024Ctx, input, output: ptr array[128, uint8]): void {.importc: "threefish1024Encrypt", cdecl.} =
    threefishEncryptC(ctx, input.toSliceArray(0, 127), output.toSliceArray(0, 127))

  proc threefish1024Decrypt*(ctx: Threefish1024Ctx, input: array[128, uint8], output: var array[128, uint8]): void =
    threefishDecryptC(ctx, input.toSliceArray(0, 127), output.toSliceArray(0, 127))
  proc threefish1024Decrypt*(ctx: Threefish1024Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    threefishDecryptC(ctx, input.toSliceArray(0, 127), output.toSliceArray(0, 127))
  proc threefish1024Decrypt*(ctx: Threefish1024Ctx, input, output: slicearray[128, uint8]): void =
    threefishDecryptC(ctx, input, output)
  proc threefish1024Decrypt*(ctx: Threefish1024Ctx, input, output: ptr array[128, uint8]): void {.importc: "threefish1024Decrypt", cdecl.} =
    threefishDecryptC(ctx, input.toSliceArray(0, 127), output.toSliceArray(0, 127))
