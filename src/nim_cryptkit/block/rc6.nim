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
  MAX_ROUNDS*: int = 24
  MAX_KEY_WORDS*: int = 2 * (MAX_ROUNDS + 2)

  PS: uint16 = 0xB7E1'u16
  QS: uint16 = 0x9E37'u16
  PW: uint32 = 0xB7E15163'u32
  QW: uint32 = 0x9E3779B9'u32
  PL: uint64 = 0xB7E151628AED2A6B'u64
  QL: uint64 = 0x9E3779B97F4A7C15'u64

type
  RC6Ctx*[T: uint16|uint32|uint64] = object
    rounds*: int
    roundKey*: array[MAX_KEY_WORDS, T]

  RC6_16Ctx* = RC6Ctx[uint16]
  RC6_32Ctx* = RC6Ctx[uint32]
  RC6_64Ctx* = RC6Ctx[uint64]

template rotateLeftBitsMod[T](x: T, y: T): T =
  let shift: int = int(y and (sizeof(T) * 8 - 1))
  rotateLeftBits(x, shift)

template rotateRightBitsMod[T](x: T, y: T): T =
  let shift: int = int(y and (sizeof(T) * 8 - 1))
  rotateRightBits(x, shift)

template rc6InitC[T](ctx: var RC6Ctx[T], key: openArray[uint8], roundsNumber: int): void =
  ctx.rounds = min(MAX_ROUNDS, roundsNumber)
  const U: int = sizeof(T)
  let keyLen: int = key.len
  const P = when T is uint16: PS elif T is uint32: PW else: PL
  const Q = when T is uint16: QS elif T is uint32: QW else: QL

  let actualKey: int = 2 * (ctx.rounds + 2)
  var c: int = (keyLen + U - 1) div U
  if c == 0: c = 1

  var l: array[64, T]
  let limit: int = min(keyLen, U * 64)
  for i in 0 ..< limit:
    l[i div U] = l[i div U] or (T(key[i]) shl ((i mod U) * 8))

  ctx.roundKey[0] = P
  for j in 1 ..< actualKey:
    ctx.roundKey[j] = ctx.roundKey[j - 1] + Q

  var a: T = 0
  var b: T = 0
  var ii: int = 0
  var jj: int = 0

  let n = 3 * max(actualKey, c)

  for h in 0 ..< n:
    ctx.roundKey[ii] = rotateLeftBits(ctx.roundKey[ii] + a + b, 3)
    a = ctx.roundKey[ii]

    l[jj] = rotateLeftBitsMod(l[jj] + a + b, a + b)
    b = l[jj]

    ii += 1
    if ii >= actualKey: ii = 0
    jj += 1
    if jj >= c: jj = 0

template rc6EncryptC[T; N: static int](ctx: RC6Ctx[T], input, output: slicearray[N, uint8]): void =
  const U: int = sizeof(T)
  static: doAssert N == U * 4
  let roundsNumber: int = ctx.rounds
  const ROT: int = when T is uint16: 4 elif T is uint32: 5 elif T is uint64: 6 else: 0

  var a, b, c, d: T
  fromBytesLE(input.toSliceArray(U * 0, U * 1 - 1), a)
  fromBytesLE(input.toSliceArray(U * 1, U * 2 - 1), b)
  fromBytesLE(input.toSliceArray(U * 2, U * 3 - 1), c)
  fromBytesLE(input.toSliceArray(U * 3, U * 4 - 1), d)

  b += ctx.roundKey[0]
  d += ctx.roundKey[1]

  var t, u: T

  for i in 0 ..< ctx.rounds:
    t = rotateLeftBits(b * (T(2) * b + T(1)), ROT)
    u = rotateLeftBits(d * (T(2) * d + T(1)), ROT)

    a = rotateLeftBitsMod(a xor t, u) + ctx.roundKey[2 * i + 2]
    c = rotateLeftBitsMod(c xor u, t) + ctx.roundKey[2 * i + 3]

    let temp: T = a
    a = b
    b = c
    c = d
    d = temp

  a += ctx.roundKey[2 * roundsNumber + 2]
  c += ctx.roundKey[2 * roundsNumber + 3]

  toBytesLE(a, output.toSliceArray(U * 0, U * 1 - 1))
  toBytesLE(b, output.toSliceArray(U * 1, U * 2 - 1))
  toBytesLE(c, output.toSliceArray(U * 2, U * 3 - 1))
  toBytesLE(d, output.toSliceArray(U * 3, U * 4 - 1))

template rc6DecryptC[T; N: static int](ctx: RC6Ctx[T], input, output: slicearray[N, uint8]): void =
  const U: int = sizeof(T)
  static: doAssert N == U * 4
  const ROT: int = when T is uint16: 4 elif T is uint32: 5 elif T is uint64: 6 else: 0
  let roundsNumber: int = ctx.rounds

  var a, b, c, d: T
  fromBytesLE(input.toSliceArray(U * 0, U * 1 - 1), a)
  fromBytesLE(input.toSliceArray(U * 1, U * 2 - 1), b)
  fromBytesLE(input.toSliceArray(U * 2, U * 3 - 1), c)
  fromBytesLE(input.toSliceArray(U * 3, U * 4 - 1), d)

  c -= ctx.roundKey[2 * roundsNumber + 3]
  a -= ctx.roundKey[2 * roundsNumber + 2]

  var u, t: T

  for i in countdown(ctx.rounds - 1, 0):
    let temp: T = d
    d = c
    c = b
    b = a
    a = temp

    u = rotateLeftBits(d * (T(2) * d + T(1)), ROT)
    t = rotateLeftBits(b * (T(2) * b + T(1)), ROT)

    c = rotateRightBitsMod(c - ctx.roundKey[2 * i + 3], t) xor u
    a = rotateRightBitsMod(a - ctx.roundKey[2 * i + 2], u) xor t

  d -= ctx.roundKey[1]
  b -= ctx.roundKey[0]

  toBytesLE(a, output.toSliceArray(U * 0, U * 1 - 1))
  toBytesLE(b, output.toSliceArray(U * 1, U * 2 - 1))
  toBytesLE(c, output.toSliceArray(U * 2, U * 3 - 1))
  toBytesLE(d, output.toSliceArray(U * 3, U * 4 - 1))

# ==============================================================================
# RC6 Export Wrappers (Full Explicit Implementation with Context Aliases)
# ==============================================================================

when defined(templateOpt):
  # --------------------------------------------------------------------------
  # RC6-16 (uint16, Block Size: 8 Bytes)
  # --------------------------------------------------------------------------
  template rc6_16Init*(ctx: var RC6_16Ctx, key: openArray[uint8], rounds: int = 20): void = rc6InitC(ctx, key, rounds)
  template rc6_16Init*(ctx: ptr RC6_16Ctx, key: ptr UncheckedArray[uint8], keyLen: int, rounds: int = 20): void = rc6InitC(ctx[], key.toOpenArray(0, keyLen - 1), rounds)

  template rc6_16Encrypt*(ctx: RC6_16Ctx, input: array[8, uint8], output: var array[8, uint8]): void = rc6EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template rc6_16Encrypt*(ctx: RC6_16Ctx, input, output: slicearray[8, uint8]): void = rc6EncryptC(ctx, input, output)
  template rc6_16Encrypt*(ctx: RC6_16Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc6EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template rc6_16Encrypt*(ctx: ptr RC6_16Ctx, input, output: ptr array[8, uint8]): void = rc6EncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  template rc6_16Decrypt*(ctx: RC6_16Ctx, input: array[8, uint8], output: var array[8, uint8]): void = rc6DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template rc6_16Decrypt*(ctx: RC6_16Ctx, input, output: slicearray[8, uint8]): void = rc6DecryptC(ctx, input, output)
  template rc6_16Decrypt*(ctx: RC6_16Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc6DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template rc6_16Decrypt*(ctx: ptr RC6_16Ctx, input, output: ptr array[8, uint8]): void = rc6DecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  # --------------------------------------------------------------------------
  # RC6-32 (uint32, Block Size: 16 Bytes)
  # --------------------------------------------------------------------------
  template rc6_32Init*(ctx: var RC6_32Ctx, key: openArray[uint8], rounds: int = 20): void = rc6InitC(ctx, key, rounds)
  template rc6_32Init*(ctx: ptr RC6_32Ctx, key: ptr UncheckedArray[uint8], keyLen: int, rounds: int = 20): void = rc6InitC(ctx[], key.toOpenArray(0, keyLen - 1), rounds)

  template rc6_32Encrypt*(ctx: RC6_32Ctx, input: array[16, uint8], output: var array[16, uint8]): void = rc6EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template rc6_32Encrypt*(ctx: RC6_32Ctx, input, output: slicearray[16, uint8]): void = rc6EncryptC(ctx, input, output)
  template rc6_32Encrypt*(ctx: RC6_32Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc6EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template rc6_32Encrypt*(ctx: ptr RC6_32Ctx, input, output: ptr array[16, uint8]): void = rc6EncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template rc6_32Decrypt*(ctx: RC6_32Ctx, input: array[16, uint8], output: var array[16, uint8]): void = rc6DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template rc6_32Decrypt*(ctx: RC6_32Ctx, input, output: slicearray[16, uint8]): void = rc6DecryptC(ctx, input, output)
  template rc6_32Decrypt*(ctx: RC6_32Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc6DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template rc6_32Decrypt*(ctx: ptr RC6_32Ctx, input, output: ptr array[16, uint8]): void = rc6DecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # --------------------------------------------------------------------------
  # RC6-64 (uint64, Block Size: 32 Bytes)
  # --------------------------------------------------------------------------
  template rc6_64Init*(ctx: var RC6_64Ctx, key: openArray[uint8], rounds: int = 20): void = rc6InitC(ctx, key, rounds)
  template rc6_64Init*(ctx: ptr RC6_64Ctx, key: ptr UncheckedArray[uint8], keyLen: int, rounds: int = 20): void = rc6InitC(ctx[], key.toOpenArray(0, keyLen - 1), rounds)

  template rc6_64Encrypt*(ctx: RC6_64Ctx, input: array[32, uint8], output: var array[32, uint8]): void = rc6EncryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))
  template rc6_64Encrypt*(ctx: RC6_64Ctx, input, output: slicearray[32, uint8]): void = rc6EncryptC(ctx, input, output)
  template rc6_64Encrypt*(ctx: RC6_64Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc6EncryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))
  template rc6_64Encrypt*(ctx: ptr RC6_64Ctx, input, output: ptr array[32, uint8]): void = rc6EncryptC(ctx[], input.toSliceArray(0, 31), output.toSliceArray(0, 31))

  template rc6_64Decrypt*(ctx: RC6_64Ctx, input: array[32, uint8], output: var array[32, uint8]): void = rc6DecryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))
  template rc6_64Decrypt*(ctx: RC6_64Ctx, input, output: slicearray[32, uint8]): void = rc6DecryptC(ctx, input, output)
  template rc6_64Decrypt*(ctx: RC6_64Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc6DecryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))
  template rc6_64Decrypt*(ctx: ptr RC6_64Ctx, input, output: ptr array[32, uint8]): void = rc6DecryptC(ctx[], input.toSliceArray(0, 31), output.toSliceArray(0, 31))

else:
  # --------------------------------------------------------------------------
  # RC6-16 (uint16, Block Size: 8 Bytes)
  # --------------------------------------------------------------------------
  proc rc6_16Init*(ctx: var RC6_16Ctx, key: openArray[uint8], rounds: int = 20): void = rc6InitC(ctx, key, rounds)
  proc rc6_16Init*(ctx: ptr RC6_16Ctx, key: ptr UncheckedArray[uint8], keyLen: int, rounds: int = 20) {.exportc: "rc6_16Init", cdecl.} = rc6InitC(ctx[], key.toOpenArray(0, keyLen - 1), rounds)

  proc rc6_16Encrypt*(ctx: RC6_16Ctx, input: array[8, uint8], output: var array[8, uint8]): void = rc6EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc rc6_16Encrypt*(ctx: RC6_16Ctx, input, output: slicearray[8, uint8]): void = rc6EncryptC(ctx, input, output)
  proc rc6_16Encrypt*(ctx: RC6_16Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc6EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc rc6_16Encrypt*(ctx: ptr RC6_16Ctx, input, output: ptr array[8, uint8]) {.exportc: "rc6_16Encrypt", cdecl.} = rc6EncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  proc rc6_16Decrypt*(ctx: RC6_16Ctx, input: array[8, uint8], output: var array[8, uint8]): void = rc6DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc rc6_16Decrypt*(ctx: RC6_16Ctx, input, output: slicearray[8, uint8]): void = rc6DecryptC(ctx, input, output)
  proc rc6_16Decrypt*(ctx: RC6_16Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc6DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc rc6_16Decrypt*(ctx: ptr RC6_16Ctx, input, output: ptr array[8, uint8]) {.exportc: "rc6_16Decrypt", cdecl.} = rc6DecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  # --------------------------------------------------------------------------
  # RC6-32 (uint32, Block Size: 16 Bytes)
  # --------------------------------------------------------------------------
  proc rc6_32Init*(ctx: var RC6_32Ctx, key: openArray[uint8], rounds: int = 20): void = rc6InitC(ctx, key, rounds)
  proc rc6_32Init*(ctx: ptr RC6_32Ctx, key: ptr UncheckedArray[uint8], keyLen: int, rounds: int = 20) {.exportc: "rc6_32Init", cdecl.} = rc6InitC(ctx[], key.toOpenArray(0, keyLen - 1), rounds)

  proc rc6_32Encrypt*(ctx: RC6_32Ctx, input: array[16, uint8], output: var array[16, uint8]): void = rc6EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc rc6_32Encrypt*(ctx: RC6_32Ctx, input, output: slicearray[16, uint8]): void = rc6EncryptC(ctx, input, output)
  proc rc6_32Encrypt*(ctx: RC6_32Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc6EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc rc6_32Encrypt*(ctx: ptr RC6_32Ctx, input, output: ptr array[16, uint8]) {.exportc: "rc6_32Encrypt", cdecl.} = rc6EncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc rc6_32Decrypt*(ctx: RC6_32Ctx, input: array[16, uint8], output: var array[16, uint8]): void = rc6DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc rc6_32Decrypt*(ctx: RC6_32Ctx, input, output: slicearray[16, uint8]): void = rc6DecryptC(ctx, input, output)
  proc rc6_32Decrypt*(ctx: RC6_32Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc6DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc rc6_32Decrypt*(ctx: ptr RC6_32Ctx, input, output: ptr array[16, uint8]) {.exportc: "rc6_32Decrypt", cdecl.} = rc6DecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # --------------------------------------------------------------------------
  # RC6-64 (uint64, Block Size: 32 Bytes)
  # --------------------------------------------------------------------------
  proc rc6_64Init*(ctx: var RC6_64Ctx, key: openArray[uint8], rounds: int = 20): void = rc6InitC(ctx, key, rounds)
  proc rc6_64Init*(ctx: ptr RC6_64Ctx, key: ptr UncheckedArray[uint8], keyLen: int, rounds: int = 20) {.exportc: "rc6_64Init", cdecl.} = rc6InitC(ctx[], key.toOpenArray(0, keyLen - 1), rounds)

  proc rc6_64Encrypt*(ctx: RC6_64Ctx, input: array[32, uint8], output: var array[32, uint8]): void = rc6EncryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))
  proc rc6_64Encrypt*(ctx: RC6_64Ctx, input, output: slicearray[32, uint8]): void = rc6EncryptC(ctx, input, output)
  proc rc6_64Encrypt*(ctx: RC6_64Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc6EncryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))
  proc rc6_64Encrypt*(ctx: ptr RC6_64Ctx, input, output: ptr array[32, uint8]) {.exportc: "rc6_64Encrypt", cdecl.} = rc6EncryptC(ctx[], input.toSliceArray(0, 31), output.toSliceArray(0, 31))

  proc rc6_64Decrypt*(ctx: RC6_64Ctx, input: array[32, uint8], output: var array[32, uint8]): void = rc6DecryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))
  proc rc6_64Decrypt*(ctx: RC6_64Ctx, input, output: slicearray[32, uint8]): void = rc6DecryptC(ctx, input, output)
  proc rc6_64Decrypt*(ctx: RC6_64Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc6DecryptC(ctx, input.toSliceArray(0, 31), output.toSliceArray(0, 31))
  proc rc6_64Decrypt*(ctx: ptr RC6_64Ctx, input, output: ptr array[32, uint8]) {.exportc: "rc6_64Decrypt", cdecl.} = rc6DecryptC(ctx[], input.toSliceArray(0, 31), output.toSliceArray(0, 31))
