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
  PS: uint16 = 0xB7E1'u16
  QS: uint16 = 0x9E37'u16
  PW: uint32 = 0xB7E15163'u32
  QW: uint32 = 0x9E3779B9'u32
  PL: uint64 = 0xB7E151628AED2A6B'u64
  QL: uint64 = 0x9E3779B97F4A7C15'u64

  MAX_ROUNDS*: int = 24
  RC5_ROUND_KEY_SIZE*: int = 2 * (MAX_ROUNDS + 1)
  

type
  RC5Ctx*[T: uint16|uint32|uint64] = object
    roundKey*: array[RC5_ROUND_KEY_SIZE, T]
    rounds*: int

  RC5_16Ctx* = RC5Ctx[uint16]
  RC5_32Ctx* = RC5Ctx[uint32]
  RC5_64Ctx* = RC5Ctx[uint64]

template rotateLeftBitsMod[T](x: T, y: T): T =
  let shift: int = int(y and (sizeof(T) * 8 - 1))
  rotateLeftBits(x, shift)

template rotateRightBitsMod[T](x: T, y: T): T =
  let shift: int = int(y and (sizeof(T) * 8 - 1))
  rotateRightBits(x, shift)

template rc5InitC[T: uint16|uint32|uint64](ctx: var RC5Ctx[T], key: openArray[uint8], roundsInput: int): void =
  let keyLen: int = key.len
  const U: int = sizeof(T)
  ctx.rounds = min(MAX_ROUNDS, roundsInput)
  const P = when T is uint16: PS elif T is uint32: PW else: PL
  const Q = when T is uint16: QS elif T is uint32: QW else: QL

  let actualKey: int = 2 * (ctx.rounds + 1)
  var c: int = (keyLen + U - 1) div U
  if c == 0: c = 1

  var l: array[64, T]

  var limit: int = min(keyLen, U * 64)
  for i in 0 ..< limit:
    l[i div U] = l[i div U] or (T(key[i]) shl ((i mod U) * 8))

  ctx.roundKey[0] = P
  for j in 1 ..< actualKey:
    ctx.roundKey[j] = ctx.roundKey[j - 1] + Q

  var a: T = 0
  var b: T = 0
  var ii: int = 0
  var jj: int = 0

  let n: int = 3 * max(actualKey, c)

  for h in 0 ..< n:
    ctx.roundKey[ii] = rotateLeftBits(ctx.roundKey[ii] + a + b, 3)
    a = ctx.roundKey[ii]

    l[jj] = rotateLeftBitsMod(l[jj] + a + b, a + b)
    b = l[jj]

    ii = (ii + 1) mod actualKey
    jj = (jj + 1) mod c

template rc5EncryptC*[T; N: static int](ctx: RC5Ctx[T], input, output: slicearray[N, uint8]): void =
  const U: int = sizeof(T)
  static: doAssert N == U * 2
  let roundsNumber: int = ctx.rounds

  var a, b: T
  fromBytesLE(input.toSliceArray(0, U - 1), a)
  fromBytesLE(input.toSliceArray(U, U * 2 - 1), b)

  a += ctx.roundKey[0]
  b += ctx.roundKey[1]

  for i in 0 ..< roundsNumber:
    a = rotateLeftBitsMod(a xor b, b) + ctx.roundKey[2 * i + 2]
    b = rotateLeftBitsMod(a xor b, a) + ctx.roundKey[2 * i + 3]

  toBytesLE(a, output.toSliceArray(0, U - 1))
  toBytesLE(b, output.toSliceArray(U, U * 2 - 1))

template rc5DecryptC*[T; N: static int](ctx: RC5Ctx[T], input, output: slicearray[N, uint8]) =
  const U: int = sizeof(T)
  static: doAssert N == U * 2
  let roundsNumber: int = ctx.rounds

  var a, b: T
  fromBytesLE(input.toSliceArray(0, U - 1), a)
  fromBytesLE(input.toSliceArray(U, U * 2 - 1), b)

  for i in countdown(roundsNumber - 1, 0):
    b = rotateRightBitsMod(b - ctx.roundKey[2 * i + 3], a) xor a
    a = rotateRightBitsMod(a - ctx.roundKey[2 * i + 2], b) xor b

  b -= ctx.roundKey[1]
  a -= ctx.roundKey[0]

  toBytesLE(a, output.toSliceArray(0, U - 1))
  toBytesLE(b, output.toSliceArray(U, U * 2 - 1))

# ==============================================================================
# RC5 Export Wrappers (Full Explicit Implementation)
# ==============================================================================

when defined(templateOpt):
  # --------------------------------------------------------------------------
  # RC5-16 (uint16, Block Size: 4 Bytes)
  # --------------------------------------------------------------------------
  template rc5_16Init*(ctx: var RC5_16Ctx, key: openArray[uint8], rounds: int): void = rc5InitC(ctx, key, rounds)
  template rc5_16Init*(ctx: ptr RC5_16Ctx, key: ptr UncheckedArray[uint8], keyLen: int, rounds: int): void = rc5InitC(ctx[], key.toOpenArray(0, keyLen - 1), rounds)

  template rc5_16Encrypt*(ctx: RC5_16Ctx, input: array[4, uint8], output: var array[4, uint8]): void = rc5EncryptC(ctx, input.toSliceArray(0, 3), output.toSliceArray(0, 3))
  template rc5_16Encrypt*(ctx: RC5_16Ctx, input, output: slicearray[4, uint8]): void = rc5EncryptC(ctx, input, output)
  template rc5_16Encrypt*(ctx: RC5_16Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc5EncryptC(ctx, input.toSliceArray(0, 3), output.toSliceArray(0, 3))
  template rc5_16Encrypt*(ctx: ptr RC5_16Ctx, input, output: ptr array[4, uint8]): void = rc5EncryptC(ctx[], input.toSliceArray(0, 3), output.toSliceArray(0, 3))

  template rc5_16Decrypt*(ctx: RC5_16Ctx, input: array[4, uint8], output: var array[4, uint8]): void = rc5DecryptC(ctx, input.toSliceArray(0, 3), output.toSliceArray(0, 3))
  template rc5_16Decrypt*(ctx: RC5_16Ctx, input, output: slicearray[4, uint8]): void = rc5DecryptC(ctx, input, output)
  template rc5_16Decrypt*(ctx: RC5_16Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc5DecryptC(ctx, input.toSliceArray(0, 3), output.toSliceArray(0, 3))
  template rc5_16Decrypt*(ctx: ptr RC5_16Ctx, input, output: ptr array[4, uint8]): void = rc5DecryptC(ctx[], input.toSliceArray(0, 3), output.toSliceArray(0, 3))

  # --------------------------------------------------------------------------
  # RC5-32 (uint32, Block Size: 8 Bytes)
  # --------------------------------------------------------------------------
  template rc5_32Init*(ctx: var RC5_32Ctx, key: openArray[uint8], rounds: int): void = rc5InitC(ctx, key, rounds)
  template rc5_32Init*(ctx: ptr RC5_32Ctx, key: ptr UncheckedArray[uint8], keyLen: int, rounds: int): void = rc5InitC(ctx[], key.toOpenArray(0, keyLen - 1), rounds)

  template rc5_32Encrypt*(ctx: RC5_32Ctx, input: array[8, uint8], output: var array[8, uint8]): void = rc5EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template rc5_32Encrypt*(ctx: RC5_32Ctx, input, output: slicearray[8, uint8]): void = rc5EncryptC(ctx, input, output)
  template rc5_32Encrypt*(ctx: RC5_32Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc5EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template rc5_32Encrypt*(ctx: ptr RC5_32Ctx, input, output: ptr array[8, uint8]): void = rc5EncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  template rc5_32Decrypt*(ctx: RC5_32Ctx, input: array[8, uint8], output: var array[8, uint8]): void = rc5DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template rc5_32Decrypt*(ctx: RC5_32Ctx, input, output: slicearray[8, uint8]): void = rc5DecryptC(ctx, input, output)
  template rc5_32Decrypt*(ctx: RC5_32Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc5DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template rc5_32Decrypt*(ctx: ptr RC5_32Ctx, input, output: ptr array[8, uint8]): void = rc5DecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  # --------------------------------------------------------------------------
  # RC5-64 (uint64, Block Size: 16 Bytes)
  # --------------------------------------------------------------------------
  template rc5_64Init*(ctx: var RC5_64Ctx, key: openArray[uint8], rounds: int): void = rc5InitC(ctx, key, rounds)
  template rc5_64Init*(ctx: ptr RC5_64Ctx, key: ptr UncheckedArray[uint8], keyLen: int, rounds: int): void = rc5InitC(ctx[], key.toOpenArray(0, keyLen - 1), rounds)

  template rc5_64Encrypt*(ctx: RC5_64Ctx, input: array[16, uint8], output: var array[16, uint8]): void = rc5EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template rc5_64Encrypt*(ctx: RC5_64Ctx, input, output: slicearray[16, uint8]): void = rc5EncryptC(ctx, input, output)
  template rc5_64Encrypt*(ctx: RC5_64Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc5EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template rc5_64Encrypt*(ctx: ptr RC5_64Ctx, input, output: ptr array[16, uint8]): void = rc5EncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template rc5_64Decrypt*(ctx: RC5_64Ctx, input: array[16, uint8], output: var array[16, uint8]): void = rc5DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template rc5_64Decrypt*(ctx: RC5_64Ctx, input, output: slicearray[16, uint8]): void = rc5DecryptC(ctx, input, output)
  template rc5_64Decrypt*(ctx: RC5_64Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc5DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template rc5_64Decrypt*(ctx: ptr RC5_64Ctx, input, output: ptr array[16, uint8]): void = rc5DecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

else:
  # --------------------------------------------------------------------------
  # RC5-16 (uint16, Block Size: 4 Bytes)
  # --------------------------------------------------------------------------
  proc rc5_16Init*(ctx: var RC5_16Ctx, key: openArray[uint8], rounds: int): void = rc5InitC(ctx, key, rounds)
  proc rc5_16Init*(ctx: ptr RC5_16Ctx, key: ptr UncheckedArray[uint8], keyLen: int, rounds: int) {.exportc: "rc5_16Init", cdecl.} = rc5InitC(ctx[], key.toOpenArray(0, keyLen - 1), rounds)

  proc rc5_16Encrypt*(ctx: RC5_16Ctx, input: array[4, uint8], output: var array[4, uint8]): void = rc5EncryptC(ctx, input.toSliceArray(0, 3), output.toSliceArray(0, 3))
  proc rc5_16Encrypt*(ctx: RC5_16Ctx, input, output: slicearray[4, uint8]): void = rc5EncryptC(ctx, input, output)
  proc rc5_16Encrypt*(ctx: RC5_16Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc5EncryptC(ctx, input.toSliceArray(0, 3), output.toSliceArray(0, 3))
  proc rc5_16Encrypt*(ctx: ptr RC5_16Ctx, input, output: ptr array[4, uint8]) {.exportc: "rc5_16Encrypt", cdecl.} = rc5EncryptC(ctx[], input.toSliceArray(0, 3), output.toSliceArray(0, 3))

  proc rc5_16Decrypt*(ctx: RC5_16Ctx, input: array[4, uint8], output: var array[4, uint8]): void = rc5DecryptC(ctx, input.toSliceArray(0, 3), output.toSliceArray(0, 3))
  proc rc5_16Decrypt*(ctx: RC5_16Ctx, input, output: slicearray[4, uint8]): void = rc5DecryptC(ctx, input, output)
  proc rc5_16Decrypt*(ctx: RC5_16Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc5DecryptC(ctx, input.toSliceArray(0, 3), output.toSliceArray(0, 3))
  proc rc5_16Decrypt*(ctx: ptr RC5_16Ctx, input, output: ptr array[4, uint8]) {.exportc: "rc5_16Decrypt", cdecl.} = rc5DecryptC(ctx[], input.toSliceArray(0, 3), output.toSliceArray(0, 3))

  # --------------------------------------------------------------------------
  # RC5-32 (uint32, Block Size: 8 Bytes)
  # --------------------------------------------------------------------------
  proc rc5_32Init*(ctx: var RC5_32Ctx, key: openArray[uint8], rounds: int): void = rc5InitC(ctx, key, rounds)
  proc rc5_32Init*(ctx: ptr RC5_32Ctx, key: ptr UncheckedArray[uint8], keyLen: int, rounds: int) {.exportc: "rc5_32Init", cdecl.} = rc5InitC(ctx[], key.toOpenArray(0, keyLen - 1), rounds)

  proc rc5_32Encrypt*(ctx: RC5_32Ctx, input: array[8, uint8], output: var array[8, uint8]): void = rc5EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc rc5_32Encrypt*(ctx: RC5_32Ctx, input, output: slicearray[8, uint8]): void = rc5EncryptC(ctx, input, output)
  proc rc5_32Encrypt*(ctx: RC5_32Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc5EncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc rc5_32Encrypt*(ctx: ptr RC5_32Ctx, input, output: ptr array[8, uint8]) {.exportc: "rc5_32Encrypt", cdecl.} = rc5EncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  proc rc5_32Decrypt*(ctx: RC5_32Ctx, input: array[8, uint8], output: var array[8, uint8]): void = rc5DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc rc5_32Decrypt*(ctx: RC5_32Ctx, input, output: slicearray[8, uint8]): void = rc5DecryptC(ctx, input, output)
  proc rc5_32Decrypt*(ctx: RC5_32Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc5DecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc rc5_32Decrypt*(ctx: ptr RC5_32Ctx, input, output: ptr array[8, uint8]) {.exportc: "rc5_32Decrypt", cdecl.} = rc5DecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  # --------------------------------------------------------------------------
  # RC5-64 (uint64, Block Size: 16 Bytes)
  # --------------------------------------------------------------------------
  proc rc5_64Init*(ctx: var RC5_64Ctx, key: openArray[uint8], rounds: int): void = rc5InitC(ctx, key, rounds)
  proc rc5_64Init*(ctx: ptr RC5_64Ctx, key: ptr UncheckedArray[uint8], keyLen: int, rounds: int) {.exportc: "rc5_64Init", cdecl.} = rc5InitC(ctx[], key.toOpenArray(0, keyLen - 1), rounds)

  proc rc5_64Encrypt*(ctx: RC5_64Ctx, input: array[16, uint8], output: var array[16, uint8]): void = rc5EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc rc5_64Encrypt*(ctx: RC5_64Ctx, input, output: slicearray[16, uint8]): void = rc5EncryptC(ctx, input, output)
  proc rc5_64Encrypt*(ctx: RC5_64Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc5EncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc rc5_64Encrypt*(ctx: ptr RC5_64Ctx, input, output: ptr array[16, uint8]) {.exportc: "rc5_64Encrypt", cdecl.} = rc5EncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc rc5_64Decrypt*(ctx: RC5_64Ctx, input: array[16, uint8], output: var array[16, uint8]): void = rc5DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc rc5_64Decrypt*(ctx: RC5_64Ctx, input, output: slicearray[16, uint8]): void = rc5DecryptC(ctx, input, output)
  proc rc5_64Decrypt*(ctx: RC5_64Ctx, input: openArray[uint8], output: var openArray[uint8]): void = rc5DecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc rc5_64Decrypt*(ctx: ptr RC5_64Ctx, input, output: ptr array[16, uint8]) {.exportc: "rc5_64Decrypt", cdecl.} = rc5DecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))
