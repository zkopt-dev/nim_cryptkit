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

template roundNumber*[T](keySize: static int): static int =
  when T is uint32:
    when keySize == 12: 26
    elif keySize == 16: 27
    else: {.error: "Invalid key size for uint32 (SPECK64). Supported: 12 or 16 bytes.".}
  elif T is uint64:
    when keySize == 16: 32
    elif keySize == 24: 33
    elif keySize == 32: 34
    else: {.error: "Invalid key size for uint64 (SPECK128). Supported: 16, 24, or 32 bytes.".}
  else:
    {.error: "Unsupported word block type. Only uint32 and uint64 are allowed for this specification.".}

type
  SpeckCtx*[T: uint32|uint64, keySize: static int] = object
    roundKey*: array[roundNumber[T](keySize), T]

  Speck_64_96Ctx* = SpeckCtx[uint32, 12]
  Speck_64_128Ctx* = SpeckCtx[uint32, 16]
  Speck_128_128Ctx* = SpeckCtx[uint64, 16]
  Speck_128_192Ctx* = SpeckCtx[uint64, 24]
  Speck_128_256Ctx* = SpeckCtx[uint64, 32]

template ER[T: uint32|uint64](x, y, k: T): void =
  x = rotateRightBits(x, 8)
  x += y
  x = x xor k
  y = rotateLeftBits(y, 3)
  y = y xor x

template DR[T: uint32|uint64](x, y, k: T): void =
  y = y xor x
  y = rotateRightBits(y, 3)
  x = x xor k
  x -= y
  x = rotateLeftBits(x, 8)

template speckInitC*[T: uint32|uint64, keySize, K: static int](ctx: var SpeckCtx[T, keySize], key: slicearray[K, uint8]): void =
  const U: int = sizeof(T)
  const R: int = roundNumber[T](keySize)
  const M: int = K div U

  static:
    doAssert K == keySize, "The slicearray size (K) must match the configured keySize."
    doAssert K mod U == 0, "Key size is not a multiple of the word alignment size."

  when T is uint32:
    when keySize == 12:
      var a, b, c: uint32
      fromBytesLE(key.toSliceArray(0, 3), a)
      fromBytesLE(key.toSliceArray(4, 7), b)
      fromBytesLE(key.toSliceArray(8, 11), c)

      for i in static(0 ..< 13):
        ctx.roundKey[i * 2 + 0] = a; ER(b, a, uint32(i * 2 + 0))
        ctx.roundKey[i * 2 + 1] = a; ER(c, a, uint32(i * 2 + 1))
    elif keySize == 16:
      var a, b, c, d: uint32
      fromBytesLE(key.toSliceArray(0, 3), a)
      fromBytesLE(key.toSliceArray(4, 7), b)
      fromBytesLE(key.toSliceArray(8, 11), c)
      fromBytesLE(key.toSliceArray(12, 15), d)

      for i in static(0 ..< 9):
        ctx.roundKey[i * 3 + 0] = a; ER(b, a, uint32(i * 3 + 0))
        ctx.roundKey[i * 3 + 1] = a; ER(c, a, uint32(i * 3 + 1))
        ctx.roundKey[i * 3 + 2] = a; ER(d, a, uint32(i * 3 + 2))
  elif T is uint64:
    when keySize == 16:
      var a, b: uint64
      fromBytesLE(key.toSliceArray(0, 7), a)
      fromBytesLE(key.toSliceArray(8, 15), b)

      for i in static(0 ..< 31):
        ctx.roundKey[i] = a; ER(b, a, uint64(i))
      ctx.roundKey[31] = a
    elif keySize == 24:
      var a, b, c: uint64
      fromBytesLE(key.toSliceArray(0, 7), a)
      fromBytesLE(key.toSliceArray(8, 15), b)
      fromBytesLE(key.toSliceArray(16, 23), c)

      for i in static(0 ..< 16):
        ctx.roundKey[i * 2 + 0] = a; ER(b, a, uint64(i * 2 + 0))
        ctx.roundKey[i * 2 + 1] = a; ER(c, a, uint64(i * 2 + 1))
      ctx.roundKey[32] = a
    elif keySize == 32:
      var a, b, c, d: uint64
      fromBytesLE(key.toSliceArray(0, 7), a)
      fromBytesLE(key.toSliceArray(8, 15), b)
      fromBytesLE(key.toSliceArray(16, 23), c)
      fromBytesLE(key.toSliceArray(24, 31), d)

      for i in static(0 ..< 11):
        ctx.roundKey[i * 3 + 0] = a; ER(b, a, uint64(i * 3 + 0))
        ctx.roundKey[i * 3 + 1] = a; ER(c, a, uint64(i * 3 + 1))
        ctx.roundKey[i * 3 + 2] = a; ER(d, a, uint64(i * 3 + 2))
      ctx.roundKey[33] = a

template speckEncryptC*[T: uint32|uint64, keySize, N: static int](ctx: SpeckCtx[T, keySize], input, output: slicearray[N, uint8]): void =
  const U: int = sizeof(T)
  const R: int = roundNumber[T](keySize)
  static: doAssert N == U * 2, "Input/Output block byte size does not match the configured word specification."

  var x, y: T
  fromBytesLE(input.toSliceArray(U * 0, U * 1 - 1), x)
  fromBytesLE(input.toSliceArray(U * 1, U * 2 - 1), y)

  for i in static(0 ..< R):
    ER(y, x, ctx.roundKey[i])

  toBytesLE(x, output.toSliceArray(U * 0, U * 1 - 1))
  toBytesLE(y, output.toSliceArray(U * 1, U * 2 - 1))

template speckDecryptC*[T: uint32|uint64, keySize, N: static int](ctx: SpeckCtx[T, keySize], input, output: slicearray[N, uint8]): void =
  const U: int = sizeof(T)
  const R: int = roundNumber[T](keySize)
  static: doAssert N == U * 2, "Input/Output block byte size does not match the configured word specification."

  var x, y: T
  fromBytesLE(input.toSliceArray(U * 0, U * 1 - 1), x)
  fromBytesLE(input.toSliceArray(U * 1, U * 2 - 1), y)

  for i in countdown(R - 1, 0):
    DR(y, x, ctx.roundKey[i])

  toBytesLE(x, output.toSliceArray(U * 0, U * 1 - 1))
  toBytesLE(y, output.toSliceArray(U * 1, U * 2 - 1))

# ==============================================================================
# SPECK Export Wrappers (Full Explicit Implementation)
# ==============================================================================

when defined(templateOpt):
  # --------------------------------------------------------------------------
  # Speck 64/96 (Block Size: 8 Bytes, Key Size: 12 Bytes)
  # --------------------------------------------------------------------------
  template speck_64_96Init*(ctx: var Speck64_96Ctx, key: array[12, uint8]): void = speckInitC(ctx, key.toSliceArray(0, 11))
  template speck_64_96Init*(ctx: var Speck64_96Ctx, key: openArray[uint8]): void = speckInitC(ctx, key.toSliceArray(0, 11))
  template speck_64_96Init*(ctx: var Speck64_96Ctx, key: slicearray[12, uint8]): void = speckInitC(ctx, key)
  template speck_64_96Init*(ctx: ptr Speck64_96Ctx, key: ptr array[12, uint8]): void = speckInitC(ctx[], key.toSliceArray(0, 11))

  template speck_64_96Encrypt*(ctx: Speck_64_96Ctx, input: array[8, uint8], output: var array[8, uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template speck_64_96Encrypt*(ctx: Speck_64_96Ctx, input, output: slicearray[8, uint8]): void = speckEncryptC(ctx, input, output)
  template speck_64_96Encrypt*(ctx: Speck_64_96Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template speck_64_96Encrypt*(ctx: ptr Speck_64_96Ctx, input, output: ptr array[8, uint8]): void = speckEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  template speck_64_96Decrypt*(ctx: Speck_64_96Ctx, input: array[8, uint8], output: var array[8, uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template speck_64_96Decrypt*(ctx: Speck_64_96Ctx, input, output: slicearray[8, uint8]): void = speckDecryptC(ctx, input, output)
  template speck_64_96Decrypt*(ctx: Speck_64_96Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template speck_64_96Decrypt*(ctx: ptr Speck_64_96Ctx, input, output: ptr array[8, uint8]): void = speckDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  # --------------------------------------------------------------------------
  # Speck 64/128 (Block Size: 8 Bytes, Key Size: 16 Bytes)
  # --------------------------------------------------------------------------
  template speck_64_128Init*(ctx: var Speck64_128Ctx, key: array[16, uint8]): void = speckInitC(ctx, key.toSliceArray(0, 15))
  template speck_64_128Init*(ctx: var Speck64_128Ctx, key: openArray[uint8]): void = speckInitC(ctx, key.toSliceArray(0, 15))
  template speck_64_128Init*(ctx: var Speck64_128Ctx, key: slicearray[16, uint8]): void = speckInitC(ctx, key)
  template speck_64_128Init*(ctx: ptr Speck64_128Ctx, key: ptr array[16, uint8]): void = speckInitC(ctx[], key.toSliceArray(0, 15))

  template speck_64_128Encrypt*(ctx: Speck_64_128Ctx, input: array[8, uint8], output: var array[8, uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template speck_64_128Encrypt*(ctx: Speck_64_128Ctx, input, output: slicearray[8, uint8]): void = speckEncryptC(ctx, input, output)
  template speck_64_128Encrypt*(ctx: Speck_64_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template speck_64_128Encrypt*(ctx: ptr Speck_64_128Ctx, input, output: ptr array[8, uint8]): void = speckEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  template speck_64_128Decrypt*(ctx: Speck_64_128Ctx, input: array[8, uint8], output: var array[8, uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template speck_64_128Decrypt*(ctx: Speck_64_128Ctx, input, output: slicearray[8, uint8]): void = speckDecryptC(ctx, input, output)
  template speck_64_128Decrypt*(ctx: Speck_64_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template speck_64_128Decrypt*(ctx: ptr Speck_64_128Ctx, input, output: ptr array[8, uint8]): void = speckDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  # --------------------------------------------------------------------------
  # Speck 128/128 (Block Size: 16 Bytes, Key Size: 16 Bytes)
  # --------------------------------------------------------------------------
  template speck_128_128Init*(ctx: var Speck128_128Ctx, key: array[16, uint8]): void = speckInitC(ctx, key.toSliceArray(0, 15))
  template speck_128_128Init*(ctx: var Speck128_128Ctx, key: openArray[uint8]): void = speckInitC(ctx, key.toSliceArray(0, 15))
  template speck_128_128Init*(ctx: var Speck128_128Ctx, key: slicearray[16, uint8]): void = speckInitC(ctx, key)
  template speck_128_128Init*(ctx: ptr Speck128_128Ctx, key: ptr array[16, uint8]): void = speckInitC(ctx[], key.toSliceArray(0, 15))

  template speck_128_128Encrypt*(ctx: Speck_128_128Ctx, input: array[16, uint8], output: var array[16, uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template speck_128_128Encrypt*(ctx: Speck_128_128Ctx, input, output: slicearray[16, uint8]): void = speckEncryptC(ctx, input, output)
  template speck_128_128Encrypt*(ctx: Speck_128_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template speck_128_128Encrypt*(ctx: ptr Speck_128_128Ctx, input, output: ptr array[16, uint8]): void = speckEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template speck_128_128Decrypt*(ctx: Speck_128_128Ctx, input: array[16, uint8], output: var array[16, uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template speck_128_128Decrypt*(ctx: Speck_128_128Ctx, input, output: slicearray[16, uint8]): void = speckDecryptC(ctx, input, output)
  template speck_128_128Decrypt*(ctx: Speck_128_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template speck_128_128Decrypt*(ctx: ptr Speck_128_128Ctx, input, output: ptr array[16, uint8]): void = speckDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # --------------------------------------------------------------------------
  # Speck 128/192 (Block Size: 16 Bytes, Key Size: 24 Bytes)
  # --------------------------------------------------------------------------
  template speck_128_192Init*(ctx: var Speck128_192Ctx, key: array[24, uint8]): void = speckInitC(ctx, key.toSliceArray(0, 23))
  template speck_128_192Init*(ctx: var Speck128_192Ctx, key: openArray[uint8]): void = speckInitC(ctx, key.toSliceArray(0, 23))
  template speck_128_192Init*(ctx: var Speck128_192Ctx, key: slicearray[24, uint8]): void = speckInitC(ctx, key)
  template speck_128_192Init*(ctx: ptr Speck128_192Ctx, key: ptr array[24, uint8]): void = speckInitC(ctx, key.toSliceArray(0, 23))

  template speck_128_192Encrypt*(ctx: Speck_128_192Ctx, input: array[16, uint8], output: var array[16, uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template speck_128_192Encrypt*(ctx: Speck_128_192Ctx, input, output: slicearray[16, uint8]): void = speckEncryptC(ctx, input, output)
  template speck_128_192Encrypt*(ctx: Speck_128_192Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template speck_128_192Encrypt*(ctx: ptr Speck_128_192Ctx, input, output: ptr array[16, uint8]): void = speckEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template speck_128_192Decrypt*(ctx: Speck_128_192Ctx, input: array[16, uint8], output: var array[16, uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template speck_128_192Decrypt*(ctx: Speck_128_192Ctx, input, output: slicearray[16, uint8]): void = speckDecryptC(ctx, input, output)
  template speck_128_192Decrypt*(ctx: Speck_128_192Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template speck_128_192Decrypt*(ctx: ptr Speck_128_192Ctx, input, output: ptr array[16, uint8]): void = speckDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # --------------------------------------------------------------------------
  # Speck 128/256 (Block Size: 16 Bytes, Key Size: 32 Bytes)
  # --------------------------------------------------------------------------
  template speck_128_256Init*(ctx: var Speck128_256Ctx, key: array[32, uint8]): void = speckInitC(ctx, key.toSliceArray(0, 31))
  template speck_128_256Init*(ctx: var Speck128_256Ctx, key: openArray[uint8]): void = speckInitC(ctx, key.toSliceArray(0, 31))
  template speck_128_256Init*(ctx: var Speck128_256Ctx, key: slicearray[32, uint8]): void = speckInitC(ctx, key)
  template speck_128_256Init*(ctx: ptr Speck128_256Ctx, key: ptr array[32, uint8]): void = speckInitC(ctx[], key.toSliceArray(0, 31))

  template speck_128_256Encrypt*(ctx: Speck_128_256Ctx, input: array[16, uint8], output: var array[16, uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template speck_128_256Encrypt*(ctx: Speck_128_256Ctx, input, output: slicearray[16, uint8]): void = speckEncryptC(ctx, input, output)
  template speck_128_256Encrypt*(ctx: Speck_128_256Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template speck_128_256Encrypt*(ctx: ptr Speck_128_256Ctx, input, output: ptr array[16, uint8]): void = speckEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template speck_128_256Decrypt*(ctx: Speck_128_256Ctx, input: array[16, uint8], output: var array[16, uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template speck_128_256Decrypt*(ctx: Speck_128_256Ctx, input, output: slicearray[16, uint8]): void = speckDecryptC(ctx, input, output)
  template speck_128_256Decrypt*(ctx: Speck_128_256Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template speck_128_256Decrypt*(ctx: ptr Speck_128_256Ctx, input, output: ptr array[16, uint8]): void = speckDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

else:
  # --------------------------------------------------------------------------
  # Speck 64/96 (Block Size: 8 Bytes, Key Size: 12 Bytes)
  # --------------------------------------------------------------------------
  proc speck_64_96Init*(ctx: var Speck64_96Ctx, key: array[12, uint8]): void = speckInitC(ctx, key.toSliceArray(0, 11))
  proc speck_64_96Init*(ctx: var Speck64_96Ctx, key: openArray[uint8]): void = speckInitC(ctx, key.toSliceArray(0, 11))
  proc speck_64_96Init*(ctx: var Speck64_96Ctx, key: slicearray[12, uint8]): void = speckInitC(ctx, key)
  proc speck_64_96Init*(ctx: ptr Speck64_96Ctx, key: ptr array[12, uint8]): void = speckInitC(ctx[], key.toSliceArray(0, 11))

  proc speck_64_96Encrypt*(ctx: Speck_64_96Ctx, input: array[8, uint8], output: var array[8, uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc speck_64_96Encrypt*(ctx: Speck_64_96Ctx, input, output: slicearray[8, uint8]): void = speckEncryptC(ctx, input, output)
  proc speck_64_96Encrypt*(ctx: Speck_64_96Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc speck_64_96Encrypt*(ctx: ptr Speck_64_96Ctx, input, output: ptr array[8, uint8]): void = speckEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  proc speck_64_96Decrypt*(ctx: Speck_64_96Ctx, input: array[8, uint8], output: var array[8, uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc speck_64_96Decrypt*(ctx: Speck_64_96Ctx, input, output: slicearray[8, uint8]): void = speckDecryptC(ctx, input, output)
  proc speck_64_96Decrypt*(ctx: Speck_64_96Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc speck_64_96Decrypt*(ctx: ptr Speck_64_96Ctx, input, output: ptr array[8, uint8]): void = speckDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  # --------------------------------------------------------------------------
  # Speck 64/128 (Block Size: 8 Bytes, Key Size: 16 Bytes)
  # --------------------------------------------------------------------------
  proc speck_64_128Init*(ctx: var Speck64_128Ctx, key: array[16, uint8]): void = speckInitC(ctx, key.toSliceArray(0, 15))
  proc speck_64_128Init*(ctx: var Speck64_128Ctx, key: openArray[uint8]): void = speckInitC(ctx, key.toSliceArray(0, 15))
  proc speck_64_128Init*(ctx: var Speck64_128Ctx, key: slicearray[16, uint8]): void = speckInitC(ctx, key)
  proc speck_64_128Init*(ctx: ptr Speck64_128Ctx, key: ptr array[16, uint8]): void = speckInitC(ctx[], key.toSliceArray(0, 15))

  proc speck_64_128Encrypt*(ctx: Speck_64_128Ctx, input: array[8, uint8], output: var array[8, uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc speck_64_128Encrypt*(ctx: Speck_64_128Ctx, input, output: slicearray[8, uint8]): void = speckEncryptC(ctx, input, output)
  proc speck_64_128Encrypt*(ctx: Speck_64_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc speck_64_128Encrypt*(ctx: ptr Speck_64_128Ctx, input, output: ptr array[8, uint8]): void = speckEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  proc speck_64_128Decrypt*(ctx: Speck_64_128Ctx, input: array[8, uint8], output: var array[8, uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc speck_64_128Decrypt*(ctx: Speck_64_128Ctx, input, output: slicearray[8, uint8]): void = speckDecryptC(ctx, input, output)
  proc speck_64_128Decrypt*(ctx: Speck_64_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc speck_64_128Decrypt*(ctx: ptr Speck_64_128Ctx, input, output: ptr array[8, uint8]): void = speckDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  # --------------------------------------------------------------------------
  # Speck 128/128 (Block Size: 16 Bytes, Key Size: 16 Bytes)
  # --------------------------------------------------------------------------
  proc speck_128_128Init*(ctx: var Speck128_128Ctx, key: array[16, uint8]): void = speckInitC(ctx, key.toSliceArray(0, 15))
  proc speck_128_128Init*(ctx: var Speck128_128Ctx, key: openArray[uint8]): void = speckInitC(ctx, key.toSliceArray(0, 15))
  proc speck_128_128Init*(ctx: var Speck128_128Ctx, key: slicearray[16, uint8]): void = speckInitC(ctx, key)
  proc speck_128_128Init*(ctx: ptr Speck128_128Ctx, key: ptr array[16, uint8]): void = speckInitC(ctx[], key.toSliceArray(0, 15))

  proc speck_128_128Encrypt*(ctx: Speck_128_128Ctx, input: array[16, uint8], output: var array[16, uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc speck_128_128Encrypt*(ctx: Speck_128_128Ctx, input, output: slicearray[16, uint8]): void = speckEncryptC(ctx, input, output)
  proc speck_128_128Encrypt*(ctx: Speck_128_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc speck_128_128Encrypt*(ctx: ptr Speck_128_128Ctx, input, output: ptr array[16, uint8]): void = speckEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc speck_128_128Decrypt*(ctx: Speck_128_128Ctx, input: array[16, uint8], output: var array[16, uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc speck_128_128Decrypt*(ctx: Speck_128_128Ctx, input, output: slicearray[16, uint8]): void = speckDecryptC(ctx, input, output)
  proc speck_128_128Decrypt*(ctx: Speck_128_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc speck_128_128Decrypt*(ctx: ptr Speck_128_128Ctx, input, output: ptr array[16, uint8]): void = speckDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # --------------------------------------------------------------------------
  # Speck 128/192 (Block Size: 16 Bytes, Key Size: 24 Bytes)
  # --------------------------------------------------------------------------
  proc speck_128_192Init*(ctx: var Speck128_192Ctx, key: array[24, uint8]): void = speckInitC(ctx, key.toSliceArray(0, 23))
  proc speck_128_192Init*(ctx: var Speck128_192Ctx, key: openArray[uint8]): void = speckInitC(ctx, key.toSliceArray(0, 23))
  proc speck_128_192Init*(ctx: var Speck128_192Ctx, key: slicearray[24, uint8]): void = speckInitC(ctx, key)
  proc speck_128_192Init*(ctx: ptr Speck128_192Ctx, key: ptr array[24, uint8]): void = speckInitC(ctx[], key.toSliceArray(0, 23))

  proc speck_128_192Encrypt*(ctx: Speck_128_192Ctx, input: array[16, uint8], output: var array[16, uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc speck_128_192Encrypt*(ctx: Speck_128_192Ctx, input, output: slicearray[16, uint8]): void = speckEncryptC(ctx, input, output)
  proc speck_128_192Encrypt*(ctx: Speck_128_192Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc speck_128_192Encrypt*(ctx: ptr Speck_128_192Ctx, input, output: ptr array[16, uint8]): void = speckEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc speck_128_192Decrypt*(ctx: Speck_128_192Ctx, input: array[16, uint8], output: var array[16, uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc speck_128_192Decrypt*(ctx: Speck_128_192Ctx, input, output: slicearray[16, uint8]): void = speckDecryptC(ctx, input, output)
  proc speck_128_192Decrypt*(ctx: Speck_128_192Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc speck_128_192Decrypt*(ctx: ptr Speck_128_192Ctx, input, output: ptr array[16, uint8]): void = speckDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # --------------------------------------------------------------------------
  # Speck 128/256 (Block Size: 16 Bytes, Key Size: 32 Bytes)
  # --------------------------------------------------------------------------
  proc speck_128_256Init*(ctx: var Speck128_256Ctx, key: array[32, uint8]): void = speckInitC(ctx, key.toSliceArray(0, 31))
  proc speck_128_256Init*(ctx: var Speck128_256Ctx, key: openArray[uint8]): void = speckInitC(ctx, key.toSliceArray(0, 31))
  proc speck_128_256Init*(ctx: var Speck128_256Ctx, key: slicearray[32, uint8]): void = speckInitC(ctx, key)
  proc speck_128_256Init*(ctx: ptr Speck128_256Ctx, key: ptr array[32, uint8]): void = speckInitC(ctx[], key.toSliceArray(0, 31))

  proc speck_128_256Encrypt*(ctx: Speck_128_256Ctx, input: array[16, uint8], output: var array[16, uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc speck_128_256Encrypt*(ctx: Speck_128_256Ctx, input, output: slicearray[16, uint8]): void = speckEncryptC(ctx, input, output)
  proc speck_128_256Encrypt*(ctx: Speck_128_256Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc speck_128_256Encrypt*(ctx: ptr Speck_128_256Ctx, input, output: ptr array[16, uint8]): void = speckEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc speck_128_256Decrypt*(ctx: Speck_128_256Ctx, input: array[16, uint8], output: var array[16, uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc speck_128_256Decrypt*(ctx: Speck_128_256Ctx, input, output: slicearray[16, uint8]): void = speckDecryptC(ctx, input, output)
  proc speck_128_256Decrypt*(ctx: Speck_128_256Ctx, input: openArray[uint8], output: var openArray[uint8]): void = speckDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc speck_128_256Decrypt*(ctx: ptr Speck_128_256Ctx, input, output: ptr array[16, uint8]): void = speckDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))
