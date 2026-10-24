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
  Z0 = 0x7369f885192c0ef5'u64
  Z1 = 0xfc2ce51207a635db'u64
  Z2 = 0x7369f885192c0ef5'u64
  Z3 = 0xfc2ce51207a635db'u64
  Z4 = 0xfdc94c3a046d678b'u64

template Z*(T: typedesc, R, M: static int): uint64 =
  when T is uint32 and R == 42 and M == 3: Z0
  elif T is uint32 and R == 44 and M == 4: Z1
  elif T is uint64 and R == 68 and M == 2: Z2
  elif T is uint64 and R == 69 and M == 3: Z3
  elif T is uint64 and R == 72 and M == 4: Z4
  else:
    {.error: "Unsupported Constant Combination for Simon Cipher".}

template roundNumber*[T](keySize: static int): static int =
  when T is uint32:
    when keySize == 12: 42
    elif keySize == 16: 44
    else: {.error: "Invalid key size for uint32 (Block 64). Only 12 bytes (96-bit) or 16 bytes (128-bit) keys are supported.".}
  elif T is uint64:
    when keySize == 16: 68
    elif keySize == 24: 69
    elif keySize == 32: 72
    else: {.error: "Invalid key size for uint64 (Block 128). Only 16 bytes (128-bit), 24 bytes (192-bit), or 32 bytes (256-bit) keys are supported.".}
  else:
    {.error: "Unsupported word block type. Only uint16, uint32, and uint64 are allowed.".}

type
  SimonCtx*[T: uint16|uint32|uint64, keySize: static int] = object
    roundKey*: array[roundNumber[T](keySize), T]

  Simon_64_96Ctx* = SimonCtx[uint32, 12] # Block: 64-bit (8B),  Key: 96-bit (12B)
  Simon_64_128Ctx* = SimonCtx[uint32, 16] # Block: 64-bit (8B),  Key: 128-bit (16B)
  Simon_128_128Ctx* = SimonCtx[uint64, 16] # Block: 128-bit (16B), Key: 128-bit (16B)
  Simon_128_192Ctx* = SimonCtx[uint64, 24] # Block: 128-bit (16B), Key: 192-bit (24B)
  Simon_128_256Ctx* = SimonCtx[uint64, 32] # Block: 128-bit (16B), Key: 256-bit (32B)

template F[T](v: T): T =
   rotateLeftBits(v, 1) and rotateLeftBits(v, 8) xor rotateLeftBits(v, 2)

template R2[T](x, y: var T, k1, k2: T) =
  y = y xor F(x)
  y = y xor k1
  x = x xor F(y)
  x = x xor k2

template simonInitC*[T: uint16|uint32|uint64, keySize, K: static int](ctx: var SimonCtx[T, keySize], key: slicearray[K, uint8]): void =
  const U: int = sizeof(T)
  const R: int = roundNumber[T](keySize)
  const M: int = K div U

  static:
    doAssert K == keySize, "The slicearray size (K) must match the configured keySize."
    doAssert K mod U == 0, "Key size is not a multiple of the word alignment size."
  var z: uint64 = Z(T, R, M)
  const mask: T = T(not 3)

  when T is uint32:
    when keySize == 12:
      decodeLE(key, ctx.roundKey.toSliceArray(0, 2))

      for i in static(3 ..< 42):
        ctx.roundKey[i] = mask xor uint32(z and 1) xor ctx.roundKey[i - 3] xor rotateRightBits(ctx.roundKey[i - 1], 3) xor rotateRightBits(ctx.roundKey[i - 1], 4)

        z = z shr 1
    elif keySize == 16:
      decodeLE(key, ctx.roundKey.toSliceArray(0, 3))

      for i in static(4 ..< 44):
        ctx.roundKey[i] = mask xor uint32(z and 1) xor ctx.roundKey[i - 4] xor rotateRightBits(ctx.roundKey[i - 1], 3) xor ctx.roundKey[i - 3] xor
        rotateRightBits(ctx.roundKey[i - 1], 4) xor rotateRightBits(ctx.roundKey[i - 3], 1)

        z = z shr 1
  elif T is uint64:
    when keySize == 16:
      var a, b: uint64
      fromBytesLE(key.toSliceArray(0, 7), a)
      fromBytesLE(key.toSliceArray(8, 15), b)

      for i in static(0 ..< 32):
        ctx.roundKey[i * 2 + 0] = a
        a = a xor mask xor (z and 1) xor rotateRightBits(b, 3) xor rotateRightBits(b, 4)
        z = z shr 1
        ctx.roundKey[i * 2 + 1] = b
        b = b xor mask xor (z and 1) xor rotateRightBits(a, 3) xor rotateRightBits(a, 4)
        z = z shr 1

      ctx.roundKey[64] = a
      a = a xor mask xor 1 xor rotateRightBits(b, 3) xor rotateRightBits(b, 4)
      ctx.roundKey[65] = b
      b = b xor mask xor 0 xor rotateRightBits(a, 3) xor rotateRightBits(a, 4)
      ctx.roundKey[66] = a
      ctx.roundKey[67] = b
    elif keySize == 24:
      var a, b, c: uint64
      fromBytesLE(key.toSliceArray(0, 7), a)
      fromBytesLE(key.toSliceArray(8, 15), b)
      fromBytesLE(key.toSliceArray(16, 23), c)

      for i in static(0 ..< 21):
        ctx.roundKey[i * 3 + 0] = a
        a = a xor mask xor (z and 1) xor rotateRightBits(c, 3) xor rotateRightBits(c, 4)
        z = z shr 1
        ctx.roundKey[i * 3 + 1] = b
        b = b xor mask xor (z and 1) xor rotateRightBits(a, 3) xor rotateRightBits(a, 4)
        z = z shr 1
        ctx.roundKey[i * 3 + 2] = c
        c = c xor mask xor (z and 1) xor rotateRightBits(b, 3) xor rotateRightBits(b, 4)
        z = z shr 1

      ctx.roundKey[63] = a
      a = a xor mask xor 1 xor rotateRightBits(c, 3) xor rotateRightBits(c, 4)
      ctx.roundKey[64] = b
      b = b xor mask xor 0 xor rotateRightBits(a, 3) xor rotateRightBits(a, 4)
      ctx.roundKey[65] = c
      c = c xor mask xor 1 xor rotateRightBits(b, 3) xor rotateRightBits(b, 4)
      ctx.roundKey[66] = a; ctx.roundKey[67] = b; ctx.roundKey[68] = c
    elif keySize == 32:
      var a, b, c, d: uint64
      fromBytesLE(key.toSliceArray(0, 7), a)
      fromBytesLE(key.toSliceArray(8, 15), b)
      fromBytesLE(key.toSliceArray(16, 23), c)
      fromBytesLE(key.toSliceArray(24, 31), d)

      for i in static(0 ..< 16):
        ctx.roundKey[i * 4 + 0] = a
        a = a xor mask xor (z and 1) xor rotateRightBits(d, 3) xor rotateRightBits(d, 4) xor b xor rotateRightBits(b, 1)
        z = z shr 1
        ctx.roundKey[i * 4 + 1] = b
        b = b xor mask xor (z and 1) xor rotateRightBits(a, 3) xor rotateRightBits(a, 4) xor c xor rotateRightBits(c, 1)
        z = z shr 1
        ctx.roundKey[i * 4 + 2] = c
        c = c xor mask xor (z and 1) xor rotateRightBits(b, 3) xor rotateRightBits(b, 4) xor d xor rotateRightBits(d, 1)
        z = z shr 1
        ctx.roundKey[i * 4 + 3] = d
        d = d xor mask xor (z and 1) xor rotateRightBits(c, 3) xor rotateRightBits(c, 4) xor a xor rotateRightBits(a, 1)
        z = z shr 1

      ctx.roundKey[64] = a
      a = a xor mask xor 0 xor rotateRightBits(d, 3) xor rotateRightBits(d, 4) xor b xor rotateRightBits(b, 1)
      ctx.roundKey[65] = b
      b = b xor mask xor 1 xor rotateRightBits(a, 3) xor rotateRightBits(a, 4) xor c xor rotateRightBits(c, 1)
      ctx.roundKey[66] = c
      c = c xor mask xor 0 xor rotateRightBits(b, 3) xor rotateRightBits(b, 4) xor d xor rotateRightBits(d, 1)
      ctx.roundKey[67] = d
      d = d xor mask xor 0 xor rotateRightBits(c, 3) xor rotateRightBits(c, 4) xor a xor rotateRightBits(a, 1)

      ctx.roundKey[68] = a
      ctx.roundKey[69] = b
      ctx.roundKey[70] = c
      ctx.roundKey[71] = d


template simonEncryptC*[T: uint16|uint32|uint64, keySize, N: static int](ctx: SimonCtx[T, keySize], input, output: slicearray[N, uint8]): void =
  const U: int = sizeof(T)
  const R: int = when keySize == 24: roundNumber[T](keySize) - 1 else: roundNumber[T](keySize)
  static: doAssert N == U * 2, "Input/Output block byte size does not match the configured word specification."

  var x, y: T
  fromBytesLE(input.toSliceArray(U * 0, U * 1 - 1), x)
  fromBytesLE(input.toSliceArray(U * 1, U * 2 - 1), y)

  for i in countup(0, R - 1, 2):
    R2(y, x, ctx.roundKey[i], ctx.roundKey[i + 1])

  when keySize == 24:
    var t: uint64 = y; y = x xor F(y) xor ctx.roundKey[68]; x = t

  toBytesLE(x, output.toSliceArray(U * 0, U * 1 - 1))
  toBytesLE(y, output.toSliceArray(U * 1, U * 2 - 1))

template simonDecryptC*[T: uint16|uint32|uint64, keySize, N: static int](ctx: SimonCtx[T, keySize], input, output: slicearray[N, uint8]): void =
  const U: int = sizeof(T)
  const R: int = when keySize == 24: roundNumber[T](keySize) - 1 else: roundNumber[T](keySize)
  static: doAssert N == U * 2, "Input/Output block byte size does not match the configured word specification."

  var x, y: T
  fromBytesLE(input.toSliceArray(U * 0, U * 1 - 1), x)
  fromBytesLE(input.toSliceArray(U * 1, U * 2 - 1), y)

  when keySize == 24:
    var t: uint64 = x; x = y xor F(x) xor ctx.roundKey[68]; y = t

  for i in countdown(R - 1, 0, 2):
    R2(x, y, ctx.roundKey[i], ctx.roundKey[i - 1])

  toBytesLE(x, output.toSliceArray(U * 0, U * 1 - 1))
  toBytesLE(y, output.toSliceArray(U * 1, U * 2 - 1))

# ==============================================================================
# Simon Export Wrappers (Full Explicit Implementation)
# ==============================================================================

when defined(templateOpt):
  # --------------------------------------------------------------------------
  # Simon 64/96 (Block Size: 8 Bytes, Key Size: 12 Bytes)
  # --------------------------------------------------------------------------
  template simon_64_96Init*(ctx: var Simon_64_96Ctx, key: array[12, uint8]): void = simonInitC(ctx, key.toSliceArray(0, 11))
  template simon_64_96Init*(ctx: var Simon_64_96Ctx, key: openArray[uint8]): void = simonInitC(ctx, key.toSliceArray(0, 11))
  template simom_64_96Init*(ctx: var Simon_64_96Ctx, key: slicearray[12, uint8]): void = simonInitC(ctx, key)
  template simon_64_96Init*(ctx: ptr Simon_64_96Ctx, key: ptr array[12, uint8]): void = simonInitC(ctx[], key.toSliceArray(0, 11))

  template simon_64_96Encrypt*(ctx: Simon_64_96Ctx, input: array[8, uint8], output: var array[8, uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template simon_64_96Encrypt*(ctx: Simon_64_96Ctx, input, output: slicearray[8, uint8]): void = simonEncryptC(ctx, input, output)
  template simon_64_96Encrypt*(ctx: Simon_64_96Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template simon_64_96Encrypt*(ctx: ptr Simon_64_96Ctx, input, output: ptr array[8, uint8]): void = simonEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  template simon_64_96Decrypt*(ctx: Simon_64_96Ctx, input: array[8, uint8], output: var array[8, uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template simon_64_96Decrypt*(ctx: Simon_64_96Ctx, input, output: slicearray[8, uint8]): void = simonDecryptC(ctx, input, output)
  template simon_64_96Decrypt*(ctx: Simon_64_96Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template simon_64_96Decrypt*(ctx: ptr Simon_64_96Ctx, input, output: ptr array[8, uint8]): void = simonDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  # --------------------------------------------------------------------------
  # Simon 64/128 (Block Size: 8 Bytes, Key Size: 16 Bytes)
  # --------------------------------------------------------------------------
  template simon_64_128Init*(ctx: var Simon_64_128Ctx, key: array[16, uint8]): void = simonInitC(ctx, key.toSliceArray(0, 15))
  template simon_64_128Init*(ctx: var Simon_64_128Ctx, key: openArray[uint8]): void = simonInitC(ctx, key.toSliceArray(0, 15))
  template simom_64_128Init*(ctx: var Simon_64_128Ctx, key: slicearray[16, uint8]): void = simonInitC(ctx, key)
  template simon_64_128Init*(ctx: ptr Simon_64_128Ctx, key: ptr array[16, uint8]): void = simonInitC(ctx[], key.toSliceArray(0, 15))

  template simon_64_128Encrypt*(ctx: Simon_64_128Ctx, input: array[8, uint8], output: var array[8, uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template simon_64_128Encrypt*(ctx: Simon_64_128Ctx, input, output: slicearray[8, uint8]): void = simonEncryptC(ctx, input, output)
  template simon_64_128Encrypt*(ctx: Simon_64_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template simon_64_128Encrypt*(ctx: ptr Simon_64_128Ctx, input, output: ptr array[8, uint8]): void = simonEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  template simon_64_128Decrypt*(ctx: Simon_64_128Ctx, input: array[8, uint8], output: var array[8, uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template simon_64_128Decrypt*(ctx: Simon_64_128Ctx, input, output: slicearray[8, uint8]): void = simonDecryptC(ctx, input, output)
  template simon_64_128Decrypt*(ctx: Simon_64_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template simon_64_128Decrypt*(ctx: ptr Simon_64_128Ctx, input, output: ptr array[8, uint8]): void = simonDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  # --------------------------------------------------------------------------
  # Simon 128/128 (Block Size: 16 Bytes, Key Size: 16 Bytes)
  # --------------------------------------------------------------------------
  template simon_128_128Init*(ctx: var Simon_128_128Ctx, key: array[16, uint8]): void = simonInitC(ctx, key.toSliceArray(0, 15))
  template simon_128_128Init*(ctx: var Simon_128_128Ctx, key: openArray[uint8]): void = simonInitC(ctx, key.toSliceArray(0, 15))
  template simom_128_128Init*(ctx: var Simon_128_128Ctx, key: slicearray[16, uint8]): void = simonInitC(ctx, key)
  template simon_128_128Init*(ctx: ptr Simon_128_128Ctx, key: ptr array[16, uint8]): void = simonInitC(ctx[], key.toSliceArray(0, 15))

  template simon_128_128Encrypt*(ctx: Simon_128_128Ctx, input: array[16, uint8], output: var array[16, uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template simon_128_128Encrypt*(ctx: Simon_128_128Ctx, input, output: slicearray[16, uint8]): void = simonEncryptC(ctx, input, output)
  template simon_128_128Encrypt*(ctx: Simon_128_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template simon_128_128Encrypt*(ctx: ptr Simon_128_128Ctx, input, output: ptr array[16, uint8]): void = simonEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template simon_128_128Decrypt*(ctx: Simon_128_128Ctx, input: array[16, uint8], output: var array[16, uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template simon_128_128Decrypt*(ctx: Simon_128_128Ctx, input, output: slicearray[16, uint8]): void = simonDecryptC(ctx, input, output)
  template simon_128_128Decrypt*(ctx: Simon_128_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template simon_128_128Decrypt*(ctx: ptr Simon_128_128Ctx, input, output: ptr array[16, uint8]): void = simonDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # --------------------------------------------------------------------------
  # Simon 128/192 (Block Size: 16 Bytes, Key Size: 24 Bytes)
  # --------------------------------------------------------------------------
  template simon_128_192Init*(ctx: var Simon_128_192Ctx, key: array[24, uint8]): void = simonInitC(ctx, key.toSliceArray(0, 23))
  template simon_128_192Init*(ctx: var Simon_128_192Ctx, key: openArray[uint8]): void = simonInitC(ctx, key.toSliceArray(0, 23))
  template simom_128_192Init*(ctx: var Simon_128_192Ctx, key: slicearray[24, uint8]): void = simonInitC(ctx, key)
  template simon_128_192Init*(ctx: ptr Simon_128_192Ctx, key: ptr array[24, uint8]): void = simonInitC(ctx[], key.toSliceArray(0, 23))

  template simon_128_192Encrypt*(ctx: Simon_128_192Ctx, input: array[16, uint8], output: var array[16, uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template simon_128_192Encrypt*(ctx: Simon_128_192Ctx, input, output: slicearray[16, uint8]): void = simonEncryptC(ctx, input, output)
  template simon_128_192Encrypt*(ctx: Simon_128_192Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template simon_128_192Encrypt*(ctx: ptr Simon_128_192Ctx, input, output: ptr array[16, uint8]): void = simonEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template simon_128_192Decrypt*(ctx: Simon_128_192Ctx, input: array[16, uint8], output: var array[16, uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template simon_128_192Decrypt*(ctx: Simon_128_192Ctx, input, output: slicearray[16, uint8]): void = simonDecryptC(ctx, input, output)
  template simon_128_192Decrypt*(ctx: Simon_128_192Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template simon_128_192Decrypt*(ctx: ptr Simon_128_192Ctx, input, output: ptr array[16, uint8]): void = simonDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # --------------------------------------------------------------------------
  # Simon 128/256 (Block Size: 16 Bytes, Key Size: 32 Bytes)
  # --------------------------------------------------------------------------
  template simon_128_256Init*(ctx: var Simon_128_256Ctx, key: array[32, uint8]): void = simonInitC(ctx, key.toSliceArray(0, 31))
  template simon_128_256Init*(ctx: var Simon_128_256Ctx, key: openArray[uint8]): void = simonInitC(ctx, key.toSliceArray(0, 31))
  template simom_128_256Init*(ctx: var Simon_128_256Ctx, key: slicearray[32, uint8]): void = simonInitC(ctx, key)
  template simon_128_256Init*(ctx: ptr Simon_128_256Ctx, key: ptr array[32, uint8]): void = simonInitC(ctx[], key.toSliceArray(0, 31))

  template simon_128_256Encrypt*(ctx: Simon_128_256Ctx, input: array[16, uint8], output: var array[16, uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template simon_128_256Encrypt*(ctx: Simon_128_256Ctx, input, output: slicearray[16, uint8]): void = simonEncryptC(ctx, input, output)
  template simon_128_256Encrypt*(ctx: Simon_128_256Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template simon_128_256Encrypt*(ctx: ptr Simon_128_256Ctx, input, output: ptr array[16, uint8]): void = simonEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template simon_128_256Decrypt*(ctx: Simon_128_256Ctx, input: array[16, uint8], output: var array[16, uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template simon_128_256Decrypt*(ctx: Simon_128_256Ctx, input, output: slicearray[16, uint8]): void = simonDecryptC(ctx, input, output)
  template simon_128_256Decrypt*(ctx: Simon_128_256Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template simon_128_256Decrypt*(ctx: ptr Simon_128_256Ctx, input, output: ptr array[16, uint8]): void = simonDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

else:
  # --------------------------------------------------------------------------
  # Simon 64/96 (Block Size: 8 Bytes, Key Size: 12 Bytes)
  # --------------------------------------------------------------------------
  proc simon_64_96Init*(ctx: var Simon_64_96Ctx, key: array[12, uint8]): void = simonInitC(ctx, key.toSliceArray(0, 11))
  proc simon_64_96Init*(ctx: var Simon_64_96Ctx, key: openArray[uint8]): void = simonInitC(ctx, key.toSliceArray(0, 11))
  proc simom_64_96Init*(ctx: var Simon_64_96Ctx, key: slicearray[12, uint8]): void = simonInitC(ctx, key)
  proc simon_64_96Init*(ctx: ptr Simon_64_96Ctx, key: ptr array[12, uint8]): void = simonInitC(ctx[], key.toSliceArray(0, 11))

  proc simon_64_96Encrypt*(ctx: Simon_64_96Ctx, input: array[8, uint8], output: var array[8, uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc simon_64_96Encrypt*(ctx: Simon_64_96Ctx, input, output: slicearray[8, uint8]): void = simonEncryptC(ctx, input, output)
  proc simon_64_96Encrypt*(ctx: Simon_64_96Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc simon_64_96Encrypt*(ctx: ptr Simon_64_96Ctx, input, output: ptr array[8, uint8]): void = simonEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  proc simon_64_96Decrypt*(ctx: Simon_64_96Ctx, input: array[8, uint8], output: var array[8, uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc simon_64_96Decrypt*(ctx: Simon_64_96Ctx, input, output: slicearray[8, uint8]): void = simonDecryptC(ctx, input, output)
  proc simon_64_96Decrypt*(ctx: Simon_64_96Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc simon_64_96Decrypt*(ctx: ptr Simon_64_96Ctx, input, output: ptr array[8, uint8]): void = simonDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  # --------------------------------------------------------------------------
  # Simon 64/128 (Block Size: 8 Bytes, Key Size: 16 Bytes)
  # --------------------------------------------------------------------------
  proc simon_64_128Init*(ctx: var Simon_64_128Ctx, key: array[16, uint8]): void = simonInitC(ctx, key.toSliceArray(0, 15))
  proc simon_64_128Init*(ctx: var Simon_64_128Ctx, key: openArray[uint8]): void = simonInitC(ctx, key.toSliceArray(0, 15))
  proc simom_64_128Init*(ctx: var Simon_64_128Ctx, key: slicearray[16, uint8]): void = simonInitC(ctx, key)
  proc simon_64_128Init*(ctx: ptr Simon_64_128Ctx, key: ptr array[16, uint8]): void = simonInitC(ctx[], key.toSliceArray(0, 15))

  proc simon_64_128Encrypt*(ctx: Simon_64_128Ctx, input: array[8, uint8], output: var array[8, uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc simon_64_128Encrypt*(ctx: Simon_64_128Ctx, input, output: slicearray[8, uint8]): void = simonEncryptC(ctx, input, output)
  proc simon_64_128Encrypt*(ctx: Simon_64_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc simon_64_128Encrypt*(ctx: ptr Simon_64_128Ctx, input, output: ptr array[8, uint8]): void = simonEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  proc simon_64_128Decrypt*(ctx: Simon_64_128Ctx, input: array[8, uint8], output: var array[8, uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc simon_64_128Decrypt*(ctx: Simon_64_128Ctx, input, output: slicearray[8, uint8]): void = simonDecryptC(ctx, input, output)
  proc simon_64_128Decrypt*(ctx: Simon_64_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc simon_64_128Decrypt*(ctx: ptr Simon_64_128Ctx, input, output: ptr array[8, uint8]): void = simonDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  # --------------------------------------------------------------------------
  # Simon 128/128 (Block Size: 16 Bytes, Key Size: 16 Bytes)
  # --------------------------------------------------------------------------
  proc simon_128_128Init*(ctx: var Simon_128_128Ctx, key: array[16, uint8]): void = simonInitC(ctx, key.toSliceArray(0, 15))
  proc simon_128_128Init*(ctx: var Simon_128_128Ctx, key: openArray[uint8]): void = simonInitC(ctx, key.toSliceArray(0, 15))
  proc simom_128_128Init*(ctx: var Simon_128_128Ctx, key: slicearray[16, uint8]): void = simonInitC(ctx, key)
  proc simon_128_128Init*(ctx: ptr Simon_128_128Ctx, key: ptr array[16, uint8]): void = simonInitC(ctx[], key.toSliceArray(0, 15))

  proc simon_128_128Encrypt*(ctx: Simon_128_128Ctx, input: array[16, uint8], output: var array[16, uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc simon_128_128Encrypt*(ctx: Simon_128_128Ctx, input, output: slicearray[16, uint8]): void = simonEncryptC(ctx, input, output)
  proc simon_128_128Encrypt*(ctx: Simon_128_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc simon_128_128Encrypt*(ctx: ptr Simon_128_128Ctx, input, output: ptr array[16, uint8]): void = simonEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc simon_128_128Decrypt*(ctx: Simon_128_128Ctx, input: array[16, uint8], output: var array[16, uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc simon_128_128Decrypt*(ctx: Simon_128_128Ctx, input, output: slicearray[16, uint8]): void = simonDecryptC(ctx, input, output)
  proc simon_128_128Decrypt*(ctx: Simon_128_128Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc simon_128_128Decrypt*(ctx: ptr Simon_128_128Ctx, input, output: ptr array[16, uint8]): void = simonDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # --------------------------------------------------------------------------
  # Simon 128/192 (Block Size: 16 Bytes, Key Size: 24 Bytes)
  # --------------------------------------------------------------------------
  proc simon_128_192Init*(ctx: var Simon_128_192Ctx, key: array[24, uint8]): void = simonInitC(ctx, key.toSliceArray(0, 23))
  proc simon_128_192Init*(ctx: var Simon_128_192Ctx, key: openArray[uint8]): void = simonInitC(ctx, key.toSliceArray(0, 23))
  proc simom_128_192Init*(ctx: var Simon_128_192Ctx, key: slicearray[24, uint8]): void = simonInitC(ctx, key)
  proc simon_128_192Init*(ctx: ptr Simon_128_192Ctx, key: ptr array[24, uint8]): void = simonInitC(ctx[], key.toSliceArray(0, 23))

  proc simon_128_192Encrypt*(ctx: Simon_128_192Ctx, input: array[16, uint8], output: var array[16, uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc simon_128_192Encrypt*(ctx: Simon_128_192Ctx, input, output: slicearray[16, uint8]): void = simonEncryptC(ctx, input, output)
  proc simon_128_192Encrypt*(ctx: Simon_128_192Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc simon_128_192Encrypt*(ctx: ptr Simon_128_192Ctx, input, output: ptr array[16, uint8]): void = simonEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc simon_128_192Decrypt*(ctx: Simon_128_192Ctx, input: array[16, uint8], output: var array[16, uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc simon_128_192Decrypt*(ctx: Simon_128_192Ctx, input, output: slicearray[16, uint8]): void = simonDecryptC(ctx, input, output)
  proc simon_128_192Decrypt*(ctx: Simon_128_192Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc simon_128_192Decrypt*(ctx: ptr Simon_128_192Ctx, input, output: ptr array[16, uint8]): void = simonDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  # --------------------------------------------------------------------------
  # Simon 128/256 (Block Size: 16 Bytes, Key Size: 32 Bytes)
  # --------------------------------------------------------------------------
  proc simon_128_256Init*(ctx: var Simon_128_256Ctx, key: array[32, uint8]): void = simonInitC(ctx, key.toSliceArray(0, 31))
  proc simon_128_256Init*(ctx: var Simon_128_256Ctx, key: openArray[uint8]): void = simonInitC(ctx, key.toSliceArray(0, 31))
  proc simom_128_256Init*(ctx: var Simon_128_256Ctx, key: slicearray[32, uint8]): void = simonInitC(ctx, key)
  proc simon_128_256Init*(ctx: ptr Simon_128_256Ctx, key: ptr array[32, uint8]): void = simonInitC(ctx[], key.toSliceArray(0, 31))

  proc simon_128_256Encrypt*(ctx: Simon_128_256Ctx, input: array[16, uint8], output: var array[16, uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc simon_128_256Encrypt*(ctx: Simon_128_256Ctx, input, output: slicearray[16, uint8]): void = simonEncryptC(ctx, input, output)
  proc simon_128_256Encrypt*(ctx: Simon_128_256Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc simon_128_256Encrypt*(ctx: ptr Simon_128_256Ctx, input, output: ptr array[16, uint8]): void = simonEncryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc simon_128_256Decrypt*(ctx: Simon_128_256Ctx, input: array[16, uint8], output: var array[16, uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc simon_128_256Decrypt*(ctx: Simon_128_256Ctx, input, output: slicearray[16, uint8]): void = simonDecryptC(ctx, input, output)
  proc simon_128_256Decrypt*(ctx: Simon_128_256Ctx, input: openArray[uint8], output: var openArray[uint8]): void = simonDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc simon_128_256Decrypt*(ctx: ptr Simon_128_256Ctx, input, output: ptr array[16, uint8]): void = simonDecryptC(ctx[], input.toSliceArray(0, 15), output.toSliceArray(0, 15))
