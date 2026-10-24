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
  # serpent information constants
  SERPENT_BLOCK_SIZE*: int = 16
  SERPENT128_KEY_SIZE*: int = 16
  SERPENT192_KEY_SIZE*: int = 24
  SERPENT256_KEY_SIZE*: int = 32
  SERPENT_ROUND_NUMBER*: int = 32

  # PHI constant
  PHI*: uint32 = 0x9E3779B9'u32

type
  # serpent generic context
  SerpentCtx*[keyBits: static int] = object
    roundKey*: array[132, uint32]

  # serpent 128/192/256 context
  Serpent128Ctx* {.exportc: "Serpent128Ctx", completeStruct.} = SerpentCtx[128]
  Serpent192Ctx* {.exportc: "Serpent192Ctx", completeStruct.} = SerpentCtx[192]
  Serpent256Ctx* {.exportc: "Serpent256Ctx", completeStruct.} = SerpentCtx[256]

# linear template
template linear(v0, v1, v2, v3: var uint32): void =
  var t0: uint32 = rotateLeftBits(v0, 13)
  var t2: uint32 = rotateLeftBits(v2, 3)
  var t1: uint32 = v1 xor t0 xor t2
  var t3: uint32 = v3 xor t2 xor (t0 shl 3)
  v1 = rotateLeftBits(t1, 1)
  v3 = rotateLeftBits(t3, 7)
  t0 = t0 xor v1 xor v3
  t2 = t2 xor v3 xor (v1 shl 7)
  v0 = rotateLeftBits(t0, 5)
  v2 = rotateLeftBits(t2, 22)

# inverse linear template
template invLinear(v0, v1, v2, v3: var uint32): void =
  var t2: uint32 = rotateRightBits(v2, 22)
  var t0: uint32 = rotateRightBits(v0, 5)
  t2 = t2 xor v3 xor (v1 shl 7)
  t0 = t0 xor v1 xor v3
  var t3: uint32 = rotateRightBits(v3, 7)
  var t1: uint32 = rotateRightBits(v1, 1)
  v3 = t3 xor t2 xor (t0 shl 3)
  v1 = t1 xor t0 xor t2
  v2 = rotateRightBits(t2, 3)
  v0 = rotateRightBits(t0, 13)

# sbox 0 encrypt template : by bitops
template S0E(r0, r1, r2, r3: var uint32): void =
  var t0: uint32 = r0 xor r3
  var t1: uint32 = r2 xor t0
  var t2: uint32 = r1 xor t1
  r3 = (r0 and r3) xor t2
  var t3: uint32 = r0 xor (r1 and t0)
  r2 = t2 xor (r2 or t3)
  var t4: uint32 = r3 and (t1 xor t3)
  r1 = (not t1) xor t4
  r0 = t4 xor (not t3)

# sbox 0 decrypt template : by bitops
template S0D(r0, r1, r2, r3: var uint32): void =
  var t0: uint32 = not r0
  var t1: uint32 = r0 xor r1
  var t2: uint32 = r3 xor (t0 or t1)
  var t3: uint32 = r2 xor t2
  r2 = t1 xor t3
  var t4: uint32 = t0 xor (r3 and t1)
  r1 = t2 xor (r2 and t4)
  r3 = (r0 and t2) xor (t3 or r1)
  r0 = r3 xor (t3 xor t4)

# sbox 1 encrypt template : by bitops
template S1E(r0, r1, r2, r3: var uint32): void =
  var t0: uint32 = r1 xor (not r0)
  var t1: uint32 = r2 xor (r0 or t0)
  r2 = r3 xor t1
  var t2: uint32 = r1 xor (r3 or t0)
  var t3: uint32 = t0 xor r2
  r3 = t3 xor (t1 and t2)
  var t4: uint32 = t1 xor t2
  r1 = r3 xor t4
  r0 = t1 xor (t3 and t4)

# sbox 1 decrypt template : by bitops
template S1D(r0, r1, r2, r3: var uint32): void =
  var t0: uint32 = r1 xor r3
  var t1: uint32 = r0 xor (r1 and t0)
  var t2: uint32 = t0 xor t1
  r3 = r2 xor t2
  var t3: uint32 = r1 xor (t0 and t1)
  var t4: uint32 = r3 or t3
  r1 = t1 xor t4
  var t5: uint32 = not r1
  var t6: uint32 = r3 xor t3
  r0 = t5 xor t6
  r2 = t2 xor (t5 or t6)

# sbox 2 encrypt template : by bitops
template S2E(r0, r1, r2, r3: var uint32): void =
  var v0: uint32 = r0
  var v3: uint32 = r3
  var t0: uint32 = not v0
  var t1: uint32 = r1 xor v3
  var t2: uint32 = r2 and t0
  r0 = t1 xor t2
  var t3: uint32 = r2 xor t0
  var t4: uint32 = r2 xor r0
  var t5: uint32 = r1 and t4
  r3 = t3 xor t5
  r2 = v0 xor ((v3 or t5) and (r0 or t3))
  r1 = (t1 xor r3) xor (r2 xor (v3 or t0))

# sbox 2 decrypt template : by bitops
template S2D(r0, r1, r2, r3: var uint32): void =
  var v0: uint32 = r0
  var v3: uint32 = r3
  var t0: uint32 = r1 xor v3
  var t1: uint32 = not t0
  var t2: uint32 = v0 xor r2
  var t3: uint32 = r2 xor t0
  var t4: uint32 = r1 and t3
  r0 = t2 xor t4
  var t5: uint32 = v0 or t1
  var t6: uint32 = v3 xor t5
  var t7: uint32 = t2 or t6
  r3 = t0 xor t7
  var t8: uint32 = not t3
  var t9: uint32 = r0 or r3
  r1 = t8 xor t9
  r2 = (v3 and t8) xor (t2 xor t9)

# sbox 3 encrypt template : by bitops
template S3E(r0, r1, r2, r3: var uint32): void =
  var v1: uint32 = r1
  var v3: uint32 = r3
  var t0: uint32 = r0 xor r1
  var t1: uint32 = r0 and r2
  var t2: uint32 = r0 or r3
  var t3: uint32 = r2 xor r3
  var t4: uint32 = t0 and t2
  var t5: uint32 = t1 or t4
  r2 = t3 xor t5
  var t6: uint32 = r1 xor t2
  var t7: uint32 = t5 xor t6
  var t8: uint32 = t3 and t7
  r0 = t0 xor t8
  var t9: uint32 = r2 and r0
  r1 = t7 xor t9
  r3 = (v1 or v3) xor (t3 xor t9)

# sbox 3 decrypt template : by bitops
template S3D(r0, r1, r2, r3: var uint32): void =
  var t0: uint32 = r0 or r1
  var t1: uint32 = r1 xor r2
  var t2: uint32 = r1 and t1
  var t3: uint32 = r0 xor t2
  var t4: uint32 = r2 xor t3
  var t5: uint32 = r3 or t3
  r0 = t1 xor t5
  var t6: uint32 = t1 or t5
  var t7: uint32 = r3 xor t6
  r2 = t4 xor t7
  var t8: uint32 = t0 xor t7
  var t9: uint32 = r0 and t8
  r3 = t3 xor t9
  r1 = r3 xor (r0 xor t8)

# sbox 4 encrypt template : by bitops
template S4E(r0, r1, r2, r3: var uint32): void =
  var v0: uint32 = r0
  var t0: uint32 = v0 xor r3
  var t1: uint32 = r3 and t0
  var t2: uint32 = r2 xor t1
  var t3: uint32 = r1 or t2
  r3 = t0 xor t3
  var t4: uint32 = not r1
  var t5: uint32 = t0 or t4
  r0 = t2 xor t5
  var t6: uint32 = v0 and r0
  var t7: uint32 = t0 xor t4
  var t8: uint32 = t3 and t7
  r2 = t6 xor t8
  r1 = (v0 xor t2) xor (t7 and r2)

# sbox 4 decrypt template : by bitops
template S4D(r0, r1, r2, r3: var uint32): void =
  var v3: uint32 = r3
  var t0: uint32 = r2 or v3
  var t1: uint32 = r0 and t0
  var t2: uint32 = r1 xor t1
  var t3: uint32 = r0 and t2
  var t4: uint32 = r2 xor t3
  r1 = v3 xor t4
  var t5: uint32 = not r0
  var t6: uint32 = t4 and r1
  r3 = t2 xor t6
  var t7: uint32 = r1 or t5
  var t8: uint32 = v3 xor t7
  r0 = r3 xor t8
  r2 = (t2 and t8) xor (r1 xor t5)

# sbox 5 encrypt template : by bitops
template S5E(r0, r1, r2, r3: var uint32): void =
  var v1: uint32 = r1
  var t0: uint32 = not r0
  var t1: uint32 = r0 xor v1
  var t2: uint32 = r0 xor r3
  var t3: uint32 = r2 xor t0
  var t4: uint32 = t1 or t2
  r0 = t3 xor t4
  var t5: uint32 = r3 and r0
  var t6: uint32 = t1 xor r0
  r1 = t5 xor t6
  var t7: uint32 = t0 or r0
  var t8: uint32 = t1 or t5
  var t9: uint32 = t2 xor t7
  r2 = t8 xor t9
  r3 = (v1 xor t5) xor (r1 and t9)

# sbox 5 decrypt template : by bitops
template S5D(r0, r1, r2, r3: var uint32): void =
  var v0: uint32 = r0
  var v1: uint32 = r1
  var v3: uint32 = r3
  var t0: uint32 = not r2
  var t1: uint32 = v1 and t0
  var t2: uint32 = v3 xor t1
  var t3: uint32 = v0 and t2
  var t4: uint32 = v1 xor t0
  r3 = t3 xor t4
  var t5: uint32 = v1 or r3
  var t6: uint32 = v0 and t5
  r1 = t2 xor t6
  var t7: uint32 = v0 or v3
  var t8: uint32 = t0 xor t5
  r0 = t7 xor t8
  r2 = (v1 and t7) xor (t3 or (v0 xor r2))

# sbox 6 encrypt template : by bitops
template S6E(r0, r1, r2, r3: var uint32): void =
  var t0: uint32 = not r0
  var t1: uint32 = r0 xor r3
  var t2: uint32 = r1 xor t1
  var t3: uint32 = t0 or t1
  var t4: uint32 = r2 xor t3
  r1 = r1 xor t4
  var t5: uint32 = t1 or r1
  var t6: uint32 = r3 xor t5
  var t7: uint32 = t4 and t6
  r2 = t2 xor t7
  var t8: uint32 = t4 xor t6
  r0 = r2 xor t8
  r3 = (not t4) xor (t2 and t8)

# sbox 6 decrypt template : by bitops
template S6D(r0, r1, r2, r3: var uint32): void =
  var v1: uint32 = r1
  var v3: uint32 = r3
  var t0: uint32 = not r0
  var t1: uint32 = r0 xor v1
  var t2: uint32 = r2 xor t1
  var t3: uint32 = r2 or t0
  var t4: uint32 = v3 xor t3
  r1 = t2 xor t4
  var t5: uint32 = t2 and t4
  var t6: uint32 = t1 xor t5
  var t7: uint32 = v1 or t6
  r3 = t4 xor t7
  var t8: uint32 = v1 or r3
  r0 = t6 xor t8
  r2 = (v3 and t0) xor (t2 xor t8)

# sbox 7 encrypt template : by bitops
template S7E(r0, r1, r2, r3: var uint32): void =
  var t0: uint32 = r1 xor r2
  var t1: uint32 = r2 and t0
  var t2: uint32 = r3 xor t1
  var t3: uint32 = r0 xor t2
  var t4: uint32 = r3 or t0
  var t5: uint32 = t3 and t4
  r1 = r1 xor t5
  var t6: uint32 = t2 or r1
  var t7: uint32 = r0 and t3
  r3 = t0 xor t7
  var t8: uint32 = t3 xor t6
  var t9: uint32 = r3 and t8
  r2 = t2 xor t9
  r0 = (not t8) xor (r3 and r2)

# sbox 7 decrypt template : by bitops
template S7D(r0, r1, r2, r3: var uint32): void =
  var v0: uint32 = r0
  var v3: uint32 = r3
  var t0: uint32 = r2 or (v0 and r1)
  var t1: uint32 = v3 and (v0 or r1)
  r3 = t0 xor t1
  var t2: uint32 = not v3
  var t3: uint32 = r1 xor t1
  var t4: uint32 = t3 or (r3 xor t2)
  r1 = v0 xor t4
  r0 = (r2 xor t3) xor (v3 or r1)
  r2 = (t0 xor r1) xor (r0 xor (v0 and r3))

# serpent init core
template serpentInitC[bits: static int](ctx: var SerpentCtx[bits], key: slicearray[bits div 8, uint8]): void =
  # declare temporal buffer
  var w: array[140, uint32]

  # decode key
  when bits == 256:
    decodeLE(key, w.toSliceArray(0, 7))
  elif bits == 192:
    decodeLE(key, w.toSliceArray(0, 5))
    w[6] = 0x00000001'u32
    w[7] = 0
  elif bits == 128:
    decodeLE(key, w.toSliceArray(0, 3))
    w[4] = 0x00000001'u32
    w[5] = 0
    w[6] = 0
    w[7] = 0

  # extend key
  var x: uint32 = 0
  for i in static(8 ..< 140):
    x = w[i - 8] xor w[i - 5] xor w[i - 3] xor w[i - 1] xor PHI xor uint32(i - 8)
    w[i] = rotateLeftBits(x, 11)

  for i in static(0 ..< 132):
    ctx.roundKey[i] = w[i + 8]

  # apply sbox to round key
  for i in static(0 .. 3):
    S3E(ctx.roundKey[i * 32 + 0], ctx.roundKey[i * 32 + 1], ctx.roundKey[i * 32 + 2], ctx.roundKey[i * 32 + 3])
    S2E(ctx.roundKey[i * 32 + 4], ctx.roundKey[i * 32 + 5], ctx.roundKey[i * 32 + 6], ctx.roundKey[i * 32 + 7])
    S1E(ctx.roundKey[i * 32 + 8], ctx.roundKey[i * 32 + 9], ctx.roundKey[i * 32 + 10], ctx.roundKey[i * 32 + 11])
    S0E(ctx.roundKey[i * 32 + 12], ctx.roundKey[i * 32 + 13], ctx.roundKey[i * 32 + 14], ctx.roundKey[i * 32 + 15])
    S7E(ctx.roundKey[i * 32 + 16], ctx.roundKey[i * 32 + 17], ctx.roundKey[i * 32 + 18], ctx.roundKey[i * 32 + 19])
    S6E(ctx.roundKey[i * 32 + 20], ctx.roundKey[i * 32 + 21], ctx.roundKey[i * 32 + 22], ctx.roundKey[i * 32 + 23])
    S5E(ctx.roundKey[i * 32 + 24], ctx.roundKey[i * 32 + 25], ctx.roundKey[i * 32 + 26], ctx.roundKey[i * 32 + 27])
    S4E(ctx.roundKey[i * 32 + 28], ctx.roundKey[i * 32 + 29], ctx.roundKey[i * 32 + 30], ctx.roundKey[i * 32 + 31])

  S3E(ctx.roundKey[128], ctx.roundKey[129], ctx.roundKey[130], ctx.roundKey[131])

# serpent encrypt core
template serpentEncryptC(ctx: SerpentCtx, input, output: slicearray[16, uint8]): void =
  # declaring temporary registers
  var r0, r1, r2, r3: uint32
  # casting state to U32 unit array
  # decode state to temporary registers
  fromBytesLE(input.toSliceArray(0, 3), r0)
  fromBytesLE(input.toSliceArray(4, 7), r1)
  fromBytesLE(input.toSliceArray(8, 11), r2)
  fromBytesLE(input.toSliceArray(12, 15), r3)

  # round template
  template applyRound(sbox: untyped, tr0, tr1, tr2, tr3: var uint32, offset: int): void =
    tr0 = tr0 xor ctx.roundKey[offset + 0]
    tr1 = tr1 xor ctx.roundKey[offset + 1]
    tr2 = tr2 xor ctx.roundKey[offset + 2]
    tr3 = tr3 xor ctx.roundKey[offset + 3]
    sbox(tr0, tr1, tr2, tr3)

  template encryptRound(i: static int): void =
    applyRound(S0E, r0, r1, r2, r3, i * 32 + 0)
    linear(r0, r1, r2, r3)
    applyRound(S1E, r0, r1, r2, r3, i * 32 + 4)
    linear(r0, r1, r2, r3)
    applyRound(S2E, r0, r1, r2, r3, i * 32 + 8)
    linear(r0, r1, r2, r3)
    applyRound(S3E, r0, r1, r2, r3, i * 32 + 12)
    linear(r0, r1, r2, r3)
    applyRound(S4E, r0, r1, r2, r3, i * 32 + 16)
    linear(r0, r1, r2, r3)
    applyRound(S5E, r0, r1, r2, r3, i * 32 + 20)
    linear(r0, r1, r2, r3)
    applyRound(S6E, r0, r1, r2, r3, i * 32 + 24)
    linear(r0, r1, r2, r3)
    when i < 3:
      applyRound(S7E, r0, r1, r2, r3, i * 32 + 28)
      linear(r0, r1, r2, r3)
    else:
      applyRound(S7E, r0, r1, r2, r3, i * 32 + 28)
      r0 = r0 xor ctx.roundKey[128]
      r1 = r1 xor ctx.roundKey[129]
      r2 = r2 xor ctx.roundKey[130]
      r3 = r3 xor ctx.roundKey[131]

  encryptRound(0)
  encryptRound(1)
  encryptRound(2)
  encryptRound(3)

  # storing state to memory
  toBytesLE(r0, output.toSliceArray(0, 3))
  toBytesLE(r1, output.toSliceArray(4, 7))
  toBytesLE(r2, output.toSliceArray(8, 11))
  toBytesLE(r3, output.toSliceArray(12, 15))

# serpent decrypt core
template serpentDecryptC(ctx: SerpentCtx, input, output: slicearray[16, uint8]): void =
  # declaring temporary registers
  var r0, r1, r2, r3: uint32

  # decode state to temporary registers
  fromBytesLE(input.toSliceArray(0, 3), r0)
  fromBytesLE(input.toSliceArray(4, 7), r1)
  fromBytesLE(input.toSliceArray(8, 11), r2)
  fromBytesLE(input.toSliceArray(12, 15), r3)

  # round template
  template applyRound(sbox: untyped, tr0, tr1, tr2, tr3: uint32, offset: int): void =
    sbox(tr0, tr1, tr2, tr3)
    tr0 = tr0 xor ctx.roundKey[offset + 0]
    tr1 = tr1 xor ctx.roundKey[offset + 1]
    tr2 = tr2 xor ctx.roundKey[offset + 2]
    tr3 = tr3 xor ctx.roundKey[offset + 3]

  # apply round
  template decryptRound(i: static int): void =
    applyRound(S7D, r0, r1, r2, r3, i * 32 + 28)
    invLinear(r0, r1, r2, r3)

    applyRound(S6D, r0, r1, r2, r3, i * 32 + 24)
    invLinear(r0, r1, r2, r3)

    applyRound(S5D, r0, r1, r2, r3, i * 32 + 20)
    invLinear(r0, r1, r2, r3)

    applyRound(S4D, r0, r1, r2, r3, i * 32 + 16)
    invLinear(r0, r1, r2, r3)

    applyRound(S3D, r0, r1, r2, r3, i * 32 + 12)
    invLinear(r0, r1, r2, r3)

    applyRound(S2D, r0, r1, r2, r3, i * 32 + 8)
    invLinear(r0, r1, r2, r3)

    applyRound(S1D, r0, r1, r2, r3, i * 32 + 4)
    invLinear(r0, r1, r2, r3)

    when i > 0:
      applyRound(S0D, r0, r1, r2, r3, i * 32 + 0)
      invLinear(r0, r1, r2, r3)
    else:
      S0D(r0, r1, r2, r3)
      r0 = r0 xor ctx.roundKey[0]
      r1 = r1 xor ctx.roundKey[1]
      r2 = r2 xor ctx.roundKey[2]
      r3 = r3 xor ctx.roundKey[3]

  # xor last round key
  r0 = r0 xor ctx.roundKey[128]
  r1 = r1 xor ctx.roundKey[129]
  r2 = r2 xor ctx.roundKey[130]
  r3 = r3 xor ctx.roundKey[131]

  decryptRound(3)
  decryptRound(2)
  decryptRound(1)
  decryptRound(0)

  # storing state to memory
  toBytesLE(r0, output.toSliceArray(0, 3))
  toBytesLE(r1, output.toSliceArray(4, 7))
  toBytesLE(r2, output.toSliceArray(8, 11))
  toBytesLE(r3, output.toSliceArray(12, 15))

# export wrappers
when defined(templateOpt):
  template serpent128Init*(ctx: var Serpent128Ctx, key: array[16, uint8]): void =
    serpentInitC(ctx, key.toSliceArray(0, 15))
  template serpent128Init*(ctx: var Serpent128Ctx, key: openArray[uint8]): void =
    serpentInitC(ctx, key.toSliceArray(0, 15))
  template serpent128Init*(ctx: var Serpent128Ctx, key: slicearray[16, uint8]): void =
    serpentInitC(ctx, key)
  template serpent128Init*(ctx: ptr Serpent128Ctx, key: ptr array[16, uint8]): void =
    serpentInitC(ctx[], key.toSliceArray(0, 15))

  template serpent128Encrypt*(ctx: Serpent128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template serpent128Encrypt*(ctx: Serpent128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template serpent128Encrypt*(ctx: Serpent128Ctx, input, output: slicearray[16, uint8]): void =
    serpentEncryptC(ctx, input, output)
  template serpent128Encrypt*(ctx: Serpent128Ctx, input, output: ptr array[16, uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template serpent128Decrypt*(ctx: Serpent128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template serpent128Decrypt*(ctx: Serpent128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template serpent128Decrypt*(ctx: Serpent128Ctx, input, output: slicearray[16, uint8]): void =
    serpentDecryptC(ctx, input, output)
  template serpent128Decrypt*(ctx: Serpent128Ctx, input, output: ptr array[16, uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template serpent192Init*(ctx: var Serpent192Ctx, key: array[24, uint8]): void =
    serpentInitC(ctx, key.toSliceArray(0, 23))
  template serpent192Init*(ctx: var Serpent192Ctx, key: openArray[uint8]): void =
    serpentInitC(ctx, key.toSliceArray(0, 23))
  template serpent192Init*(ctx: var Serpent192Ctx, key: slicearray[24, uint8]): void =
    serpentInitC(ctx, key)
  template serpent192Init*(ctx: ptr Serpent192Ctx, key: ptr array[24, uint8]): void =
    serpentInitC(ctx[], key.toSliceArray(0, 23))

  template serpent192Encrypt*(ctx: Serpent192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template serpent192Encrypt*(ctx: Serpent192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template serpent192Encrypt*(ctx: Serpent192Ctx, input, output: slicearray[16, uint8]): void =
    serpentEncryptC(ctx, input, output)
  template serpent192Encrypt*(ctx: Serpent192Ctx, input, output: ptr array[16, uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template serpent192Decrypt*(ctx: Serpent192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template serpent192Decrypt*(ctx: Serpent192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template serpent192Decrypt*(ctx: Serpent192Ctx, input, output: slicearray[16, uint8]): void =
    serpentDecryptC(ctx, input, output)
  template serpent192Decrypt*(ctx: Serpent192Ctx, input, output: ptr array[16, uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template serpent256Init*(ctx: var Serpent256Ctx, key: array[32, uint8]): void =
    serpentInitC(ctx, key.toSliceArray(0, 31))
  template serpent256Init*(ctx: var Serpent256Ctx, key: openArray[uint8]): void =
    serpentInitC(ctx, key.toSliceArray(0, 31))
  template serpent256Init*(ctx: var Serpent256Ctx, key: slicearray[32, uint8]): void =
    serpentInitC(ctx, key)
  template serpent256Init*(ctx: ptr Serpent256Ctx, key: ptr array[32, uint8]): void =
    serpentInitC(ctx[], key.toSliceArray(0, 31))

  template serpent256Encrypt*(ctx: Serpent256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template serpent256Encrypt*(ctx: Serpent256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template serpent256Encrypt*(ctx: Serpent256Ctx, input, output: slicearray[16, uint8]): void =
    serpentEncryptC(ctx, input, output)
  template serpent256Encrypt*(ctx: Serpent256Ctx, input, output: ptr array[16, uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  template serpent256Decrypt*(ctx: Serpent256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template serpent256Decrypt*(ctx: Serpent256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  template serpent256Decrypt*(ctx: Serpent256Ctx, input, output: slicearray[16, uint8]): void =
    serpentDecryptC(ctx, input, output)
  template serpent256Decrypt*(ctx: Serpent256Ctx, input, output: ptr array[16, uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
else:
  proc serpent128Init*(ctx: var Serpent128Ctx, key: array[16, uint8]): void =
    serpentInitC(ctx, key.toSliceArray(0, 15))
  proc serpent128Init*(ctx: var Serpent128Ctx, key: openArray[uint8]): void =
    serpentInitC(ctx, key.toSliceArray(0, 15))
  proc serpent128Init*(ctx: var Serpent128Ctx, key: slicearray[16, uint8]): void =
    serpentInitC(ctx, key)
  proc serpent128Init*(ctx: ptr Serpent128Ctx, key: ptr array[16, uint8]): void =
    serpentInitC(ctx[], key.toSliceArray(0, 15))

  proc serpent128Encrypt*(ctx: Serpent128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc serpent128Encrypt*(ctx: Serpent128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc serpent128Encrypt*(ctx: Serpent128Ctx, input, output: slicearray[16, uint8]): void =
    serpentEncryptC(ctx, input, output)
  proc serpent128Encrypt*(ctx: Serpent128Ctx, input, output: ptr array[16, uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc serpent128Decrypt*(ctx: Serpent128Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc serpent128Decrypt*(ctx: Serpent128Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc serpent128Decrypt*(ctx: Serpent128Ctx, input, output: slicearray[16, uint8]): void =
    serpentDecryptC(ctx, input, output)
  proc serpent128Decrypt*(ctx: Serpent128Ctx, input, output: ptr array[16, uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc serpent192Init*(ctx: var Serpent192Ctx, key: array[24, uint8]): void =
    serpentInitC(ctx, key.toSliceArray(0, 23))
  proc serpent192Init*(ctx: var Serpent192Ctx, key: openArray[uint8]): void =
    serpentInitC(ctx, key.toSliceArray(0, 23))
  proc serpent192Init*(ctx: var Serpent192Ctx, key: slicearray[24, uint8]): void =
    serpentInitC(ctx, key)
  proc serpent192Init*(ctx: ptr Serpent192Ctx, key: ptr array[24, uint8]): void =
    serpentInitC(ctx[], key.toSliceArray(0, 23))

  proc serpent192Encrypt*(ctx: Serpent192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc serpent192Encrypt*(ctx: Serpent192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc serpent192Encrypt*(ctx: Serpent192Ctx, input, output: slicearray[16, uint8]): void =
    serpentEncryptC(ctx, input, output)
  proc serpent192Encrypt*(ctx: Serpent192Ctx, input, output: ptr array[16, uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc serpent192Decrypt*(ctx: Serpent192Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc serpent192Decrypt*(ctx: Serpent192Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc serpent192Decrypt*(ctx: Serpent192Ctx, input, output: slicearray[16, uint8]): void =
    serpentDecryptC(ctx, input, output)
  proc serpent192Decrypt*(ctx: Serpent192Ctx, input, output: ptr array[16, uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc serpent256Init*(ctx: var Serpent256Ctx, key: array[32, uint8]): void =
    serpentInitC(ctx, key.toSliceArray(0, 31))
  proc serpent256Init*(ctx: var Serpent256Ctx, key: openArray[uint8]): void =
    serpentInitC(ctx, key.toSliceArray(0, 31))
  proc serpent256Init*(ctx: var Serpent256Ctx, key: slicearray[32, uint8]): void =
    serpentInitC(ctx, key)
  proc serpent256Init*(ctx: ptr Serpent256Ctx, key: ptr array[32, uint8]): void =
    serpentInitC(ctx[], key.toSliceArray(0, 31))

  proc serpent256Encrypt*(ctx: Serpent256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc serpent256Encrypt*(ctx: Serpent256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc serpent256Encrypt*(ctx: Serpent256Ctx, input, output: slicearray[16, uint8]): void =
    serpentEncryptC(ctx, input, output)
  proc serpent256Encrypt*(ctx: Serpent256Ctx, input, output: ptr array[16, uint8]): void =
    serpentEncryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))

  proc serpent256Decrypt*(ctx: Serpent256Ctx, input: array[16, uint8], output: var array[16, uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc serpent256Decrypt*(ctx: Serpent256Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
  proc serpent256Decrypt*(ctx: Serpent256Ctx, input, output: slicearray[16, uint8]): void =
    serpentDecryptC(ctx, input, output)
  proc serpent256Decrypt*(ctx: Serpent256Ctx, input, output: ptr array[16, uint8]): void =
    serpentDecryptC(ctx, input.toSliceArray(0, 15), output.toSliceArray(0, 15))
   


