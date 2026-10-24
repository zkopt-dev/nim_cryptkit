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
  # IDEA information constants
  IDEA_KEY_SIZE*: int = 16
  IDEA_BLOCK_SIZE*: int = 8
  ROUND_NUMBER*: int = 8
  SUB_KEY_NUMBER*: int = 52

  # IDEA modules constant
  ADD_MODULES*: uint32 = 0x10000'u32
  MUL_MODULES*: uint32 = 0x10001'u32

  # CPU's Bits
  Bits*: int = sizeof(uint) * 8

type
  # IDEA context
  IDEACtx* = object
    encryptKey*: array[52, uint16]
    decryptKey*: array[52, uint16]

# add inverse
template addInverse(number: uint16): uint16 {.autoSizeOpt.} =
  uint16((ADD_MODULES - number.uint32) and 0xFFFF'u32)

# idea multiplication 
template ideaMul(a, b: uint16): uint16 {.autoSizeOpt.} =
  block:
    let val_a = a.uint32
    let val_b = b.uint32

    # Case 3: a != 0 and b != 0
    let p = val_a * val_b
    var res_mul_signed = int64(p and 0xFFFF'u32) - int64(p shr 16)
    # Branchless borrow check. Add 1 if the result was negative.
    res_mul_signed += (res_mul_signed shr 63) and 1
    let res_mul = uint32(res_mul_signed)

    # Case 1: a == 0
    let res_a_zero = 1'u32 - val_b

    # Case 2: b == 0
    let res_b_zero = 1'u32 - val_a

    # Select the correct result using bitwise operations
    let mask_a_zero = uint32(-int(a == 0))
    let mask_b_zero = uint32(-int(b == 0))

    let res_nonzero = (mask_b_zero and res_b_zero) or (not mask_b_zero and res_mul)
    let final_res = (mask_a_zero and res_a_zero) or (not mask_a_zero and res_nonzero)

    uint16(final_res and 0xFFFF'u32)

# idea multiplication inverse constant time
template mulInverse(x: uint16): uint16 {.autoSizeOpt.} =
  block:
    var n = x
    var m = x
    # Unrolled loop for i in 1..15 to compute x^65535 mod (2^16+1)
    # This is equivalent to mulInverse(x) by Fermat's Little Theorem.
    # The loop is unrolled to avoid data-dependent branches.
    m = ideaMul(m, m); n = ideaMul(n, m)
    m = ideaMul(m, m); n = ideaMul(n, m)
    m = ideaMul(m, m); n = ideaMul(n, m)
    m = ideaMul(m, m); n = ideaMul(n, m)
    m = ideaMul(m, m); n = ideaMul(n, m)
    m = ideaMul(m, m); n = ideaMul(n, m)
    m = ideaMul(m, m); n = ideaMul(n, m)
    m = ideaMul(m, m); n = ideaMul(n, m)
    m = ideaMul(m, m); n = ideaMul(n, m)
    m = ideaMul(m, m); n = ideaMul(n, m)
    m = ideaMul(m, m); n = ideaMul(n, m)
    m = ideaMul(m, m); n = ideaMul(n, m)
    m = ideaMul(m, m); n = ideaMul(n, m)
    m = ideaMul(m, m); n = ideaMul(n, m)
    m = ideaMul(m, m); n = ideaMul(n, m)
    n

# idea round template
template ideaRound(x1, x2, x3, x4: var uint16, k: slicearray[6, uint16]): void {.autoSizeOpt.} =
  x1 = ideaMul(x1, k[0])
  x2 = x2 + k[1]
  x3 = x3 + k[2]
  x4 = ideaMul(x4, k[3])

  let t0 = x1 xor x3
  let t1 = x2 xor x4

  let u0 = ideaMul(t0, k[4])
  let u1 = u0 + t1
  let u2 = ideaMul(u1, k[5])
  let u3 = u0 + u2

  let v1 = x1 xor u2
  let v4 = x4 xor u3
  let v2 = x3 xor u2
  let v3 = x2 xor u3

  x1 = v1
  x2 = v2
  x3 = v3
  x4 = v4

# idea final template
template ideaFinal(x1, x2, x3, x4: var uint16, k: slicearray[4, uint16]): void {.autoSizeOpt.} =
  x1 = ideaMul(x1, k[0])
  let t2 = x3 + k[1]
  let t3 = x2 + k[2]
  x4 = ideaMul(x4, k[3])
  x2 = t2
  x3 = t3

# idea routine template 
template ideaRoutine(subKey: array[52, uint16], message: var array[4, uint16]): void {.autoSizeOpt.} =
  ideaRound(message[0], message[1], message[2], message[3], subKey.toSliceArray(0, 5))
  ideaRound(message[0], message[1], message[2], message[3], subKey.toSliceArray(6, 11))
  ideaRound(message[0], message[1], message[2], message[3], subKey.toSliceArray(12, 17))
  ideaRound(message[0], message[1], message[2], message[3], subKey.toSliceArray(18, 23))
  ideaRound(message[0], message[1], message[2], message[3], subKey.toSliceArray(24, 29))
  ideaRound(message[0], message[1], message[2], message[3], subKey.toSliceArray(30, 35))
  ideaRound(message[0], message[1], message[2], message[3], subKey.toSliceArray(36, 41))
  ideaRound(message[0], message[1], message[2], message[3], subKey.toSliceArray(42, 47))
  ideaFinal(message[0], message[1], message[2], message[3], subKey.toSliceArray(48, 51))

# idea init core
template ideaInitC(ctx: var IDEACtx, key: slicearray[16, uint8]): void {.autoSizeOpt.} =
  # decode key to k 
  decodeBE(key, ctx.encryptKey.toSliceArray(0, 7))
  
  # generate encrypt sub key
  for i in static(8 ..< 52):
    if (i mod 8) == 6:
      ctx.encryptKey[i] = (ctx.encryptKey[i - 7] shl 9) or (ctx.encryptKey[i - 14] shr 7)
    elif (i mod 8) == 7:
      ctx.encryptKey[i] = (ctx.encryptKey[i - 15] shl 9) or (ctx.encryptKey[i - 14] shr 7)
    else:
      ctx.encryptKey[i] = (ctx.encryptKey[i - 7] shl 9) or (ctx.encryptKey[i - 6] shr 7)

  # generate decrypt sub key
  for i in countup(0, 48, 6):
    ctx.decryptKey[i] = mulInverse(ctx.encryptKey[48 - i])

    if i == 0 or i == 48:
      ctx.decryptKey[i + 1] = addInverse(ctx.encryptKey[49 - i])
      ctx.decryptKey[i + 2] = addInverse(ctx.encryptKey[50 - i])
    else:
      ctx.decryptKey[i + 1] = addInverse(ctx.encryptKey[50 - i])
      ctx.decryptKey[i + 2] = addInverse(ctx.encryptKey[49 - i])

    ctx.decryptKey[i + 3] = mulInverse(ctx.encryptKey[51 - i])

    if i < 48:
      ctx.decryptKey[i + 4] = ctx.encryptKey[46 - i]
      ctx.decryptKey[i + 5] = ctx.encryptKey[47 - i]

# idea encrypt core
template ideaEncryptC(ctx: IDEACtx, input, output: slicearray[8, uint8]): void {.autoSizeOpt.} =
  var message: array[4, uint16]
  
  # use decode function in other endian
  decodeBE(input, message.toSliceArray(0, 3))

  # call routine template
  ideaRoutine(ctx.encryptKey, message)
  
  # use encode function in other endian
  encodeBE(message.toSliceArray(0, 3), output)

# idea decrypt core
template ideaDecryptC(ctx: IDEACtx, input, output: slicearray[8, uint8]): void {.autoSizeOpt.} =
  var message: array[4, uint16]

  # use decode function in other endian
  decodeBE(input, message.toSliceArray(0, 3))

  # call routine template
  ideaRoutine(ctx.decryptKey, message)

  # use encode function in other endian 
  encodeBE(message.toSliceArray(0, 3), output)

# export wrappers
when defined(templateOpt):
  template ideaInit*(ctx: var IDEACtx, key: array[16, uint8]): void =
    ideaInitC(ctx, key.toSliceArray(0, 15))
  template ideaInit*(ctx: var IDEACtx, key: openArray[uint8]): void =
    ideaInitC(ctx, key.toSliceArray(0, 15))
  template ideaInit*(ctx: var IDEACtx, key: slicearray[16, uint8]): void =
    ideaInitC(ctx, key)
  template ideaInit*(ctx: ptr IDEACtx, key: ptr array[16, uint8]): void =
    ideaInitC(ctx[], key.toSliceArray(0, 15))
  
  template ideaEncrypt*(ctx: IDEACtx, input: array[8, uint8], output: var array[8, uint8]): void =
    ideaEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template ideaEncrypt*(ctx: IDEACtx, input: openArray[uint8], output: var openArray[uint8]): void =
    ideaEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template ideaEncrypt*(ctx: IDEACtx, input, output: slicearray[8, uint8]): void =
    ideaEncryptC(ctx, input, output)
  template ideaEncrypt*(ctx: IDEACtx, input, output: ptr array[8, uint8]): void =
    ideaEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  template ideaDecrypt*(ctx: IDEACtx, input: array[8, uint8], output: var array[8, uint8]): void =
    ideaDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template ideaDecrypt*(ctx: IDEACtx, input: openArray[uint8], output: var openArray[uint8]): void =
    ideaDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template ideaDecrypt*(ctx: IDEACtx, input, output: slicearray[8, uint8]): void =
    ideaDecryptC(ctx, input, output)
  template ideaDecrypt*(ctx: IDEACtx, input, output: ptr array[8, uint8]): void =
    ideaDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
else:
  proc ideaInit*(ctx: var IDEACtx, key: array[16, uint8]): void =
    ideaInitC(ctx, key.toSliceArray(0, 15))
  proc ideaInit*(ctx: var IDEACtx, key: openArray[uint8]): void =
    ideaInitC(ctx, key.toSliceArray(0, 15))
  proc ideaInit*(ctx: var IDEACtx, key: slicearray[16, uint8]): void =
    ideaInitC(ctx, key)
  proc ideaInit*(ctx: ptr IDEACtx, key: ptr array[16, uint8]): void {.exportc: "ideaInit", cdecl.} =
    ideaInitC(ctx[], key.toSliceArray(0, 15))
  
  proc ideaEncrypt*(ctx: IDEACtx, input: array[8, uint8], output: var array[8, uint8]): void =
    ideaEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc ideaEncrypt*(ctx: IDEACtx, input: openArray[uint8], output: var openArray[uint8]): void =
    ideaEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc ideaEncrypt*(ctx: IDEACtx, input, output: slicearray[8, uint8]): void =
    ideaEncryptC(ctx, input, output)
  proc ideaEncrypt*(ctx: IDEACtx, input, output: ptr array[8, uint8]): void {.exportc: "ideaEncrypt", cdecl.} =
    ideaEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  proc ideaDecrypt*(ctx: IDEACtx, input: array[8, uint8], output: var array[8, uint8]): void =
    ideaDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc ideaDecrypt*(ctx: IDEACtx, input: openArray[uint8], output: var openArray[uint8]): void =
    ideaDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc ideaDecrypt*(ctx: IDEACtx, input, output: slicearray[8, uint8]): void =
    ideaDecryptC(ctx, input, output)
  proc ideaDecrypt*(ctx: IDEACtx, input, output: ptr array[8, uint8]): void {.exportc: "ideaDecrypt", cdecl.} =
    ideaDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))

