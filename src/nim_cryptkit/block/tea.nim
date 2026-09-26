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
  # TEA context
  TEACtx* {.exportc: "TEACtx", completeStruct.} = object
    roundKey*: array[4, uint32]
  # XTEA context
  XTEACtx* {.exportc: "XTEACtx", completeStruct.} = object
    roundKey*: array[4, uint32]
  # XXTEA context
  XXTEACtx* {.exportc: "XXTEACtx", completeStruct.} = object
    roundKey*: array[4, uint32]

template teaInitC(ctx: var TEACtx, key: slicearray[16, uint8]): void =
  decodeLE(key, ctx.roundKey.toSliceArray(0, 3))

# tea encrypt core
template teaEncryptC(ctx: TEACtx, input, output: slicearray[8, uint8]): void =
  # declare temporal registers and decode input to it
  var v0, v1: uint32
  fromBytesLE(input.toSliceArray(0, 3), v0)
  fromBytesLE(input.toSliceArray(4, 7), v1)

  # declare sum and initialise
  var sum: uint32 = 0

  # main encryption loop(for 32)
  # use static to unroll it in compile time
  for i in static(0 ..< 32):
    # add constant delta to sum
    sum += 0x9E3779B9'u32
    # feistel network structure
    # exchange v0 and v1 after calculating
    v0 += ((v1 shl 4) + ctx.roundKey[0]) xor (v1 + sum) xor ((v1 shr 5) + ctx.roundKey[1])
    v1 += ((v0 shl 4) + ctx.roundKey[2]) xor (v0 + sum) xor ((v0 shr 5) + ctx.roundKey[3])

  # encode temporal register to output
  toBytesLE(v0, output.toSliceArray(0, 3))
  toBytesLE(v1, output.toSliceArray(4, 7))

# tea decrypt core
template teaDecryptC(ctx: TEACtx, input, output: slicearray[8, uint8]): void =
  # declare temporal registers and decode input to it
  var v0, v1: uint32
  fromBytesLE(input.toSliceArray(0, 3), v0)
  fromBytesLE(input.toSliceArray(4, 7), v1)
  # declare sum and initialise
  var sum: uint32 = 0xC6EF3720'u32

  # main encryption loop(for 32)
  # use static to unroll it in compile time
  for i in static(0 ..< 32):
    # feistel network structure
    # exchange v0 and v1 after calculating
    v1 -= ((v0 shl 4) + ctx.roundKey[2]) xor (v0 + sum) xor ((v0 shr 5) + ctx.roundKey[3])
    v0 -= ((v1 shl 4) + ctx.roundKey[0]) xor (v1 + sum) xor ((v1 shr 5) + ctx.roundKey[1])
    # sub constant delta to sum
    sum -= 0x9E3779B9'u32

  # encode temporal register to output
  toBytesLE(v0, output.toSliceArray(0, 3))
  toBytesLE(v1, output.toSliceArray(4, 7))

template xteaInitC(ctx: var XTEACtx, key: slicearray[16, uint8]): void =
  decodeLE(key, ctx.roundKey.toSliceArray(0, 3))

template xteaEncryptC(ctx: XTEACtx, input, output: slicearray[8, uint8], round: int): void =
  # declare temporal registers and decode input to it
  var v0, v1: uint32
  fromBytesLE(input.toSliceArray(0, 3), v0)
  fromBytesLE(input.toSliceArray(4, 7), v1)
  # declare sum and initialise
  var sum: uint32 = 0

  # main encryption loop(for round)
  for i in 0 ..< round:
    # feistel network structure
    # exchange v0 and v1 after calculating
    # add constant delta to sum in middle
    v0 += ((v1 shl 4) xor (v1 shr 5) + v1) xor (sum + ctx.roundKey[sum and 3])
    sum += 0x9E3779B9'u32
    v1 += ((v0 shl 4) xor (v0 shr 5) + v0) xor (sum + ctx.roundKey[(sum shr 11) and 3])

  # encode temporal register to output
  toBytesLE(v0, output.toSliceArray(0, 3))
  toBytesLE(v1, output.toSliceArray(4, 7))

# xtea decrypt core
template xteaDecryptC(ctx: XTEACtx, input, output: slicearray[8, uint8], round: int): void =
  # declare temporal registers and decode input to it
  var v0, v1: uint32
  fromBytesLE(input.toSliceArray(0, 3), v0)
  fromBytesLE(input.toSliceArray(4, 7), v1)
  # declare sum and initialise
  var sum: uint32 = 0

  # main encryption loop(for round)
  for i in 0 ..< round:
    # feistel network structure
    # exchange v0 and v1 after calculating
    # add constant delta to sum in middle
    v1 -= ((v0 shl 4) xor (v0 shr 5) + v0) xor (sum + ctx.roundKey[(sum shr 11) and 3])
    sum -= 0x9E3779B9'u32
    v0 -= ((v1 shl 4) xor (v1 shr 5) + v1) xor (sum + ctx.roundKey[sum and 3])

  # encode temporal register to output
  toBytesLE(v0, output.toSliceArray(0, 3))
  toBytesLE(v1, output.toSliceArray(4, 7))

# mx template
template mx(z, y, sum, p, e: uint32, key: ptr array[4, uint32]): uint32 =
  ((z shr 5) xor (y shl 2)) + ((y shr 3) xor (z shl 4)) xor ((sum xor y) + (key[p and 3 xor e] xor z))

# xxtea decrypt core : UncheckedArray version(must need length)
template xxteaEncryptC(ctx: XXTEACtx, input: ptr UncheckedArray[uint8], inputLen: int): void =
  # number of 32 bit words
  let n: int = inputLen div 4
  # dynamic rounds calculation
  var q = 6 + 52 div n

  # cast key and value for 32bit operations
  let key: ptr array[4, uint32] = cast[ptr array[4, uint32]](addr ctx.roundKey[0])
  let value: ptr UncheckedArray[uint32] = cast[ptr UncheckedArray[uint32]](input)

  # store last element of block in temporary variables
  var z: uint32 = value[n - 1]
  # store first element of block in temporary variables
  var y: uint32 = value[0]
  # declare sum and initialise
  var sum: uint32  = 0
  var e: uint32 = 0

  # main dcryption loop (reverse of encryption)
  while (q > 0):
    sum += 0x9E3779B9'u32
    e = (sum shr 2) and 3

    # update elements in reverse order (from last to second)
    for i in 0 ..< n - 1:
      y = value[i + 1]
      value[i] += mx(z, y, sum, i.uint32, e, key)
      z = value[i]

    # final step : update the first element using the last element
    y = value[0]
    value[n - 1] += mx(z, y, sum, (n - 1).uint32, e, key)
    z = value[n - 1]
    q.dec

template xxteaDecryptC(ctx: XXTEACtx, input: ptr UncheckedArray[uint8], inputLen: int): void =
  # number of 32 bit words
  let n: int = inputLen div 4
  # dynamic rounds calculation
  var q: int = 6 + 52 div n

  # cast key and value for 32bit operations
  let key: ptr array[4, uint32] = cast[ptr array[4, uint32]](addr ctx.roundKey[0])
  let value: ptr UncheckedArray[uint32] = cast[ptr UncheckedArray[uint32]](input)

  # store last element of block in temporary variables
  var z: uint32 = value[n - 1]
  # store first element of block in temporary variables
  var y: uint32 = value[0]
  # declare sum and initialise
  var sum: uint32 = 0x9E3779B9'u32 * q.uint32
  var e: uint32 = 0

  # main dcryption loop (reverse of encryption)
  while q > 0:
    e = (sum shr 2) and 3
    for i in countdown(n - 1, 1):
      z = value[i - 1]
      value[i] -= mx(z, y, sum, i.uint32, e, key)
      y = value[i]

    # final step : update the first element using the last element
    z = value[n - 1]
    value[0] -= mx(z, y, sum, 0.uint32, e, key)
    y = value[0]

    # de-accumulate delta
    sum -= 0x9E3779B9'u32
    q.dec

# export wrappers
when defined(templateOpt):
  template teaInit*(ctx: var TEACtx, key: array[16, uint8]): void =
    teaInitC(ctx, key.toSliceArray(0, 15))
  template teaInit*(ctx: var TEACtx, key: openArray[uint8]): void =
    teaInitC(ctx, key.toSliceArray(0, 15))
  template teaInit*(ctx: var TEACtx, key: slicearray[16, uint8]): void =
    teaInitC(ctx, key)
  template teaInit*(ctx: ptr TEACtx, key: ptr array[16, uint8]): void =
    teaInitC(ctx[], key.toSliceArray(0, 15))

  template teaEncrypt*(ctx: TEACtx, input: array[8, uint8], output: var array[8, uint8]): void =
    teaEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template teaEncrypt*(ctx: TEACtx, input: openArray[uint8], output: var openArray[uint8]): void =
    teaEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template teaEncrypt*(ctx: TEACtx, input, output: slicearray[8, uint8]): void =
    teaEncryptC(ctx, input, output)
  template teaEncrypt*(ctx: ptr TEACtx, input, output: ptr array[8, uint8]): void =
    teaEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  template teaDecrypt*(ctx: TEACtx, input: array[8, uint8], output: var array[8, uint8]): void =
    teaDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template teaDecrypt*(ctx: TEACtx, input: openArray[uint8], output: var openArray[uint8]): void =
    teaDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template teaDecrypt*(ctx: TEACtx, input, output: slicearray[8, uint8]): void =
    teaDecryptC(ctx, input, output)
  template teaDecrypt*(ctx: ptr TEACtx, input, output: ptr array[8, uint8]): void =
    teaDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  template xteaInit*(ctx: var XTEACtx, key: array[16, uint8]): void =
    xteaInitC(ctx, key.toSliceArray(0, 15))
  template xteaInit*(ctx: var XTEACtx, key: openArray[uint8]): void =
    xteaInitC(ctx, key.toSliceArray(0, 15))
  template xteaInit*(ctx: var XTEACtx, key: slicearray[16, uint8]): void =
    xteaInitC(ctx, key)
  template xteaInit*(ctx: ptr XTEACtx, key: ptr array[16, uint8]): void =
    xteaInitC(ctx[], key.toSliceArray(0, 15))

  template xteaEncrypt*(ctx: XTEACtx, input: array[8, uint8], output: var array[8, uint8], rounds: int): void =
    xteaEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7), rounds)
  template xteaEncrypt*(ctx: XTEACtx, input: openArray[uint8], output: var openArray[uint8], rounds: int): void =
    xteaEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7), rounds)
  template xteaEncrypt*(ctx: XTEACtx, input, output: slicearray[8, uint8], rounds: int): void =
    xteaEncryptC(ctx, input, output, rounds)
  template xteaEncrypt*(ctx: ptr XTEACtx, input, output: ptr array[8, uint8], rounds: int): void =
    xteaEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7), rounds)

  template xteaDecrypt*(ctx: XTEACtx, input: array[8, uint8], output: var array[8, uint8], rounds: int): void =
    xteaDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7), rounds)
  template xteaDecrypt*(ctx: XTEACtx, input: openArray[uint8], output: var openArray[uint8], rounds: int): void =
    xteaDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7), rounds)
  template xteaDecrypt*(ctx: XTEACtx, input, output: slicearray[8, uint8], rounds: int): void =
    xteaDecryptC(ctx, input, output, rounds)
  template xteaDecrypt*(ctx: ptr XTEACtx, input, output: ptr array[8, uint8], rounds: int): void =
    xteaDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7), rounds)

  template xxteaEncrypt*(ctx: XXTEACtx, input: var openArray[uint8]): void =
    xxteaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]), input.len)
  template xxteaEncrypt*(ctx: XXTEACtx, input: ptr UncheckedArray[uint8], inputLen: int): void =
    xxteaEncryptC(ctx, input, inputLen)
  template xxteaDecrypt*(ctx: XXTEACtx, input: var openArray[uint8]): void =
    xxteaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]), input.len)
  template xxteaDecrypt*(ctx: XXTEACtx, input: ptr UncheckedArray[uint8], inputLen: int): void =
    xxteaDecryptC(ctx, input, inputLen)
else:
  proc teaInit*(ctx: var TEACtx, key: array[16, uint8]): void =
    teaInitC(ctx, key.toSliceArray(0, 15))
  proc teaInit*(ctx: var TEACtx, key: openArray[uint8]): void =
    teaInitC(ctx, key.toSliceArray(0, 15))
  proc teaInit*(ctx: var TEACtx, key: slicearray[16, uint8]): void =
    teaInitC(ctx, key)
  proc teaInit*(ctx: ptr TEACtx, key: ptr array[16, uint8]): void =
    teaInitC(ctx[], key.toSliceArray(0, 15))

  proc teaEncrypt*(ctx: TEACtx, input: array[8, uint8], output: var array[8, uint8]): void =
    teaEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc teaEncrypt*(ctx: TEACtx, input: openArray[uint8], output: var openArray[uint8]): void =
    teaEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc teaEncrypt*(ctx: TEACtx, input, output: slicearray[8, uint8]): void =
    teaEncryptC(ctx, input, output)
  proc teaEncrypt*(ctx: ptr TEACtx, input, output: ptr array[8, uint8]): void =
    teaEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  proc teaDecrypt*(ctx: TEACtx, input: array[8, uint8], output: var array[8, uint8]): void =
    teaDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc teaDecrypt*(ctx: TEACtx, input: openArray[uint8], output: var openArray[uint8]): void =
    teaDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc teaDecrypt*(ctx: TEACtx, input, output: slicearray[8, uint8]): void =
    teaDecryptC(ctx, input, output)
  proc teaDecrypt*(ctx: ptr TEACtx, input, output: ptr array[8, uint8]): void =
    teaDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  proc xteaInit*(ctx: var XTEACtx, key: array[16, uint8]): void =
    xteaInitC(ctx, key.toSliceArray(0, 15))
  proc xteaInit*(ctx: var XTEACtx, key: openArray[uint8]): void =
    xteaInitC(ctx, key.toSliceArray(0, 15))
  proc xteaInit*(ctx: var XTEACtx, key: slicearray[16, uint8]): void =
    xteaInitC(ctx, key)
  proc xteaInit*(ctx: ptr XTEACtx, key: ptr array[16, uint8]): void =
    xteaInitC(ctx[], key.toSliceArray(0, 15))

  proc xteaEncrypt*(ctx: XTEACtx, input: array[8, uint8], output: var array[8, uint8], rounds: int): void =
    xteaEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7), rounds)
  proc xteaEncrypt*(ctx: XTEACtx, input: openArray[uint8], output: var openArray[uint8], rounds: int): void =
    xteaEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7), rounds)
  proc xteaEncrypt*(ctx: XTEACtx, input, output: slicearray[8, uint8], rounds: int): void =
    xteaEncryptC(ctx, input, output, rounds)
  proc xteaEncrypt*(ctx: ptr XTEACtx, input, output: ptr array[8, uint8], rounds: int): void =
    xteaEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7), rounds)

  proc xteaDecrypt*(ctx: XTEACtx, input: array[8, uint8], output: var array[8, uint8], rounds: int): void =
    xteaDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7), rounds)
  proc xteaDecrypt*(ctx: XTEACtx, input: openArray[uint8], output: var openArray[uint8], rounds: int): void =
    xteaDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7), rounds)
  proc xteaDecrypt*(ctx: XTEACtx, input, output: slicearray[8, uint8], rounds: int): void =
    xteaDecryptC(ctx, input, output, rounds)
  proc xteaDecrypt*(ctx: ptr XTEACtx, input, output: ptr array[8, uint8], rounds: int): void =
    xteaDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7), rounds)

  proc xxteaEncrypt*(ctx: XXTEACtx, input: var openArray[uint8]): void =
    xxteaEncryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]), input.len)
  proc xxteaEncrypt*(ctx: XXTEACtx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "xxtea_encrypt", cdecl.} =
    xxteaEncryptC(ctx, input, inputLen)
  proc xxteaDecrypt*(ctx: XXTEACtx, input: var openArray[uint8]): void =
    xxteaDecryptC(ctx, cast[ptr UncheckedArray[uint8]](unsafeAddr input[0]), input.len)
  proc xxteaDecrypt*(ctx: XXTEACtx, input: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "xxtea_decrypt", cdecl.} =
    xxteaDecryptC(ctx, input, inputLen)

when defined(test):
  template benchmark(name: string, code: untyped) =
    let start = getMonoTime()
    code
    let elapsed = getMonoTime() - start
    echo name, " took: ", elapsed.inMicroseconds, " μs (", elapsed.inNanoseconds, " ns)"

  var key: array[16, uint8] = [
    0x00'u8, 0x11'u8, 0x22'u8, 0x33'u8, 0x44'u8, 0x55'u8, 0x66'u8, 0x77'u8, 0x88'u8, 0x99'u8, 0xAA'u8, 0xBB'u8, 0xCC'u8, 0xDD'u8, 0xEE'u8, 0xFF'u8
  ]
  var text: array[8, uint8] = [
    0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8
  ]
  var ctxTEA: TEACtx
  var ctxXTEA: XTEACtx
  var ctxXXTEA: XXTEACtx
  teaInit(ctxTEA, key)
  xteaInit(ctxXTEA, key)
  xxteaInit(ctxXXTEA, key)

  benchmark("TEA Encrypt"):
    for i in 1 .. 1_000_000:
      teaEncrypt(ctxTEA, text, text)

  benchmark("TEA Decrypt"):
    for i in 1 .. 1_000_000:
      teaDecrypt(ctxTEA, text, text)

  benchmark("XTEA Encrypt"):
    for i in 1 .. 1_000_000:
      xteaEncrypt(ctxXTEA, text, text, 32)
      
  benchmark("XTEA Decrypt"):
    for i in 1 .. 1_000_000:
      xteaDecrypt(ctxXTEA, text, text, 32)

  benchmark("XXTEA Encrypt"):
    for i in 1 .. 1_000_000:
      xxteaEncrypt(ctxXXTEA, text)

  benchmark("XXTEA Decrypt"):
    for i in 1 .. 1_000_000:
      xxteaDecrypt(ctxXXTEA, text)
