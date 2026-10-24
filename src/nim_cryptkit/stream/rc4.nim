import ../utils/optmacro
import ../utils/bitutils
import ../utils/errorutils
import ../utils/digits
import ../utils/slicearray
import ../utils/endian
import ../utils/envconst
import ../utils/biguintBE
import std/[monotimes, times]
import std/bitops
import strutils

type
  # RC4 context
  RC4Ctx* = object
    keyStream*: array[256, uint8]
    i*: uint8
    j*: uint8

# rc4 init core
template rc4InitC(ctx: var RC4Ctx, key: openArray[uint8]): void =
  let keyLen: int = key.len
  var j: uint8 = 0
  for i in static(0 ..< 256):
    ctx.keyStream[i] = i.uint8

  for i in static(0 ..< 256):
    j = j + ctx.keyStream[i] + key[i mod keyLen]
    swap(ctx.keyStream[i], ctx.keyStream[j])

  ctx.i = 0
  ctx.j = 0

# rc4 xor core
template rc4XorC(ctx: var RC4Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
  var i = ctx.i
  var j = ctx.j
  
  for k in 0 ..< input.len:
    i = i + 1
    j = j + ctx.keyStream[i]
    swap(ctx.keyStream[i], ctx.keyStream[j])
    
    let t = ctx.keyStream[i] + ctx.keyStream[j]
    output[k] = input[k] xor ctx.keyStream[t]
  
  ctx.i = i
  ctx.j = j

# export wrappers
when defined(templateOpt):
  template rc4Init*(ctx: var RC4Ctx, key: openArray[uint8]): void =
    rc4InitC(ctx, key)
  template rc4Init*(ctx: ptr RC4Ctx, key: ptr UncheckedArray[uint8], keyLen: int): void =
    rc4InitC(ctx[], key.toOpenArray(0, keyLen - 1))
  
  template rc4Xor*(ctx: var RC4Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    rc4XorC(ctx, input, output)
  template rc4Xor*(ctx: ptr RC4Ctx, input, output: ptr UncheckedArray[uint8], inputLen: int): void =
    rc4XorC(ctx[], input.toOpenArray(0, inputLen - 1), output.toOpenArray(0, inputLen - 1))
else:
  proc rc4Init*(ctx: var RC4Ctx, key: openArray[uint8]): void =
    rc4InitC(ctx, key)
  proc rc4Init*(ctx: ptr RC4Ctx, key: ptr UncheckedArray[uint8], keyLen: int): void {.exportc: "rc2Init".} =
    rc4InitC(ctx[], key.toOpenArray(0, keyLen - 1))
  
  proc rc4Xor*(ctx: var RC4Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    rc4XorC(ctx, input, output)
  proc rc4Xor*(ctx: ptr RC4Ctx, input, output: ptr UncheckedArray[uint8], inputLen: int): void {.exportc: "rc2Xor".} =
    rc4XorC(ctx[], input.toOpenArray(0, inputLen - 1), output.toOpenArray(0, inputLen - 1))

