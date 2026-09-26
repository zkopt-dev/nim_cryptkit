import ../utils/endian
import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils
import ../utils/vectorop
import std/[monotimes, times]
import std/bitops

type
  GMACCtx* = object
    h*, state*: array[16, uint8]
    buffer*: array[16, uint8]
    index*: int
    length*: uint64

template ghashMul*(x, h: array[16, uint8]): array[16, uint8] =
  var output: array[16, uint8]
  var v: array[16, uint8] = h
  for byteIndex in static(0 ..< 16):
    for bit in countdown(7, 0):
      let mask = 0'u8 - ((x[byteIndex] shr bit) and 1'u8)
      for i in static(0 ..< 16):
        output[i] = output[i] xor (v[i] and mask)

      let lsb = v[15] and 1
      for i in countdown(15, 1):
        v[i] = (v[i] shr 1) or ((v[i - 1] and 1) shl 7)
      v[0] = v[0] shr 1
      v[0] = v[0] xor (0xE1'u8 and (0'u8 - lsb))

  output

template gmacTransform(ctx: var GMACCtx, work: slicearray[16, uint8]): void =
  unroll(i, 0, 15):
    ctx.state[i] = ctx.state[i] xor work[i]
  ctx.state = ghashMul(ctx.state, ctx.h)

template gmacInit*[C](ctx: var GMACCtx; init, encrypt: untyped; key: openArray[byte]): void =
  zeroMem(addr ctx, sizeof(ctx))
  var cipher: C
  var zero: array[16, byte]
  init(cipher, key)
  encrypt(cipher, zero, ctx.h)

template gmacInput*(ctx: var GMACCtx, input: openArray[uint8]): void =
  let inputLen: int = input.len

  var check: bool = true

  if inputLen <= 0: check = false

  if check:
    var index: int = ctx.index

    ctx.length += uint64(inputLen)

    let left: int = 16 - index
    var position: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      gmacTransform(ctx, ctx.buffer.toSliceArray(0, 15))
      position = left
      index = 0

      while position + 16 <= inputLen:
        gmacTransform(ctx, input.toSliceArray(position, position + 15, 16))
        position += 16

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

template gmacFinal*(ctx: var GMACCtx, tagMask: array[16, uint8]): array[16, uint8] =
  var output: array[16, uint8]
  var index: int = ctx.index

  if index != 0:
    zeroMem(addr ctx.buffer[index], 16 - index)
    gmacTransform(ctx, ctx.buffer.toSliceArray(0, 15))

  var length: array[16, uint8]
  let bitLength: uint64 = ctx.length shl 3

  toBytesBE(bitLength, length.toSliceArray(0, 7))

  gmacTransform(ctx, length.toSliceArray(0, 15))

  unroll(i, 0, 15):
    output[i] = ctx.state[i] xor tagMask[i]

  output

template ghash*(hInput: array[16, uint8]; input: openArray[uint8]): array[16, uint8] =
  var ctx: GMACCtx
  ctx.h = hInput
  ctx.gmacInput(input)
  var tagMask: array[16, uint8]
  zeroMem(addr tagMask[0], 16)
  gmacFinal(ctx, tagMask)

template generateNonce(hInput: array[16, uint8]; iv: openArray[uint8]): array[16, uint8] =
  var output: array[16, uint8]
  zeroMem(addr output[0], 16)
  if iv.len == 12:
    copyMem(addr output[0], addr iv[0], 12)
    output[15] = 1
  else:
    var nonceCtx: GMACCtx
    nonceCtx.h = hInput
    gmacInput(nonceCtx, iv)
    if nonceCtx.index != 0:
      for i in nonceCtx.index ..< 16:
        nonceCtx.buffer[i] = 0
      gmacTransform(nonceCtx, nonceCtx.buffer.toSliceArray(0, 15))
    var lengthBlock: array[16, uint8]
    zeroMem(addr lengthBlock[0], 16)
    let bitLength = uint64(iv.len) shl 3
    toBytesBE(bitLength, lengthBlock.toSliceArray(0, 7))
    gmacTransform(nonceCtx, lengthBlock.toSliceArray(0, 15))
    output = nonceCtx.state
  output

template generateTagMask*[C](init, encrypt: untyped; key, iv: openArray[uint8]): array[16, uint8] =
  var cipher: C
  var zero, h: array[16, uint8]
  zeroMem(addr zero[0], 16)
  init(cipher, key)
  encrypt(cipher, zero, h)
  let nonce: array[16, uint8] = generateNonce(h, iv)
  var output: array[16, uint8]
  encrypt(cipher, nonce, output)
  output

template gmacOne*[C](init, encrypt: untyped; key, iv, message: openArray[uint8]): array[16, uint8] =
  var ctx: GMACCtx
  gmacInit[C](ctx, init, encrypt, key)
  gmacInput(ctx, message)
  var tagMask: array[16, uint8] = generateTagMask[C](init, encrypt, key, iv)
  gmacFinal(ctx, tagMask)
