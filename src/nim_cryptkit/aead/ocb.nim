import std/bitops
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
import strutils

const OCBMaxL* = 64

type
  OCBCtx*[C; blockSize: static int] = object
    context*: C
    delta*: array[blockSize, uint8]
    checksum*: array[blockSize, uint8]
    lStar*: array[blockSize, uint8]
    lTable*: array[OCBMaxL, array[blockSize, uint8]]
    blockIndex*: int
    buffer*: array[blockSize, uint8]
    index*: int
    aadHash*: array[blockSize, uint8]
    aadDelta*: array[blockSize, uint8]
    aadBuffer*: array[blockSize, uint8]
    aadBufferLen*: int
    aadBlockIndex*: int
    headerDone*: bool

template ocbInit*[C; B: static int](init, encrypt: untyped, ctx: var OCBCtx[C, B], key, nonce: openArray[uint8]): void =
  static: doAssert(B == 16, "OCB requires 128-bit block cipher")

  # 논스 길이 검증: OCB3는 1~120비트 (1~15바이트)
  doAssert(nonce.len >= 1 and nonce.len <= 15, "OCB nonce must be 1..15 bytes")

  zeroMem(addr ctx, sizeof(ctx))
  init(ctx.context, key)

  var zeroBlock: array[B, uint8]
  encrypt(ctx.context, zeroBlock, ctx.lStar)

  ctx.lTable[0] = ocbDouble(ctx.lStar)
  for i in 1 ..< OCBMaxL:
    ctx.lTable[i] = ocbDouble(ctx.lTable[i - 1])

  var nonceBlock: array[B, uint8]
  copyMem(addr nonceBlock[0], unsafeAddr nonce[0], nonce.len)
  nonceBlock[15] = nonceBlock[15] xor uint8(nonce.len)
  encrypt(ctx.context, nonceBlock, ctx.delta)

  ctx.headerDone = false

template ocbHeaderInput*[C; B: static int](encrypt: untyped, ctx: var OCBCtx[C, B], aad: openArray[uint8]): void =
  let aadLen = aad.len
  if aadLen <= 0: return

  var index = ctx.aadBufferLen
  let left = B - index
  var position = 0

  if aadLen >= left and left > 0:
    copyMem(addr ctx.aadBuffer[index], unsafeAddr aad[0], left)
    position = left
    index = 0

    ctx.aadBlockIndex.inc
    let ntzVal = ocbNtz(ctx.aadBlockIndex)
    unroll(j, 0, B - 1):
      ctx.aadDelta[j] = ctx.aadDelta[j] xor ctx.lTable[ntzVal][j]
    var aadBlock: array[B, uint8]
    copyMem(addr aadBlock[0], addr ctx.aadBuffer[0], B)
    unroll(j, 0, B - 1):
      aadBlock[j] = aadBlock[j] xor ctx.aadDelta[j]
    encrypt(ctx.context, aadBlock, aadBlock)
    unroll(j, 0, B - 1):
      ctx.aadHash[j] = ctx.aadHash[j] xor aadBlock[j]

  while position + B <= aadLen:
    ctx.aadBlockIndex.inc
    let ntzVal = ocbNtz(ctx.aadBlockIndex)
    unroll(j, 0, B - 1):
      ctx.aadDelta[j] = ctx.aadDelta[j] xor ctx.lTable[ntzVal][j]
    var aadBlock: array[B, uint8]
    copyMem(addr aadBlock[0], unsafeAddr aad[position], B)
    unroll(j, 0, B - 1):
      aadBlock[j] = aadBlock[j] xor ctx.aadDelta[j]
    encrypt(ctx.context, aadBlock, aadBlock)
    unroll(j, 0, B - 1):
      ctx.aadHash[j] = ctx.aadHash[j] xor aadBlock[j]
    position += B

  let remain = aadLen - position
  if remain > 0:
    copyMem(addr ctx.aadBuffer[0], unsafeAddr aad[position], remain)
  ctx.aadBufferLen = remain

template ocbHeaderFinal*[C; B: static int](encrypt: untyped, ctx: var OCBCtx[C, B]): void =
  if ctx.aadBufferLen > 0:
    var aadBlock: array[B, uint8]
    zeroMem(addr aadBlock[0], B)
    copyMem(addr aadBlock[0], addr ctx.aadBuffer[0], ctx.aadBufferLen)
    aadBlock[ctx.aadBufferLen] = 0x80'u8
    unroll(j, 0, B - 1):
      aadBlock[j] = aadBlock[j] xor ctx.aadDelta[j] xor ctx.lStar[j]
    encrypt(ctx.context, aadBlock, aadBlock)
    unroll(j, 0, B - 1):
      ctx.aadHash[j] = ctx.aadHash[j] xor aadBlock[j]
  ctx.headerDone = true

template ocbEncryptInput*[C; B: static int](encrypt: untyped, ctx: var OCBCtx[C, B], plaintext: openArray[uint8]): seq[uint8] =
  doAssert(ctx.headerDone, "Call ocbHeaderFinal first")

  let inputLen = plaintext.len
  if inputLen <= 0: return newSeq[uint8](0)

  var index = ctx.index
  let left = B - index
  var position = 0
  var point = 0

  let fullBlocks = (index + inputLen) div B
  var output = newSeq[uint8](fullBlocks * B)

  if inputLen >= left:
    copyMem(addr ctx.buffer[index], unsafeAddr plaintext[0], left)
    position = left
    index = 0

    ctx.blockIndex.inc
    let ntzVal = ocbNtz(ctx.blockIndex)
    unroll(j, 0, B - 1):
      ctx.delta[j] = ctx.delta[j] xor ctx.lTable[ntzVal][j]
    unroll(j, 0, B - 1):
      ctx.checksum[j] = ctx.checksum[j] xor ctx.buffer[j]

    var encInput, encOutput: array[B, uint8]
    unroll(j, 0, B - 1):
      encInput[j] = ctx.buffer[j] xor ctx.delta[j]
    encrypt(ctx.context, encInput, encOutput)
    unroll(j, 0, B - 1):
      output[point + j] = encOutput[j] xor ctx.delta[j]
    point += B

  while position + B <= inputLen:
    ctx.blockIndex.inc
    let ntzVal = ocbNtz(ctx.blockIndex)
    unroll(j, 0, B - 1):
      ctx.delta[j] = ctx.delta[j] xor ctx.lTable[ntzVal][j]
    unroll(j, 0, B - 1):
      ctx.checksum[j] = ctx.checksum[j] xor plaintext[position + j]

    var encInput, encOutput: array[B, uint8]
    unroll(j, 0, B - 1):
      encInput[j] = plaintext[position + j] xor ctx.delta[j]
    encrypt(ctx.context, encInput, encOutput)
    unroll(j, 0, B - 1):
      output[point + j] = encOutput[j] xor ctx.delta[j]
    position += B
    point += B

  let remain = inputLen - position
  if remain > 0:
    copyMem(addr ctx.buffer[0], unsafeAddr plaintext[position], remain)
  ctx.index = remain

  output

template ocbEncryptFinal*[C; B, T: static int](encrypt: untyped, ctx: var OCBCtx[C, B], tagLen: static int): tuple[tail: seq[uint8], tag: array[tagLen, uint8]] =
  static: doAssert(tagLen >= 1 and tagLen <= B)

  var tail: seq[uint8]

  if ctx.index > 0:
    unroll(j, 0, B - 1):
      ctx.delta[j] = ctx.delta[j] xor ctx.lStar[j]

    var pad: array[B, uint8]
    encrypt(ctx.context, ctx.delta, pad)

    unroll(j, 0, B - 1):
      if j < ctx.index:
        ctx.checksum[j] = ctx.checksum[j] xor ctx.buffer[j]
      elif j == ctx.index:
        ctx.checksum[j] = ctx.checksum[j] xor 0x80'u8

    tail = newSeq[uint8](ctx.index)
    for j in 0 ..< ctx.index:
      tail[j] = ctx.buffer[j] xor pad[j]
    ctx.index = 0
  else:
    tail = newSeq[uint8](0)

  var tagInput, tagFull: array[B, uint8]
  unroll(j, 0, B - 1):
    tagInput[j] = ctx.checksum[j] xor ctx.delta[j] xor ctx.lStar[j]
  encrypt(ctx.context, tagInput, tagFull)
  unroll(j, 0, B - 1):
    tagFull[j] = tagFull[j] xor ctx.aadHash[j]

  var tag: array[tagLen, uint8]
  for i in 0 ..< tagLen:
    tag[i] = tagFull[i]

  (tail: tail, tag: tag)

template ocbDecryptInput*[C; B: static int](decrypt: untyped, ctx: var OCBCtx[C, B], ciphertext: openArray[uint8]): seq[uint8] =
  doAssert(ctx.headerDone, "Call ocbHeaderFinal first")

  let inputLen = ciphertext.len
  if inputLen <= 0: return newSeq[uint8](0)

  var index = ctx.index
  let left = B - index
  var position = 0
  var point = 0

  let fullBlocks = (index + inputLen) div B
  var output = newSeq[uint8](fullBlocks * B)

  if inputLen >= left:
    copyMem(addr ctx.buffer[index], unsafeAddr ciphertext[0], left)
    position = left
    index = 0

    ctx.blockIndex.inc
    let ntzVal = ocbNtz(ctx.blockIndex)
    unroll(j, 0, B - 1):
      ctx.delta[j] = ctx.delta[j] xor ctx.lTable[ntzVal][j]

    var decInput, decOutput: array[B, uint8]
    unroll(j, 0, B - 1):
      decInput[j] = ctx.buffer[j] xor ctx.delta[j]
    decrypt(ctx.context, decInput, decOutput)
    unroll(j, 0, B - 1):
      output[point + j] = decOutput[j] xor ctx.delta[j]

    unroll(j, 0, B - 1):
      ctx.checksum[j] = ctx.checksum[j] xor output[point + j]
    point += B

  while position + B <= inputLen:
    ctx.blockIndex.inc
    let ntzVal = ocbNtz(ctx.blockIndex)
    unroll(j, 0, B - 1):
      ctx.delta[j] = ctx.delta[j] xor ctx.lTable[ntzVal][j]

    var decInput, decOutput: array[B, uint8]
    unroll(j, 0, B - 1):
      decInput[j] = ciphertext[position + j] xor ctx.delta[j]
    decrypt(ctx.context, decInput, decOutput)
    unroll(j, 0, B - 1):
      output[point + j] = decOutput[j] xor ctx.delta[j]

    unroll(j, 0, B - 1):
      ctx.checksum[j] = ctx.checksum[j] xor output[point + j]
    position += B
    point += B

  let remain = inputLen - position
  if remain > 0:
    copyMem(addr ctx.buffer[0], unsafeAddr ciphertext[position], remain)
  ctx.index = remain

  output

template ocbDecryptFinal*[C; B, T: static int](encrypt, decrypt: untyped, ctx: var OCBCtx[C, B], expectedTag: openArray[uint8], tagLen: static int): Result[tuple[tail: seq[uint8]], ModeError] =
  static: doAssert(tagLen >= 1 and tagLen <= B)

  doAssert(expectedTag.len >= tagLen, "expectedTag too short")

  var tail: seq[uint8]

  if ctx.index > 0:
    unroll(j, 0, B - 1):
      ctx.delta[j] = ctx.delta[j] xor ctx.lStar[j]

    var pad: array[B, uint8]
    encrypt(ctx.context, ctx.delta, pad)

    tail = newSeq[uint8](ctx.index)
    for j in 0 ..< ctx.index:
      tail[j] = ctx.buffer[j] xor pad[j]

    unroll(j, 0, B - 1):
      if j < ctx.index:
        ctx.checksum[j] = ctx.checksum[j] xor tail[j]
      elif j == ctx.index:
        ctx.checksum[j] = ctx.checksum[j] xor 0x80'u8
    ctx.index = 0
  else:
    tail = newSeq[uint8](0)

  var tagInput, computedFull: array[B, uint8]
  unroll(j, 0, B - 1):
    tagInput[j] = ctx.checksum[j] xor ctx.delta[j] xor ctx.lStar[j]
  encrypt(ctx.context, tagInput, computedFull)
  unroll(j, 0, B - 1):
    computedFull[j] = computedFull[j] xor ctx.aadHash[j]

  var diff: uint8 = 0
  for i in 0 ..< tagLen:
    diff = diff or (computedFull[i] xor expectedTag[i])

  if diff != 0:
    if tail.len > 0:
      zeroMem(addr tail[0], tail.len)
    Result[tuple[tail: seq[uint8]], ModeError](kind: Failure, error: TagError)
  else:
    Result[tuple[tail: seq[uint8]], ModeError](kind: Success, value: tail)
