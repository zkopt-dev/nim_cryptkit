import std/bitops
import ../mac/cmac
import ../mode/padding
import ../utils/endian
import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils
import ../utils/vectorop
import std/[monotimes, times]
import strutils

const OCBMaxL* = 64

type
  OCBCtx*[C; blockSize: static int] = object
    context*: C
    delta*: array[blockSize, uint8]
    checksum*: array[blockSize, uint8]
    lStar*: array[blockSize, uint8]
    lDollar*: array[blockSize, uint8]
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

func ocbDouble*(value: array[16, uint8]): array[16, uint8] =
  ## Multiplication by x in GF(2^128) with reduction polynomial
  ## x^128 + x^7 + x^2 + x + 1 (same operation used by CMAC-AES).
  var carry: uint8
  for i in countdown(15, 0):
    let nextCarry = value[i] shr 7
    result[i] = (value[i] shl 1) or carry
    carry = nextCarry
  result[15] = result[15] xor (0x87'u8 and (0'u8 - carry))

func ocbNtz*(n: int): int =
  ## Number of trailing zero bits of the positive integer n.
  var v = n
  while (v and 1) == 0:
    inc result
    v = v shr 1

func ocbExtract(stretch: array[24, uint8], bitOffset: int): array[16, uint8] =
  ## Stretch[1+bitOffset .. 128+bitOffset] with the rightmost bit being bit 0.
  for i in 0 ..< 16:
    let bitpos = bitOffset + i * 8
    let byte = bitpos div 8
    let shift = bitpos mod 8
    if shift == 0:
      result[i] = stretch[byte]
    else:
      result[i] = (stretch[byte] shl shift) or (stretch[byte + 1] shr (8 - shift))

proc ocbCopyFrom(dest: var openArray[uint8], destIdx: int, src: openArray[uint8], srcIdx: int, count: int) =
  ## Copy `count` bytes from an arbitrary openArray source.  A proc (rather
  ## than a raw copyMem) is used because taking the address of an element of
  ## an rvalue openArray is rejected by the compiler.
  if count > 0:
    copyMem(addr dest[destIdx], unsafeAddr src[srcIdx], count)

template ocbInit*[C; B, TAGBITS: static int](init, encrypt: untyped, ctx: var OCBCtx[C, B], key, nonce: openArray[uint8]): void =
  static: doAssert(B == 16, "OCB requires 128-bit block cipher")
  doAssert(nonce.len >= 1 and nonce.len <= 15, "OCB nonce must be 1..15 bytes")

  zeroMem(addr ctx, sizeof(ctx))
  init(ctx.context, key)

  # Key-dependent variables.
  var zeroBlock: array[B, uint8]
  encrypt(ctx.context, zeroBlock, ctx.lStar)      # L_* = ENCIPHER(K, zeros(128))
  ctx.lDollar = ocbDouble(ctx.lStar)              # L_$ = double(L_*)
  ctx.lTable[0] = ocbDouble(ctx.lDollar)          # L_0 = double(L_$)
  for i in 1 ..< OCBMaxL:
    ctx.lTable[i] = ocbDouble(ctx.lTable[i - 1])

  # Nonce = num2str(TAGLEN mod 128, 7) || zeros(120-bitlen(N)) || 1 || N
  var nonceBlock: array[B, uint8]
  nonceBlock[0] = uint8((TAGBITS mod 128) shl 1)
  let nlen = nonce.len
  let oneBit = 127 - 8 * nlen
  nonceBlock[oneBit div 8] = nonceBlock[oneBit div 8] or (0x80'u8 shr (oneBit mod 8))
  ocbCopyFrom(nonceBlock, B - nlen, nonce, 0, nlen)

  # Ktop = ENCIPHER(K, Nonce[1..122] || zeros(6))
  var ktopIn, ktop: array[B, uint8]
  for i in 0 ..< B - 1:
    ktopIn[i] = nonceBlock[i]
  ktopIn[B - 1] = nonceBlock[B - 1] and 0xC0'u8
  encrypt(ctx.context, ktopIn, ktop)

  # Stretch = Ktop || (Ktop[1..64] xor Ktop[9..72]); Offset_0 = Stretch[1+bottom..128+bottom]
  let bottom = int(nonceBlock[B - 1] and 0x3F'u8)
  var stretch: array[24, uint8]
  for i in 0 ..< 16:
    stretch[i] = ktop[i]
  for j in 0 ..< 8:
    stretch[16 + j] = ktop[j] xor ktop[j + 1]
  ctx.delta = ocbExtract(stretch, bottom)

  ctx.headerDone = false

template ocbHeaderInput*[C; B: static int](encrypt: untyped, ctx: var OCBCtx[C, B], aad: openArray[uint8]): void =
  let aadLen = aad.len
  if aadLen > 0:
    var index = ctx.aadBufferLen
    let left = B - index
    var position = 0

    template absorbAadBlock(blk: array[B, uint8]): void =
      ctx.aadBlockIndex.inc
      let ntzVal = ocbNtz(ctx.aadBlockIndex)
      unroll(j, 0, B - 1):
        ctx.aadDelta[j] = ctx.aadDelta[j] xor ctx.lTable[ntzVal][j]
      var x: array[B, uint8]
      unroll(j, 0, B - 1):
        x[j] = blk[j] xor ctx.aadDelta[j]
      encrypt(ctx.context, x, x)
      unroll(j, 0, B - 1):
        ctx.aadHash[j] = ctx.aadHash[j] xor x[j]

    if aadLen >= left and left > 0:
      ocbCopyFrom(ctx.aadBuffer, index, aad, 0, left)
      position = left
      index = 0
      absorbAadBlock(ctx.aadBuffer)

    while position + B <= aadLen:
      var blk: array[B, uint8]
      ocbCopyFrom(blk, 0, aad, position, B)
      absorbAadBlock(blk)
      position += B

    let remain = aadLen - position
    if remain > 0:
      ocbCopyFrom(ctx.aadBuffer, 0, aad, position, remain)
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
  var output: seq[uint8]
  if inputLen > 0:
    var index = ctx.index
    let left = B - index
    var position = 0
    var point = 0

    let fullBlocks = (index + inputLen) div B
    output = newSeq[uint8](fullBlocks * B)

    template encryptBlock(blk: array[B, uint8]): void =
      ctx.blockIndex.inc
      let ntzVal = ocbNtz(ctx.blockIndex)
      unroll(j, 0, B - 1):
        ctx.delta[j] = ctx.delta[j] xor ctx.lTable[ntzVal][j]
      unroll(j, 0, B - 1):
        ctx.checksum[j] = ctx.checksum[j] xor blk[j]
      var encInput, encOutput: array[B, uint8]
      unroll(j, 0, B - 1):
        encInput[j] = blk[j] xor ctx.delta[j]
      encrypt(ctx.context, encInput, encOutput)
      unroll(j, 0, B - 1):
        output[point + j] = encOutput[j] xor ctx.delta[j]
      point += B

    if inputLen >= left and left > 0:
      ocbCopyFrom(ctx.buffer, index, plaintext, 0, left)
      position = left
      index = 0
      encryptBlock(ctx.buffer)

    while position + B <= inputLen:
      var blk: array[B, uint8]
      ocbCopyFrom(blk, 0, plaintext, position, B)
      encryptBlock(blk)
      position += B

    let remain = inputLen - position
    if remain > 0:
      ocbCopyFrom(ctx.buffer, index, plaintext, position, remain)
    ctx.index = index + remain

  output

template ocbEncryptFinal*[C; B: static int](encrypt: untyped, ctx: var OCBCtx[C, B], tagLen: static int): tuple[tail: seq[uint8], tag: array[tagLen, uint8]] =
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
    tagInput[j] = ctx.checksum[j] xor ctx.delta[j] xor ctx.lDollar[j]
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
  var output: seq[uint8]
  if inputLen > 0:
    var index = ctx.index
    let left = B - index
    var position = 0
    var point = 0

    let fullBlocks = (index + inputLen) div B
    output = newSeq[uint8](fullBlocks * B)

    template decryptBlock(blk: array[B, uint8]): void =
      ctx.blockIndex.inc
      let ntzVal = ocbNtz(ctx.blockIndex)
      unroll(j, 0, B - 1):
        ctx.delta[j] = ctx.delta[j] xor ctx.lTable[ntzVal][j]
      var decInput, decOutput: array[B, uint8]
      unroll(j, 0, B - 1):
        decInput[j] = blk[j] xor ctx.delta[j]
      decrypt(ctx.context, decInput, decOutput)
      unroll(j, 0, B - 1):
        output[point + j] = decOutput[j] xor ctx.delta[j]
      unroll(j, 0, B - 1):
        ctx.checksum[j] = ctx.checksum[j] xor output[point + j]
      point += B

    if inputLen >= left and left > 0:
      ocbCopyFrom(ctx.buffer, index, ciphertext, 0, left)
      position = left
      index = 0
      decryptBlock(ctx.buffer)

    while position + B <= inputLen:
      var blk: array[B, uint8]
      ocbCopyFrom(blk, 0, ciphertext, position, B)
      decryptBlock(blk)
      position += B

    let remain = inputLen - position
    if remain > 0:
      ocbCopyFrom(ctx.buffer, index, ciphertext, position, remain)
    ctx.index = index + remain

  output

template ocbDecryptFinal*[C; B: static int](encrypt, decrypt: untyped, ctx: var OCBCtx[C, B], expectedTag: openArray[uint8], tagLen: static int): Result[seq[uint8], ModeError] =
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
    tagInput[j] = ctx.checksum[j] xor ctx.delta[j] xor ctx.lDollar[j]
  encrypt(ctx.context, tagInput, computedFull)
  unroll(j, 0, B - 1):
    computedFull[j] = computedFull[j] xor ctx.aadHash[j]

  var diff: uint8 = 0
  for i in 0 ..< tagLen:
    diff = diff or (computedFull[i] xor expectedTag[i])

  if diff != 0:
    if tail.len > 0:
      zeroMem(addr tail[0], tail.len)
    Result[seq[uint8], ModeError](kind: Failure, error: TagError)
  else:
    Result[seq[uint8], ModeError](kind: Success, value: tail)

template ocbEncryptOne*[C; B, T: static int](init, encrypt: untyped, key, nonce, aad, plaintext: openArray[uint8]): tuple[ciphertext: seq[uint8], tag: array[T, uint8]] =
  var ctx: OCBCtx[C, B]
  ocbInit[C, B, T * 8](init, encrypt, ctx, key, nonce)
  ocbHeaderInput(encrypt, ctx, aad)
  ocbHeaderFinal(encrypt, ctx)
  let ct = ocbEncryptInput(encrypt, ctx, plaintext)
  let (tail, tag) = ocbEncryptFinal(encrypt, ctx, T)
  var ciphertext = ct
  if tail.len > 0:
    ciphertext.add(tail)
  (ciphertext: ciphertext, tag: tag)

template ocbDecryptOne*[C; B, T: static int](init, encrypt, decrypt: untyped, key, nonce, aad, ciphertext, expectedTag: openArray[uint8]): Result[seq[uint8], ModeError] =
  var ctx: OCBCtx[C, B]
  ocbInit[C, B, T * 8](init, encrypt, ctx, key, nonce)
  ocbHeaderInput(encrypt, ctx, aad)
  ocbHeaderFinal(encrypt, ctx)
  let pt = ocbDecryptInput(decrypt, ctx, ciphertext)
  let tailRes = ocbDecryptFinal(encrypt, decrypt, ctx, expectedTag, T)
  if tailRes.kind == Success:
    var plaintext = pt
    if tailRes.value.len > 0:
      plaintext.add(tailRes.value)
    Result[seq[uint8], ModeError](kind: Success, value: plaintext)
  else:
    Result[seq[uint8], ModeError](kind: Failure, error: TagError)
