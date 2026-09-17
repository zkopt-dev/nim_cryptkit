import ../mac/cmac
import ../mode/ctr

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

type
  EAXCtx*[C; blockSize, keySize, nonceSize, counterSize: static int] = object
    ctr*: CTRCtx[C, blockSize, keySize, nonceSize, counterSize]
    headerMac*: CMACCtx[C, blockSize]
    cipherMac*: CMACCtx[C, blockSize]
    nonceTag*: array[blockSize, uint8]
    headerDone*: bool

template eaxInit*[C; B, K, N, T: static int](init, encrypt: untyped, ctx: var EAXCtx[C, B, K, N, T], key, nonce: openArray[uint8]): void =
  static: doAssert(B == N + T, "nonceSize + counterSize must equal blockSize")

  ctrInit(init, ctx.ctr, key, nonce, BigEndian, 1)

  var nonceMac: CMACCtx[C, B]
  cmacInit(nonceMac, init, encrypt, key)
  cmacInput(nonceMac, encrypt, nonce)
  ctx.nonceTag = cmacFinal(nonceMac, encrypt)

  cmacInit(ctx.headerMac, init, encrypt, key)
  ctx.headerDone = false

  cmacInit(ctx.cipherMac, init, encrypt, key)

template eaxHeaderInput*[C; B, K, N, T: static int](encrypt: untyped, ctx: var EAXCtx[C, B, K, N, T], header: openArray[uint8]): void =
  cmacInput(ctx.headerMac, encrypt, header)

template eaxHeaderFinal*[C; B, K, N, T: static int](encrypt: untyped, ctx: var EAXCtx[C, B, K, N, T]): void =
  ctx.headerDone = true

template eaxEncryptInput*[C; B, K, N, T: static int](encrypt: untyped, ctx: var EAXCtx[C, B, K, N, T], plaintext: openArray[uint8]): seq[uint8] =
  let ciphertext = ctrInput(encrypt, ctx.ctr, plaintext)

  cmacInput(ctx.cipherMac, encrypt, ciphertext)

  ciphertext

template eaxEncryptFinal*[C; B, K, N, T: static int](encrypt: untyped, ctx: var EAXCtx[C, B, K, N, T], tagLen: static int): tuple[tail: seq[uint8], tag: array[tagLen, uint8]] =
  static: doAssert(tagLen <= B and tagLen > 0, "Invalid tag length")

  let tail = ctrFinal(encrypt, ctx.ctr)
  if tail.len > 0:
    cmacInput(ctx.cipherMac, encrypt, tail)

  let hTag = cmacFinal(ctx.headerMac, encrypt)
  let cTag = cmacFinal(ctx.cipherMac, encrypt)

  var fullTag: array[B, uint8]
  unroll(i, 0, B - 1):
    fullTag[i] = ctx.nonceTag[i] xor hTag[i] xor cTag[i]

  var tag: array[tagLen, uint8]
  for i in 0 ..< tagLen:
    tag[i] = fullTag[i]

  (tail: tail, tag: tag)

template eaxDecryptInput*[C; B, K, N, T: static int](encrypt: untyped, ctx: var EAXCtx[C, B, K, N, T], ciphertext: openArray[uint8]): seq[uint8] =
  cmacInput(ctx.cipherMac, encrypt, ciphertext)
  let plaintext = ctrInput(encrypt, ctx.ctr, ciphertext)

  plaintext

template eaxDecryptFinal*[C; B, K, N, T: static int](encrypt: untyped, ctx: var EAXCtx[C, B, K, N, T], expectedTag: openArray[uint8], tagLen: static int): Result[seq[uint8], ModeError] =
  static: doAssert(tagLen <= B and tagLen > 0, "Invalid tag length")

  let tail = ctrFinal(encrypt, ctx.ctr)
  var plaintextTail: seq[uint8]
  if tail.len > 0:
    cmacInput(ctx.cipherMac, encrypt, tail)
    plaintextTail = tail

  let hTag = cmacFinal(ctx.headerMac, encrypt)
  let cTag = cmacFinal(ctx.cipherMac, encrypt)

  var computedTag: array[tagLen, uint8]
  unroll(i, 0, B - 1):
    let v = ctx.nonceTag[i] xor hTag[i] xor cTag[i]
    if i < tagLen:
      computedTag[i] = v

  var diff: uint8 = 0
  for i in 0 ..< tagLen:
    diff = diff or (computedTag[i] xor expectedTag[i])

  if diff != 0:
    Result[seq[uint8], ModeError](kind: Failure, error: PaddingError)
  else:
    Result[seq[uint8], ModeError](kind: Success, value: @[])

template eaxEncryptOne*[C; B, K, N, T: static int](
    init, encrypt: untyped,
    key, nonce, header, plaintext: openArray[uint8],
    tagLen: static int
): tuple[ciphertext: seq[uint8], tag: array[tagLen, uint8]] =
  var ctx: EAXCtx[C, B, K, N, T]
  eaxInit(init, encrypt, ctx, key, nonce)
  eaxAddHeader(encrypt, ctx, header)
  eaxFinishHeader(encrypt, ctx)
  let ct = eaxEncryptInput(encrypt, ctx, plaintext)
  let (tail, tag) = eaxEncryptFinal(encrypt, ctx, tagLen)
  var ciphertext = ct
  if tail.len > 0:
    ciphertext.add(tail)
  (ciphertext: ciphertext, tag: tag)

template eaxDecryptOne*[C; B, K, N, T: static int](
    init, encrypt: untyped,
    key, nonce, header, ciphertext, expectedTag: openArray[uint8],
    tagLen: static int
): Result[seq[uint8], ModeError] =
  var ctx: EAXCtx[C, B, K, N, T]
  eaxInit(init, encrypt, ctx, key, nonce)
  eaxAddHeader(encrypt, ctx, header)
  eaxFinishHeader(encrypt, ctx)
  let pt = eaxDecryptInput(encrypt, ctx, ciphertext)
  let result = eaxDecryptFinal(encrypt, ctx, expectedTag, tagLen)
  if result.kind == Success:
    var plaintext = pt
    if result.value.len > 0:
      plaintext.add(result.value)
    Result[seq[uint8], ModeError](kind: Success, value: plaintext)
  else:
    result
