import ../mac/gmac
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
  GCMCtx*[C; blockSize, keySize, nonceSize, counterSize: static int] = object
    ctr*: CTRCtx[C, blockSize, keySize, nonceSize, counterSize]
    gmac*: GMACCtx
    tagMask*: array[16, uint8]
    headerDone*: bool

# ─── Init ───

template gcmInit*[C; B, K, N, T: static int](init, encrypt: untyped, ctx: var GCMCtx[C, B, K, N, T], key, nonce: openArray[uint8]): void =
  static: doAssert(B == 16, "GCM requires 128-bit block cipher")
  static: doAssert(B == N + T, "nonceSize + counterSize must equal blockSize")

  gmacInit[C](ctx.gmac, init, encrypt, key)

  ctx.tagMask = generateTagMask[C](init, encrypt, key, nonce)

  ctrInit(init, ctx.ctr, key, nonce, BigEndian, 1)

  ctx.headerDone = false

template gcmHeaderInput*[C; B, K, N, T: static int](ctx: var GCMCtx[C, B, K, N, T], header: openArray[uint8]): void =
  doAssert(not ctx.headerDone, "Header must be added before encryption")
  gmacInput(ctx.gmac, header)

template gcmHeaderFinal*[C; B, K, N, T: static int](ctx: var GCMCtx[C, B, K, N, T]): void =
  ctx.headerDone = true

template gcmEncryptInput*[C; B, K, N, T: static int](encrypt: untyped, ctx: var GCMCtx[C, B, K, N, T], plaintext: openArray[uint8]): seq[uint8] =
  let ciphertext = ctrInput(encrypt, ctx.ctr, plaintext)
  gmacInput(ctx.gmac, ciphertext)
  ciphertext

template gcmEncryptFinal*[C; B, K, N, T: static int](encrypt: untyped, ctx: var GCMCtx[C, B, K, N, T], tagLen: static int): tuple[tail: seq[uint8], tag: array[tagLen, uint8]] =
  static: doAssert(tagLen <= 16 and tagLen > 0, "Invalid tag length")

  let tail = ctrFinal(encrypt, ctx.ctr)
  if tail.len > 0:
    gmacInput(ctx.gmac, tail)

  let fullTag = gmacFinal(ctx.gmac, ctx.tagMask)

  var tag: array[tagLen, uint8]
  for i in 0 ..< tagLen:
    tag[i] = fullTag[i]

  (tail: tail, tag: tag)

template gcmDecryptInput*[C; B, K, N, T: static int](encrypt: untyped, ctx: var GCMCtx[C, B, K, N, T], ciphertext: openArray[uint8]): seq[uint8] =
  gmacInput(ctx.gmac, ciphertext)
  let plaintext = ctrInput(encrypt, ctx.ctr, ciphertext)
  plaintext

template gcmDecryptFinal*[C; B, K, N, T: static int](encrypt: untyped, ctx: var GCMCtx[C, B, K, N, T], expectedTag: openArray[uint8], tagLen: static int): Result[seq[uint8], ModeError] =
  static: doAssert(tagLen <= 16 and tagLen > 0, "Invalid tag length")

  let tail = ctrFinal(encrypt, ctx.ctr)
  if tail.len > 0:
    gmacInput(ctx.gmac, tail)

  let computedFullTag = gmacFinal(ctx.gmac, ctx.tagMask)

  var diff: uint8 = 0
  for i in 0 ..< tagLen:
    diff = diff or (computedFullTag[i] xor expectedTag[i])

  if diff != 0:
    Result[seq[uint8], ModeError](kind: Failure, error: PaddingError)
  else:
    Result[seq[uint8], ModeError](kind: Success, value: @[])

template gcmEncryptOne*[C; B, K, N, T: static int](init, encrypt: untyped, key, nonce, header, plaintext: openArray[uint8], tagLen: static int): tuple[ciphertext: seq[uint8], tag: array[tagLen, uint8]] =
  var ctx: GCMCtx[C, B, K, N, T]
  gcmInit(init, encrypt, ctx, key, nonce)
  gcmAddHeader(ctx, header)
  gcmFinishHeader(ctx)
  let ct = gcmEncryptInput(encrypt, ctx, plaintext)
  let (tail, tag) = gcmEncryptFinal(encrypt, ctx, tagLen)
  var ciphertext = ct
  if tail.len > 0:
    ciphertext.add(tail)
  (ciphertext: ciphertext, tag: tag)

template gcmDecryptOne*[C; B, K, N, T: static int](init, encrypt: untyped, key, nonce, header, ciphertext, expectedTag: openArray[uint8], tagLen: static int): Result[seq[uint8], ModeError] =
  var ctx: GCMCtx[C, B, K, N, T]
  gcmInit(init, encrypt, ctx, key, nonce)
  gcmAddHeader(ctx, header)
  gcmFinishHeader(ctx)
  let pt = gcmDecryptInput(encrypt, ctx, ciphertext)
  let result = gcmDecryptFinal(encrypt, ctx, expectedTag, tagLen)
  if result.kind == Success:
    var plaintext = pt
    if result.value.len > 0:
      plaintext.add(result.value)
    Result[seq[uint8], ModeError](kind: Success, value: plaintext)
  else:
    result
