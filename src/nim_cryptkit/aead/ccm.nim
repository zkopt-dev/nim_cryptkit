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

import ../mac/cbcmac
import ../mode/ctr

type
  ModeError = enum
    WrongInputLen, PaddingError

template ccmmacInit[C; B, T: static int](init: untyped, ctx: var CBCMACCtx[C, B], key, nonce: openArray[uint8], msgLen: uint64, adaLen: int): void =
  static: doAssert B == 16, "CCM requires 128-bit block"
  static: doAssert T >= 4 and T <= 16 and T mod 2 == 0

  init(ctx.context, key)
  zeroMem(addr ctx.state, B)
  ctx.index = 0

  let nonceLen: int = nonce.len

  let q: int = B - 1 - nonceLen
  var b0: array[B, uint8]
  zeroMem(addr b0[0], B)

  var flags: uint8 = uint8((q - 1) and 0x07)
  flags = flags or uint8(((T - 2) div 2) shl 3)
  if aadLen > 0: flags = flags or 0x40'u8
  b0[0] = flags

  copyMem(addr b0[1], addr nonce[0], nonceLen)

  var lenVal: uint64 = msgLen
  for i in countdown(B - 1, B - q):
    b0[i] = uint8(lenVal and 0xFF)
    lenVal = lenVal shr 8

  var temp: array[B, uint8]
  unroll(i, 0, B - 1):
    temp[i] = ctx.state[i] xor b0[i]
  encrypt(ctx.context, temp, ctx.state)

template ccmMacAddAAD*[C; B: static int](encrypt: untyped, ctx: var CBCMACCtx[C, B], aad: openArray[uint8]): void =
  let aadLen = aad.len
  if aadLen == 0: return

  if aadLen < 65280:
    var hdr: array[2, uint8]
    hdr[0] = uint8((aadLen shr 8) and 0xFF)
    hdr[1] = uint8(aadLen and 0xFF)
    cbcmacInput(ctx, encrypt, hdr.toOpenArray(0, 1))
  elif aadLen < 4294967296'u64:
    var hdr: array[6, uint8]
    hdr[0] = 0xFF; hdr[1] = 0xFE
    hdr[2] = uint8((aadLen shr 24) and 0xFF)
    hdr[3] = uint8((aadLen shr 16) and 0xFF)
    hdr[4] = uint8((aadLen shr 8) and 0xFF)
    hdr[5] = uint8(aadLen and 0xFF)
    cbcmacInput(ctx, encrypt, hdr.toOpenArray(0, 5))
  else:
    var hdr: array[10, uint8]
    hdr[0] = 0xFF; hdr[1] = 0xFF
    for i in 0..7:
      hdr[2 + i] = uint8((aadLen shr ((7 - i) * 8)) and 0xFF)
    cbcmacInput(ctx, encrypt, hdr.toOpenArray(0, 9))

  cbcmacInput(ctx, encrypt, aad)

template ccmMacFinal*[C; B, T: static int](encrypt: untyped, ctx: var CBCMACCtx[C, B]): CCMTag[T] =
  if ctx.index > 0:
    var padBlock: array[B, uint8]
    zeroMem(addr padBlock[0], B)
    copyMem(addr padBlock[0], addr ctx.buffer[0], ctx.index)
    unroll(i, 0, B - 1):
      ctx.state[i] = ctx.state[i] xor padBlock[i]
    encrypt(ctx.context, ctx.state, ctx.state)
    ctx.index = 0

  var tag: CCMTag[T]
  unroll(i, 0, T - 1):
    tag[i] = ctx.state[i]
  tag

template cbcmacEncryptOne[C; B, T: static int](init, encrypt, padding: untyped, key, input: openArray[uint8]): tuple[value: seq[uint8], tag: array[T, uint8]] =
  var ctx: CBCMACCtx[C, B]
  cbcmacInit(ctx, init, key)
  cbcmacInput(ctx, encrypt, input)
  cbcmacFinal(ctx, encrypt, padding)

template ccmCtrProcess*[C; B: static int](encrypt: untyped, context: var C, nonce: openArray[uint8], input: openArray[uint8], output: var openArray[uint8], startCounter: uint64): void =
  let inputLen: int = input.len
  let nonceLen: int = nonce.len
  let q: int = B - 1 - nonceLen

  var counter: uint64 = startCounter
  var position: int = 0

  while position < inputLen:
    var ctrBlock: array[B, uint8]
    zeroMem(addr ctrBlock[0], B)
    ctrBlock[0] = uint8((q - 1) and 0x07)
    copyMem(addr ctrBlock[1], addr nonce[0], nonceLen)
    var cnt = counter
    for i in countdown(B - 1, B - q):
      ctrBlock[i] = uint8(cnt and 0xFF)
      cnt = cnt shr 8

    var ks: array[B, uint8]
    encrypt(context, ctrBlock, ks)

    let chunk = min(inputLen - position, B)
    for i in 0 ..< chunk:
      output[position + i] = input[position + i] xor ks[i]

    position += chunk
    counter.inc

template ccmEncryptOne*[C; B, K, T: static int](init, encrypt: untyped, key, nonce, aad, plaintext: openArray[uint8]): tuple[ciphertext: seq[uint8], tag: CCMTag[T]] =
  static:
    doAssert(B == 16, "CCM requires 128-bit block cipher")
    doAssert(T >= 4 and T <= 16 and T mod 2 == 0, "Invalid tag length")

  let msgLen: int = plaintext.len
  let aadLen: int = aad.len
  let nonceLen: int = nonce.len
  let q: int = B - 1 - nonceLen

  var macCtx: CBCMACCtx[C, B]
  ccmMacInit(init, key, macCtx, nonce, uint64(msgLen), aadLen, T)
  ccmMacAddAAD(encrypt, macCtx, aad)
  cbcmacInput(encrypt, macCtx, plaintext)
  var rawTag: array[T, uint8] = ccmMacFinal[C, B, T](encrypt, macCtx)

  var ciphertext = newSeq[uint8](msgLen)

  var s0: array[B, uint8]
  zeroMem(addr s0[0], B)
  s0[0] = uint8((q - 1) and 0x07)
  copyMem(addr s0[1], addr nonce[0], nonceLen)
  encrypt(macCtx.context, s0, s0)

  ccmCtrProcess(encrypt, macCtx.context, nonce, plaintext, ciphertext, 1'u64)

  var s0: array[B, uint8]
  zeroMem(addr s0[0], B)
  s0[0] = uint8((q - 1) and 0x07)
  copyMem(addr s0[1], addr nonce[0], nonceLen)
  encrypt(macCtx.context, s0, s0)

  var tag: CCMTag[T]
  unroll(i, 0, T - 1):
    tag[i] = rawTag[i] xor s0[i]

  (value: ciphertext, tag: tag)

template ccmDecryptOne*[C; B, K, T: static int](init, encrypt: untyped, key, nonce, aad, ciphertext: openArray[uint8], expectedTag: openArray[uint8]): Result[seq[uint8], ModeError] =
  static:
    doAssert(B == 16, "CCM requires 128-bit block cipher")
    doAssert(T >= 4 and T <= 16 and T mod 2 == 0, "Invalid tag length")

  let msgLen: int = ciphertext.len
  let aadLen: int = aad.len
  let nonceLen: int = nonce.len
  let q: int = B - 1 - nonceLen

  var plaintext: seq[uint8] = newSeq[uint8](msgLen)

  var ctx: C
  init(ctx, key)
  ccmCtrProcess(encrypt, ctx, nonce, ciphertext, plaintext, 1'u64)

  var s0: array[B, uint8]
  zeroMem(addr s0[0], B)
  s0[0] = uint8((q - 1) and 0x07)
  copyMem(addr s0[1], addr nonce[0], nonceLen)
  encrypt(ctx, s0, s0)

  var macCtx: CBCMACCtx[C, B]
  ccmMacInit(init, key, macCtx, nonce, uint64(msgLen), aadLen, T)
  ccmMacAddAAD(encrypt, macCtx, aad)
  cbcmacInput(encrypt, macCtx, plaintext)
  var rawTag: array[T, uint8] = ccmMacFinal[C, B, T](encrypt, macCtx)

  var diff: uint8 = 0
  unroll(i, 0, T - 1):
    diff = diff or ((rawTag[i] xor s0[i]) xor expectedTag[i])

  if diff != 0:
    zeroMem(addr plaintext[0], msgLen)
    Result[seq[uint8], ModeError](kind: Failure, error: PaddingError)
  else:
    Result[seq[uint8], ModeError](kind: Success, value: plaintext)
