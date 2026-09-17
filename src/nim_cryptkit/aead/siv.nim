import ../mac/cmac
import ../utils/errorutils

template sivDbl(value: array[16, uint8]): array[16, uint8] =
  cmacDouble(value)

template sivPad(input: openArray[uint8], output: var array[16, uint8]): void =
  zeroMem(addr output[0], 16)
  let len = min(input.len, 15)
  copyMem(addr output[0], unsafeAddr input[0], len)
  output[len] = 0x80'u8

template sivS2V[C; B: static int](init, encrypt: untyped, key: openArray[uint8], aad: openArray[uint8], plaintext: openArray[uint8]): array[B, uint8] =
  var zeroBlock: array[B, uint8]
  var d: array[B, uint8] = cmacOne[C, B](init, encrypt, key, zeroBlock)

  if aad.len > 0:
    var aadMac = cmacOne[C, B](init, encrypt, key, aad)
    d = sivDbl(d)
    unroll(i, 0, B - 1):
      d[i] = d[i] xor aadMac[i]

  if plaintext.len >= B:
    var macCtx: CMACCtx[C, B]
    cmacInit(macCtx, init, encrypt, key)
    let prefixLen = plaintext.len - B
    if prefixLen > 0:
      cmacInput(macCtx, encrypt, plaintext.toOpenArray(0, prefixLen - 1))
    var lastBlock: array[B, uint8]
    copyMem(addr lastBlock[0], unsafeAddr plaintext[prefixLen], B)
    unroll(i, 0, B - 1):
      lastBlock[i] = lastBlock[i] xor d[i]
    cmacInput(macCtx, encrypt, lastBlock)
    cmacFinal(macCtx, encrypt)
  else:
    d = sivDbl(d)
    var t: array[B, uint8]
    sivPad(plaintext, t)
    unroll(i, 0, B - 1):
      t[i] = t[i] xor d[i]
    cmacOne[C, B](init, encrypt, key, t)

template sivToQ(v: array[16, uint8]): array[16, uint8] =
  var q = v
  q[8] = q[8] and 0x7F'u8
  q[12] = q[12] and 0x7F'u8
  q

template sivCtr[C; B: static int](context: var C, encrypt: untyped, q: array[B, uint8], input: openArray[uint8], output: var openArray[uint8]): void =
  var counter = q
  var pos = 0
  let inputLen = input.len
  while pos < inputLen:
    var ks: array[B, uint8]
    encrypt(context, counter, ks)
    let chunk = min(inputLen - pos, B)
    for i in 0 ..< chunk:
      output[pos + i] = input[pos + i] xor ks[i]
    var c = (uint32(counter[12]) shl 24) or (uint32(counter[13]) shl 16) or
            (uint32(counter[14]) shl 8)  or  uint32(counter[15])
    c = (c + 1) and 0x7FFFFFFF'u32
    counter[12] = uint8((c shr 24) and 0xFF)
    counter[13] = uint8((c shr 16) and 0xFF)
    counter[14] = uint8((c shr 8)  and 0xFF)
    counter[15] = uint8(c and 0xFF)
    pos += chunk

template sivEncryptOne*[C; B, K: static int](init, encrypt: untyped, key: openArray[uint8], aad: openArray[uint8], plaintext: openArray[uint8]): tuple[iv: array[B, uint8], ciphertext: seq[uint8]] =
  static: doAssert(B == 16, "SIV requires 128-bit block cipher")

  var ctx: C
  init(ctx, key)

  let v = sivS2V[C, B](init, encrypt, key, aad, plaintext)
  let q = sivToQ(v)

  var ciphertext = newSeq[uint8](plaintext.len)
  sivCtr(ctx, encrypt, q, plaintext, ciphertext)

  (iv: v, ciphertext: ciphertext)

template sivDecryptOne*[C; B, K: static int](init, encrypt: untyped, key: openArray[uint8], aad: openArray[uint8], iv: array[B, uint8], ciphertext: openArray[uint8]): Result[seq[uint8], ModeError] =
  static: doAssert(B == 16, "SIV requires 128-bit block cipher")

  var ctx: C
  init(ctx, key)

  let q = sivToQ(iv)
  var plaintext = newSeq[uint8](ciphertext.len)
  sivCtr(ctx, encrypt, q, ciphertext, plaintext)

  let v2 = sivS2V[C, B](init, encrypt, key, aad, plaintext)

  var diff: uint8 = 0
  unroll(i, 0, B - 1):
    diff = diff or (v2[i] xor iv[i])

  if diff != 0:
    zeroMem(addr plaintext[0], plaintext.len)
    Result[seq[uint8], ModeError](kind: Failure, error: PaddingError)
  else:
    Result[seq[uint8], ModeError](kind: Success, value: plaintext)
