import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils

import ./[common, biguint, montgomery]
import ../hash/sha2

type
  RSAPublicKey*[K: static int] = object
    n*: BigUint[K]

  RSAPrivateKey*[K: static int] = object
    n*: BigUint[K]
    d*: BigUint[K]
    p*: BigUint[K div 2]
    q*: BigUint[K div 2]
    dp*: BigUint[K div 2]
    dq*: BigUint[K div 2]
    qInv*: BigUint[K div 2]

  RSASharedSecret* = array[32, uint8]

  RSASignature*[K: static int] = array[K, uint8]
  RSACipherText*[K: static int] = array[K, uint8]

  RSACtx*[K: static int] = object
    publicKey*: RSAPublicKey[K]
    privateKey*: RSAPrivateKey[K]
    rng*: Rng

  RSAPublicKey1024* = RSAPublicKey[128]
  RSAPublicKey2048* = RSAPublicKey[256]
  RSAPublicKey3072* = RSAPublicKey[384]
  RSAPublicKey4096* = RSAPublicKey[512]

  RSAPrivateKey1024* = RSAPrivateKey[128]
  RSAPrivateKey2048* = RSAPrivateKey[256]
  RSAPrivateKey3072* = RSAPrivateKey[384]
  RSAPrivateKey4096* = RSAPrivateKey[512]

  RSASignature1024* = RSASignature[128]
  RSASignature2048* = RSASignature[256]
  RSASignature3072* = RSASignature[384]
  RSASignature4096* = RSASignature[512]

  RSACipherText1024* = RSACipherText[128]
  RSACipherText2048* = RSACipherText[256]
  RSACipherText3072* = RSACipherText[384]
  RSACipherText4096* = RSACipherText[512]

  RSA1024Ctx* = RSACtx[128]   # 1024-bit = 128 bytes
  RSA2048Ctx* = RSACtx[256]   # 2048-bit = 256 bytes
  RSA3072Ctx* = RSACtx[384]   # 3072-bit = 384 bytes
  RSA4096Ctx* = RSACtx[512]   # 4096-bit = 512 bytes

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------

const
  PublicExponent* = 65537'u32

  EmptyHash: array[32, uint8] = [
    0xe3'u8, 0xb0'u8, 0xc4'u8, 0x42'u8, 0x98'u8, 0xfc'u8, 0x1c'u8, 0x14'u8,
    0x9a'u8, 0xfb'u8, 0xf4'u8, 0xc8'u8, 0x99'u8, 0x6f'u8, 0xb9'u8, 0x24'u8,
    0x27'u8, 0xae'u8, 0x41'u8, 0xe4'u8, 0x64'u8, 0x9b'u8, 0x93'u8, 0x4c'u8,
    0xa4'u8, 0x95'u8, 0x99'u8, 0x1b'u8, 0x78'u8, 0x52'u8, 0xb8'u8, 0x55'u8
  ]

# ----------------------------------------------------------------------
# Hash helpers
# ----------------------------------------------------------------------

proc sha256*(a: openArray[uint8]): array[32, uint8] {.inline.} =
  var h: SHA2_256Ctx
  h.sha2_256Init()
  if a.len > 0: h.sha2_256Input(a)
  result = h.sha2_256Final()

proc sha256*(a, b: openArray[uint8]): array[32, uint8] {.inline.} =
  var h: SHA2_256Ctx
  h.sha2_256Init()
  if a.len > 0: h.sha2_256Input(a)
  if b.len > 0: h.sha2_256Input(b)
  result = h.sha2_256Final()

# ----------------------------------------------------------------------
# Small math
# ----------------------------------------------------------------------

func inverseSmall(value, modulus: uint32): uint32 {.inline.} =
  var oldR = int64(value); var r = int64(modulus)
  var oldT = 1'i64; var t = 0'i64
  while r != 0:
    let q = oldR div r
    (oldR, r) = (r, oldR - q * r)
    (oldT, t) = (t, oldT - q * t)
  if oldR != 1: return 0
  var answer = oldT mod int64(modulus)
  if answer < 0: answer += int64(modulus)
  uint32(answer)

# ----------------------------------------------------------------------
# Byte helpers
# ----------------------------------------------------------------------

template zeroBytes(dst: var openArray[uint8]) =
  for i in 0 ..< dst.len: dst[i] = 0'u8

template storeNatBE[W: static int](dst: var openArray[uint8], value: Nat[W]) =
  let enc = value.toBytesBE()
  if enc.len == dst.len:
    for i in 0 ..< dst.len: dst[i] = enc[i]
  elif enc.len < dst.len:
    for i in 0 ..< dst.len: dst[i] = 0'u8
    let start = dst.len - enc.len
    for i in 0 ..< enc.len: dst[start + i] = enc[i]
  else:
    let start = enc.len - dst.len
    for i in 0 ..< dst.len: dst[i] = enc[start + i]

template subBeAssumeGE(dst: var openArray[uint8], a, b: openArray[uint8]) =
  var borrow = 0
  for i in countdown(dst.high, 0):
    let av = int(a[i]); let bv = int(b[i]) + borrow
    if av >= bv: dst[i] = uint8(av - bv); borrow = 0
    else: dst[i] = uint8(av + 256 - bv); borrow = 1

template addBeToTail(dst: var openArray[uint8], src: openArray[uint8]) =
  var carry = 0
  let dstStart = dst.len - src.len
  for i in countdown(src.high, 0):
    let s = int(dst[dstStart + i]) + int(src[i]) + carry
    dst[dstStart + i] = uint8(s and 255); carry = s shr 8
  var j = dstStart - 1
  while carry > 0 and j >= 0:
    let s = int(dst[j]) + carry
    dst[j] = uint8(s and 255); carry = s shr 8; dec j

# ----------------------------------------------------------------------
# MGF1
# ----------------------------------------------------------------------

template mgf1(seed: openArray[uint8], output: var openArray[uint8]) =
  var offset = 0; var counter = 0'u32
  while offset < output.len:
    var suffix: array[4, uint8]
    suffix[0] = uint8(counter shr 24); suffix[1] = uint8(counter shr 16)
    suffix[2] = uint8(counter shr 8); suffix[3] = uint8(counter)
    let digest = sha256(seed, suffix)
    let limit = min(32, output.len - offset)
    for i in 0 ..< limit: output[offset + i] = digest[i]
    offset += 32; inc counter

# ----------------------------------------------------------------------
# BigUint <-> Nat bridges (K = bytes)
# ----------------------------------------------------------------------

template toBig[B: static int, W: static int](x: Nat[W]): BigUint[B] =
  biguint.fromBytesBE[B](x.toBytesBE())

template toNat[W: static int, B: static int](x: BigUint[B]): Nat[W] =
  montgomery.fromBytesBE[W](x.toBytesBE())

# ----------------------------------------------------------------------
# Public key helpers
# ----------------------------------------------------------------------

template publicKeyFromBytes*[K: static int](data: array[K, uint8]): RSAPublicKey[K] =
  var key: RSAPublicKey[K]
  key.n = biguint.fromBytesBE[K](data)
  key

template publicKeyBytes*[K: static int](key: RSAPublicKey[K]): array[K, uint8] =
  key.n.toBytesBE()

template rsaPublicKey*[K: static int](data: array[K, uint8]): RSAPublicKey[K] =
  publicKeyFromBytes[K](data)

template rsaPublicKeyBytes*[K: static int](key: RSAPublicKey[K]): array[K, uint8] =
  publicKeyBytes[K](key)

# ----------------------------------------------------------------------
# Validation (K = bytes)
# ----------------------------------------------------------------------

template validatePublicKey*[K: static int](key: RSAPublicKey[K]): bool =
  ctNonZero(key.n) != 0 and
    (key.n[0] and 1) != 0 and
    ctBitBE(key.n, 0) != 0

template validatePrivateKeyFast*[K: static int](ctx: RSACtx[K]): bool =
  let n = ctx.privateKey.n
  let d = ctx.privateKey.d
  let p = ctx.privateKey.p
  let q = ctx.privateKey.q
  ctNonZero(n) != 0 and ctNonZero(d) != 0 and
    ctNonZero(p) != 0 and ctNonZero(q) != 0 and
    (n[0] and 1) != 0 and (p[0] and 1) != 0 and (q[0] and 1) != 0 and
    ctBitBE(n, 0) != 0 and not ctEqual(p, q) and ctLess(d, n)

template validatePrivateKey*[K: static int](ctx: RSACtx[K]): bool =
  var ok = validatePrivateKeyFast(ctx)
  if ok:
    const
      W = K div 8       # half-size Nat limbs (bytes/4/2 = bytes/8)
      FullW = K div 4   # full-size Nat limbs (bytes/4)
    let n = toNat[FullW, K](ctx.privateKey.n)
    let p = toNat[W, K div 2](ctx.privateKey.p)
    let q = toNat[W, K div 2](ctx.privateKey.q)
    ok = multiply(p, q).equal(n)
  ok

# ----------------------------------------------------------------------
# Prime generation
# ----------------------------------------------------------------------

template generatePrime[W: static int](random: Rng): Nat[W] =
  var bytes: array[W * 4, uint8]
  var candidate: Nat[W]
  while true:
    random(bytes)
    bytes[0] = bytes[0] or 0xc0'u8
    bytes[^1] = bytes[^1] or 0x01'u8
    candidate = montgomery.fromBytesBE[W](bytes)
    if candidate.modSmall(PublicExponent) != 1 and candidate.probablePrime():
      break
  candidate

# ----------------------------------------------------------------------
# Key generation (K = bytes)
# ----------------------------------------------------------------------

template generateParameters[K: static int](ctx: var RSACtx[K]) =
  static:
    doAssert K == 128 or K == 256 or K == 384 or K == 512,
      "unsupported RSA size"

template validateParameters[K: static int](ctx: RSACtx[K]): bool =
  K == 128 or K == 256 or K == 384 or K == 512

template publicKeyFromPrivate[K: static int](ctx: var RSACtx[K]) =
  ctx.publicKey.n = ctx.privateKey.n

template generatePrivateKey[K: static int](ctx: var RSACtx[K]) =
  const
    W = K div 8         # half-size Nat limbs
    FullW = K div 4     # full-size Nat limbs
    HalfBytes = K div 2

  if ctx.rng == nil:
    raise newException(PubKeyError, "nil RNG")

  var p = generatePrime[W](ctx.rng)
  var q: Nat[W]
  while true:
    q = generatePrime[W](ctx.rng)
    if not q.equal(p): break

  if p.less(q): swap(p, q)

  let p1 = p.decrement()
  let q1 = q.decrement()
  let phi = multiply(p1, q1)
  let phiRemainder = phi.modSmall(PublicExponent)
  let inverse = inverseSmall(phiRemainder, PublicExponent)

  if inverse == 0:
    raise newException(PubKeyError, "RSA exponent is not coprime")

  let k = (PublicExponent - inverse) mod PublicExponent
  let quotient = phi.divSmall(PublicExponent)
  let tail = uint32((uint64(phiRemainder) * uint64(k) + 1) div uint64(PublicExponent))
  let d = quotient.mulSmallAdd(k, tail)

  let n = multiply(p, q)
  let dp = remainder(d, p1)
  let dq = remainder(d, q1)

  let pMont = initMontgomery(p)
  let qInv = pMont.powMod(q, p.subtractSmall(2).toBytesBE())

  ctx.privateKey.n    = toBig[K, FullW](n)
  ctx.privateKey.d    = toBig[K, FullW](d)
  ctx.privateKey.p    = toBig[HalfBytes, W](p)
  ctx.privateKey.q    = toBig[HalfBytes, W](q)
  ctx.privateKey.dp   = toBig[HalfBytes, W](dp)
  ctx.privateKey.dq   = toBig[HalfBytes, W](dq)
  ctx.privateKey.qInv = toBig[HalfBytes, W](qInv)

template keyInitC*[K: static int](ctx: var RSACtx[K], random: Rng) =
  ctx.rng = random
  generateParameters(ctx)
  if not validateParameters(ctx):
    raise newException(PubKeyError, "invalid RSA parameters")
  generatePrivateKey(ctx)
  publicKeyFromPrivate(ctx)
  if not validatePublicKey(ctx.publicKey):
    raise newException(PubKeyError, "invalid RSA public key")
  if not validatePrivateKey(ctx):
    raise newException(PubKeyError, "invalid RSA private key")

# ----------------------------------------------------------------------
# Raw RSA primitives (K = bytes)
# ----------------------------------------------------------------------

template rsaPublic[K: static int](
    key: RSAPublicKey[K], input: array[K, uint8]
): array[K, uint8] =
  const FullW = K div 4
  var outBytes: array[K, uint8]
  let n = toNat[FullW, K](key.n)
  let value = montgomery.fromBytesBE[FullW](input)
  if value.less(n):
    outBytes = initMontgomery(n).powMod(value, [1'u8, 0'u8, 1'u8]).toBytesBE()
  outBytes

template rsaPrivateFull[K: static int](
    ctx: RSACtx[K], input: array[K, uint8]
): array[K, uint8] =
  const FullW = K div 4
  var outBytes: array[K, uint8]
  let n = toNat[FullW, K](ctx.privateKey.n)
  let d = toNat[FullW, K](ctx.privateKey.d)
  let value = montgomery.fromBytesBE[FullW](input)
  if value.less(n):
    outBytes = initMontgomery(n).powMod(value, d.toBytesBE()).toBytesBE()
  outBytes

template rsaPrivateCrt[K: static int](
    ctx: RSACtx[K], input: array[K, uint8]
): array[K, uint8] =
  const
    W = K div 8
    FullW = K div 4
    HalfBytes = K div 2

  var outBytes: array[K, uint8]
  let n = toNat[FullW, K](ctx.privateKey.n)
  let value = montgomery.fromBytesBE[FullW](input)

  if value.less(n):
    let p    = toNat[W, HalfBytes](ctx.privateKey.p)
    let q    = toNat[W, HalfBytes](ctx.privateKey.q)
    let dp   = toNat[W, HalfBytes](ctx.privateKey.dp)
    let dq   = toNat[W, HalfBytes](ctx.privateKey.dq)
    let qInv = toNat[W, HalfBytes](ctx.privateKey.qInv)

    let vp = remainder(value, p)
    let vq = remainder(value, q)

    let m1 = initMontgomery(p).powMod(vp, dp.toBytesBE())
    let m2 = initMontgomery(q).powMod(vq, dq.toBytesBE())

    var m1Bytes: array[HalfBytes, uint8]
    var m2Bytes: array[HalfBytes, uint8]
    var pBytes:  array[HalfBytes, uint8]
    storeNatBE(m1Bytes, m1)
    storeNatBE(m2Bytes, m2)
    storeNatBE(pBytes, p)

    var diffBytes: array[HalfBytes, uint8]
    if m1.equal(m2):
      zeroBytes(diffBytes)
    elif m1.less(m2):
      var tmp: array[HalfBytes, uint8]
      subBeAssumeGE(tmp, m2Bytes, m1Bytes)
      subBeAssumeGE(diffBytes, pBytes, tmp)
    else:
      subBeAssumeGE(diffBytes, m1Bytes, m2Bytes)

    let diff = montgomery.fromBytesBE[W](diffBytes)
    let h = remainder(multiply(diff, qInv), p)
    let qh = multiply(q, h)

    var finalBytes: array[K, uint8]
    storeNatBE(finalBytes, qh)
    addBeToTail(finalBytes, m2Bytes)
    outBytes = finalBytes

  outBytes

template rsaPrivate[K: static int](
    ctx: RSACtx[K], input: array[K, uint8]
): array[K, uint8] =
  when defined(rsaNoCrt): rsaPrivateFull(ctx, input)
  else: rsaPrivateCrt(ctx, input)

# ----------------------------------------------------------------------
# RSA-PSS-SHA256 (K = bytes)
# ----------------------------------------------------------------------

template generateNonce[K: static int](ctx: RSACtx[K]): array[32, uint8] =
  if ctx.rng == nil: raise newException(PubKeyError, "nil RNG")
  var nonce: array[32, uint8]
  ctx.rng(nonce)
  nonce

template pssSign[K: static int](
    ctx: RSACtx[K], message: openArray[uint8]
): RSASignature[K] =
  const
    EmLen = K
    DbLen = K - 33
  static: doAssert K >= 98, "RSA-PSS-SHA256 modulus too short"

  let mHash = sha256(message)
  let salt = generateNonce(ctx)

  var prefix: array[72, uint8]; zeroBytes(prefix)
  for i in 0 ..< 32:
    prefix[8 + i] = mHash[i]; prefix[40 + i] = salt[i]
  let h = sha256(prefix)

  var db: array[DbLen, uint8]; zeroBytes(db)
  db[DbLen - 33] = 1'u8
  for i in 0 ..< 32: db[DbLen - 32 + i] = salt[i]

  var mask: array[DbLen, uint8]; mgf1(h, mask)

  var encoded: array[EmLen, uint8]
  for i in 0 ..< DbLen: encoded[i] = db[i] xor mask[i]
  encoded[0] = encoded[0] and 0x7f'u8
  for i in 0 ..< 32: encoded[DbLen + i] = h[i]
  encoded[EmLen - 1] = 0xbc'u8

  rsaPrivate(ctx, encoded)

template pssVerify[K: static int](
    key: RSAPublicKey[K], message: openArray[uint8], signature: RSASignature[K]
): bool =
  const
    EmLen = K
    DbLen = K - 33

  let encoded = rsaPublic(key, signature)

  var failure = encoded[EmLen - 1] xor 0xbc'u8
  failure = failure or (encoded[0] and 0x80'u8)

  var h: array[32, uint8]
  for i in 0 ..< 32: h[i] = encoded[DbLen + i]

  var mask: array[DbLen, uint8]; mgf1(h, mask)
  var db: array[DbLen, uint8]
  for i in 0 ..< DbLen: db[i] = encoded[i] xor mask[i]
  db[0] = db[0] and 0x7f'u8

  for i in 0 ..< DbLen - 33: failure = failure or db[i]
  failure = failure or (db[DbLen - 33] xor 1'u8)

  let mHash = sha256(message)
  var prefix: array[72, uint8]; zeroBytes(prefix)
  for i in 0 ..< 32:
    prefix[8 + i] = mHash[i]; prefix[40 + i] = db[DbLen - 32 + i]
  let expected = sha256(prefix)

  for i in 0 ..< 32: failure = failure or (h[i] xor expected[i])
  failure == 0

# ----------------------------------------------------------------------
# RSA-OAEP-SHA256 KEM (K = bytes)
# ----------------------------------------------------------------------

template oaepEncode[K: static int](
    random: Rng, secret: RSASharedSecret
): array[K, uint8] =
  const
    EmLen = K
    DbLen = K - 33
  static: doAssert K >= 98, "RSA-OAEP-SHA256 modulus too short"

  var seed: array[32, uint8]; random(seed)

  var db: array[DbLen, uint8]; zeroBytes(db)
  for i in 0 ..< 32: db[i] = EmptyHash[i]
  db[DbLen - 33] = 1'u8
  for i in 0 ..< 32: db[DbLen - 32 + i] = secret[i]

  var encoded: array[EmLen, uint8]; encoded[0] = 0'u8

  var dbMask: array[DbLen, uint8]; mgf1(seed, dbMask)
  for i in 0 ..< DbLen: encoded[33 + i] = db[i] xor dbMask[i]

  var seedMask: array[32, uint8]
  mgf1(encoded.toOpenArray(33, encoded.high), seedMask)
  for i in 0 ..< 32: encoded[1 + i] = seed[i] xor seedMask[i]
  encoded

template oaepDecode[K: static int](
    encoded: array[K, uint8]
): tuple[secret: RSASharedSecret, valid: bool] =
  const
    EmLen = K
    DbLen = K - 33

  var failure = encoded[0]

  var seedMask: array[32, uint8]
  mgf1(encoded.toOpenArray(33, encoded.high), seedMask)
  var seed: array[32, uint8]
  for i in 0 ..< 32: seed[i] = encoded[1 + i] xor seedMask[i]

  var dbMask: array[DbLen, uint8]; mgf1(seed, dbMask)
  var db: array[DbLen, uint8]
  for i in 0 ..< DbLen: db[i] = encoded[33 + i] xor dbMask[i]

  for i in 0 ..< 32: failure = failure or (db[i] xor EmptyHash[i])
  for i in 32 ..< DbLen - 33: failure = failure or db[i]
  failure = failure or (db[DbLen - 33] xor 1'u8)

  var secret: RSASharedSecret
  for i in 0 ..< 32: secret[i] = db[DbLen - 32 + i]

  var ret: tuple[secret: RSASharedSecret, valid: bool]
  ret.secret = secret; ret.valid = failure == 0
  ret

# ----------------------------------------------------------------------
# Internal C templates (K = bytes)
# ----------------------------------------------------------------------

template signC*[K: static int](
    ctx: RSACtx[K], message: openArray[uint8]
): RSASignature[K] =
  if ctx.rng == nil: raise newException(PubKeyError, "nil RNG")
  when defined(rsaStrict):
    if not validatePrivateKey(ctx):
      raise newException(PubKeyError, "invalid RSA signing context")
  else:
    if not validatePrivateKeyFast(ctx):
      raise newException(PubKeyError, "invalid RSA signing context")
  pssSign(ctx, message)

template verifyC*[K: static int](
    ctx: RSACtx[K], message: openArray[uint8], signature: RSASignature[K]
): bool =
  validatePublicKey(ctx.publicKey) and pssVerify(ctx.publicKey, message, signature)

template encapsC*[K: static int](
    ctx: RSACtx[K], peer: RSAPublicKey[K]
): tuple[secret: RSASharedSecret, cipher: RSACipherText[K]] =
  if ctx.rng == nil: raise newException(PubKeyError, "nil RNG")
  if not validatePublicKey(peer):
    raise newException(PubKeyError, "invalid RSA peer key")
  oaepEncaps(ctx, peer)

template decapsC*[K: static int](
    ctx: RSACtx[K], cipher: RSACipherText[K]
): RSASharedSecret =
  when defined(rsaStrict):
    if not validatePrivateKey(ctx):
      raise newException(PubKeyError, "invalid RSA private key")
  else:
    if not validatePrivateKeyFast(ctx):
      raise newException(PubKeyError, "invalid RSA private key")
  oaepDecaps(ctx, cipher)


# ----------------------------------------------------------------------
# Export Wrappers
# ----------------------------------------------------------------------

when defined(templateOpt):
  template rsaInit*(ctx: var RSA1024Ctx, random: Rng): void = keyInitC(ctx, random)
  template rsaSign*(ctx: RSA1024Ctx, message: openArray[uint8]): RSASignature1024 = signC(ctx, message)
  template rsaVerify*(ctx: RSA1024Ctx, message: openArray[uint8], signature: RSASignature1024): bool = verifyC(ctx, message, signature)
  template rsaEncaps*(ctx: RSA1024Ctx, peer: RSAPublicKey1024): tuple[secret: RSASharedSecret, cipher: RSACipherText1024] = encapsC(ctx, peer)
  template rsaDecaps*(ctx: RSA1024Ctx, cipher: RSACipherText1024): RSASharedSecret = decapsC(ctx, cipher)

  template rsaInit*(ctx: var RSA2048Ctx, random: Rng): void = keyInitC(ctx, random)
  template rsaSign*(ctx: RSA2048Ctx, message: openArray[uint8]): RSASignature2048 = signC(ctx, message)
  template rsaVerify*(ctx: RSA2048Ctx, message: openArray[uint8], signature: RSASignature2048): bool = verifyC(ctx, message, signature)
  template rsaEncaps*(ctx: RSA2048Ctx, peer: RSAPublicKey2048): tuple[secret: RSASharedSecret, cipher: RSACipherText2048] = encapsC(ctx, peer)
  template rsaDecaps*(ctx: RSA2048Ctx, cipher: RSACipherText2048): RSASharedSecret = decapsC(ctx, cipher)

  template rsaInit*(ctx: var RSA3072Ctx, random: Rng): void = keyInitC(ctx, random)
  template rsaSign*(ctx: RSA3072Ctx, message: openArray[uint8]): RSASignature3072 = signC(ctx, message)
  template rsaVerify*(ctx: RSA3072Ctx, message: openArray[uint8], signature: RSASignature3072): bool = verifyC(ctx, message, signature)
  template rsaEncaps*(ctx: RSA3072Ctx, peer: RSAPublicKey3072): tuple[secret: RSASharedSecret, cipher: RSACipherText3072] = encapsC(ctx, peer)
  template rsaDecaps*(ctx: RSA3072Ctx, cipher: RSACipherText3072): RSASharedSecret = decapsC(ctx, cipher)

  template rsaInit*(ctx: var RSA4096Ctx, random: Rng): void = keyInitC(ctx, random)
  template rsaSign*(ctx: RSA4096Ctx, message: openArray[uint8]): RSASignature4096 = signC(ctx, message)
  template rsaVerify*(ctx: RSA4096Ctx, message: openArray[uint8], signature: RSASignature4096): bool = verifyC(ctx, message, signature)
  template rsaEncaps*(ctx: RSA4096Ctx, peer: RSAPublicKey4096): tuple[secret: RSASharedSecret, cipher: RSACipherText4096] = encapsC(ctx, peer)
  template rsaDecaps*(ctx: RSA4096Ctx, cipher: RSACipherText4096): RSASharedSecret = decapsC(ctx, cipher)

  when Native:
    template rsaInit*(ctx: ptr RSA1024Ctx, random: Rng): void = keyInitC(ctx[], random)
    template rsaSign*(ctx: ptr RSA1024Ctx, msg: ptr UncheckedArray[uint8], msgLen: int): RSASignature1024 = signC(ctx[], msg.toOpenArray(0, msgLen - 1))
    template rsaVerify*(ctx: ptr RSA1024Ctx, msg: ptr UncheckedArray[uint8], msgLen: int, sig: ptr RSASignature1024): bool = verifyC(ctx[], msg.toOpenArray(0, msgLen - 1), sig[])
    template rsaEncaps*(ctx: ptr RSA1024Ctx, peer: ptr RSAPublicKey1024, outSecret: ptr RSASharedSecret, outCipher: ptr RSACipherText1024): void =
      let r = encapsC(ctx[], peer[]); outSecret[] = r.secret; outCipher[] = r.cipher
    template rsaDecaps*(ctx: ptr RSA1024Ctx, cipher: ptr RSACipherText1024, outSecret: ptr RSASharedSecret): void = outSecret[] = decapsC(ctx[], cipher[])

    template rsaInit*(ctx: ptr RSA2048Ctx, random: Rng): void = keyInitC(ctx[], random)
    template rsaSign*(ctx: ptr RSA2048Ctx, msg: ptr UncheckedArray[uint8], msgLen: int): RSASignature2048 = signC(ctx[], msg.toOpenArray(0, msgLen - 1))
    template rsaVerify*(ctx: ptr RSA2048Ctx, msg: ptr UncheckedArray[uint8], msgLen: int, sig: ptr RSASignature2048): bool = verifyC(ctx[], msg.toOpenArray(0, msgLen - 1), sig[])
    template rsaEncaps*(ctx: ptr RSA2048Ctx, peer: ptr RSAPublicKey2048, outSecret: ptr RSASharedSecret, outCipher: ptr RSACipherText2048): void =
      let r = encapsC(ctx[], peer[]); outSecret[] = r.secret; outCipher[] = r.cipher
    template rsaDecaps*(ctx: ptr RSA2048Ctx, cipher: ptr RSACipherText2048, outSecret: ptr RSASharedSecret): void = outSecret[] = decapsC(ctx[], cipher[])

    template rsaInit*(ctx: ptr RSA3072Ctx, random: Rng): void = keyInitC(ctx[], random)
    template rsaSign*(ctx: ptr RSA3072Ctx, msg: ptr UncheckedArray[uint8], msgLen: int): RSASignature3072 = signC(ctx[], msg.toOpenArray(0, msgLen - 1))
    template rsaVerify*(ctx: ptr RSA3072Ctx, msg: ptr UncheckedArray[uint8], msgLen: int, sig: ptr RSASignature3072): bool = verifyC(ctx[], msg.toOpenArray(0, msgLen - 1), sig[])
    template rsaEncaps*(ctx: ptr RSA3072Ctx, peer: ptr RSAPublicKey3072, outSecret: ptr RSASharedSecret, outCipher: ptr RSACipherText3072): void =
      let r = encapsC(ctx[], peer[]); outSecret[] = r.secret; outCipher[] = r.cipher
    template rsaDecaps*(ctx: ptr RSA3072Ctx, cipher: ptr RSACipherText3072, outSecret: ptr RSASharedSecret): void = outSecret[] = decapsC(ctx[], cipher[])

    template rsaInit*(ctx: ptr RSA4096Ctx, random: Rng): void = keyInitC(ctx[], random)
    template rsaSign*(ctx: ptr RSA4096Ctx, msg: ptr UncheckedArray[uint8], msgLen: int): RSASignature4096 = signC(ctx[], msg.toOpenArray(0, msgLen - 1))
    template rsaVerify*(ctx: ptr RSA4096Ctx, msg: ptr UncheckedArray[uint8], msgLen: int, sig: ptr RSASignature4096): bool = verifyC(ctx[], msg.toOpenArray(0, msgLen - 1), sig[])
    template rsaEncaps*(ctx: ptr RSA4096Ctx, peer: ptr RSAPublicKey4096, outSecret: ptr RSASharedSecret, outCipher: ptr RSACipherText4096): void =
      let r = encapsC(ctx[], peer[]); outSecret[] = r.secret; outCipher[] = r.cipher
    template rsaDecaps*(ctx: ptr RSA4096Ctx, cipher: ptr RSACipherText4096, outSecret: ptr RSASharedSecret): void = outSecret[] = decapsC(ctx[], cipher[])

else:
  proc rsaInit*(ctx: var RSA1024Ctx, random: Rng): void {.inline.} = keyInitC(ctx, random)
  proc rsaSign*(ctx: RSA1024Ctx, message: openArray[uint8]): RSASignature1024 {.inline.} = signC(ctx, message)
  proc rsaVerify*(ctx: RSA1024Ctx, message: openArray[uint8], signature: RSASignature1024): bool {.inline.} = verifyC(ctx, message, signature)
  proc rsaEncaps*(ctx: RSA1024Ctx, peer: RSAPublicKey1024): tuple[secret: RSASharedSecret, cipher: RSACipherText1024] {.inline.} = encapsC(ctx, peer)
  proc rsaDecaps*(ctx: RSA1024Ctx, cipher: RSACipherText1024): RSASharedSecret {.inline.} = decapsC(ctx, cipher)

  proc rsaInit*(ctx: var RSA2048Ctx, random: Rng): void {.inline.} = keyInitC(ctx, random)
  proc rsaSign*(ctx: RSA2048Ctx, message: openArray[uint8]): RSASignature2048 {.inline.} = signC(ctx, message)
  proc rsaVerify*(ctx: RSA2048Ctx, message: openArray[uint8], signature: RSASignature2048): bool {.inline.} = verifyC(ctx, message, signature)
  proc rsaEncaps*(ctx: RSA2048Ctx, peer: RSAPublicKey2048): tuple[secret: RSASharedSecret, cipher: RSACipherText2048] {.inline.} = encapsC(ctx, peer)
  proc rsaDecaps*(ctx: RSA2048Ctx, cipher: RSACipherText2048): RSASharedSecret {.inline.} = decapsC(ctx, cipher)

  proc rsaInit*(ctx: var RSA3072Ctx, random: Rng): void {.inline.} = keyInitC(ctx, random)
  proc rsaSign*(ctx: RSA3072Ctx, message: openArray[uint8]): RSASignature3072 {.inline.} = signC(ctx, message)
  proc rsaVerify*(ctx: RSA3072Ctx, message: openArray[uint8], signature: RSASignature3072): bool {.inline.} = verifyC(ctx, message, signature)
  proc rsaEncaps*(ctx: RSA3072Ctx, peer: RSAPublicKey3072): tuple[secret: RSASharedSecret, cipher: RSACipherText3072] {.inline.} = encapsC(ctx, peer)
  proc rsaDecaps*(ctx: RSA3072Ctx, cipher: RSACipherText3072): RSASharedSecret {.inline.} = decapsC(ctx, cipher)

  proc rsaInit*(ctx: var RSA4096Ctx, random: Rng): void {.inline.} = keyInitC(ctx, random)
  proc rsaSign*(ctx: RSA4096Ctx, message: openArray[uint8]): RSASignature4096 {.inline.} = signC(ctx, message)
  proc rsaVerify*(ctx: RSA4096Ctx, message: openArray[uint8], signature: RSASignature4096): bool {.inline.} = verifyC(ctx, message, signature)
  proc rsaEncaps*(ctx: RSA4096Ctx, peer: RSAPublicKey4096): tuple[secret: RSASharedSecret, cipher: RSACipherText4096] {.inline.} = encapsC(ctx, peer)
  proc rsaDecaps*(ctx: RSA4096Ctx, cipher: RSACipherText4096): RSASharedSecret {.inline.} = decapsC(ctx, cipher)

  when defined(c) or defined(cpp) or defined(objc):
    proc rsaInit*(ctx: ptr RSA1024Ctx, random: Rng): void {.exportc: "rsa1024Init".} = keyInitC(ctx[], random)
    proc rsaSign*(ctx: ptr RSA1024Ctx, msg: ptr UncheckedArray[uint8], msgLen: int, outSig: ptr RSASignature1024): void {.exportc: "rsa1024Sign".} = outSig[] = signC(ctx[], msg.toOpenArray(0, msgLen - 1))
    proc rsaVerify*(ctx: ptr RSA1024Ctx, msg: ptr UncheckedArray[uint8], msgLen: int, sig: ptr RSASignature1024): bool {.exportc: "rsa1024Verify".} = result = verifyC(ctx[], msg.toOpenArray(0, msgLen - 1), sig[])
    proc rsaEncaps*(ctx: ptr RSA1024Ctx, peer: ptr RSAPublicKey1024, outSecret: ptr RSASharedSecret, outCipher: ptr RSACipherText1024): void {.exportc: "rsa1024Encaps".} =
      let r = encapsC(ctx[], peer[]); outSecret[] = r.secret; outCipher[] = r.cipher
    proc rsaDecaps*(ctx: ptr RSA1024Ctx, cipher: ptr RSACipherText1024, outSecret: ptr RSASharedSecret): void {.exportc: "rsa1024Decaps".} = outSecret[] = decapsC(ctx[], cipher[])

    proc rsaInit*(ctx: ptr RSA2048Ctx, random: Rng): void {.exportc: "rsa2048Init".} = keyInitC(ctx[], random)
    proc rsaSign*(ctx: ptr RSA2048Ctx, msg: ptr UncheckedArray[uint8], msgLen: int, outSig: ptr RSASignature2048): void {.exportc: "rsa2048Sign".} = outSig[] = signC(ctx[], msg.toOpenArray(0, msgLen - 1))
    proc rsaVerify*(ctx: ptr RSA2048Ctx, msg: ptr UncheckedArray[uint8], msgLen: int, sig: ptr RSASignature2048): bool {.exportc: "rsa2048Verify".} = result = verifyC(ctx[], msg.toOpenArray(0, msgLen - 1), sig[])
    proc rsaEncaps*(ctx: ptr RSA2048Ctx, peer: ptr RSAPublicKey2048, outSecret: ptr RSASharedSecret, outCipher: ptr RSACipherText2048): void {.exportc: "rsa2048Encaps".} =
      let r = encapsC(ctx[], peer[]); outSecret[] = r.secret; outCipher[] = r.cipher
    proc rsaDecaps*(ctx: ptr RSA2048Ctx, cipher: ptr RSACipherText2048, outSecret: ptr RSASharedSecret): void {.exportc: "rsa2048Decaps".} = outSecret[] = decapsC(ctx[], cipher[])

    proc rsaInit*(ctx: ptr RSA3072Ctx, random: Rng): void {.exportc: "rsa3072Init".} = keyInitC(ctx[], random)
    proc rsaSign*(ctx: ptr RSA3072Ctx, msg: ptr UncheckedArray[uint8], msgLen: int, outSig: ptr RSASignature3072): void {.exportc: "rsa3072Sign".} = outSig[] = signC(ctx[], msg.toOpenArray(0, msgLen - 1))
    proc rsaVerify*(ctx: ptr RSA3072Ctx, msg: ptr UncheckedArray[uint8], msgLen: int, sig: ptr RSASignature3072): bool {.exportc: "rsa3072Verify".} = result = verifyC(ctx[], msg.toOpenArray(0, msgLen - 1), sig[])
    proc rsaEncaps*(ctx: ptr RSA3072Ctx, peer: ptr RSAPublicKey3072, outSecret: ptr RSASharedSecret, outCipher: ptr RSACipherText3072): void {.exportc: "rsa3072Encaps".} =
      let r = encapsC(ctx[], peer[]); outSecret[] = r.secret; outCipher[] = r.cipher
    proc rsaDecaps*(ctx: ptr RSA3072Ctx, cipher: ptr RSACipherText3072, outSecret: ptr RSASharedSecret): void {.exportc: "rsa3072Decaps".} = outSecret[] = decapsC(ctx[], cipher[])

    proc rsaInit*(ctx: ptr RSA4096Ctx, random: Rng): void {.exportc: "rsa4096Init".} = keyInitC(ctx[], random)
    proc rsaSign*(ctx: ptr RSA4096Ctx, msg: ptr UncheckedArray[uint8], msgLen: int, outSig: ptr RSASignature4096): void {.exportc: "rsa4096Sign".} = outSig[] = signC(ctx[], msg.toOpenArray(0, msgLen - 1))
    proc rsaVerify*(ctx: ptr RSA4096Ctx, msg: ptr UncheckedArray[uint8], msgLen: int, sig: ptr RSASignature4096): bool {.exportc: "rsa4096Verify".} = result = verifyC(ctx[], msg.toOpenArray(0, msgLen - 1), sig[])
    proc rsaEncaps*(ctx: ptr RSA4096Ctx, peer: ptr RSAPublicKey4096, outSecret: ptr RSASharedSecret, outCipher: ptr RSACipherText4096): void {.exportc: "rsa4096Encaps".} =
      let r = encapsC(ctx[], peer[]); outSecret[] = r.secret; outCipher[] = r.cipher
    proc rsaDecaps*(ctx: ptr RSA4096Ctx, cipher: ptr RSACipherText4096, outSecret: ptr RSASharedSecret): void {.exportc: "rsa4096Decaps".} = outSecret[] = decapsC(ctx[], cipher[])
