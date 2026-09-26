import common
import ../hash/sha2
import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils

type
  FieldElement = array[16, int64]
  EdwardsPoint = array[4, FieldElement]
  Ed25519PublicKey* = object
    data*: array[32, uint8]
  Ed25519PrivateKey* = object
    data*: array[32, uint8]
  Ed25519Signature* = array[64, uint8]
  Ed25519Ctx* = Object
    publicKey*: Ed25519PublicKey
    privateKey*: Ed25519PrivateKey
    rng*: Rng
    nonceSeed*: array[32, uint8]

const
  Zero: FieldElement = [0'i64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  One: FieldElement = [1'i64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

  D: FieldElement = [
    0x78a3'i64, 0x1359, 0x4dca, 0x75eb,
    0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7,
    0xfe73, 0x2b6f, 0x6cee, 0x5203
  ]

  D2: FieldElement = [
    0xf159'i64, 0x26b2, 0x9b94, 0xebd6,
    0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e,
    0xfce7, 0x56df, 0xd9dc, 0x2406
  ]

  BaseX: FieldElement = [
    0xd51a'i64, 0x8f25, 0x2d60, 0xc956,
    0xa7b2, 0x9525, 0xc760, 0x692c,
    0xdc5c, 0xfdd6, 0xe231, 0xc0a4,
    0x53fe, 0xcd6e, 0x36d3, 0x2169
  ]

  BaseY: FieldElement = [
    0x6658'i64, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666,
    0x6666, 0x6666, 0x6666, 0x6666
  ]

  SqrtM1: FieldElement = [
    0xa0b0'i64, 0x4a0e, 0x1b27, 0xc4ee,
    0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d,
    0xdf0b, 0x4fc1, 0x2480, 0x2b83
  ]

  GroupOrder: array[32, int64] = [
    0xed'i64, 0xd3, 0xf5, 0x5c,
    0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2,
    0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x10
  ]

# -----------------------------------------------------------------------------
# Field arithmetic
# -----------------------------------------------------------------------------

template carry(fe: var FieldElement) =
  ## Branchless carry.
  for i in 0 .. 14:
    fe[i] += 1'i64 shl 16
    let c = fe[i] shr 16
    fe[i + 1] += c - 1
    fe[i] -= c shl 16

  fe[15] += 1'i64 shl 16
  let c = fe[15] shr 16
  fe[0] += 38 * (c - 1)
  fe[15] -= c shl 16

template conditionalSwap(a, b: var FieldElement, bit: int64) =
  let mask = not (bit - 1)
  for i in 0 .. 15:
    let value = mask and (a[i] xor b[i])
    a[i] = a[i] xor value
    b[i] = b[i] xor value

template add(outFe: var FieldElement, a, b: FieldElement) =
  for i in 0 .. 15:
    outFe[i] = a[i] + b[i]

template sub(outFe: var FieldElement, a, b: FieldElement) =
  for i in 0 .. 15:
    outFe[i] = a[i] - b[i]

template multiply(outFe: var FieldElement, a, b: FieldElement) =
  var product: array[31, int64]

  for i in 0 .. 15:
    for j in 0 .. 15:
      product[i + j] += a[i] * b[j]

  for i in 0 ..< 15:
    product[i] += 38 * product[i + 16]

  for i in 0 .. 15:
    outFe[i] = product[i]

  outFe.carry()
  outFe.carry()

template square(outFe: var FieldElement, a: FieldElement) =
  outFe.multiply(a, a)

template packField(output: var array[32, uint8], input: FieldElement) =
  var t = input
  var reduced: FieldElement

  t.carry()
  t.carry()
  t.carry()

  for round in 0 .. 1:
    reduced[0] = t[0] - 0xffed

    for i in 1 .. 14:
      reduced[i] = t[i] - 0xffff - ((reduced[i - 1] shr 16) and 1)
      reduced[i - 1] = reduced[i - 1] and 0xffff

    reduced[15] = t[15] - 0x7fff - ((reduced[14] shr 16) and 1)
    let borrow = (reduced[15] shr 16) and 1
    reduced[14] = reduced[14] and 0xffff

    conditionalSwap(t, reduced, 1 - borrow)

  for i in 0 .. 15:
    output[2 * i] = uint8(t[i] and 0xff)
    output[2 * i + 1] = uint8((t[i] shr 8) and 0xff)

template unpackField(output: var FieldElement, input: openArray[uint8]) =
  for i in 0 .. 15:
    output[i] = int64(input[2 * i]) or (int64(input[2 * i + 1]) shl 8)
  output[15] = output[15] and 0x7fff

template fieldNotEqual(a, b: FieldElement): bool =
  var output: bool
  var ap, bp: array[32, uint8]

  ap.packField(a)
  bp.packField(b)

  output = not ctEqual(ap, bp)
  output

template parity(a: FieldElement): int64 =
  var output: int64
  var packed: array[32, uint8]

  packed.packField(a)
  output = int64(packed[0] and 1)
  output

template invert(output: var FieldElement, input: FieldElement) =
  var value = input

  for bit in countdown(253, 0):
    value.square(value)
    if bit != 2 and bit != 4:
      value.multiply(value, input)

  output = value

template pow2523(output: var FieldElement, input: FieldElement) =
  var value = input

  for bit in countdown(250, 0):
    value.square(value)
    if bit != 1:
      value.multiply(value, input)

  output = value

# -----------------------------------------------------------------------------
# Point arithmetic
# -----------------------------------------------------------------------------

template pointAdd(p: var EdwardsPoint, q: EdwardsPoint) =
  var a, b, c, d, e, f, g, h, t: FieldElement

  a.sub(p[1], p[0])
  t.sub(q[1], q[0])
  a.multiply(a, t)

  b.add(p[0], p[1])
  t.add(q[0], q[1])
  b.multiply(b, t)

  c.multiply(p[3], q[3])
  c.multiply(c, D2)

  d.multiply(p[2], q[2])
  d.add(d, d)

  e.sub(b, a)
  f.sub(d, c)
  g.add(d, c)
  h.add(b, a)

  p[0].multiply(e, f)
  p[1].multiply(h, g)
  p[2].multiply(g, f)
  p[3].multiply(e, h)

template pointSwap(p, q: var EdwardsPoint, bit: int64) =
  for i in 0 .. 3:
    conditionalSwap(p[i], q[i], bit)

template scalarMult(output: var EdwardsPoint, input: EdwardsPoint, scalar: openArray[uint8]) =
  var q = input

  output[0] = Zero
  output[1] = One
  output[2] = One
  output[3] = Zero

  for bitPosition in countdown(255, 0):
    let bit = int64((scalar[bitPosition shr 3] shr (bitPosition and 7)) and 1)

    pointSwap(output, q, bit)
    q.pointAdd(output)
    output.pointAdd(output)
    pointSwap(output, q, bit)

template scalarBase(output: var EdwardsPoint, scalar: openArray[uint8]) =
  var base: EdwardsPoint

  base[0] = BaseX
  base[1] = BaseY
  base[2] = One
  base[3].multiply(BaseX, BaseY)

  output.scalarMult(base, scalar)

template packPoint(output: var array[32, uint8], point: EdwardsPoint) =
  var tx, ty, zi: FieldElement

  zi.invert(point[2])
  tx.multiply(point[0], zi)
  ty.multiply(point[1], zi)

  output.packField(ty)
  output[31] = output[31] xor uint8(parity(tx) shl 7)

template unpackNegative(point: var EdwardsPoint, encoded: openArray[uint8]): bool =
  var output: bool = true

  block earlyReturn:
    var num, den, den2, den4, den6, check: FieldElement

    point[2] = One
    point[1].unpackField(encoded)

    num.square(point[1])
    den.multiply(num, D)

    num.sub(num, point[2])
    den.add(point[2], den)

    den2.square(den)
    den4.square(den2)
    den6.multiply(den4, den2)

    point[0].multiply(den6, num)
    point[0].multiply(point[0], den)

    point[0].pow2523(point[0])
    point[0].multiply(point[0], num)
    point[0].multiply(point[0], den)
    point[0].multiply(point[0], den)
    point[0].multiply(point[0], den)

    check.square(point[0])
    check.multiply(check, den)

    if check.fieldNotEqual(num):
      point[0].multiply(point[0], SqrtM1)

    check.square(point[0])
    check.multiply(check, den)

    if check.fieldNotEqual(num):
      output = false
      break earlyReturn

    if parity(point[0]) == int64(encoded[31] shr 7):
      point[0].sub(Zero, point[0])

    point[3].multiply(point[0], point[1])

  output

# -----------------------------------------------------------------------------
# SHA-512 helpers
#
# varargs[openArray]를 피하고, 힙 할당을 없애기 위해
# 실제 사용되는 형태에 맞춘 오버로드만 제공합니다.
# -----------------------------------------------------------------------------

template sha512(a: openArray[uint8]): array[64, uint8] =
  var shaOut: array[64, uint8]
  var shaCtx: SHA2_512Ctx

  shaCtx.sha2_512Init()
  if a.len > 0:
    shaCtx.sha2_512Input(a)
  shaOut = shaCtx.sha2_512Final()
  shaOut

template sha512(a: array[32, uint8]): array[64, uint8] =
  var shaOut: array[64, uint8]
  var shaCtx: SHA2_512Ctx

  shaCtx.sha2_512Init()
  shaCtx.sha2_512Input(a)
  shaOut = shaCtx.sha2_512Final()
  shaOut

template sha512(a: array[32, uint8], b: openArray[uint8]): array[64, uint8] =
  var shaOut: array[64, uint8]
  var shaCtx: SHA2_512Ctx

  shaCtx.sha2_512Init()
  shaCtx.sha2_512Input(a)
  if b.len > 0:
    shaCtx.sha2_512Input(b)
  shaOut = shaCtx.sha2_512Final()
  shaOut

template sha512(a, b: array[32, uint8], c: openArray[uint8]): array[64, uint8] =
  var shaOut: array[64, uint8]
  var shaCtx: SHA2_512Ctx

  shaCtx.sha2_512Init()
  shaCtx.sha2_512Input(a)
  shaCtx.sha2_512Input(b)
  if c.len > 0:
    shaCtx.sha2_512Input(c)
  shaOut = shaCtx.sha2_512Final()
  shaOut

# -----------------------------------------------------------------------------
# Scalar helpers
# -----------------------------------------------------------------------------

template reduceScalar(output: var array[32, uint8], input: array[64, uint8]) =
  var x: array[64, int64]

  for i in 0 ..< 64:
    x[i] = int64(input[i])

  var carryValue: int64

  for i in countdown(63, 32):
    carryValue = 0
    var j = i - 32
    let stop = i - 12

    while j < stop:
      x[j] += carryValue - 16 * x[i] * GroupOrder[j - (i - 32)]
      carryValue = (x[j] + 128) shr 8
      x[j] -= carryValue shl 8
      inc j

    x[j] += carryValue
    x[i] = 0

  carryValue = 0

  for j in 0 ..< 32:
    x[j] += carryValue - (x[31] shr 4) * GroupOrder[j]
    carryValue = x[j] shr 8
    x[j] = x[j] and 255

  for j in 0 ..< 32:
    x[j] -= carryValue * GroupOrder[j]

  for i in 0 ..< 32:
    x[i + 1] += x[i] shr 8
    output[i] = uint8(x[i] and 255)

template scalarCanonical(s: openArray[uint8]): bool =
  var output = false

  if s.len == 32:
    var borrow = 0'i64

    for i in 0 .. 31:
      borrow = int64(s[i]) - GroupOrder[i] - ((borrow shr 8) and 1)

    output = ((borrow shr 8) and 1) == 1

  output

# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------

template validatePrivateKey*(key: Ed25519PrivateKey): bool =
  var output: bool
  output = not ctIsZero(key.data)
  output

template validateEncodedPoint(encoded: openArray[uint8]): bool =
  var output: bool = true

  block earlyReturn:
    if encoded.len != 32:
      output = false
      break earlyReturn

    var canonicalInput, canonicalY: array[32, uint8]

    for i in 0 ..< 32:
      canonicalInput[i] = encoded[i]

    canonicalInput[31] = canonicalInput[31] and 0x7f

    var y: FieldElement
    y.unpackField(canonicalInput)
    canonicalY.packField(y)

    if not ctEqual(canonicalInput, canonicalY):
      output = false
      break earlyReturn

    var point: EdwardsPoint
    if not point.unpackNegative(encoded):
      output = false
      break earlyReturn

    var cofactor = [
      8'u8, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0
    ]

    var multiplied: EdwardsPoint
    multiplied.scalarMult(point, cofactor)

    var packed: array[32, uint8]
    packed.packPoint(multiplied)

    var identity: array[32, uint8]
    identity[0] = 1

    output = not ctEqual(packed, identity)

  output

template validatePublicKey*(key: Ed25519PublicKey): bool =
  var output: bool
  output = validateEncodedPoint(key.data)
  output

# -----------------------------------------------------------------------------
# Key generation / derivation
# -----------------------------------------------------------------------------

template generatePrivateKey*(ctx: var Ed25519Ctx) =
  if ctx.rng == nil:
    raise newException(PubKeyError, "nil RNG")

  ctx.rng(ctx.privateKey.data)

  if not ctx.privateKey.validatePrivateKey():
    raise newException(PubKeyError, "Ed25519 RNG returned an all-zero seed")

template publicKeyFromPrivate*(ctx: var Ed25519Ctx) =
  var expanded: array[64, uint8] = sha512(ctx.privateKey.data)

  # RFC 8032: use the first 32 bytes as the clamped scalar.
  var scalar: array[32, uint8]
  for i in 0 .. 31:
    scalar[i] = expanded[i]

  scalar[0] = scalar[0] and 248'u8
  scalar[31] = (scalar[31] and 127'u8) or 64'u8

  var point: EdwardsPoint
  point.scalarBase(scalar)

  ctx.publicKey.data.packPoint(point)

template keyInitC*(ctx: var Ed25519Ctx, rngProc: Rng) =
  ctx.rng = rngProc
  ctx.generatePrivateKey()
  ctx.publicKeyFromPrivate()

  if not ctx.publicKey.validatePublicKey():
    raise newException(PubKeyError, "invalid Ed25519 public key")

  if not ctx.privateKey.validatePrivateKey():
    raise newException(PubKeyError, "invalid Ed25519 private key")

# -----------------------------------------------------------------------------
# Nonce
# -----------------------------------------------------------------------------

template generateNonce*(ctx: Ed25519Ctx, message: openArray[uint8]): array[32, uint8] =
  ## RFC 8032 deterministic nonce:
  ##
  ##   expanded = SHA-512(seed)
  ##   prefix   = expanded[32..63]
  ##   r        = SHA-512(prefix || message) mod L
  ##
  var output: array[32, uint8]

  var expanded: array[64, uint8] = sha512(ctx.privateKey.data)

  var prefix: array[32, uint8]
  for i in 0 .. 31:
    prefix[i] = expanded[i + 32]

  let digest = sha512(prefix, message)
  output.reduceScalar(digest)

  output

# -----------------------------------------------------------------------------
# Sign / Verify
# -----------------------------------------------------------------------------

template signC*(ctx: Ed25519Ctx, message: openArray[uint8]): Ed25519Signature =
  var output: Ed25519Signature

  var expanded: array[64, uint8] = sha512(ctx.privateKey.data)
  expanded[0] = expanded[0] and 248'u8
  expanded[31] = (expanded[31] and 127'u8) or 64'u8

  let r = ctx.generateNonce(message)

  var point: EdwardsPoint
  point.scalarBase(r)

  var encodedR: array[32, uint8]
  encodedR.packPoint(point)

  for i in 0 .. 31:
    output[i] = encodedR[i]

  let hDigest = sha512(encodedR, ctx.publicKey.data, message)

  var h: array[32, uint8]
  h.reduceScalar(hDigest)

  var accumulator: array[64, int64]

  for i in 0 .. 31:
    accumulator[i] = int64(r[i])

  for i in 0 .. 31:
    for j in 0 .. 31:
      accumulator[i + j] += int64(h[i]) * int64(expanded[j])

  var wide: array[64, uint8]
  var carryValue = 0'i64

  for i in 0 .. 63:
    accumulator[i] += carryValue
    wide[i] = uint8(accumulator[i] and 255)
    carryValue = accumulator[i] shr 8

  var s: array[32, uint8]
  s.reduceScalar(wide)

  for i in 0 .. 31:
    output[i + 32] = s[i]

  output

template verifyC*(ctx: Ed25519Ctx, message: openArray[uint8], signature: Ed25519Signature): bool =
  var output: bool = true

  block earlyReturn:
    if not scalarCanonical(signature.toOpenArray(32, 63)):
      output = false
      break earlyReturn

    if not validateEncodedPoint(signature.toOpenArray(0, 31)):
      output = false
      break earlyReturn

    var publicPoint: EdwardsPoint
    if not publicPoint.unpackNegative(ctx.publicKey.data):
      output = false
      break earlyReturn

    var encodedR: array[32, uint8]
    for i in 0 .. 31:
      encodedR[i] = signature[i]

    let digest = sha512(encodedR, ctx.publicKey.data, message)

    var h: array[32, uint8]
    h.reduceScalar(digest)

    var p, q: EdwardsPoint

    p.scalarMult(publicPoint, h)
    q.scalarBase(signature.toOpenArray(32, 63))

    p.pointAdd(q)

    var check: array[32, uint8]
    check.packPoint(p)

    output = ctEqual(check, encodedR)

  output = output and ctx.publicKey.validatePublicKey()
  output


# ----------------------------------------------------------------------
# Export Wrappers
# ----------------------------------------------------------------------

when defined(templateOpt):
  template ed25519Init*(ctx: var Ed25519Ctx, random: Rng): void =
    keyInitC(ctx, random)
  template ed25519Init*(ctx: ptr Ed25519Ctx, random: ptr Rng): void =
    keyInitC(ctx[], random[])

  template ed25519Sign*(ctx: Ed25519Ctx, message: openArray[uint8]): Ed25519Signature =
    signC(ctx, message)
  template ed25519Sign*(ctx: ptr Ed25519Ctx, msg: ptr UncheckedArray[uint8], msgLen: int): Ed25519Signature =
    signC(ctx[], msg.toOpenArray(0, msgLen - 1))

  template ed25519Verify*(ctx: Ed25519Ctx, message: openArray[uint8], signature: Ed25519Signature): bool =
    verifyC(ctx, message, signature)
  template ed25519Verify*(ctx: ptr Ed25519Ctx, msg: ptr UncheckedArray[uint8], msgLen: int, sig: ptr Ed25519Signature): bool =
    verifyC(ctx[], msg.toOpenArray(0, msgLen - 1), sig[])

else:
  proc ed25519Init*(ctx: var Ed25519Ctx, random: Rng): void =
    keyInitC(ctx, random)
  proc ed25519Init*(ctx: ptr Ed25519Ctx, random: ptr Rng): void {.exportc: "ed25519Init".} =
    keyInitC(ctx[], random[])

  proc ed25519Sign*(ctx: Ed25519Ctx, message: openArray[uint8]): Ed25519Signature =
    signC(ctx, message)
  proc ed25519Sign*(ctx: ptr Ed25519Ctx, msg: ptr UncheckedArray[uint8], msgLen: int, outSig: ptr Ed25519Signature): void {.exportc: "ed25519Sign".} =
    outSig[] = signC(ctx[], msg.toOpenArray(0, msgLen - 1))

  proc ed25519Verify*(ctx: Ed25519Ctx, message: openArray[uint8], signature: Ed25519Signature): bool =
    verifyC(ctx, message, signature)
  proc ed25519Verify*(ctx: ptr Ed25519Ctx, msg: ptr UncheckedArray[uint8], msgLen: int, sig: ptr Ed25519Signature): bool {.exportc: "ed25519Verify".} =
    verifyC(ctx[], msg.toOpenArray(0, msgLen - 1), sig[])
