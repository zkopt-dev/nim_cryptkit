import ./[common, fixedint, ec]
import ../hash/sha2
import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils

type
  FieldElement = array[16, int64]
  X25519PublicKey* = object
    data*: array[32, uint8]
  X25519PrivateKey* = object
    data*: array[32, uint8]
  X25519SharedSecret* = array[32, uint8]
  X25519Ctx* = object
    publicKey*: X25519PublicKey
    privateKey*: X25519PrivateKey
    rng*: Rng

const
  BasePoint: array[32, uint8] = [
    9'u8, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
  ]

  Zero: FieldElement = [
    0'i64, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
  ]

  One: FieldElement = [
    1'i64, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
  ]

  C121665: FieldElement = [
    0xdb41'i64, 1, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
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

  carry(outFe)
  carry(outFe)

template square(outFe: var FieldElement, a: FieldElement) =
  multiply(outFe, a, a)

template unpack(outFe: var FieldElement, input: array[32, uint8]) =
  for i in 0 .. 15:
    outFe[i] = int64(input[2 * i]) or (int64(input[2 * i + 1]) shl 8)
  outFe[15] = outFe[15] and 0x7fff

template pack(output: var array[32, uint8], input: FieldElement) =
  var t = input
  var reduced: FieldElement

  carry(t)
  carry(t)
  carry(t)

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

template invert(outFe: var FieldElement, input: FieldElement) =
  var value = input

  for exponentBit in countdown(253, 0):
    square(value, value)
    if exponentBit != 2 and exponentBit != 4:
      multiply(value, value, input)

  outFe = value

# -----------------------------------------------------------------------------
# X25519 scalar multiplication core
# -----------------------------------------------------------------------------

template scalarMultCore(output: var array[32, uint8], scalar, point: array[32, uint8]) =
  var clamped = scalar

  clamped[0] = clamped[0] and 248'u8
  clamped[31] = (clamped[31] and 127'u8) or 64'u8

  var x, a, b, c, d, e, f: FieldElement

  unpack(x, point)

  a = One
  b = x
  c = Zero
  d = One

  for position in countdown(254, 0):
    let bit = int64((clamped[position shr 3] shr (position and 7)) and 1)

    conditionalSwap(a, b, bit)
    conditionalSwap(c, d, bit)

    add(e, a, c)
    sub(a, a, c)

    add(c, b, d)
    sub(b, b, d)

    square(d, e)
    square(f, a)

    multiply(a, c, a)
    multiply(c, b, e)

    add(e, a, c)
    sub(a, a, c)

    square(b, a)
    sub(c, d, f)

    multiply(a, c, C121665)
    add(a, a, d)

    multiply(c, c, a)
    multiply(a, d, f)
    multiply(d, b, x)
    square(b, e)

    conditionalSwap(a, b, bit)
    conditionalSwap(c, d, bit)

  invert(c, c)
  multiply(a, a, c)
  pack(output, a)

# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------

template validatePrivateKey*(key: X25519PrivateKey): bool =
  not ctIsZero(key.data)

template validatePublicKey*(key: X25519PublicKey): bool =
  not ctIsZero(key.data)

# -----------------------------------------------------------------------------
# Key generation / derivation
# -----------------------------------------------------------------------------

template generatePrivateKey*(ctx: var X25519Ctx) =
  if ctx.rng == nil:
    raise newException(PubKeyError, "nil RNG")

  ctx.rng(ctx.privateKey.data)

  if not validatePrivateKey(ctx.privateKey):
    raise newException(PubKeyError, "X25519 RNG returned an all-zero scalar")

template publicKeyFromPrivate*(ctx: var X25519Ctx) =
  scalarMultCore(ctx.publicKey.data, ctx.privateKey.data, BasePoint)

template keyInitC*(ctx: var X25519Ctx, rngProc: Rng) =
  ctx.rng = rngProc

  generatePrivateKey(ctx)
  publicKeyFromPrivate(ctx)

  if not validatePublicKey(ctx.publicKey):
    raise newException(PubKeyError, "invalid X25519 public key")

  if not validatePrivateKey(ctx.privateKey):
    raise newException(PubKeyError, "invalid X25519 private key")

# -----------------------------------------------------------------------------
# DH / shared secret
# -----------------------------------------------------------------------------

template deriveC*(ctx: X25519Ctx, peer: X25519PublicKey): X25519SharedSecret =
  if not validatePrivateKey(ctx.privateKey) or not validatePublicKey(peer):
    raise newException(PubKeyError, "invalid X25519 key")

  var output: X25519SharedSecret
  scalarMultCore(output, ctx.privateKey.data, peer.data)

  if ctIsZero(output):
    raise newException(PubKeyError, "X25519 low-order peer public key")

  output

# ----------------------------------------------------------------------
# Export Wrappers
# ----------------------------------------------------------------------

when defined(templateOpt):
  template x25519Init*(ctx: var X25519Ctx, random: Rng): void =
    keyInitC(ctx, random)
  template x25519Init*(ctx: ptr X25519Ctx, random: ptr Rng): void =
    keyInitC(ctx[], random[])

  template x25519Derive*(ctx: X25519Ctx, peer: X25519PublicKey): X25519SharedSecret =
    deriveC(ctx, peer)
  template x25519Derive*(ctx: ptr X25519Ctx, peer: ptr X25519PublicKey): X25519SharedSecret =
    deriveC(ctx[], peer[])

else:
  proc x25519Init*(ctx: var X25519Ctx, random: Rng): void =
    keyInitC(ctx, random)
  proc x25519Init*(ctx: ptr X25519Ctx, random: ptr Rng): void {.exportc: "x25519Init".} =
    keyInitC(ctx[], random[])

  proc x25519Derive*(ctx: X25519Ctx, peer: X25519PublicKey): X25519SharedSecret =
    deriveC(ctx, peer)
  proc x25519Derive*(ctx: ptr X25519Ctx, peer: ptr X25519PublicKey, outSecret: ptr X25519SharedSecret): void {.exportc: "x25519Derive".} =
    outSecret[] = deriveC(ctx[], peer[])
