import ./[common, fixedint, ec]
import ../hash/sha2
import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils

# -----------------------------------------------------------------------------
# Type Definitions
# -----------------------------------------------------------------------------
type
  ECKCDSAPublicKey* = object
    data*: array[65, uint8]

  ECKCDSAPrivateKey* = object
    data*: array[32, uint8]

  ECKCDSASignature* = array[64, uint8]

  ECKCDSACtx* = object
    publicKey*: ECKCDSAPublicKey
    privateKey*: ECKCDSAPrivateKey
    rng*: Rng

# -----------------------------------------------------------------------------
# Internal Helper Templates
# -----------------------------------------------------------------------------

template sha256(a, b, c: openArray[uint8]): array[32, uint8] =
  var ctx: SHA2_256Ctx
  ctx.sha2_256Init()
  ctx.sha2_256Input(a)
  ctx.sha2_256Input(b)
  ctx.sha2_256Input(c)
  ctx.sha2_256Final()

template sha256(a: openArray[uint8]): array[32, uint8] =
  var ctx: SHA2_256Ctx
  ctx.sha2_256Init()
  ctx.sha2_256Input(a)
  ctx.sha2_256Final()

template decodePublic(key: ECKCDSAPublicKey, point: var EcPoint[32]): bool =
  decodeUncompressed[32](key.data, point) and p256().isOnCurve(point)

template xHash(point: EcPoint[32]): BigUint[32] =
  fromBytesBE[32](sha256(toBytesBE[32](point.x)))

template messageRepresentative(publicKey: ECKCDSAPublicKey,
                               msg: openArray[uint8]): BigUint[32] =
  var tmpPoint: EcPoint[32]
  if not publicKey.decodePublic(tmpPoint): default(BigUint[32])
  else: fromBytesBE[32](sha256(toBytesBE[32](tmpPoint.x), toBytesBE[32](tmpPoint.y), msg))

# -----------------------------------------------------------------------------
# Validation Templates
# -----------------------------------------------------------------------------
template validatePrivateKey*(key: ECKCDSAPrivateKey): bool =
  let tmpD = fromBytesBE[32](key.data)
  ctNonZero(tmpD) == 1 and ctLess(tmpD, p256().n)

template validatePublicKey*(key: ECKCDSAPublicKey): bool =
  var tmpPt: EcPoint[32]
  key.decodePublic(tmpPt)

# -----------------------------------------------------------------------------
# Key Generation Templates
# -----------------------------------------------------------------------------
template generatePrivateKey*(ctx: var ECKCDSACtx) =
  if ctx.rng == nil: raise newException(PubKeyError, "nil RNG")
  let tmpCurve = p256()
  var tmpD: BigUint[32]
  while true:
    ctx.rng(ctx.privateKey.data)
    tmpD = fromBytesBE[32](ctx.privateKey.data)
    if ctNonZero(tmpD) == 1 and ctLess(tmpD, tmpCurve.n): break

template publicKeyFromPrivate*(ctx: var ECKCDSACtx) =
  let tmpD = fromBytesBE[32](ctx.privateKey.data)
  ctx.publicKey.data = p256().scalarBaseMult(tmpD).encodeUncompressed()

template keyInitC(ctx: var ECKCDSACtx, random: Rng) =
  ctx.rng = random
  ctx.generatePrivateKey()
  ctx.publicKeyFromPrivate()
  if not ctx.publicKey.validatePublicKey():
    raise newException(PubKeyError, "invalid EC-KCDSA public key generated")

template generateNonce*(ctx: ECKCDSACtx): BigUint[32] =
  let tmpCurve = p256()
  var tmpBytes: array[32, uint8]
  var tmpResult: BigUint[32]
  while true:
    ctx.rng(tmpBytes)
    tmpResult = fromBytesBE[32](tmpBytes)
    if ctNonZero(tmpResult) == 1 and ctLess(tmpResult, tmpCurve.n): break
  tmpResult

# -----------------------------------------------------------------------------
# Sign / Verify
# -----------------------------------------------------------------------------
template signC(ctx: ECKCDSACtx, message: openArray[uint8]): ECKCDSASignature =
  var output: ECKCDSASignature
  zeroMem(addr output, sizeof(output))

  if not ctx.privateKey.validatePrivateKey() or ctx.rng == nil:
    raise newException(PubKeyError, "invalid EC-KCDSA signing context")

  let curve = p256()
  let d = fromBytesBE[32](ctx.privateKey.data)
  let v = ctx.publicKey.messageRepresentative(message)

  var nonce: BigUint[32]
  var kG: EcPoint[32]
  var r: BigUint[32]
  var e: BigUint[32]
  var s: BigUint[32]
  var rb: array[32, uint8]
  var sb: array[32, uint8]

  while true:
    nonce = ctx.generateNonce()
    kG = curve.scalarBaseMult(nonce)
    r = kG.xHash()
    e = reduce(r xor v, curve.n)
    s = mulMod(d, subMod(nonce, e, curve.n), curve.n)

    if ctNonZero(r) == 1 and ctNonZero(s) == 1:
      rb = toBytesBE[32](r)
      sb = toBytesBE[32](s)
      for i in 0 ..< 32:
        output[i] = rb[i]
        output[i + 32] = sb[i]
      break

  output

template verifyC(ctx: ECKCDSACtx, message: openArray[uint8],
                 signature: ECKCDSASignature): bool =
  if not ctx.publicKey.validatePublicKey(): false
  else:
    let curve = p256()
    var pubPoint: EcPoint[32]
    if not ctx.publicKey.decodePublic(pubPoint): false
    else:
      let r = fromBytesBE[32](signature.toOpenArray(0, 31))
      let s = fromBytesBE[32](signature.toOpenArray(32, 63))
      if ctNonZero(r) == 0 or ctNonZero(s) == 0 or not ctLess(s, curve.n): false
      else:
        let v = ctx.publicKey.messageRepresentative(message)
        let e = reduce(r xor v, curve.n)
        let computed = curve.add(
          curve.scalarMult(pubPoint, s),
          curve.scalarBaseMult(e)
        )
        not computed.infinity and ctEqual(computed.xHash(), r)

when defined(test):
  proc signCWithNonce*(
      ctx: ECKCDSACtx,
      message: openArray[uint8],
      nonce: BigUint[32]
  ): ECKCDSASignature =
    block:
      var tmpOutput: ECKCDSASignature
      for i in 0 ..< tmpOutput.len: tmpOutput[i] = 0

      if not ctx.privateKey.validatePrivateKey():
        raise newException(ValueError, "invalid EC-KCDSA private key")
      if not ctx.publicKey.validatePublicKey():
        raise newException(ValueError, "invalid EC-KCDSA public key")

      let curve: EcCurve[32] = p256()
      if ctNonZero(nonce) == 0.UINT or not ctLess(nonce, curve.n):
        raise newException(ValueError, "invalid EC-KCDSA nonce")

      let d: BigUint[32] = fromBytesBE[32](ctx.privateKey.data)
      let v: BigUint[32] = ctx.publicKey.messageRepresentative(message)
      let kG: EcPoint[32] = curve.scalarBaseMult(nonce)
      let r: BigUint[32] = kG.xHash()

      let xorVal: BigUint[32] = r xor v
      let e: BigUint[32] = reduce(xorVal, curve.n)
      let s: BigUint[32] = mulMod(d, subMod(nonce, e, curve.n), curve.n)

      if ctNonZero(r) == 0.UINT or ctNonZero(s) == 0.UINT:
        raise newException(ValueError, "nonce produced invalid EC-KCDSA r/s")

      let rb: array[32, uint8] = toBytesBE[32](r)
      let sb: array[32, uint8] = toBytesBE[32](s)
      for i in 0 ..< 32:
        tmpOutput[i] = rb[i]
        tmpOutput[i + 32] = sb[i]

      tmpOutput


# -----------------------------------------------------------------------------
# Export wrappers
# -----------------------------------------------------------------------------

when defined(templateOpt):
  template eckcdsaInit*(ctx: var ECKCDSACtx, random: Rng): void =
    keyInitC(ctx, random)
  template eckcdsaInit*(ctx: ptr ECKCDSACtx, random: ptr Rng): void =
    keyInitC(ctx[], random[])

  template eckcdsaSign*(ctx: ECKCDSACtx, message: openArray[uint8]): ECKCDSASignature =
    signC(ctx, message)
  template eckcdsaSign*(ctx: ptr ECKCDSACtx, message: ptr UncheckedArray[uint8], messageLen: int, outSignature: ptr ECKCDSASignature): void =
    outSignature[] = signC(ctx[], message.toOpenArray(0, messageLen - 1))

  template eckcdsaVerify*(ctx: ECKCDSACtx, message: openArray[uint8], signature: ECKCDSASignature): bool =
    verifyC(ctx, message, signature)
  template eckcdsaVerify*(ctx: ptr ECKCDSACtx, message: ptr UncheckedArray[uint8], messageLen: int, signature: ptr ECKCDSASignature): bool =
    verifyC(ctx[], message.toOpenArray(0, messageLen - 1), signature[])

else:
  proc eckcdsaInit*(ctx: var ECKCDSACtx, random: Rng): void =
    keyInitC(ctx, random)
  proc eckcdsaInit*(ctx: ptr ECKCDSACtx, random: ptr Rng): void {.exportc: "eckcdsaInit".} =
    keyInitC(ctx[], random[])

  proc eckcdsaSign*(ctx: ECKCDSACtx, message: openArray[uint8]): ECKCDSASignature =
    signC(ctx, message)
  proc eckcdsaSign*(ctx: ptr ECKCDSACtx, message: ptr UncheckedArray[uint8], messageLen: int, outSignature: ptr ECKCDSASignature): void {.exportc: "eckcdsaSign".} =
    outSignature[] = signC(ctx[], message.toOpenArray(0, messageLen - 1))

  proc eckcdsaVerify*(ctx: ECKCDSACtx, message: openArray[uint8], signature: ECKCDSASignature): bool =
    verifyC(ctx, message, signature)
  proc eckcdsaVerify*(ctx: ptr ECKCDSACtx, message: ptr UncheckedArray[uint8], messageLen: int, signature: ptr ECKCDSASignature): bool {.exportc: "eckcdsaVerify".} =
    verifyC(ctx[], message.toOpenArray(0, messageLen - 1), signature[])
