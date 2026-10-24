import ./[common, fixedint, ec]
import ../hash/sm3
import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils

type
  SM2PublicKey* = PublicKeyCtx[65]
  SM2PrivateKey* = PrivateKeyCtx[32]
  SM2Signature* = array[64, uint8]
  SM2Ctx* = DSACtx[65, 32]

const DefaultIdentity* = "1234567812345678"

template sm2DecodePublic(key: SM2PublicKey, point: var EcPoint[32]): bool =
  decodeUncompressed[32](key.data, point) and sm2Curve().isOnCurve(point)

template sm2ValidatePrivateKey*(key: SM2PrivateKey): bool =
  var svpD: BigUint[32] = fromBytesBE[32](key.data)
  var svpUpper: BigUint[32] = subMod(sm2Curve().n, one[32](), sm2Curve().n)
  ctNonZero(svpD) == 1.UINT and ctLess(svpD, svpUpper)

template sm2ValidatePublicKey*(key: SM2PublicKey): bool =
  var svpubPoint: EcPoint[32]
  key.sm2DecodePublic(svpubPoint)

template sm2GeneratePrivateKey*(ctx: var SM2Ctx) =
  if ctx.rng == nil: raise newException(PubKeyError, "nil RNG")
  var gpCurve: EcCurve[32] = sm2Curve()
  var gpValue: BigUint[32]
  var gpUpper: BigUint[32] = subMod(gpCurve.n, one[32](), gpCurve.n)
  while true:
    ctx.rng(ctx.privateKey.data)
    gpValue = fromBytesBE[32](ctx.privateKey.data)
    if ctNonZero(gpValue) == 1.UINT and ctLess(gpValue, gpUpper): break

template sm2PublicKeyFromPrivate*(ctx: var SM2Ctx) =
  var pkCurve: EcCurve[32] = sm2Curve()
  var pkScalar: BigUint[32] = fromBytesBE[32](ctx.privateKey.data)
  ctx.publicKey.data = pkCurve.scalarBaseMult(pkScalar).encodeUncompressed()

template sm2GenerateNonce*(ctx: SM2Ctx): BigUint[32] =
  var gnCurve: EcCurve[32] = sm2Curve()
  var gnBytes: array[32, uint8]
  var gnResult: BigUint[32]
  while true:
    ctx.rng(gnBytes)
    gnResult = fromBytesBE[32](gnBytes)
    if ctNonZero(gnResult) == 1.UINT and ctLess(gnResult, gnCurve.n): break
  gnResult

# -----------------------------------------------------------------------------
# Z digest / Message digest (SM3 streaming, no seq)
# -----------------------------------------------------------------------------

template sm2ZDigest(publicKey: SM2PublicKey,
                    identity: openArray[uint8]): array[32, uint8] =
  if identity.len > 8191:
    raise newException(PubKeyError, "SM2 identity is too long")
  var zdPoint: EcPoint[32]
  if not publicKey.sm2DecodePublic(zdPoint):
    raise newException(PubKeyError, "invalid SM2 public key")

  var zdCurve: EcCurve[32] = sm2Curve()
  var zdEntl: array[2, uint8] = [
    uint8((identity.len * 8) shr 8),
    uint8(identity.len * 8)
  ]

  var zdCtx: SM3Ctx
  zdCtx.sm3Init()
  zdCtx.sm3Input(zdEntl)
  zdCtx.sm3Input(identity)
  zdCtx.sm3Input(toBytesBE[32](zdCurve.a))
  zdCtx.sm3Input(toBytesBE[32](zdCurve.b))
  zdCtx.sm3Input(toBytesBE[32](zdCurve.gx))
  zdCtx.sm3Input(toBytesBE[32](zdCurve.gy))
  zdCtx.sm3Input(toBytesBE[32](zdPoint.x))
  zdCtx.sm3Input(toBytesBE[32](zdPoint.y))
  zdCtx.sm3Final()

template sm2MessageDigest(publicKey: SM2PublicKey, message: openArray[uint8],
                          identity: openArray[uint8]): array[32, uint8] =
  var mdZ: array[32, uint8] = publicKey.sm2ZDigest(identity)
  var mdCtx: SM3Ctx
  mdCtx.sm3Init()
  mdCtx.sm3Input(mdZ)
  mdCtx.sm3Input(message)
  mdCtx.sm3Final()

# -----------------------------------------------------------------------------
# Sign / Verify digest core
# -----------------------------------------------------------------------------

template sm2SignDigestC(ctx: SM2Ctx, digest: array[32, uint8]): SM2Signature =
  var sdOutput: SM2Signature
  zeroMem(addr sdOutput, sizeof(sdOutput))

  var sdCurve: EcCurve[32] = sm2Curve()
  var sdD: BigUint[32] = fromBytesBE[32](ctx.privateKey.data)
  var sdE: BigUint[32] = fromBytesBE[32](digest)

  var sdNonce: BigUint[32]
  var sdPoint: EcPoint[32]
  var sdR: BigUint[32]
  var sdS: BigUint[32]
  var sdOnePlusD: BigUint[32]
  var sdValid: UINT
  var sdRb: array[32, uint8]
  var sdSb: array[32, uint8]

  while true:
    sdNonce = ctx.sm2GenerateNonce()
    sdPoint = sdCurve.scalarBaseMult(sdNonce)
    sdR = addMod(reduce(sdE, sdCurve.n), reduce(sdPoint.x, sdCurve.n), sdCurve.n)
    sdOnePlusD = addMod(one[32](), sdD, sdCurve.n)
    sdS = mulMod(inversePrime(sdOnePlusD, sdCurve.n),
      subMod(sdNonce, mulMod(sdR, sdD, sdCurve.n), sdCurve.n), sdCurve.n)
    sdValid = ctNonZero(sdR) and ctNonZero(sdS) and
      ctNonZero(addMod(sdR, sdNonce, sdCurve.n))
    if sdValid == 1.UINT:
      sdRb = toBytesBE[32](sdR)
      sdSb = toBytesBE[32](sdS)
      for sdI in 0 ..< 32:
        sdOutput[sdI] = sdRb[sdI]
        sdOutput[sdI + 32] = sdSb[sdI]
      break

  sdOutput

template sm2VerifyDigestC(ctx: SM2Ctx, digest: array[32, uint8],
                          signature: SM2Signature): bool =
  var vdCurve: EcCurve[32] = sm2Curve()
  var vdPubPoint: EcPoint[32]
  if not ctx.publicKey.sm2DecodePublic(vdPubPoint):
    false
  else:
    var vdR: BigUint[32] = fromBytesBE[32](signature.toOpenArray(0, 31))
    var vdS: BigUint[32] = fromBytesBE[32](signature.toOpenArray(32, 63))
    if ctNonZero(vdR) == 0.UINT or ctNonZero(vdS) == 0.UINT or
       not ctLess(vdR, vdCurve.n) or not ctLess(vdS, vdCurve.n):
      false
    else:
      var vdT: BigUint[32] = addMod(vdR, vdS, vdCurve.n)
      if ctNonZero(vdT) == 0.UINT:
        false
      else:
        var vdPoint: EcPoint[32] = vdCurve.add(
          vdCurve.scalarBaseMult(vdS), vdCurve.scalarMult(vdPubPoint, vdT))
        if vdPoint.infinity:
          false
        else:
          var vdE: BigUint[32] = fromBytesBE[32](digest)
          ctEqual(
            addMod(reduce(vdE, vdCurve.n), reduce(vdPoint.x, vdCurve.n), vdCurve.n),
            vdR)

template keyInitC*(ctx: var SM2Ctx, random: Rng): void =
  ctx.rng = random
  ctx.sm2GeneratePrivateKey()
  ctx.sm2PublicKeyFromPrivate()
  if not ctx.publicKey.sm2ValidatePublicKey():
    raise newException(PubKeyError, "invalid SM2 public key generated")

template signC*(ctx: SM2Ctx, message: openArray[uint8], identity: openArray[uint8]): SM2Signature =
  if not ctx.privateKey.sm2ValidatePrivateKey() or ctx.rng == nil:
    raise newException(PubKeyError, "invalid SM2 signing context")
  ctx.sm2SignDigestC(ctx.publicKey.sm2MessageDigest(message, identity))

template verifyC*(ctx: SM2Ctx, message: openArray[uint8], signature: SM2Signature, identity: openArray[uint8]): bool =
  if not ctx.publicKey.sm2ValidatePublicKey():
    false
  else:
    ctx.sm2VerifyDigestC(ctx.publicKey.sm2MessageDigest(message, identity), signature)


# -----------------------------------------------------------------------------
# Export wrappers
# -----------------------------------------------------------------------------

when defined(templateOpt):
  # ── Init ────────────────────────────────────────────────────────────────────
  template sm2Init*(ctx: var SM2Ctx, random: Rng): void =
    keyInitC(ctx, random)
  template sm2Init*(ctx: ptr SM2Ctx, random: ptr Rng): void =
    keyInitC(ctx[], random[])

  # ── Sign ────────────────────────────────────────────────────────────────────
  template sm2Sign*(ctx: SM2Ctx, message: openArray[uint8], identity: openArray[uint8]): SM2Signature =
    signC(ctx, message, identity)
  template sm2Sign*(ctx: ptr SM2Ctx, message: ptr UncheckedArray[uint8], messageLen: int, identity: ptr UncheckedArray[uint8], identityLen: int, outSignature: ptr SM2Signature): void =
    outSignature[] = signC(ctx[], message.toOpenArray(0, messageLen - 1), identity.toOpenArray(0, identityLen - 1))

  # ── Verify ──────────────────────────────────────────────────────────────────
  template sm2Verify*(ctx: SM2Ctx, message: openArray[uint8], signature: SM2Signature, identity: openArray[uint8]): bool =
    verifyC(ctx, message, signature, identity)
  template sm2Verify*(ctx: ptr SM2Ctx, message: ptr UncheckedArray[uint8], messageLen: int, signature: ptr SM2Signature, identity: ptr UncheckedArray[uint8], identityLen: int): bool =
    verifyC(ctx[],
      message.toOpenArray(0, messageLen - 1),
      signature[],
      identity.toOpenArray(0, identityLen - 1))

else:
  # ── Init ────────────────────────────────────────────────────────────────────
  proc sm2Init*(ctx: var SM2Ctx, random: Rng): void =
    keyInitC(ctx, random)
  proc sm2Init*(ctx: ptr SM2Ctx, random: ptr Rng): void {.exportc: "sm2Init".} =
    keyInitC(ctx[], random[])

  # ── Sign ────────────────────────────────────────────────────────────────────
  proc sm2Sign*(ctx: SM2Ctx, message: openArray[uint8], identity: openArray[uint8]): SM2Signature =
    signC(ctx, message, identity)
  proc sm2Sign*(ctx: ptr SM2Ctx, message: ptr UncheckedArray[uint8], messageLen: int, identity: ptr UncheckedArray[uint8], identityLen: int, outSignature: ptr SM2Signature): void {.exportc: "sm2Sign".} =
    outSignature[] = signC(ctx[],
      message.toOpenArray(0, messageLen - 1),
      identity.toOpenArray(0, identityLen - 1))

  # ── Verify ──────────────────────────────────────────────────────────────────
  proc sm2Verify*(ctx: SM2Ctx, message: openArray[uint8], signature: SM2Signature, identity: openArray[uint8]): bool =
    verifyC(ctx, message, signature, identity)
  proc sm2Verify*(ctx: ptr SM2Ctx, message: ptr UncheckedArray[uint8], messageLen: int, signature: ptr SM2Signature, identity: ptr UncheckedArray[uint8], identityLen: int): bool {.exportc: "sm2Verify".} =
    verifyC(ctx[], message.toOpenArray(0, messageLen - 1), signature[], identity.toOpenArray(0, identityLen - 1))
