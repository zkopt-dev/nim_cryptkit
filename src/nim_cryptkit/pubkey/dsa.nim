import common, fixedint
import montgomery as mont
import ../hash/sha1
import ../hash/sha2
import ../mac/hmac
import ../utils/envconst
import ../utils/digits
import ../utils/bitutils
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils

type
  DSAParams*[L, N: static int] = object
    p*: mont.Nat[L div 4]
    g*: mont.Nat[L div 4]
    q*: mont.Nat[N div 4]
    montP*: mont.MontgomeryCtx[L div 4]
    montQ*: mont.MontgomeryCtx[N div 4]

  DSACtx*[L, N: static int] = object
    params*: DSAParams[L, N]
    privateKey*: mont.Nat[N div 4]
    publicKey*: mont.Nat[L div 4]
    privateBytes*: array[N, uint8]
    rng*: Rng

  DSASignature*[N: static int] = array[2 * N, uint8]

  DSA1024_160Ctx*  = DSACtx[128, 20]
  DSA2048_224Ctx*  = DSACtx[256, 28]
  DSA2048_256Ctx*  = DSACtx[256, 32]
  DSA3072_256Ctx*  = DSACtx[384, 32]

  DSA160Signature* = DSASignature[20]
  DSA224Signature* = DSASignature[28]
  DSA256Signature* = DSASignature[32]


template dsaHmac[N: static int](key, data: untyped): array[N, uint8] =
  when N == 20:
    hmacOne[SHA1Ctx, 64, 20](sha1Init, sha1Input, sha1Final, key, data)
  elif N == 28:
    hmacOne[SHA2_224Ctx, 64, 28](sha2_224Init, sha2_224Input, sha2_224Final, key, data)
  else:
    hmacOne[SHA2_256Ctx, 64, 32](sha2_256Init, sha2_256Input, sha2_256Final, key, data)

template generateNonce*[L, N: static int](ctx: DSACtx[L, N], digest: array[N, uint8]): mont.Nat[N div 4] =
  var output: Nat[N div 4]

  var vector: array[N, uint8]
  var key: array[N, uint8]
  for i in 0 ..< N:
    vector[i] = 0x01'u8
    key[i] = 0x00'u8

  var data: seq[uint8]
  data.add(vector)
  data.add(0x00'u8)
  data.add(ctx.privateBytes)
  data.add(digest)
  key = dsaHmac[N](key, data)
  vector = dsaHmac[N](key, vector)

  data.setLen(0)
  data.add(vector)
  data.add(0x01'u8)
  data.add(ctx.privateBytes)
  data.add(digest)
  key = dsaHmac[N](key, data)
  vector = dsaHmac[N](key, vector)

  while true:
    var temp: seq[uint8]
    while temp.len < N:
      vector = dsaHmac[N](key, vector)
      temp.add(vector)
    output = bits2int[N div 4](temp.toOpenArray(0, N - 1), ctx.params.q)
    if mont.nonZero(output) != 0 and mont.less(output, ctx.params.q):
      break
    data.setLen(0)
    data.add(vector)
    data.add(0x00'u8)
    key = dsaHmac[N](key, data)
    vector = dsaHmac[N](key, vector)

  output

template validateParameters*[L, N: static int](parameters: DSAParams[L, N]): bool =
  var output: bool = true

  let p: mont.Nat[L div 4] = parameters.p
  let g: mont.Nat[L div 4] = parameters.g
  let q: mont.Nat[N div 4] = parameters.q

  # p, q prime number check
  if not mont.probablePrime(p): output = false
  if not mont.probablePrime(q): output = false

  # q | (p - 1) check
  let pMinus1: mont.Nat[L div 4] = mont.decrement(p)
  let remain: mont.Nat[N div 4] = mont.remainder[L div 4, N div 4](pMinus1, q)
  if nonZero(remain) != 0: output = false

  # 1 < g < p
  let oneL: mont.Nat[L div 4] = mont.oneNat[L div 4]()
  if not less(oneL, g): output = false # g <= 1
  if not less(g, p): output = false # g >= p

  # g ^ q mod p == 1
  let qBytes: array[N, uint8] = mont.toBytesBE(q)
  let gPowQ: mont.Nat[L div 4] = mont.powMod(parameters.montP, g, qBytes)
  if not equal(gPowQ, oneL): output = false

  output

template validatePrivateKey*[N: static int](private: mont.Nat[N div 4], q: mont.Nat[N div 4]): bool =
  var output: bool = true

  # 0 < private < q
  if nonZero(private) == 0: output = false
  if not less(private, q): output = false

  output

template validatePublicKey*[L, N: static int](public: mont.Nat[L div 4], parameters: DSAParams[L, N]): bool =
  var output: bool = true

  # 1 < public < p
  let oneL: mont.Nat[L div 4] = mont.oneNat[L div 4]()
  if not less(oneL, public): output = false
  if not less(public, parameters.p): output = false

  # y ^ q mod p == 1
  let qBytes: array[N, uint8] = toBytesBE(parameters.q)
  let yPowQ: mont.Nat[L div 4] = mont.powMod(parameters.montP, public, qBytes)
  if not equal(yPowQ, oneL): output = false

  output

template generatePrivateKey*[L, N: static int](ctx: var DSACtx[L, N]): void =
  const NW: int = N div 4
  const extraBytes: int = 8
  const bufLen: int = N + extraBytes

  let qMinus1: mont.Nat[NW] = decrement(ctx.params.q)

  var buf: array[bufLen, uint8]

  while true:
    ctx.rng(buf.toOpenArray(0, bufLen - 1))

    let rawBig: BigUint[bufLen] = fixedint.fromBytesBE[bufLen](buf)
    let rawNat = bigUintToNat[bufLen div 4, bufLen](rawBig)

    let reduced = reduceMixed[bufLen div 4, NW](rawNat, qMinus1)

    let oneN: mont.Nat[NW] = oneNat[NW]()
    let x: mont.Nat[NW] = addMod(reduced, oneN, ctx.params.q)

    if nonZero(x) != 0'u32:
      ctx.privateKey = x
      ctx.privateBytes = toBytesBE(x)
      break

template publicKeyFromPrivate*[L, N: static int](ctx: var DSACtx[L, N]): void =
  ctx.publicKey = mont.powMod(ctx.params.montP, ctx.params.g, ctx.privateBytes)

template dsaInitC*[L, N: static int](ctx: var DSACtx[L, N], random: Rng, pIn: array[L, uint8], qIn: array[N, uint8], gIn: array[L, uint8]): void =
  ctx.params.p = mont.fromBytesBE[L div 4](pIn)
  ctx.params.q = mont.fromBytesBE[N div 4](qIn)
  ctx.params.g = mont.fromBytesBE[L div 4](gIn)
  ctx.rng = random

  ctx.params.montP = mont.initMontgomery(ctx.params.p)
  ctx.params.montQ = mont.initMontgomery(ctx.params.q)

  if not validateParameters(ctx.params):
    raise newException(PubKeyError, "invalid DSA parameters")
  generatePrivateKey(ctx)
  publicKeyFromPrivate(ctx)
  if not validatePublicKey(ctx.publicKey, ctx.params):
    raise newException(PubKeyError, "invalid DSA public key")

template dsaSignC*[L, N: static int](ctx: DSACtx[L, N], input: array[N, uint8]): DSASignature[N] =
  const LW = L div 4
  const NW = N div 4

  var output: DSASignature[N]

  let z: mont.Nat[NW] = bits2int[NW](input, ctx.params.q)

  let qMinus2: mont.Nat[NW] = mont.subtractSmall(ctx.params.q, 2'u32)
  let qMinus2Bytes: array[N, uint8] = mont.toBytesBE(qMinus2)

  while true:
    let k: mont.Nat[NW] = generateNonce(ctx, input)

    let kBytes: array[N, uint8] = mont.toBytesBE(k)
    let gk: mont.Nat[LW] = mont.powMod(ctx.params.montP, ctx.params.g, kBytes)
    let r: mont.Nat[NW] = reduceMixed[LW, NW](gk, ctx.params.q)

    if mont.nonZero(r) == 0'u32:
      continue

    let kInv: mont.Nat[NW] = mont.powMod(ctx.params.montQ, k, qMinus2Bytes)

    let xr: mont.Nat[NW] = mont.mulMod(ctx.params.montQ, ctx.privateKey, r)
    let zPlusXr: mont.Nat[NW] = mont.addMod(z, xr, ctx.params.q)
    let s: mont.Nat[NW] = mont.mulMod(ctx.params.montQ, kInv, zPlusXr)

    if mont.nonZero(s) == 0'u32:
      continue

    let rBytes: array[N, uint8] = mont.toBytesBE(r)
    let sBytes: array[N, uint8] = mont.toBytesBE(s)

    copyMem(addr output[0], addr rBytes[0], N)
    copyMem(addr output[N], addr sBytes[0], N)

    break

  output

template dsaVerifyC*[L, N: static int](ctx: DSACtx[L, N], input: array[N, uint8], signature: DSASignature[N]): bool =
  var output: bool = true

  const LW = L div 4
  const NW = N div 4

  var rBytes: array[N, uint8]
  var sBytes: array[N, uint8]

  copyMem(addr rBytes[0], unsafeAddr signature[0], N)
  copyMem(addr sBytes[0], unsafeAddr signature[N], N)

  let r: mont.Nat[NW] = mont.fromBytesBE[NW](rBytes)
  let s: mont.Nat[NW] = mont.fromBytesBE[NW](sBytes)

  if mont.nonZero(r) == 0'u32 or not mont.less(r, ctx.params.q): output = false
  if mont.nonZero(s) == 0'u32 or not mont.less(s, ctx.params.q): output = false

  let z: mont.Nat[NW] = bits2int[NW](input, ctx.params.q)

  let qMinus2: mont.Nat[NW] = mont.subtractSmall(ctx.params.q, 2'u32)
  let qMinus2Bytes: array[N, uint8] = mont.toBytesBE(qMinus2)
  let w: mont.Nat[NW] = mont.powMod(ctx.params.montQ, s, qMinus2Bytes)

  let u1: mont.Nat[NW] = mont.mulMod(ctx.params.montQ, z, w)
  let u2: mont.Nat[NW] = mont.mulMod(ctx.params.montQ, r, w)

  let u1Bytes: array[N, uint8] = mont.toBytesBE(u1)
  let u2Bytes: array[N, uint8] = mont.toBytesBE(u2)

  let gu1: mont.Nat[LW] = mont.powMod(ctx.params.montP, ctx.params.g, u1Bytes)
  let yu2: mont.Nat[LW] = mont.powMod(ctx.params.montP, ctx.publicKey, u2Bytes)
  let gu1yu2: mont.Nat[LW] = mont.mulMod(ctx.params.montP, gu1, yu2)
  let v: mont.Nat[NW] = reduceMixed[LW, NW](gu1yu2, ctx.params.q)

  if not mont.equal(v, r): output = false

  output


when defined(templateOpt):
  template dsa1024Init*(ctx: var DSA1024_160Ctx, random: Rng, pIn: array[128, uint8], qIn: array[20, uint8], gIn: array[128, uint8]): void = dsaInitC(ctx, random, pIn, qIn, gIn)
  template dsa1024Init*(ctx: ptr DSA1024_160Ctx, random: ptr Rng, pIn: ptr array[128, uint8], qIn: ptr array[20, uint8], gIn: ptr array[128, uint8]): void = dsaInitC(ctx[], random[], pIn[], qIn[], gIn[])

  template dsa1024Sign*(ctx: DSA1024_160Ctx, digest: array[20, uint8]): DSA160Signature = dsaSignC(ctx, digest)
  template dsa1024Sign*(ctx: ptr DSA1024_160Ctx, digest: ptr array[20, uint8]): DSA160Signature = dsaSignC(ctx[], digest[])

  template dsa1024Verify*(ctx: DSA1024_160Ctx, digest: array[20, uint8], signature: DSA160Signature): bool = dsaVerifyC(ctx, digest, signature)
  template dsa1024Verify*(ctx: ptr DSA1024_160Ctx, digest: ptr array[20, uint8], signature: ptr DSA160Signature): bool = dsaVerifyC(ctx[], digest[], signature[])


  template dsa2048_224Init*(ctx: var DSA2048_224Ctx, random: Rng, pIn: array[256, uint8], qIn: array[28, uint8], gIn: array[256, uint8]): void = dsaInitC(ctx, random, pIn, qIn, gIn)
  template dsa2048_224Init*(ctx: ptr DSA2048_224Ctx, random: ptr Rng, pIn: ptr array[256, uint8], qIn: ptr array[28, uint8], gIn: ptr array[256, uint8]): void = dsaInitC(ctx[], random[], pIn[], qIn[], gIn[])

  template dsa2048_224Sign*(ctx: DSA2048_224Ctx, digest: array[28, uint8]): DSA224Signature = dsaSignC(ctx, digest)
  template dsa2048_224Sign*(ctx: ptr DSA2048_224Ctx, digest: ptr array[28, uint8]): DSA224Signature = dsaSignC(ctx[], digest[])

  template dsa2048_224Verify*(ctx: DSA2048_224Ctx, digest: array[28, uint8], signature: DSA224Signature): bool = dsaVerifyC(ctx, digest, signature)
  template dsa2048_224Verify*(ctx: ptr DSA2048_224Ctx, digest: ptr array[28, uint8], signature: ptr DSA224Signature): bool = dsaVerifyC(ctx[], digest[], signature[])


  template dsa2048_256Init*(ctx: var DSA2048_256Ctx, random: Rng, pIn: array[256, uint8], qIn: array[32, uint8], gIn: array[256, uint8]): void = dsaInitC(ctx, random, pIn, qIn, gIn)
  template dsa2048_256Init*(ctx: ptr DSA2048_256Ctx, random: ptr Rng, pIn: ptr array[256, uint8], qIn: ptr array[32, uint8], gIn: ptr array[256, uint8]): void = dsaInitC(ctx[], random[], pIn[], qIn[], gIn[])

  template dsa2048_256Sign*(ctx: DSA2048_256Ctx, digest: array[32, uint8]): DSA256Signature = dsaSignC(ctx, digest)
  template dsa2048_256Sign*(ctx: ptr DSA2048_256Ctx, digest: ptr array[32, uint8]): DSA256Signature = dsaSignC(ctx[], digest[])

  template dsa2048_256Verify*(ctx: DSA2048_256Ctx, digest: array[32, uint8], signature: DSA256Signature): bool = dsaVerifyC(ctx, digest, signature)
  template dsa2048_256Verify*(ctx: ptr DSA2048_256Ctx, digest: ptr array[32, uint8], signature: ptr DSA256Signature): bool = dsaVerifyC(ctx[], digest[], signature[])


  template dsa3072Init*(ctx: var DSA3072_256Ctx, random: Rng, pIn: array[384, uint8], qIn: array[32, uint8], gIn: array[384, uint8]): void = dsaInitC(ctx, random, pIn, qIn, gIn)
  template dsa3072Init*(ctx: ptr DSA3072_256Ctx, random: ptr Rng, pIn: ptr array[384, uint8], qIn: ptr array[32, uint8], gIn: ptr array[384, uint8]): void = dsaInitC(ctx[], random[], pIn[], qIn[], gIn[])

  template dsa3072Sign*(ctx: DSA3072_256Ctx, digest: array[32, uint8]): DSA256Signature = dsaSignC(ctx, digest)
  template dsa3072Sign*(ctx: ptr DSA3072_256Ctx, digest: ptr array[32, uint8]): DSA256Signature = dsaSignC(ctx[], digest[])

  template dsa3072Verify*(ctx: DSA3072_256Ctx, digest: array[32, uint8], signature: DSA256Signature): bool = dsaVerifyC(ctx, digest, signature)
  template dsa3072Verify*(ctx: ptr DSA3072_256Ctx, digest: ptr array[32, uint8], signature: ptr DSA256Signature): bool = dsaVerifyC(ctx[], digest[], signature[])
else:
  proc dsa1024Init*(ctx: var DSA1024_160Ctx, random: Rng, pIn: array[128, uint8], qIn: array[20, uint8], gIn: array[128, uint8]): void = dsaInitC(ctx, random, pIn, qIn, gIn)
  proc dsa1024Init*(ctx: ptr DSA1024_160Ctx, random: ptr Rng, pIn: ptr array[128, uint8], qIn: ptr array[20, uint8], gIn: ptr array[128, uint8]): void {.exportc: "dsa1024Init".} = dsaInitC(ctx[], random[], pIn[], qIn[], gIn[])

  proc dsa1024Sign*(ctx: DSA1024_160Ctx, digest: array[20, uint8]): DSA160Signature = dsaSignC(ctx, digest)
  proc dsa1024Sign*(ctx: ptr DSA1024_160Ctx, digest: ptr array[20, uint8], outSig: ptr DSA160Signature): void {.exportc: "dsa1024Sign".} = outSig[] = dsaSignC(ctx[], digest[])

  proc dsa1024Verify*(ctx: DSA1024_160Ctx, digest: array[20, uint8], signature: DSA160Signature): bool = dsaVerifyC(ctx, digest, signature)
  proc dsa1024Verify*(ctx: ptr DSA1024_160Ctx, digest: ptr array[20, uint8], signature: ptr DSA160Signature): bool {.exportc: "dsa1024Verify".} = dsaVerifyC(ctx[], digest[], signature[])


  proc dsa2048_224Init*(ctx: var DSA2048_224Ctx, random: Rng, pIn: array[256, uint8], qIn: array[28, uint8], gIn: array[256, uint8]): void = dsaInitC(ctx, random, pIn, qIn, gIn)
  proc dsa2048_224Init*(ctx: ptr DSA2048_224Ctx, random: ptr Rng, pIn: ptr array[256, uint8], qIn: ptr array[28, uint8], gIn: ptr array[256, uint8]): void {.exportc: "dsa2048_224Init".} = dsaInitC(ctx[], random[], pIn[], qIn[], gIn[])

  proc dsa2048_224Sign*(ctx: DSA2048_224Ctx, digest: array[28, uint8]): DSA224Signature = dsaSignC(ctx, digest)
  proc dsa2048_224Sign*(ctx: ptr DSA2048_224Ctx, digest: ptr array[28, uint8], outSig: ptr DSA224Signature): void {.exportc: "dsa2048_224Sign".} = outSig[] = dsaSignC(ctx[], digest[])

  proc dsa2048_224Verify*(ctx: DSA2048_224Ctx, digest: array[28, uint8], signature: DSA224Signature): bool = dsaVerifyC(ctx, digest, signature)
  proc dsa2048_224Verify*(ctx: ptr DSA2048_224Ctx, digest: ptr array[28, uint8], signature: ptr DSA224Signature): bool {.exportc: "dsa2048_224Verify".} = dsaVerifyC(ctx[], digest[], signature[])

  proc dsa2048_256Init*(ctx: var DSA2048_256Ctx, random: Rng, pIn: array[256, uint8], qIn: array[32, uint8], gIn: array[256, uint8]): void = dsaInitC(ctx, random, pIn, qIn, gIn)
  proc dsa2048_256Init*(ctx: ptr DSA2048_256Ctx, random: ptr Rng, pIn: ptr array[256, uint8], qIn: ptr array[32, uint8], gIn: ptr array[256, uint8]): void {.exportc: "dsa2048_256Init".} = dsaInitC(ctx[], random[], pIn[], qIn[], gIn[])

  proc dsa2048_256Sign*(ctx: DSA2048_256Ctx, digest: array[32, uint8]): DSA256Signature = dsaSignC(ctx, digest)
  proc dsa2048_256Sign*(ctx: ptr DSA2048_256Ctx, digest: ptr array[32, uint8], outSig: ptr DSA256Signature): void {.exportc: "dsa2048_256Sign".} = outSig[] = dsaSignC(ctx[], digest[])

  proc dsa2048_256Verify*(ctx: DSA2048_256Ctx, digest: array[32, uint8], signature: DSA256Signature): bool = dsaVerifyC(ctx, digest, signature)
  proc dsa2048_256Verify*(ctx: ptr DSA2048_256Ctx, digest: ptr array[32, uint8], signature: ptr DSA256Signature): bool {.exportc: "dsa2048_256Verify".} = dsaVerifyC(ctx[], digest[], signature[])


  proc dsa3072Init*(ctx: var DSA3072_256Ctx, random: Rng, pIn: array[384, uint8], qIn: array[32, uint8], gIn: array[384, uint8]): void = dsaInitC(ctx, random, pIn, qIn, gIn)
  proc dsa3072Init*(ctx: ptr DSA3072_256Ctx, random: ptr Rng, pIn: ptr array[384, uint8], qIn: ptr array[32, uint8], gIn: ptr array[384, uint8]): void {.exportc: "dsa3072Init".} = dsaInitC(ctx[], random[], pIn[], qIn[], gIn[])

  proc dsa3072Sign*(ctx: DSA3072_256Ctx, digest: array[32, uint8]): DSA256Signature = dsaSignC(ctx, digest)
  proc dsa3072Sign*(ctx: ptr DSA3072_256Ctx, digest: ptr array[32, uint8], outSig: ptr DSA256Signature): void {.exportc: "dsa3072Sign".} = outSig[] = dsaSignC(ctx[], digest[])

  proc dsa3072Verify*(ctx: DSA3072_256Ctx, digest: array[32, uint8], signature: DSA256Signature): bool = dsaVerifyC(ctx, digest, signature)
  proc dsa3072Verify*(ctx: ptr DSA3072_256Ctx, digest: ptr array[32, uint8], signature: ptr DSA256Signature): bool {.exportc: "dsa3072Verify".} = dsaVerifyC(ctx[], digest[], signature[])
