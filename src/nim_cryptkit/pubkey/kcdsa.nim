import std/bitops

import ./common
import ./montgomery
import ../hash/sha2

const
  KCDSADefaultPBytes*: array[256, uint8] = [
    0x8F'u8, 0xC3'u8, 0xDD'u8, 0x39'u8, 0xF1'u8, 0xEB'u8, 0x67'u8, 0x43'u8,
    0x65'u8, 0x24'u8, 0x50'u8, 0x32'u8, 0x60'u8, 0xC8'u8, 0xF5'u8, 0x61'u8,
    0xC3'u8, 0xDF'u8, 0x7A'u8, 0xAA'u8, 0x55'u8, 0xC6'u8, 0xB7'u8, 0x69'u8,
    0x5A'u8, 0xCE'u8, 0xD5'u8, 0x1D'u8, 0x2E'u8, 0xD1'u8, 0x07'u8, 0x34'u8,
    0x4C'u8, 0x86'u8, 0x29'u8, 0x0C'u8, 0x46'u8, 0xE7'u8, 0x49'u8, 0xB3'u8,
    0x61'u8, 0x2A'u8, 0x30'u8, 0x4F'u8, 0xA9'u8, 0xAE'u8, 0xBC'u8, 0xAC'u8,
    0x85'u8, 0x8F'u8, 0x6F'u8, 0x73'u8, 0x2A'u8, 0x95'u8, 0xF4'u8, 0xA2'u8,
    0x47'u8, 0x13'u8, 0x48'u8, 0xAD'u8, 0x1F'u8, 0xC1'u8, 0xBA'u8, 0xF8'u8,
    0x70'u8, 0x8E'u8, 0x9D'u8, 0x7F'u8, 0x39'u8, 0x77'u8, 0xF3'u8, 0xEB'u8,
    0x97'u8, 0x8E'u8, 0x50'u8, 0xB4'u8, 0x26'u8, 0xCF'u8, 0x36'u8, 0xAB'u8,
    0xE2'u8, 0x2D'u8, 0xA6'u8, 0xC4'u8, 0x97'u8, 0x34'u8, 0x89'u8, 0xC8'u8,
    0xE5'u8, 0x61'u8, 0xF0'u8, 0x92'u8, 0x07'u8, 0x4D'u8, 0xF2'u8, 0x5B'u8,
    0x91'u8, 0x52'u8, 0x0B'u8, 0x79'u8, 0x8A'u8, 0xA4'u8, 0x6C'u8, 0x7C'u8,
    0x3F'u8, 0x95'u8, 0xEC'u8, 0xD5'u8, 0xB5'u8, 0x43'u8, 0x6F'u8, 0x7F'u8,
    0x66'u8, 0x0F'u8, 0xEC'u8, 0xF9'u8, 0x57'u8, 0x16'u8, 0x8A'u8, 0xF7'u8,
    0x5D'u8, 0xB5'u8, 0x02'u8, 0x5B'u8, 0xE1'u8, 0x21'u8, 0x8C'u8, 0xBB'u8,
    0xB6'u8, 0xE8'u8, 0xC2'u8, 0x21'u8, 0x64'u8, 0x15'u8, 0x4A'u8, 0x4A'u8,
    0x10'u8, 0x7E'u8, 0x5B'u8, 0xDC'u8, 0x80'u8, 0xA2'u8, 0x6F'u8, 0x7E'u8,
    0x58'u8, 0xDE'u8, 0xD9'u8, 0x0E'u8, 0xC0'u8, 0xE5'u8, 0x79'u8, 0x7E'u8,
    0xB1'u8, 0xA3'u8, 0x35'u8, 0xAD'u8, 0xCA'u8, 0x8C'u8, 0x1C'u8, 0x65'u8,
    0x3E'u8, 0xD0'u8, 0xD2'u8, 0x86'u8, 0x38'u8, 0x73'u8, 0x00'u8, 0x64'u8,
    0xA1'u8, 0xA5'u8, 0x62'u8, 0x2D'u8, 0xBF'u8, 0x7A'u8, 0xEF'u8, 0x25'u8,
    0x73'u8, 0xD1'u8, 0x0D'u8, 0x51'u8, 0x9C'u8, 0x4A'u8, 0xDA'u8, 0x45'u8,
    0x72'u8, 0xCA'u8, 0xB6'u8, 0x94'u8, 0xD9'u8, 0xCF'u8, 0xB2'u8, 0x28'u8,
    0xF6'u8, 0x78'u8, 0xDD'u8, 0x47'u8, 0xA2'u8, 0xD1'u8, 0x5F'u8, 0xAA'u8,
    0xE1'u8, 0x57'u8, 0x0F'u8, 0xD0'u8, 0xCE'u8, 0xD0'u8, 0x42'u8, 0x77'u8,
    0x5B'u8, 0x3F'u8, 0x6B'u8, 0xBC'u8, 0xCB'u8, 0x24'u8, 0xA9'u8, 0x94'u8,
    0xC2'u8, 0x7A'u8, 0x27'u8, 0xBF'u8, 0x2C'u8, 0xE8'u8, 0x32'u8, 0x02'u8,
    0x7F'u8, 0x5B'u8, 0x4E'u8, 0x4B'u8, 0xFC'u8, 0xDC'u8, 0x74'u8, 0xB7'u8,
    0x9D'u8, 0x60'u8, 0x6F'u8, 0xEE'u8, 0x20'u8, 0x3F'u8, 0x39'u8, 0x62'u8,
    0xD7'u8, 0x77'u8, 0x42'u8, 0x01'u8, 0xB8'u8, 0x16'u8, 0x46'u8, 0xF5'u8,
    0x54'u8, 0xDD'u8, 0x76'u8, 0x5E'u8, 0xBA'u8, 0xE2'u8, 0xC5'u8, 0xEB'u8
  ]

  KCDSADefaultQBytes*: array[32, uint8] = [
    0x88'u8, 0x44'u8, 0x60'u8, 0x25'u8, 0x5C'u8, 0x60'u8, 0x79'u8, 0x17'u8,
    0x4F'u8, 0xC9'u8, 0xDF'u8, 0x90'u8, 0x5F'u8, 0x36'u8, 0x38'u8, 0x7C'u8,
    0xF2'u8, 0x84'u8, 0x20'u8, 0x2B'u8, 0x08'u8, 0x9F'u8, 0x5A'u8, 0x1B'u8,
    0x56'u8, 0x18'u8, 0xE0'u8, 0x04'u8, 0x7E'u8, 0xDB'u8, 0x96'u8, 0x5D'u8
  ]

  KCDSADefaultGBytes*: array[256, uint8] = [
    0x75'u8, 0xD6'u8, 0x33'u8, 0x7A'u8, 0x74'u8, 0x6C'u8, 0xB9'u8, 0x0D'u8,
    0xD9'u8, 0x12'u8, 0xAA'u8, 0x5D'u8, 0x30'u8, 0x8D'u8, 0x05'u8, 0xF8'u8,
    0x2C'u8, 0x33'u8, 0x16'u8, 0xE6'u8, 0xD6'u8, 0x61'u8, 0xD0'u8, 0xBC'u8,
    0x09'u8, 0x38'u8, 0xE6'u8, 0x76'u8, 0x47'u8, 0x4E'u8, 0x65'u8, 0xA6'u8,
    0xB5'u8, 0xEE'u8, 0x97'u8, 0xB0'u8, 0xE0'u8, 0xCE'u8, 0x40'u8, 0x2F'u8,
    0xB3'u8, 0x23'u8, 0x62'u8, 0x24'u8, 0x5F'u8, 0xCE'u8, 0x04'u8, 0x06'u8,
    0x19'u8, 0xC0'u8, 0xDB'u8, 0x35'u8, 0x3B'u8, 0xF2'u8, 0xAC'u8, 0x9D'u8,
    0xE9'u8, 0x8B'u8, 0xBC'u8, 0xF3'u8, 0xC0'u8, 0xED'u8, 0xD1'u8, 0x5C'u8,
    0x65'u8, 0xFE'u8, 0x3B'u8, 0xED'u8, 0x4C'u8, 0x42'u8, 0x8D'u8, 0xB9'u8,
    0x53'u8, 0x99'u8, 0x61'u8, 0x03'u8, 0x21'u8, 0x25'u8, 0x78'u8, 0x0E'u8,
    0xB4'u8, 0xDC'u8, 0x9E'u8, 0xF5'u8, 0x9D'u8, 0x9E'u8, 0xB8'u8, 0x66'u8,
    0xF9'u8, 0x1A'u8, 0xB4'u8, 0xFF'u8, 0x60'u8, 0x3D'u8, 0xE8'u8, 0x1F'u8,
    0x14'u8, 0xD6'u8, 0xD9'u8, 0xF4'u8, 0x73'u8, 0xCE'u8, 0xAC'u8, 0x03'u8,
    0xDF'u8, 0x84'u8, 0x8A'u8, 0x10'u8, 0x2E'u8, 0xB2'u8, 0xB6'u8, 0x0E'u8,
    0x04'u8, 0xDE'u8, 0x7A'u8, 0xD0'u8, 0xA1'u8, 0xCF'u8, 0x8D'u8, 0x1D'u8,
    0xE0'u8, 0x0C'u8, 0x88'u8, 0xE6'u8, 0xAE'u8, 0x96'u8, 0x2F'u8, 0xD3'u8,
    0x90'u8, 0x6C'u8, 0x86'u8, 0x49'u8, 0xA9'u8, 0x8D'u8, 0xA4'u8, 0xE5'u8,
    0xD9'u8, 0x95'u8, 0x88'u8, 0xF1'u8, 0x59'u8, 0x3D'u8, 0x84'u8, 0xC0'u8,
    0xC6'u8, 0x36'u8, 0xE0'u8, 0xB1'u8, 0xCE'u8, 0x28'u8, 0xC3'u8, 0xCC'u8,
    0xAB'u8, 0xD6'u8, 0xE3'u8, 0x5C'u8, 0xC7'u8, 0xEC'u8, 0x78'u8, 0x80'u8,
    0x76'u8, 0xB1'u8, 0x81'u8, 0xCA'u8, 0xE1'u8, 0xF7'u8, 0x18'u8, 0x76'u8,
    0x8E'u8, 0x6F'u8, 0x90'u8, 0xB7'u8, 0x4B'u8, 0x0E'u8, 0x7C'u8, 0x87'u8,
    0x0B'u8, 0x0B'u8, 0xE2'u8, 0x79'u8, 0xB5'u8, 0x10'u8, 0xBE'u8, 0x79'u8,
    0xDC'u8, 0x07'u8, 0x81'u8, 0x9A'u8, 0x4D'u8, 0x6F'u8, 0x89'u8, 0xD5'u8,
    0xD7'u8, 0x99'u8, 0xB3'u8, 0xE0'u8, 0x07'u8, 0x54'u8, 0x45'u8, 0x64'u8,
    0xAB'u8, 0xD4'u8, 0x35'u8, 0xE9'u8, 0x8E'u8, 0x9B'u8, 0x56'u8, 0x18'u8,
    0xAA'u8, 0xA4'u8, 0x8F'u8, 0x55'u8, 0x27'u8, 0xDD'u8, 0x20'u8, 0xE0'u8,
    0x67'u8, 0x6A'u8, 0x31'u8, 0x28'u8, 0x82'u8, 0x69'u8, 0xE3'u8, 0xF1'u8,
    0xB7'u8, 0xBC'u8, 0x65'u8, 0x5A'u8, 0x51'u8, 0x8A'u8, 0xD8'u8, 0x96'u8,
    0x87'u8, 0x85'u8, 0x91'u8, 0x92'u8, 0x43'u8, 0x44'u8, 0xBB'u8, 0x09'u8,
    0xD8'u8, 0x67'u8, 0x85'u8, 0xA9'u8, 0xC7'u8, 0xEF'u8, 0x81'u8, 0x59'u8,
    0xC5'u8, 0xCF'u8, 0x15'u8, 0x79'u8, 0x1D'u8, 0x54'u8, 0x23'u8, 0x53'u8
  ]

type
  KCDSAParameters* = object
    p*: Nat[64]
    q*: Nat[8]
    g*: Nat[64]
    q64*: Nat[64]
    pCtx*: MontgomeryCtx[64]
    qCtx*: MontgomeryCtx[8]
    qMinus2Bytes*: array[32, uint8]

  KCDSAPublicKey* = object
    data*: array[256, uint8]

  KCDSAPrivateKey* = object
    data*: array[32, uint8]

  KCDSASignature* = array[64, uint8]

  KCDSACtx* = object
    publicKey*: KCDSAPublicKey
    privateKey*: KCDSAPrivateKey
    parameters*: KCDSAParameters
    rng*: Rng

template kcdsaSha256(a: openArray[uint8]): array[32, uint8] =
  block:
    var h: SHA2_256Ctx
    h.sha2_256Init()
    if a.len > 0:
      h.sha2_256Input(a)
    h.sha2_256Final()

template kcdsaSha256(a, b: openArray[uint8]): array[32, uint8] =
  block:
    var h: SHA2_256Ctx
    h.sha2_256Init()
    if a.len > 0:
      h.sha2_256Input(a)
    if b.len > 0:
      h.sha2_256Input(b)
    h.sha2_256Final()

template kcdsaXorNat[W: static int](a, b: Nat[W]): Nat[W] =
  block:
    var output: Nat[W]
    for i in 0 ..< W:
      output[i] = a[i] xor b[i]
    output

template kcdsaHashInteger(value: Nat[64]): Nat[8] =
  block:
    let encoded = toBytesBE(value)
    let digest = kcdsaSha256(encoded)
    fromBytesBE[8](digest)

template kcdsaMessageRepresentative(
    publicKey: KCDSAPublicKey;
    message: openArray[uint8]): Nat[8] =
  block:
    var suffix: array[64, uint8]
    for i in 0 ..< 64:
      suffix[i] = publicKey.data[192 + i]
    let digest = kcdsaSha256(suffix, message)
    fromBytesBE[8](digest)

template generateParameters*(parameters: var KCDSAParameters) =
  parameters.p = fromBytesBE[64](KCDSADefaultPBytes)
  parameters.q = fromBytesBE[8](KCDSADefaultQBytes)
  parameters.g = fromBytesBE[64](KCDSADefaultGBytes)
  parameters.q64 = fromBytesBE[64](KCDSADefaultQBytes)

  parameters.pCtx = initMontgomery(parameters.p)
  parameters.qCtx = initMontgomery(parameters.q)

  parameters.qMinus2Bytes = toBytesBE(subtractSmall(parameters.q, 2))

template validateParameters*(parameters: KCDSAParameters): bool =
  block:
    let oneP = oneNat[64]()
    let qBytes = toBytesBE(parameters.q)
    let gq = powMod(parameters.pCtx, parameters.g, qBytes)

    var ok = 1'u32
    ok = ok and nonZero(parameters.p)
    ok = ok and nonZero(parameters.q)
    ok = ok and nonZero(parameters.g)
    ok = ok and uint32(ord(less(parameters.q64, parameters.p)))
    ok = ok and uint32(ord(less(parameters.g, parameters.p)))
    ok = ok and (1'u32 - uint32(ord(equal(parameters.g, oneP))))
    ok = ok and uint32(ord(equal(gq, oneP)))
    ok == 1'u32

template validatePublicKey*(
    parameters: KCDSAParameters;
    publicKey: KCDSAPublicKey): bool =
  block:
    let y = fromBytesBE[64](publicKey.data)
    let oneP = oneNat[64]()
    let qBytes = toBytesBE(parameters.q)
    let yq = powMod(parameters.pCtx, y, qBytes)

    var ok = 1'u32
    ok = ok and nonZero(y)
    ok = ok and uint32(ord(less(y, parameters.p)))
    ok = ok and (1'u32 - uint32(ord(equal(y, oneP))))
    ok = ok and uint32(ord(equal(yq, oneP)))
    ok == 1'u32

template validatePublicKey*(ctx: KCDSACtx): bool =
  validatePublicKey(ctx.parameters, ctx.publicKey)

template validatePrivateKey*(
    privateKey: KCDSAPrivateKey;
    q: Nat[8]): bool =
  block:
    let x = fromBytesBE[8](privateKey.data)
    var ok = 1'u32
    ok = ok and nonZero(x)
    ok = ok and uint32(ord(less(x, q)))
    ok == 1'u32

template validatePrivateKey*(ctx: KCDSACtx): bool =
  validatePrivateKey(ctx.privateKey, ctx.parameters.q)

template generatePrivateKey*(ctx: var KCDSACtx) =
  if ctx.rng == nil:
    raise newException(PubKeyError, "nil RNG")

  block:
    var done = false
    while not done:
      ctx.rng(ctx.privateKey.data)
      let x = fromBytesBE[8](ctx.privateKey.data)
      if nonZero(x) == 1'u32 and less(x, ctx.parameters.q):
        done = true

template publicKeyFromPrivate*(ctx: var KCDSACtx) =
  if not validatePrivateKey(ctx.privateKey, ctx.parameters.q):
    raise newException(PubKeyError, "invalid KCDSA private key")

  block:
    let x = fromBytesBE[8](ctx.privateKey.data)
    let inv = powMod(ctx.parameters.qCtx, x, ctx.parameters.qMinus2Bytes)
    let invBytes = toBytesBE(inv)
    let y = powMod(ctx.parameters.pCtx, ctx.parameters.g, invBytes)
    ctx.publicKey.data = toBytesBE(y)

template generateNonce*(ctx: KCDSACtx): Nat[8] =
  block:
    if ctx.rng == nil:
      raise newException(PubKeyError, "nil RNG")

    var output: Nat[8]
    var done = false

    while not done:
      var bytes: array[32, uint8]
      ctx.rng(bytes)
      output = fromBytesBE[8](bytes)

      # Best-effort stack cleanup of the raw nonce bytes.
      for i in 0 ..< 32:
        bytes[i] = 0'u8

      if nonZero(output) == 1'u32 and less(output, ctx.parameters.q):
        done = true

    output

template keyInitC*(ctx: var KCDSACtx; random: Rng) =
  ctx.rng = random

  generateParameters(ctx.parameters)

  if not validateParameters(ctx.parameters):
    raise newException(PubKeyError, "invalid KCDSA parameters")

  generatePrivateKey(ctx)
  publicKeyFromPrivate(ctx)

  if not validatePublicKey(ctx.parameters, ctx.publicKey):
    raise newException(PubKeyError, "invalid KCDSA public key")

template signC*(ctx: KCDSACtx; message: openArray[uint8]): KCDSASignature =
  block:
    if ctx.rng == nil:
      raise newException(PubKeyError, "nil RNG")

    if not validateParameters(ctx.parameters):
      raise newException(PubKeyError, "invalid KCDSA parameters")

    if not validatePublicKey(ctx.parameters, ctx.publicKey):
      raise newException(PubKeyError, "invalid KCDSA public key")

    if not validatePrivateKey(ctx.privateKey, ctx.parameters.q):
      raise newException(PubKeyError, "invalid KCDSA private key")

    let x = fromBytesBE[8](ctx.privateKey.data)
    let z = kcdsaMessageRepresentative(ctx.publicKey, message)

    var output: KCDSASignature
    var done = false

    while not done:
      var nonce = generateNonce(ctx)
      var nonceBytes = toBytesBE(nonce)

      let v = powMod(ctx.parameters.pCtx, ctx.parameters.g, nonceBytes)

      for i in 0 ..< 32:
        nonceBytes[i] = 0'u8

      let r = kcdsaHashInteger(v)
      let mixed = kcdsaXorNat(r, z)
      let e = remainder[8, 8](mixed, ctx.parameters.q)
      let delta = subMod(nonce, e, ctx.parameters.q)

      for i in 0 ..< 8:
        nonce[i] = 0'u32

      let s = mulMod(ctx.parameters.qCtx, x, delta)

      if nonZero(r) == 1'u32 and nonZero(s) == 1'u32:
        let rb = toBytesBE(r)
        let sb = toBytesBE(s)

        for i in 0 ..< 32:
          output[i] = rb[i]
          output[32 + i] = sb[i]

        done = true

    output

template verifyC*(ctx: KCDSACtx, message: openArray[uint8], signature: KCDSASignature): bool =
  block:
    var output = false

    if validateParameters(ctx.parameters) and
       validatePublicKey(ctx.parameters, ctx.publicKey):
      var rBytes: array[32, uint8]
      var sBytes: array[32, uint8]

      for i in 0 ..< 32:
        rBytes[i] = signature[i]
        sBytes[i] = signature[32 + i]

      let r = fromBytesBE[8](rBytes)
      let s = fromBytesBE[8](sBytes)

      if nonZero(r) == 1'u32 and
         nonZero(s) == 1'u32 and
         less(s, ctx.parameters.q):
        let z = kcdsaMessageRepresentative(ctx.publicKey, message)
        let mixed = kcdsaXorNat(r, z)
        let e = remainder[8, 8](mixed, ctx.parameters.q)

        let y = fromBytesBE[64](ctx.publicKey.data)

        let sExp = toBytesBE(s)
        let eExp = toBytesBE(e)

        let w1 = powMod(ctx.parameters.pCtx, y, sExp)
        let w2 = powMod(ctx.parameters.pCtx, ctx.parameters.g, eExp)
        let w = mulMod(ctx.parameters.pCtx, w1, w2)

        output = equal(kcdsaHashInteger(w), r)

    output

when defined(templateOpt):
  template kcdsaKeyInit*(ctx: var KCDSACtx, random: Rng): void =
    keyInitC(ctx, random)
  template kcdsaKeyInit*(ctx: ptr KCDSACtx, random: ptr Rng): void =
    keyInitC(ctx[], random[])

  template kcdsaSign*(ctx: KCDSACtx, message: openArray[uint8]): KCDSASignature =
    signC(ctx, message)
  template kcdsaSign*(ctx: ptr KCDSACtx, msg: ptr UncheckedArray[uint8], msgLen: int, outSig: ptr KCDSASignature): void =
    outSig[] = signC(ctx[], toOpenArray(msg, 0, msgLen - 1))

  template kcdsaVerify*(ctx: KCDSACtx, message: openArray[uint8], sig: KCDSASignature): bool =
    verifyC(ctx, message, sig)
  template kcdsaVerify*(ctx: ptr KCDSACtx, msg: ptr UncheckedArray[uint8], msgLen: int, sig: ptr KCDSASignature): bool =
    verifyC(ctx[], toOpenArray(msg, 0, msgLen - 1), sig[])

else:
  proc kcdsaKeyInit*(ctx: var KCDSACtx, random: Rng): void =
    keyInitC(ctx, random)
  proc kcdsaKeyInit*(ctx: ptr KCDSACtx, random: ptr Rng): void {.exportc: "kcdsaKeyInit".} =
    keyInitC(ctx[], random[])

  proc kcdsaSign*(ctx: KCDSACtx, message: openArray[uint8]): KCDSASignature =
    signC(ctx, message)
  proc kcdsaSign*(ctx: ptr KCDSACtx, msg: ptr UncheckedArray[uint8], msgLen: int, outSig: ptr KCDSASignature): void {.exportc: "kcdsaSign".} =
    outSig[] = signC(ctx[], toOpenArray(msg, 0, msgLen - 1))

  proc kcdsaVerify*(ctx: KCDSACtx, message: openArray[uint8], sig: KCDSASignature): bool =
    verifyC(ctx, message, sig)
  proc kcdsaVerify*(ctx: ptr KCDSACtx, msg: ptr UncheckedArray[uint8], msgLen: int, sig: ptr KCDSASignature): bool {.exportc: "kcdsaVerify".} =
    verifyC(ctx[], toOpenArray(msg, 0, msgLen - 1), sig[])
