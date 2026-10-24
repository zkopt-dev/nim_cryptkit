import ./fixedint
import ../utils/envconst
import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils

type
  EcCurve*[B: static int] = object
    p*, a*, b*, n*, gx*, gy*: BigUint[B]
    r2*, halfPPlus1*, oneMont*: BigUint[B]
    aMont*, bMont*, gxMont*, gyMont*: BigUint[B]

  EcPoint*[B: static int] = object
    x*, y*: BigUint[B]
    infinity*: bool

  JacobianPoint*[B: static int] = object
    x*, y*, z*: BigUint[B]

proc ctBitLE[B: static int](x: BigUint[B], bitFromLsb: int): UINT {.inline.} =
  var output: UINT
  output = ctBitBE(x, B * 8 - 1 - bitFromLsb)
  output

proc ctLsb[B: static int](x: BigUint[B]): UINT {.inline.} =
  var output: UINT
  output = ctBitLE(x, 0)
  output

proc halveMod[B: static int](curve: EcCurve[B], x: BigUint[B]): BigUint[B] {.inline.} =
  let odd: UINT = ctLsb(x)
  let shifted: BigUint[B] = shiftRightOne(x)
  let adjusted: BigUint[B] = addMod(shifted, curve.halfPPlus1, curve.p)
  var output: BigUint[B]
  output = ctSelect(adjusted, shifted, odd)
  output

proc montMul*[B: static int](curve: EcCurve[B], a, b: BigUint[B]): BigUint[B] =
  var t: BigUint[B] = default(BigUint[B])
  for i in 0 ..< (B * 8):
    let bit: UINT = ctBitLE(b, i)
    let added: BigUint[B] = addMod(t, a, curve.p)
    t = ctSelect(added, t, bit)
    t = halveMod(curve, t)
  var output: BigUint[B]
  output = t
  output

proc toMont[B: static int](curve: EcCurve[B], x: BigUint[B]): BigUint[B] {.inline.} =
  var output: BigUint[B]
  output = montMul(curve, x, curve.r2)
  output

proc fromMont[B: static int](curve: EcCurve[B], x: BigUint[B]): BigUint[B] {.inline.} =
  var output: BigUint[B]
  output = montMul(curve, x, one[B]())
  output

proc computeR2[B: static int](p: BigUint[B]): BigUint[B] =
  var r: BigUint[B] = one[B]()
  for i in 0 ..< (2 * B * 8):
    r = addMod(r, r, p)
  var output: BigUint[B]
  output = r
  output

proc makeCurve[B: static int](pIn, aIn, bIn, nIn, gxIn, gyIn: array[B, uint8]): EcCurve[B] =
  var output: EcCurve[B]

  let pBU: BigUint[B] = fromBytesBE[B](pIn)
  let aBU: BigUint[B] = fromBytesBE[B](aIn)
  let bBU: BigUint[B] = fromBytesBE[B](bIn)
  let nBU: BigUint[B] = fromBytesBE[B](nIn)
  let gxBU: BigUint[B] = fromBytesBE[B](gxIn)
  let gyBU: BigUint[B] = fromBytesBE[B](gyIn)

  output.p = pBU
  output.a = aBU
  output.b = bBU
  output.n = nBU
  output.gx = gxBU
  output.gy = gyBU

  output.halfPPlus1 = addMod(shiftRightOne(pBU), one[B](), pBU)
  output.r2 = computeR2(pBU)
  output.oneMont = montMul(output, one[B](), output.r2)
  output.aMont = montMul(output, aBU, output.r2)
  output.bMont = montMul(output, bBU, output.r2)
  output.gxMont = montMul(output, gxBU, output.r2)
  output.gyMont = montMul(output, gyBU, output.r2)

  output

proc fadd[B: static int](a, b, p: BigUint[B]): BigUint[B] {.inline.} =
  var output: BigUint[B]
  output = addMod(a, b, p)
  output

proc fsub[B: static int](a, b, p: BigUint[B]): BigUint[B] {.inline.} =
  var output: BigUint[B]
  output = subMod(a, b, p)
  output

proc fmul[B: static int](curve: EcCurve[B], a, b: BigUint[B]): BigUint[B] {.inline.} =
  var output: BigUint[B]
  output = montMul(curve, a, b)
  output

proc ctPointSelect[B: static int](
    whenOne, whenZero: JacobianPoint[B],
    choice: UINT
): JacobianPoint[B] {.inline.} =
  var output: JacobianPoint[B]
  output.x = ctSelect(whenOne.x, whenZero.x, choice)
  output.y = ctSelect(whenOne.y, whenZero.y, choice)
  output.z = ctSelect(whenOne.z, whenZero.z, choice)
  output

proc baseJacobianMont[B: static int](curve: EcCurve[B]): JacobianPoint[B] {.inline.} =
  var output: JacobianPoint[B]
  output.x = curve.gxMont
  output.y = curve.gyMont
  output.z = curve.oneMont
  output

proc toJacobian[B: static int](
    curve: EcCurve[B],
    point: EcPoint[B]
): JacobianPoint[B] {.inline.} =
  var output: JacobianPoint[B]
  output.x = toMont(curve, point.x)
  output.y = toMont(curve, point.y)
  output.z = ctSelect(
    default(BigUint[B]),
    curve.oneMont,
    UINT(ord(point.infinity))
  )
  output

proc toAffine[B: static int](
    curve: EcCurve[B],
    point: JacobianPoint[B]
): EcPoint[B] =
  let zNorm: BigUint[B] = fromMont(curve, point.z)
  let nonZero: UINT = ctNonZero(zNorm)
  let invZ: BigUint[B] = inversePrime(zNorm, curve.p)
  let invZM: BigUint[B] = toMont(curve, invZ)
  let invZ2M: BigUint[B] = fmul(curve, invZM, invZM)
  let invZ3M: BigUint[B] = fmul(curve, invZ2M, invZM)

  var output: EcPoint[B]
  output.x = fromMont(curve, fmul(curve, point.x, invZ2M))
  output.y = fromMont(curve, fmul(curve, point.y, invZ3M))
  output.infinity = nonZero == 0.UINT
  output

proc jDouble[B: static int](
    curve: EcCurve[B],
    pt: JacobianPoint[B]
): JacobianPoint[B] =
  let xx: BigUint[B] = fmul(curve, pt.x, pt.x)
  let yy: BigUint[B] = fmul(curve, pt.y, pt.y)
  let yyyy: BigUint[B] = fmul(curve, yy, yy)

  let xPlusYy: BigUint[B] = fadd(pt.x, yy, curve.p)
  let d0: BigUint[B] = fsub(
    fsub(fmul(curve, xPlusYy, xPlusYy), xx, curve.p),
    yyyy, curve.p
  )
  let d: BigUint[B] = fadd(d0, d0, curve.p)

  let zz: BigUint[B] = fmul(curve, pt.z, pt.z)
  let zzzz: BigUint[B] = fmul(curve, zz, zz)

  let threeXx: BigUint[B] = fadd(fadd(xx, xx, curve.p), xx, curve.p)
  let e: BigUint[B] = fadd(threeXx, fmul(curve, curve.aMont, zzzz), curve.p)
  let ff: BigUint[B] = fmul(curve, e, e)

  var output: JacobianPoint[B]
  output.x = fsub(ff, fadd(d, d, curve.p), curve.p)

  let eightYyyy: BigUint[B] = fadd(
    fadd(yyyy, yyyy, curve.p),
    fadd(yyyy, yyyy, curve.p),
    curve.p
  )

  output.y = fsub(
    fmul(curve, e, fsub(d, output.x, curve.p)),
    fadd(eightYyyy, eightYyyy, curve.p),
    curve.p
  )

  output.z = fmul(curve, fadd(pt.y, pt.y, curve.p), pt.z)
  output

proc jAdd[B: static int](
    curve: EcCurve[B],
    pntP, pntQ: JacobianPoint[B]
): JacobianPoint[B] =
  let z1z1: BigUint[B] = fmul(curve, pntP.z, pntP.z)
  let z2z2: BigUint[B] = fmul(curve, pntQ.z, pntQ.z)

  let u1: BigUint[B] = fmul(curve, pntP.x, z2z2)
  let u2: BigUint[B] = fmul(curve, pntQ.x, z1z1)

  let s1: BigUint[B] = fmul(curve, fmul(curve, pntP.y, pntQ.z), z2z2)
  let s2: BigUint[B] = fmul(curve, fmul(curve, pntQ.y, pntP.z), z1z1)

  let h: BigUint[B] = fsub(u2, u1, curve.p)
  let r0: BigUint[B] = fsub(s2, s1, curve.p)
  let r: BigUint[B] = fadd(r0, r0, curve.p)

  let twoH: BigUint[B] = fadd(h, h, curve.p)
  let ii: BigUint[B] = fmul(curve, twoH, twoH)
  let jj: BigUint[B] = fmul(curve, h, ii)
  let vv: BigUint[B] = fmul(curve, u1, ii)

  var ordinary: JacobianPoint[B]

  ordinary.x = fsub(
    fsub(fmul(curve, r, r), jj, curve.p),
    fadd(vv, vv, curve.p),
    curve.p
  )

  ordinary.y = fsub(
    fmul(curve, r, fsub(vv, ordinary.x, curve.p)),
    fmul(curve, fadd(s1, s1, curve.p), jj),
    curve.p
  )

  let zsum: BigUint[B] = fadd(pntP.z, pntQ.z, curve.p)
  ordinary.z = fmul(curve,
    fsub(
      fsub(fmul(curve, zsum, zsum), z1z1, curve.p),
      z2z2, curve.p
    ),
    h
  )

  let pInf: UINT = 1.UINT xor ctNonZero(pntP.z)
  let qInf: UINT = 1.UINT xor ctNonZero(pntQ.z)
  let sameX: UINT = 1.UINT xor ctNonZero(h)
  let sameY: UINT = 1.UINT xor ctNonZero(r0)
  let doubling: UINT = sameX and sameY
  let opposite: UINT = sameX and (sameY xor 1.UINT)

  var infinity: JacobianPoint[B]

  var output: JacobianPoint[B] = ctPointSelect(jDouble(curve, pntP), ordinary, doubling)
  output = ctPointSelect(infinity, output, opposite)
  output = ctPointSelect(pntQ, output, pInf)
  output = ctPointSelect(pntP, output, qInf)
  output

proc scalarMultJacobian[B: static int](
    curve: EcCurve[B],
    base: JacobianPoint[B],
    scalar: BigUint[B]
): EcPoint[B] =
  var r0: JacobianPoint[B] = default(JacobianPoint[B])
  var r1: JacobianPoint[B] = base

  for bit in 0 ..< (B * 8):
    let bitVal: UINT = ctBitBE(scalar, bit)
    let sum: JacobianPoint[B] = jAdd(curve, r0, r1)
    let d0: JacobianPoint[B] = jDouble(curve, r0)
    let d1: JacobianPoint[B] = jDouble(curve, r1)
    r0 = ctPointSelect(sum, d0, bitVal)
    r1 = ctPointSelect(d1, sum, bitVal)

  var output: EcPoint[B]
  output = toAffine(curve, r0)
  output

proc add*[B: static int](
    curve: EcCurve[B],
    p, q: EcPoint[B]
): EcPoint[B] {.inline.} =
  let pj: JacobianPoint[B] = toJacobian(curve, p)
  let qj: JacobianPoint[B] = toJacobian(curve, q)
  var output: EcPoint[B]
  output = toAffine(curve, jAdd(curve, pj, qj))
  output

proc scalarMult*[B: static int](
    curve: EcCurve[B],
    point: EcPoint[B],
    scalar: BigUint[B]
): EcPoint[B] {.inline.} =
  var output: EcPoint[B]
  output = scalarMultJacobian(curve, toJacobian(curve, point), scalar)
  output

proc basePoint*[B: static int](curve: EcCurve[B]): EcPoint[B] {.inline.} =
  var output: EcPoint[B]
  output = EcPoint[B](x: curve.gx, y: curve.gy, infinity: false)
  output

proc scalarBaseMult*[B: static int](
    curve: EcCurve[B],
    scalar: BigUint[B]
): EcPoint[B] {.inline.} =
  var output: EcPoint[B]
  output = scalarMultJacobian(curve, baseJacobianMont(curve), scalar)
  output

proc isOnCurve*[B: static int](
    curve: EcCurve[B],
    point: EcPoint[B]
): bool =
  if point.infinity or
     not ctLess(point.x, curve.p) or
     not ctLess(point.y, curve.p):
    return false
  let left: BigUint[B] = mulMod(point.y, point.y, curve.p)
  let x2: BigUint[B] = mulMod(point.x, point.x, curve.p)
  let x3: BigUint[B] = mulMod(x2, point.x, curve.p)
  let ax: BigUint[B] = mulMod(curve.a, point.x, curve.p)
  let right: BigUint[B] = addMod(addMod(x3, ax, curve.p), curve.b, curve.p)
  var output: bool
  output = ctEqual(left, right)
  output

proc encodeUncompressed*[B: static int](
    point: EcPoint[B]
): array[1 + 2 * B, uint8] =
  var output: array[1 + 2 * B, uint8]
  output[0] = 4
  let x: array[B, uint8] = toBytesBE(point.x)
  let y: array[B, uint8] = toBytesBE(point.y)
  for i in 0 ..< B:
    output[1 + i] = x[i]
    output[1 + B + i] = y[i]
  output

proc decodeUncompressed*[B: static int](
    encoded: openArray[uint8],
    point: var EcPoint[B]
): bool =
  if encoded.len != 1 + 2 * B or encoded[0] != 4:
    return false
  point.x = fromBytesBE[B](encoded.toOpenArray(1, B))
  point.y = fromBytesBE[B](encoded.toOpenArray(1 + B, 2 * B))
  point.infinity = false
  var output: bool
  output = true
  output

const
  P256_P*  = [0xFF'u8, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
  P256_A*  = [0xFF'u8, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC]
  P256_B*  = [0x5A'u8, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
              0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
              0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
              0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B]
  P256_N*  = [0xFF'u8, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
              0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51]
  P256_GX* = [0x6B'u8, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
              0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
              0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
              0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96]
  P256_GY* = [0x4F'u8, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
              0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
              0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
              0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5]

  SM2_P*  = [0xFF'u8, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
  SM2_A*  = [0xFF'u8, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC]
  SM2_B*  = [0x28'u8, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
             0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
             0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
             0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93]
  SM2_N*  = [0xFF'u8, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
             0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
             0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B,
             0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23]
  SM2_GX* = [0x32'u8, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
             0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
             0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
             0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7]
  SM2_GY* = [0xBC'u8, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
             0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
             0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
             0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0]


proc p256*(): EcCurve[32] =
  var output: EcCurve[32]
  output = makeCurve[32](P256_P, P256_A, P256_B, P256_N, P256_GX, P256_GY)
  output

proc sm2Curve*(): EcCurve[32] =
  var output: EcCurve[32]
  output = makeCurve[32](SM2_P, SM2_A, SM2_B, SM2_N, SM2_GX, SM2_GY)
  output
