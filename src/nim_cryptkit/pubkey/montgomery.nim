import std/bitops

type
  Nat*[W: static int] = array[W, uint32]

  MontgomeryCtx*[W: static int] = object
    modulus*: Nat[W]
    n0: uint32
    r2: Nat[W]

template low32(x: uint64): uint32 =
  uint32(x and 0xFFFFFFFF'u64)

proc ctMask(choice: uint32): uint32 =
  var output: uint32
  let bit = uint64(choice and 1'u32)
  output = low32(0x100000000'u64 - bit)
  return output

proc ctNonZero32(x: uint32): uint32 =
  var output: uint32
  let y = uint64(x)
  let neg = low32(0x100000000'u64 - y)
  output = uint32((uint64(x or neg) shr 31) and 1'u64)
  return output

proc nonZero*[W: static int](a: Nat[W]): uint32 =
  var output: uint32
  var x: uint32 = 0

  for v in a:
    x = x or v

  output = ctNonZero32(x)
  return output

proc equal*[W: static int](a, b: Nat[W]): bool =
  var output: bool
  var x: uint32 = 0

  for i in 0 ..< W:
    x = x or (a[i] xor b[i])

  output = (x == 0)
  return output

proc less*[W: static int](a, b: Nat[W]): bool =
  var output: bool
  var borrow: uint64 = 0

  for i in 0 ..< W:
    let sub = uint64(b[i]) + borrow
    borrow = uint64(uint64(a[i]) < sub)

  output = (borrow != 0)
  return output

proc subNat*[W: static int](a, b: Nat[W]): tuple[value: Nat[W], borrow: uint32] =
  var output: tuple[value: Nat[W], borrow: uint32]
  var borrow: uint64 = 0

  for i in 0 ..< W:
    let ai = uint64(a[i])
    let bi = uint64(b[i]) + borrow

    if ai < bi:
      output.value[i] = low32(ai + 0x100000000'u64 - bi)
      borrow = 1
    else:
      output.value[i] = low32(ai - bi)
      borrow = 0

  output.borrow = uint32(borrow)
  return output

proc select*[W: static int](a, b: Nat[W], choice: uint32): Nat[W] =
  var output: Nat[W]
  let mask = ctMask(choice)
  let nmask = not mask

  for i in 0 ..< W:
    output[i] = (a[i] and mask) or (b[i] and nmask)

  return output

proc addMod*[W: static int](a, b, modulus: Nat[W]): Nat[W] =
  var output: Nat[W]
  var sum: Nat[W]
  var carry: uint64 = 0

  for i in 0 ..< W:
    let z = uint64(a[i]) + uint64(b[i]) + carry
    sum[i] = low32(z)
    carry = z shr 32

  let diff = subNat[W](sum, modulus)
  let choice = low32(carry) or (diff.borrow xor 1'u32)

  output = select[W](diff.value, sum, choice)
  return output

proc subMod*[W: static int](a, b, modulus: Nat[W]): Nat[W] =
  var output: Nat[W]
  let diff = subNat[W](a, b)

  var repaired: Nat[W]
  var carry: uint64 = 0

  for i in 0 ..< W:
    let z = uint64(diff.value[i]) + uint64(modulus[i]) + carry
    repaired[i] = low32(z)
    carry = z shr 32

  output = select[W](repaired, diff.value, diff.borrow)
  return output

proc remainder*[W, V: static int](a: Nat[W], modulus: Nat[V]): Nat[V] =
  var output: Nat[V]

  var temp: Nat[W]
  var modExt: Nat[W]

  for i in 0 ..< V:
    modExt[i] = modulus[i]

  for bit in countdown(W * 32 - 1, 0):
    var carry: uint32 = 0

    for i in 0 ..< W:
      let nextCarry = temp[i] shr 31
      temp[i] = low32((uint64(temp[i]) shl 1) or uint64(carry))
      carry = nextCarry

    temp[0] = temp[0] or ((a[bit div 32] shr (bit mod 32)) and 1'u32)

    let diff = subNat[W](temp, modExt)
    let choice = carry or (diff.borrow xor 1'u32)
    temp = select[W](diff.value, temp, choice)

  for i in 0 ..< V:
    output[i] = temp[i]

  return output

proc oneNat*[W: static int](): Nat[W] =
  var output: Nat[W]
  output[0] = 1
  return output

proc fromBytesBE*[W: static int](input: openArray[uint8]): Nat[W] =
  var output: Nat[W]

  if input.len > W * 4:
    raise newException(ValueError, "integer too large")

  for i in 0 ..< input.len:
    let reverse = input.len - 1 - i
    output[i div 4] =
      output[i div 4] or low32(uint64(input[reverse]) shl ((i mod 4) * 8))

  return output

proc toBytesBE*[W: static int](a: Nat[W]): array[W * 4, uint8] =
  var output: array[W * 4, uint8]

  for i in 0 ..< output.len:
    output[output.high - i] = uint8(a[i div 4] shr ((i mod 4) * 8))

  return output

proc inverseWord(a: uint32): uint32 =
  var output: uint32

  let a64 = uint64(a)
  var x = a64 and 0xFFFFFFFF'u64

  for _ in 0 ..< 5:
    let ax = (a64 * x) and 0xFFFFFFFF'u64
    let term = ((2'u64 + 0x100000000'u64 - ax) and 0xFFFFFFFF'u64)
    x = (x * term) and 0xFFFFFFFF'u64

  output = uint32((0x100000000'u64 - x) and 0xFFFFFFFF'u64)
  return output

proc montMul*[W: static int](ctx: MontgomeryCtx[W], a, b: Nat[W]): Nat[W] =
  var output: Nat[W]

  var t: array[W + 2, uint32]
  for i in 0 ..< (W + 2):
    t[i] = 0

  for i in 0 ..< W:
    var carry: uint64 = 0

    for j in 0 ..< W:
      let z = uint64(t[j]) + uint64(a[j]) * uint64(b[i]) + carry
      t[j] = low32(z)
      carry = z shr 32

    var z = uint64(t[W]) + carry
    t[W] = low32(z)
    t[W + 1] = low32(uint64(t[W + 1]) + (z shr 32))

    let m = low32(uint64(t[0]) * uint64(ctx.n0))
    carry = 0

    for j in 0 ..< W:
      z = uint64(t[j]) + uint64(m) * uint64(ctx.modulus[j]) + carry
      t[j] = low32(z)
      carry = z shr 32

    z = uint64(t[W]) + carry
    t[W] = low32(z)
    t[W + 1] = low32(uint64(t[W + 1]) + (z shr 32))

    for j in 0 .. W:
      t[j] = t[j + 1]
    t[W + 1] = 0

  var low: Nat[W]
  for i in 0 ..< W:
    low[i] = t[i]

  let diff = subNat[W](low, ctx.modulus)
  let top = ctNonZero32(t[W])

  output = select[W](diff.value, low, top or (diff.borrow xor 1'u32))
  return output

proc initMontgomery*[W: static int](modulus: Nat[W]): MontgomeryCtx[W] =
  if nonZero(modulus) == 0 or (modulus[0] and 1'u32) == 0:
    raise newException(ValueError, "Montgomery modulus must be positive and odd")

  if modulus.equal(oneNat[W]()):
    raise newException(ValueError, "Montgomery modulus must be greater than 1")

  var output: MontgomeryCtx[W]

  output.modulus = modulus
  output.n0 = inverseWord(modulus[0])

  var r2 = oneNat[W]()
  for _ in 0 ..< (64 * W):
    r2 = addMod[W](r2, r2, modulus)

  output.r2 = r2
  return output

proc reduceMod*[W: static int](a, modulus: Nat[W]): Nat[W] =
  var output: Nat[W]

  if less(a, modulus):
    output = a
  else:
    output = remainder[W, W](a, modulus)

  return output

proc toMontgomery*[W: static int](ctx: MontgomeryCtx[W], a: Nat[W]): Nat[W] =
  var output: Nat[W]
  let reduced = reduceMod[W](a, ctx.modulus)
  output = ctx.montMul(reduced, ctx.r2)
  return output

proc fromMontgomery*[W: static int](ctx: MontgomeryCtx[W], a: Nat[W]): Nat[W] =
  var output: Nat[W]
  let reduced = reduceMod[W](a, ctx.modulus)
  output = ctx.montMul(reduced, oneNat[W]())
  return output

proc powMod*[W: static int](ctx: MontgomeryCtx[W], base: Nat[W], exponent: openArray[uint8]): Nat[W] =
  var output: Nat[W]

  var accumulator = ctx.toMontgomery(oneNat[W]())
  let encodedBase = ctx.toMontgomery(base)

  for octet in exponent:
    for bit in countdown(7, 0):
      accumulator = ctx.montMul(accumulator, accumulator)
      let product = ctx.montMul(accumulator, encodedBase)
      accumulator = select[W](product, accumulator, uint32((octet shr bit) and 1'u8))

  output = ctx.fromMontgomery(accumulator)
  return output

proc mulMod*[W: static int](ctx: MontgomeryCtx[W], a, b: Nat[W]): Nat[W] =
  var output: Nat[W]

  let ar = reduceMod[W](a, ctx.modulus)
  let br = reduceMod[W](b, ctx.modulus)

  let am = ctx.montMul(ar, ctx.r2)
  output = ctx.montMul(am, br)

  return output

proc decrement*[W: static int](a: Nat[W]): Nat[W] =
  var output: Nat[W] = a
  var borrow: uint64 = 1

  for i in 0 ..< W:
    let old = uint64(output[i])

    if old < borrow:
      output[i] = low32(old + 0x100000000'u64 - borrow)
      borrow = 1
    else:
      output[i] = low32(old - borrow)
      borrow = 0

  return output

proc subtractSmall*[W: static int](a: Nat[W], amount: uint32): Nat[W] =
  var output: Nat[W] = a
  var borrow: uint64 = uint64(amount)

  for i in 0 ..< W:
    let old = uint64(output[i])

    if old < borrow:
      output[i] = low32(old + 0x100000000'u64 - borrow)
      borrow = 1
    else:
      output[i] = low32(old - borrow)
      borrow = 0

  return output

proc trailingZeros*[W: static int](a: Nat[W]): int =
  var output: int = W * 32

  block search:
    for i in 0 ..< W:
      if a[i] != 0:
        output = i * 32 + countTrailingZeroBits(a[i])
        break search

  return output

proc shiftRight*[W: static int](a: Nat[W], bits: int): Nat[W] =
  var output: Nat[W]

  if bits <= 0:
    output = a
    return output

  if bits >= W * 32:
    return output

  let words = bits div 32
  let shift = bits mod 32

  for i in 0 ..< (W - words):
    let source = i + words
    var v = uint64(a[source]) shr shift

    if shift != 0 and source + 1 < W:
      v = v or (uint64(a[source + 1]) shl (32 - shift))

    output[i] = low32(v)

  return output

proc modSmall*[W: static int](a: Nat[W], divisor: uint32): uint32 =
  var output: uint32

  if divisor == 0:
    raise newException(ValueError, "division by zero")

  var rem: uint64 = 0
  let d = uint64(divisor)

  for i in countdown(W - 1, 0):
    rem = ((rem shl 32) or uint64(a[i])) mod d

  output = uint32(rem)
  return output

proc multiply*[W: static int](a, b: Nat[W]): Nat[W * 2] =
  var output: Nat[W * 2]

  for i in 0 ..< W:
    var carry: uint64 = 0

    for j in 0 ..< W:
      let k = i + j
      let z = uint64(output[k]) + uint64(a[i]) * uint64(b[j]) + carry
      output[k] = low32(z)
      carry = z shr 32

    var k = i + W
    while carry != 0 and k < W * 2:
      let z = uint64(output[k]) + carry
      output[k] = low32(z)
      carry = z shr 32
      inc k

  return output

proc mulSmallAdd*[W: static int](a: Nat[W], multiplier, addend: uint32): Nat[W] =
  var output: Nat[W]
  var carry: uint64 = uint64(addend)

  for i in 0 ..< W:
    let z = uint64(a[i]) * uint64(multiplier) + carry
    output[i] = low32(z)
    carry = z shr 32

  return output

proc divSmall*[W: static int](a: Nat[W], divisor: uint32): Nat[W] =
  var output: Nat[W]

  if divisor == 0:
    raise newException(ValueError, "division by zero")

  var rem: uint64 = 0
  let d = uint64(divisor)

  for i in countdown(W - 1, 0):
    let z = (rem shl 32) or uint64(a[i])
    output[i] = low32(z div d)
    rem = z mod d

  return output

const SmallPrimes = [
  3'u32, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41,
  43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
  101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
  151, 157, 163, 167, 173, 179, 181, 191, 193, 197,
  199, 211, 223, 227, 229, 233, 239, 241, 251
]

proc probablePrime*[W: static int](candidate: Nat[W]): bool =
  const bases = [
    2'u32, 3'u32, 5'u32, 7'u32, 11'u32, 13'u32, 17'u32, 19'u32,
    23'u32, 29'u32, 31'u32, 37'u32, 41'u32, 43'u32, 47'u32, 53'u32
  ]

  var output: bool = false

  block main:
    if nonZero(candidate) == 0:
      break main

    if candidate.equal(oneNat[W]()):
      break main

    var two: Nat[W]
    two[0] = 2
    if candidate.equal(two):
      output = true
      break main

    if (candidate[0] and 1'u32) == 0:
      break main

    for p in SmallPrimes:
      var pn: Nat[W]
      pn[0] = p

      if candidate.equal(pn):
        output = true
        break main

      if candidate.modSmall(p) == 0:
        break main

    let minusOne = candidate.decrement()
    let s = minusOne.trailingZeros()
    let d = minusOne.shiftRight(s)
    let exponent = d.toBytesBE()

    let mont = initMontgomery(candidate)

    for baseValue in bases:
      var base: Nat[W]
      base[0] = baseValue

      var x = mont.powMod(base, exponent)

      if x.equal(oneNat[W]()) or x.equal(minusOne):
        continue

      var passed = false

      for _ in 1 ..< s:
        x = mont.mulMod(x, x)

        if x.equal(minusOne):
          passed = true
          break

        if x.equal(oneNat[W]()):
          break

      if not passed:
        break main

    output = true

  return output
