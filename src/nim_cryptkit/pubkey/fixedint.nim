import ../utils/envconst
import montgomery as mont
const
  FIWordBytes* = sizeof(UINT)
  FIWordBits* = sizeof(UINT) * 8

type
  BigUint*[B: static int] = array[B div FIWordBytes, UINT]

template bigUintToNat*[W, B: static int](input: BigUint[B]): mont.Nat[W] =
  const W_UINT = B div sizeof(UINT)
  const W32    = B div 4
  var output: mont.Nat[W32]

  when CPUBytes == 8:
    for i in static(0 ..< W_UINT):
      when LE:
        output[i * 2] = uint32(input[i])
        output[i * 2 + 1] = uint32(input[i] shr 32)
      else: # Big Endian
        output[i * 2] = uint32(input[i] shr 32)
        output[i * 2 + 1] = uint32(input[i])
  elif CPUBytes == 4:
    for i in static(0 ..< W_UINT):
      output[i] = uint32(input[i])
  elif CPUBytes == 2: # uint16
    for i in static(0 ..< W32):
      when LE:
        output[i] = uint32(input[i * 2]) or (uint32(input[i * 2 + 1]) shl 16)
      else:
        output[i] = (uint32(input[i * 2]) shl 16) or uint32(input[i * 2 + 1])
  elif CPUBytes == 1:
    for i in static(0 ..< W32):
      when LE:
        output[i] = (uint32(input[i * 4 + 0]) shl  0) or
                    (uint32(input[i * 4 + 1]) shl  8) or
                    (uint32(input[i * 4 + 2]) shl 16) or
                    (uint32(input[i * 4 + 3]) shl 24)
      else:
        output[i] = (uint32(input[i * 4 + 0]) shl 24) or
                    (uint32(input[i * 4 + 1]) shl 16) or
                    (uint32(input[i * 4 + 2]) shl  8) or
                    (uint32(input[i * 4 + 3]) shl  0)
  else:
    {.error: "Unsupported UINT size for bigUintToNat".}

  output

template nat32ToBigUint*[W, B: static int](input: mont.Nat[W]): BigUint[B] =
  const W_UINT = B div CPUBytes
  const W32    = B div 4
  var output: BigUint[B]

  when CPUBytes == 8:
    for i in static(0 ..< W_UINT):
      when LE:
        output[i] = (uint64(input[i * 2 + 1]) shl 32) or uint64(input[i * 2])
      else:
        output[i] = (uint64(input[i * 2]) shl 32) or uint64(input[i * 2 + 1])
  elif CPUBytes == 4:
    for i in 0 ..< W_UINT:
      output[i] = UINT(src[i])

  elif CPUBytes == 2:
    for i in static(0 ..< W32):
      when LE:
        output[i * 2 + 0] = UINT(input[i] and 0xFFFF)
        output[i * 2 + 1] = UINT((input[i] shr 16) and 0xFFFF)
      else:
        output[i * 2 + 1] = UINT(input[i] and 0xFFFF)
        output[i * 2 + 0] = UINT((input[i] shr 16) and 0xFFFF)

  elif CPUBytes == 1:
    for i in static(0 ..< W32):
      for j in static(0 ..< 4):
        when LE:
          output[i * 4 + j] = UINT((input[i] shr (j * 8)) and 0xFF)
        else:
          output[i * 4 + j] = UINT((input[i] shr ((3 - j) * 8)) and 0xFF)
  else:
    {.error: "Unsupported UINT size for nat32ToBigUint".}

  output

# ---------------------------------------------------
# Construction / Constants
# ---------------------------------------------------

template one*[B: static int](): BigUint[B] =
  var output: BigUint[B]
  output[0] = 1.UINT
  output

template zero*[B: static int](): BigUint[B] =
  default(BigUint[B])

template `xor`*[B: static int](a, b: BigUint[B]): BigUint[B] =
  var output: BigUint[B]
  for i in 0 ..< output.len:
    output[i] = a[i] xor b[i]
  output

template `and`*[B: static int](a, b: BigUint[B]): BigUint[B] =
  var output: BigUint[B]
  for i in 0 ..< output.len:
    output[i] = a[i] and b[i]
  output

template `or`*[B: static int](a, b: BigUint[B]): BigUint[B] =
  var output: BigUint[B]
  for i in 0 ..< output.len:
    output[i] = a[i] or b[i]
  output

template `not`*[B: static int](a: BigUint[B]): BigUint[B] =
  var output: BigUint[B]
  for i in 0 ..< output.len:
    output[i] = not a[i]
  output

# ---------------------------------------------------
# Serialization (BE byte boundary ONLY)
# ---------------------------------------------------

proc fromBytesBE*[B: static int](input: openArray[uint8]): BigUint[B] =
  var output: BigUint[B]
  const wordCount: int = B div FIWordBytes
  let padLen: int = B - min(input.len, B)

  for w in 0 ..< wordCount:
    var word: UINT = 0.UINT
    for j in 0 ..< FIWordBytes:
      let fullPos: int = B - 1 - w * FIWordBytes - j
      let inputPos: int = fullPos - padLen
      if inputPos >= 0 and inputPos < input.len:
        word = word or (UINT(input[inputPos]) shl (j * 8))
    output[w] = word

  output

proc toBytesBE*[B: static int](value: BigUint[B]): array[B, uint8] =
  var output: array[B, uint8]
  const wordCount: int = B div FIWordBytes

  for w in 0 ..< wordCount:
    for j in 0 ..< FIWordBytes:
      let fullPos: int = B - 1 - w * FIWordBytes - j
      output[fullPos] = uint8(value[w] shr (j * 8))

  output

# ---------------------------------------------------
# Bitwise operators
# ---------------------------------------------------

proc bigXor*[B: static int](a, b: BigUint[B]): BigUint[B] {.inline.} =
  var output: BigUint[B]
  for i in 0 ..< output.len:
    output[i] = a[i] xor b[i]
  output

proc bigAnd*[B: static int](a, b: BigUint[B]): BigUint[B] {.inline.} =
  var output: BigUint[B]
  for i in 0 ..< output.len:
    output[i] = a[i] and b[i]
  output

proc bigOr*[B: static int](a, b: BigUint[B]): BigUint[B] {.inline.} =
  var output: BigUint[B]
  for i in 0 ..< output.len:
    output[i] = a[i] or b[i]
  output

proc bigNot*[B: static int](a: BigUint[B]): BigUint[B] {.inline.} =
  var output: BigUint[B]
  for i in 0 ..< output.len:
    output[i] = not a[i]
  output

proc ctNonZero*[B: static int](value: BigUint[B]): UINT {.inline.} =
  var folded: UINT = 0.UINT
  for i in 0 ..< value.len:
    folded = folded or value[i]
  var output: UINT
  output = (folded or (0.UINT - folded)) shr (FIWordBits - 1)
  output

proc ctEqual*[B: static int](a, b: BigUint[B]): bool {.inline.} =
  var difference: UINT = 0.UINT
  for i in 0 ..< a.len:
    difference = difference or (a[i] xor b[i])
  var output: bool
  output = difference == 0.UINT
  output

proc ctLess*[B: static int](a, b: BigUint[B]): bool {.inline.} =
  var less: UINT = 0.UINT
  var undecided: UINT = 1.UINT
  for i in countdown(a.high, 0):
    let x: UINT = a[i]
    let y: UINT = b[i]
    let difference: UINT = x xor y
    let different: UINT = (difference or (0.UINT - difference)) shr (FIWordBits - 1)
    let wordLess: UINT = (x xor ((x xor y) or ((x - y) xor y))) shr (FIWordBits - 1)
    less = less or (wordLess and different and undecided)
    undecided = undecided and (different xor 1.UINT)
  var output: bool
  output = less != 0.UINT
  output

proc ctSelect*[B: static int](whenOne, whenZero: BigUint[B],
                              choice: UINT): BigUint[B] {.inline.} =
  var output: BigUint[B]
  let mask: UINT = 0.UINT - (choice and 1.UINT)
  for i in 0 ..< output.len:
    output[i] = (whenOne[i] and mask) or (whenZero[i] and not mask)
  output

proc ctBitBE*[B: static int](value: BigUint[B], bitFromMsb: int): UINT {.inline.} =
  const wordCount: int = B div FIWordBytes
  let wordFromMsb: int = bitFromMsb div FIWordBits
  let arrayIdx: int = wordCount - 1 - wordFromMsb
  let bitOffset: int = FIWordBits - 1 - (bitFromMsb mod FIWordBits)
  var output: UINT
  output = (value[arrayIdx] shr bitOffset) and 1.UINT
  output

# ---------------------------------------------------
# Shift operations
# ---------------------------------------------------

proc shiftRightOne*[B: static int](a: BigUint[B]): BigUint[B] {.inline.} =
  var output: BigUint[B]
  var carry: UINT = 0.UINT
  for i in countdown(a.high, 0):
    let nextCarry: UINT = a[i] and 1.UINT
    output[i] = (a[i] shr 1) or (carry shl (FIWordBits - 1))
    carry = nextCarry
  output

proc shiftLeftOne*[B: static int](a: BigUint[B]): tuple[value: BigUint[B], carry: UINT] {.inline.} =
  var output: tuple[value: BigUint[B], carry: UINT]
  var carry: UINT = 0.UINT
  for i in 0 .. a.high:
    let nextCarry: UINT = a[i] shr (FIWordBits - 1)
    output.value[i] = (a[i] shl 1) or carry
    carry = nextCarry
  output.carry = carry
  output

# ---------------------------------------------------
# Add / Sub with carry / borrow
# ---------------------------------------------------

proc addWithCarry*[B: static int](a, b: BigUint[B]): tuple[value: BigUint[B], carry: UINT] {.inline.} =
  var output: tuple[value: BigUint[B], carry: UINT]
  var carry: UINT = 0.UINT
  for i in 0 .. a.high:
    let sum1: UINT = a[i] + b[i]
    let carry1: UINT = UINT(sum1 < a[i])
    let sum2: UINT = sum1 + carry
    let carry2: UINT = UINT(sum2 < sum1)
    output.value[i] = sum2
    carry = carry1 or carry2
  output.carry = carry
  output

proc subWithBorrow*[B: static int](a, b: BigUint[B]): tuple[value: BigUint[B], borrow: UINT] {.inline.} =
  var output: tuple[value: BigUint[B], borrow: UINT]
  var borrow: UINT = 0.UINT
  for i in 0 .. a.high:
    let subtrahend: UINT = b[i] + borrow
    let overflow: UINT = UINT(subtrahend < b[i])
    let diff: UINT = a[i] - subtrahend
    let nextBorrow: UINT = UINT(a[i] < subtrahend)
    output.value[i] = diff
    borrow = overflow or nextBorrow
  output.borrow = borrow
  output

# ---------------------------------------------------
# Modular arithmetic
# ---------------------------------------------------

proc reduce*[B: static int](a, modulus: BigUint[B]): BigUint[B] =
  var remainder: BigUint[B]
  for bit in 0 ..< (B * 8):
    let shifted: tuple[value: BigUint[B], carry: UINT] = shiftLeftOne(remainder)
    var low: BigUint[B] = shifted.value
    low[0] = low[0] or ctBitBE(a, bit)
    let difference: tuple[value: BigUint[B], borrow: UINT] = subWithBorrow(low, modulus)
    let choice: UINT = shifted.carry or (difference.borrow xor 1.UINT)
    remainder = ctSelect(difference.value, low, choice)
  var output: BigUint[B]
  output = remainder
  output

proc addMod*[B: static int](a, b, modulus: BigUint[B]): BigUint[B] {.inline.} =
  let sum: tuple[value: BigUint[B], carry: UINT] = addWithCarry(a, b)
  let difference: tuple[value: BigUint[B], borrow: UINT] = subWithBorrow(sum.value, modulus)
  let choice: UINT = sum.carry or (difference.borrow xor 1.UINT)
  var output: BigUint[B]
  output = ctSelect(difference.value, sum.value, choice)
  output

proc subMod*[B: static int](a, b, modulus: BigUint[B]): BigUint[B] {.inline.} =
  let difference: tuple[value: BigUint[B], borrow: UINT] = subWithBorrow(a, b)
  let repaired: BigUint[B] = addWithCarry(difference.value, modulus).value
  var output: BigUint[B]
  output = ctSelect(repaired, difference.value, difference.borrow)
  output

proc mulMod*[B: static int](a, b, modulus: BigUint[B]): BigUint[B] =
  var accumulator: BigUint[B]
  let addend: BigUint[B] = reduce(a, modulus)
  for bit in 0 ..< (B * 8):
    accumulator = addMod(accumulator, accumulator, modulus)
    let candidate: BigUint[B] = addMod(accumulator, addend, modulus)
    accumulator = ctSelect(candidate, accumulator, ctBitBE(b, bit))
  var output: BigUint[B]
  output = accumulator
  output

proc powMod*[B: static int](base, exponent, modulus: BigUint[B]): BigUint[B] =
  let valid: UINT = ctNonZero(modulus)
  let safeModulus: BigUint[B] = ctSelect(modulus, one[B](), valid)
  var accumulator: BigUint[B] = one[B]()
  let reducedBase: BigUint[B] = reduce(base, safeModulus)
  for bit in 0 ..< (B * 8):
    accumulator = mulMod(accumulator, accumulator, safeModulus)
    let candidate: BigUint[B] = mulMod(accumulator, reducedBase, safeModulus)
    accumulator = ctSelect(candidate, accumulator, ctBitBE(exponent, bit))
  var output: BigUint[B]
  output = ctSelect(accumulator, default(BigUint[B]), valid)
  output

proc inversePrime*[B: static int](value, prime: BigUint[B]): BigUint[B] {.inline.} =
  let two: BigUint[B] = addMod(one[B](), one[B](), prime)
  var output: BigUint[B]
  output = powMod(value, subMod(prime, two, prime), prime)
  output

# ---------------------------------------------------
# Montgomery Nat helpers
# ---------------------------------------------------

template natToBytesBE*[W: static int](a: mont.Nat[W]): array[W * 4, uint8] =
  var output: array[W * 4, uint8]
  for i in static(0 ..< W):
    let offset: int = (W - 1 - i) * 4
    let w: uint32 = a[i]
    output[offset]     = uint8(w shr 24)
    output[offset + 1] = uint8(w shr 16)
    output[offset + 2] = uint8(w shr 8)
    output[offset + 3] = uint8(w)
  output

func fromBytesBENat*[W: static int](input: openArray[uint8]): mont.Nat[W] =
  var output: mont.Nat[W]
  doAssert input.len <= W * 4
  for i in 0 ..< input.len:
    let byteIdx: int = input.len - 1 - i
    let wordIdx: int = i div 4
    let shift: int = (i mod 4) * 8
    output[wordIdx] = output[wordIdx] or (uint32(input[byteIdx]) shl shift)
  output

func reduceMixed*[LW, NW: static int](
    a: mont.Nat[LW], modulus: mont.Nat[NW]): mont.Nat[NW] =
  var output: mont.Nat[NW]
  for bit in countdown(LW * 32 - 1, 0):
    var carry: uint32 = 0'u32
    for i in 0 ..< NW:
      let next: uint32 = output[i] shr 31
      output[i] = (output[i] shl 1) or carry
      carry = next
    output[0] = output[0] or ((a[bit div 32] shr (bit mod 32)) and 1)
    let difference: tuple[value: mont.Nat[NW], borrow: uint32] = mont.subNat(output, modulus)
    output = mont.select(difference.value, output,
                         carry or (difference.borrow xor 1))
  output

func bits2int*[NW: static int](
    bits: openArray[uint8], q: mont.Nat[NW]): mont.Nat[NW] =
  var output: mont.Nat[NW] = fromBytesBENat[NW](bits)
  let bitLen: int = bits.len * 8
  let qlen: int = NW * 32
  if bitLen > qlen:
    output = mont.shiftRight(output, bitLen - qlen)
  if not mont.less(output, q):
    let diff: tuple[value: mont.Nat[NW], borrow: uint32] = mont.subNat(output, q)
    output = diff.value
  output

template ctIsZero*(data: openArray[uint8]): bool =
  var value = 0'u8
  for item in data:
    value = value or item
  (value == 0)

template ctEqual*(a, b: openArray[uint8]): bool =
  var output: bool
  if a.len != b.len:
    output = false
  var value = 0'u8
  for i in 0 ..< a.len:
    value = value or (a[i] xor b[i])
  output = (value == 0)
  output
