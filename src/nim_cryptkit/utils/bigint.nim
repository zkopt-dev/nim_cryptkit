import optmacro
import std/strutils
import envconst

when Native and Unix and defined(antiForensic):
  import ../codeutils/securetype


type
  BigInt* = object
    value*: seq[uint32]
    sign*: bool

  IntegerType* = concept x
    x is (int8 or int16 or int32 or int64 or uint8 or uint16 or uint32 or uint64)

  SmallInt* = int8 | int16 | int32
  SmallUInt* = uint8 | uint16 | uint32

# --- Destruction and Normalization ---

proc normalize*(a: var BigInt) {.inline.} =
  while a.value.len > 1 and a.value[^1] == 0'u32:
    a.value.setLen(a.value.len - 1)
  if a.value.len == 0:
    a.value = @[0'u32]
    a.sign = false
  elif a.value.len == 1 and a.value[0] == 0'u32:
    a.sign = false

proc `=destroy`*(s: var BigInt): void {.inline.} =
  when defined(antiForensic):
    if s.value.len > 0:
      zerofill(addr s.value[0], 1, s.value.len * sizeof(uint32))
  # The default destructor will handle seq deallocation

# --- Initializers ---

func initBigInt*[T: IntegerType](input: T): BigInt =
  when T is SmallInt:
    if input < 0:
      result.value = @[uint32(-input)]
      result.sign = true
    else:
      result.value = @[uint32(input)]
      result.sign = false
  elif T is SmallUInt:
    result.value = @[uint32(input)]
    result.sign = false
  elif T is int64:
    let absInput = if input < 0: uint64(-(input + 1)) + 1 else: uint64(input)
    if absInput > uint32.high.uint64:
      result.value = @[(absInput and 0xFFFFFFFF'u64).uint32, (absInput shr 32).uint32]
    else:
      result.value = @[absInput.uint32]
    result.sign = (input < 0)
  elif T is uint64:
    if input > uint32.high.uint64:
      result.value = @[(input and 0xFFFFFFFF'u64).uint32, (input shr 32).uint32]
    else:
      result.value = @[input.uint32]
    result.sign = false
  result.normalize()

func isZero*(b: BigInt): bool {.inline.} =
  b.value.len == 0 or (b.value.len == 1 and b.value[0] == 0'u32)

# --- Comparisons ---

func cmpAbs*(a, b: BigInt): int =
  if a.value.len > b.value.len: return 1
  if a.value.len < b.value.len: return -1
  for i in countdown(a.value.high, 0):
    if a.value[i] > b.value[i]: return 1
    if a.value[i] < b.value[i]: return -1
  return 0

func `==`*(a, b: BigInt): bool =
  if a.sign != b.sign:
    if a.isZero and b.isZero: return true
    return false
  return cmpAbs(a, b) == 0

func `<`*(a, b: BigInt): bool =
  if a.isZero and b.isZero: return false
  if a.sign != b.sign:
    return a.sign # If a is negative and b is positive, a < b
  let cmp = cmpAbs(a, b)
  if a.sign:
    return cmp > 0
  else:
    return cmp < 0

func `<=`*(a, b: BigInt): bool = (a < b) or (a == b)
func `>`*(a, b: BigInt): bool = not (a <= b)
func `>=`*(a, b: BigInt): bool = not (a < b)
func `!=`*(a, b: BigInt): bool = not (a == b)

# --- Arithmetic Abs ---

func addAbs*(a, b: BigInt): BigInt =
  let maxLen = max(a.value.len, b.value.len)
  result.value = newSeq[uint32](maxLen)
  var carry: uint64 = 0
  for i in 0 ..< maxLen:
    let ai = if i < a.value.len: uint64(a.value[i]) else: 0'u64
    let bi = if i < b.value.len: uint64(b.value[i]) else: 0'u64
    let sum = ai + bi + carry
    result.value[i] = uint32(sum and 0xFFFFFFFF'u64)
    carry = sum shr 32
  if carry > 0:
    result.value.add(uint32(carry))

func subAbs*(a, b: BigInt): BigInt =
  # Assumes |a| >= |b|
  result.value = newSeq[uint32](a.value.len)
  var borrow: uint64 = 0
  for i in 0 ..< a.value.len:
    let ai = uint64(a.value[i])
    let bi = if i < b.value.len: uint64(b.value[i]) else: 0'u64
    if ai < bi + borrow:
      result.value[i] = uint32(ai + 0x100000000'u64 - bi - borrow)
      borrow = 1
    else:
      result.value[i] = uint32(ai - bi - borrow)
      borrow = 0
  result.normalize()

func mulAbs*(a, b: BigInt): BigInt =
  if a.isZero or b.isZero: return initBigInt(0)
  result.value = newSeq[uint32](a.value.len + b.value.len)
  for i in 0 ..< a.value.len:
    var carry: uint64 = 0
    let ai = uint64(a.value[i])
    for j in 0 ..< b.value.len:
      let prod = ai * uint64(b.value[j]) + uint64(result.value[i + j]) + carry
      result.value[i + j] = uint32(prod and 0xFFFFFFFF'u64)
      carry = prod shr 32
    result.value[i + b.value.len] = uint32(carry)
  result.normalize()

# --- Public Arithmetic ---

func `+`*(a, b: BigInt): BigInt =
  if a.sign == b.sign:
    result = addAbs(a, b)
    result.sign = a.sign
  else:
    let cmp = cmpAbs(a, b)
    if cmp >= 0:
      result = subAbs(a, b)
      result.sign = a.sign
    else:
      result = subAbs(b, a)
      result.sign = b.sign
  result.normalize()

func `-`*(a, b: BigInt): BigInt =
  if a.sign != b.sign:
    result = addAbs(a, b)
    result.sign = a.sign
  else:
    let cmp = cmpAbs(a, b)
    if cmp >= 0:
      result = subAbs(a, b)
      result.sign = a.sign
    else:
      result = subAbs(b, a)
      result.sign = not a.sign
  result.normalize()

func `*`*(a, b: BigInt): BigInt =
  result = mulAbs(a, b)
  result.sign = a.sign xor b.sign
  result.normalize()

func `+=`*(a: var BigInt, b: BigInt) {.inline.} = a = a + b
func `-=`*(a: var BigInt, b: BigInt) {.inline.} = a = a - b
func `*=`*(a: var BigInt, b: BigInt) {.inline.} = a = a * b

# --- Bitwise Operations ---

func `shl`*(a: BigInt, shift: Natural): BigInt =
  if shift == 0 or a.isZero: return a
  let limbShift = shift div 32
  let bitShift = shift mod 32
  result.value = newSeq[uint32](a.value.len + limbShift + 1)
  var carry: uint64 = 0
  for i in 0 ..< a.value.len:
    let val = (uint64(a.value[i]) shl bitShift) or carry
    result.value[i + limbShift] = uint32(val and 0xFFFFFFFF'u64)
    carry = val shr 32
  result.value[^1] = uint32(carry)
  result.sign = a.sign
  result.normalize()

func `shr`*(a: BigInt, shift: Natural): BigInt =
  if shift == 0 or a.isZero: return a
  let limbShift = shift div 32
  let bitShift = shift mod 32
  if limbShift >= a.value.len: return initBigInt(0)
  let newLen = a.value.len - limbShift
  result.value = newSeq[uint32](newLen)
  var carry: uint64 = 0
  for i in countdown(newLen - 1, 0):
    let val = uint64(a.value[i + limbShift])
    result.value[i] = uint32((val shr bitShift) or carry)
    carry = (val shl (32 - bitShift)) and 0xFFFFFFFF'u64
  result.sign = a.sign
  result.normalize()

func `and`*(a, b: BigInt): BigInt =
  let minLen = min(a.value.len, b.value.len)
  result.value = newSeq[uint32](minLen)
  for i in 0 ..< minLen:
    result.value[i] = a.value[i] and b.value[i]
  result.normalize()

func `or`*(a, b: BigInt): BigInt =
  let maxLen = max(a.value.len, b.value.len)
  result.value = newSeq[uint32](maxLen)
  for i in 0 ..< maxLen:
    let ai = if i < a.value.len: a.value[i] else: 0'u32
    let bi = if i < b.value.len: b.value[i] else: 0'u32
    result.value[i] = ai or bi
  result.normalize()

func `xor`*(a, b: BigInt): BigInt =
  let maxLen = max(a.value.len, b.value.len)
  result.value = newSeq[uint32](maxLen)
  for i in 0 ..< maxLen:
    let ai = if i < a.value.len: a.value[i] else: 0'u32
    let bi = if i < b.value.len: b.value[i] else: 0'u32
    result.value[i] = ai xor bi
  result.normalize()

func `not`*(a: BigInt): BigInt =
  result.value = newSeq[uint32](a.value.len)
  for i in 0 ..< a.value.len:
    result.value[i] = not a.value[i]
  result.normalize()

# --- Division ---

func divMod*(a, b: BigInt): tuple[q, r: BigInt] =
  if b.isZero: raise newException(DivByZeroDefect, "Division by zero")
  let cmp = cmpAbs(a, b)
  if cmp < 0:
    return (initBigInt(0), a)
  if cmp == 0:
    var q = initBigInt(1)
    q.sign = a.sign xor b.sign
    return (q, initBigInt(0))

  # Simple schoolbook division for now
  if b.value.len == 1:
    var r_val: uint64 = 0
    let b_val = uint64(b.value[0])
    var q_value = newSeq[uint32](a.value.len)
    for i in countdown(a.value.high, 0):
      let cur = (r_val shl 32) or uint64(a.value[i])
      q_value[i] = uint32(cur div b_val)
      r_val = cur mod b_val
    var q = BigInt(value: q_value, sign: a.sign xor b.sign)
    var r = initBigInt(r_val)
    r.sign = a.sign # Remainder sign matches dividend
    q.normalize()
    r.normalize()
    return (q, r)

  # Bit-by-bit division for multi-limb b (stable and correct)
  var q = initBigInt(0)
  var r = initBigInt(0)
  r.sign = false

  for i in countdown(a.value.high, 0):
    for j in countdown(31, 0):
      r = r shl 1
      if (a.value[i] and (1'u32 shl j)) != 0:
        r.value[0] = r.value[0] or 1'u32

      if cmpAbs(r, b) >= 0:
        r = subAbs(r, b)
        q = q or (initBigInt(1'u32) shl (i * 32 + j))

  q.sign = a.sign xor b.sign
  r.sign = a.sign
  q.normalize()
  r.normalize()
  return (q, r)

func `div`*(a, b: BigInt): BigInt = divMod(a, b).q
func `mod`*(a, b: BigInt): BigInt = divMod(a, b).r

# --- String Conversion ---

const Power10_9 = 1000000000'u32

func toString*(a: BigInt): string =
  if a.isZero: return "0"
  var res = ""
  var tmp = a
  tmp.sign = false
  let b10_9 = initBigInt(Power10_9)

  while not tmp.isZero:
    let (q, r) = divMod(tmp, b10_9)
    let s = $r.value[0]
    if q.isZero:
      res = s & res
    else:
      res = repeat('0', 9 - s.len) & s & res
    tmp = q

  if a.sign: res = "-" & res
  return res

func `$`*(a: BigInt): string = toString(a)

func initBigInt*(s: string): BigInt =
  if s.len == 0: return initBigInt(0)
  var start = 0
  var neg = false
  if s[0] == '-':
    neg = true
    start = 1
  elif s[0] == '+':
    start = 1

  result = initBigInt(0'u32)
  let b10 = initBigInt(10'u32)
  for i in start ..< s.len:
    if s[i] in {'0'..'9'}:
      result = result * b10 + initBigInt(uint32(ord(s[i]) - ord('0')))
    else:
      raise newException(ValueError, "Invalid character in BigInt string")
  result.sign = neg
  result.normalize()

# --- Helpers ---

func toInt*(a: BigInt): int64 =
  if a.isZero: return 0
  if a.value.len > 2: raise newException(ValueError, "BigInt too large for int64")
  if a.value.len == 2:
    result = (int64(a.value[1]) shl 32) or int64(a.value[0])
  else:
    result = int64(a.value[0])
  if a.sign: result = -result

func abs*(a: BigInt): BigInt =
  result = a
  result.sign = false

# --- Template Wrappers ---

template `+`*(a: BigInt, b: int): BigInt = a + initBigInt(b)
template `-`*(a: BigInt, b: int): BigInt = a - initBigInt(b)
template `*`*(a: BigInt, b: int): BigInt = a * initBigInt(b)
template `div`*(a: BigInt, b: int): BigInt = a div initBigInt(b)
template `mod`*(a: BigInt, b: int): BigInt = a mod initBigInt(b)

template addOptimized*(a, b: BigInt): BigInt {.autoSizeOpt.} = a + b
template subOptimized*(a, b: BigInt): BigInt {.autoSizeOpt.} = a - b
template mulOptimized*(a, b: BigInt): BigInt {.autoSizeOpt.} = a * b
