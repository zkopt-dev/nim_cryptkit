import bigint
import optmacro
import std/strutils

type
  BigDecimal* = object
    value*: BigInt
    scale*: int

# --- Utilities ---

func pow10(n: int): BigInt =
  result = initBigInt(1'u32)
  if n <= 0: return result
  let b10 = initBigInt(10'u32)
  for i in 0 ..< n:
    result = result * b10

func align(a: var BigDecimal, b: var BigDecimal) =
  if a.scale > b.scale:
    let diff = a.scale - b.scale
    b.value = b.value * pow10(diff)
    b.scale = a.scale
  elif b.scale > a.scale:
    let diff = b.scale - a.scale
    a.value = a.value * pow10(diff)
    a.scale = b.scale

# --- Initializers ---

func initBigDecimal*(v: BigInt, s: int = 0): BigDecimal =
  result.value = v
  result.scale = s

func initBigDecimal*(v: int64, s: int = 0): BigDecimal =
  result.value = initBigInt(v)
  result.scale = s

func initBigDecimal*(s: string): BigDecimal =
  var dotIdx = -1
  var filtered = ""
  for i in 0 ..< s.len:
    if s[i] == '.':
      if dotIdx != -1: raise newException(ValueError, "Multiple decimal points")
      dotIdx = i
    else:
      filtered.add(s[i])

  result.value = initBigInt(filtered)
  if dotIdx == -1:
    result.scale = 0
  else:
    result.scale = s.len - 1 - dotIdx

# --- Comparisons ---

func `==`*(a, b: BigDecimal): bool =
  var a2 = a
  var b2 = b
  align(a2, b2)
  return a2.value == b2.value

func `<`*(a, b: BigDecimal): bool =
  var a2 = a
  var b2 = b
  align(a2, b2)
  return a2.value < b2.value

func `<=`*(a, b: BigDecimal): bool = (a < b) or (a == b)
func `>`*(a, b: BigDecimal): bool = not (a <= b)
func `>=`*(a, b: BigDecimal): bool = not (a < b)
func `!=`*(a, b: BigDecimal): bool = not (a == b)

# --- Arithmetic ---

func `+`*(a, b: BigDecimal): BigDecimal =
  var a2 = a
  var b2 = b
  align(a2, b2)
  result.value = a2.value + b2.value
  result.scale = a2.scale

func `-`*(a, b: BigDecimal): BigDecimal =
  var a2 = a
  var b2 = b
  align(a2, b2)
  result.value = a2.value - b2.value
  result.scale = a2.scale

func `*`*(a, b: BigDecimal): BigDecimal =
  result.value = a.value * b.value
  result.scale = a.scale + b.scale

func `/`*(a, b: BigDecimal, precision: int = 10): BigDecimal =
  let targetScale = precision
  let shift = targetScale + b.scale - a.scale
  var scaledA = a.value
  if shift > 0:
    scaledA = scaledA * pow10(shift)
  elif shift < 0:
    scaledA = scaledA div pow10(-shift)

  result.value = scaledA div b.value
  result.scale = targetScale

func `+=`*(a: var BigDecimal, b: BigDecimal) = a = a + b
func `-=`*(a: var BigDecimal, b: BigDecimal) = a = a - b
func `*=`*(a: var BigDecimal, b: BigDecimal) = a = a * b
func `/=`*(a: var BigDecimal, b: BigDecimal) = a = a / b

# --- String Conversion ---

func toString*(a: BigDecimal): string =
  var s = a.value.toString()
  if a.scale <= 0:
    return s & repeat('0', -a.scale)

  let neg = s[0] == '-'
  if neg: s = s[1..^1]

  if s.len <= a.scale:
    s = repeat('0', a.scale - s.len + 1) & s

  let dotPos = s.len - a.scale
  result = s[0 ..< dotPos] & "." & s[dotPos .. ^1]
  if neg: result = "-" & result

func `$`*(a: BigDecimal): string = toString(a)
