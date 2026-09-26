import bitops
import optmacro

# left rotate
template rotateLeftBits*[T: SomeInteger](value: T, shift: T): T {.autoSizeOpt.} =
  when defined(nostd):
    ((value shl shift.int) or (value shr (int(sizeof(T)) * 8) - shift.int))
  else:
    rotateLeftBits(value, shift)

# right rotate
template rotateRightBits*[T: SomeInteger](value: T, shift: T): T {.autoSizeOpt.} =
  when defined(nostd):
    ((value shr shift.int) or (value shl (int(sizeof(T)) * 8) - shift.int))
  else:
    rotateRightBits(value, shift)

# bit reverse for uint8
template reverseBit8(n: uint8): uint8 {.autoSizeOpt.} =
  var x = n
  x = (x shr 4) or (x shl 4)
  x = ((x shr 2) and 0x33'u8) or ((x shl 2) and 0xCC'u8)
  x = ((x shr 1) and 0x55'u8) or ((x shl 1) and 0xAA'u8)
  x

# bit reverse for uint16
template reverseBit16(n: uint16): uint16 {.autoSizeOpt.} =
  var x = n
  x = (x shr 8) or (x shl 8)
  x = ((x shr 4) and 0x0F0F'u16) or ((x shl 4) and 0xF0F0'u16)
  x = ((x shr 2) and 0x3333'u16) or ((x shl 2) and 0xCCCC'u16)
  x = ((x shr 1) and 0x5555'u16) or ((x shl 1) and 0xAAAA'u16)
  x

# bit reverse for uint32
template reverseBit32(n: uint32): uint32 {.autoSizeOpt.} =
  var x = n
  x = (x shr 16) or (x shl 16)
  x = ((x shr 8) and 0x00FF00FF'u32) or ((x shl 8) and 0xFF00FF00'u32)
  x = ((x shr 4) and 0x0F0F0F0F'u32) or ((x shl 4) and 0xF0F0F0F0'u32)
  x = ((x shr 2) and 0x33333333'u32) or ((x shl 2) and 0xCCCCCCCC'u32)
  x = ((x shr 1) and 0x55555555'u32) or ((x shl 1) and 0xAAAAAAAA'u32)
  x

# bit reverse for uint64
template reverseBit64(n: uint64): uint64 {.autoSizeOpt.} =
  var x = n
  x = (x shr 32) or (x shl 32)
  x = ((x shr 16) and 0x0000FFFF0000FFFF'u64) or ((x shl 16) and 0xFFFF0000FFFF0000'u64)
  x = ((x shr 8) and 0x00FF00FF00FF00FF'u64) or ((x shl 8) and 0xFF00FF00FF00FF00'u64)
  x = ((x shr 4) and 0x0F0F0F0F0F0F0F0F'u64) or ((x shl 4) and 0xF0F0F0F0F0F0F0F0'u64)
  x = ((x shr 2) and 0x3333333333333333'u64) or ((x shl 2) and 0xCCCCCCCCCCCCCCCC'u64)
  x = ((x shr 1) and 0x5555555555555555'u64) or ((x shl 1) and 0xAAAAAAAAAAAAAAAA'u64)
  x

template swap*[T: uint16 | uint32 | uint64](input: T): T =
  when sizeof(T) == 2:
    ((input and 0xff00'u16) shr 8) or
    ((input and 0x00ff'u16) shl 8)
  elif sizeof(T) == 4:
    ((input and 0xff000000'u32) shr 24) or
    ((input and 0x00ff0000'u32) shr 8)  or
    ((input and 0x0000ff00'u32) shl 8)  or
    ((input and 0x000000ff'u32) shl 24)
  elif sizeof(T) == 8:
    ((input and 0xff00000000000000'u64) shr 56) or
    ((input and 0x00ff000000000000'u64) shr 40) or
    ((input and 0x0000ff0000000000'u64) shr 24) or
    ((input and 0x000000ff00000000'u64) shr 8)  or
    ((input and 0x00000000ff000000'u64) shl 8)  or
    ((input and 0x0000000000ff0000'u64) shl 24) or
    ((input and 0x000000000000ff00'u64) shl 40) or
    ((input and 0x00000000000000ff'u64) shl 56)

# bit reverse for generic
template reverseBit*[T: SomeUnsignedInt](n: T): T {.autoSizeOpt.} =
  when T is uint64:
    reverseBit64(n)
  elif T is uint32:
    reverseBit32(n)
  elif T is uint16:
    reverseBit16(n)
  elif T is uint8:
    reverseBit8(n)

# nand generic operator
template `nand`*[T: SomeInteger](a, b: T): T =
  not (a and b)

# nor generic operator
template `nor`*[T: SomeInteger](a, b: T): T =
  not (a or b)

# and sign operator
template `&`*[T: SomeInteger](a, b: T): T =
  a and b

# or sign operator
template `|`*[T: SomeInteger](a, b: T): T =
  a or b

# xor sign operator
template `^`*[T: SomeInteger](a, b: T): T =
  a xor b

# not sign operator
template `~`*[T: SomeInteger](a: T): T =
  not a

# and assign sign operator
template `&=`*[T: SomeInteger](a: var T, b: T): void =
  a = a and b

# or assign sign operator
template `|=`*[T: SomeInteger](a: var T, b: T): void =
  a = a or b

# xor assign sign operator
template `^=`*[T: SomeInteger](a: var T, b: T): void =
  a = a xor b

# not assign sign operator
template `~=`*[T: SomeInteger](a: var T): void =
  a = not a
