import std/[math, algorithm]
import optmacro
import bitutils
import endian
import envconst
import errorutils
import bigint

# enum for DataformatError
# this project use Result<T, E>, not options or exception
# Result<T, E> logic is defined in erroutils
type
  DataformatError* = enum
    WrongCharacters = 0

# --- bin to BaseN Char array ---

# bin to Hex Char encoding array
const Hex*: array[16, char] = [
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  'A', 'B', 'C', 'D', 'E', 'F'
]

# bin to Oct Char encoding array
const Oct*: array[8, char] = [
  '0', '1', '2', '3', '4', '5', '6', '7'
]

# bin to Base32 Char encoding array
const Base32*: array[32, char] = [
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', '2', '3', '4', '5', '6', '7']

# bin to Base36 Char encoding array
const Base36*: array[36, char] = [
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
  'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
  'U', 'V', 'W', 'X', 'Y', 'Z'
]

# bin to Base45 Char encoding array
const Base45*: array[45, char] = [
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
  'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
  'U', 'V', 'W', 'X', 'Y', 'Z', ' ', '$', '%', '*',
  '+', '-', '.', '/', ':'
]

# bin to Base56 Char encoding array
const Base56*: array[56, char] = [
  '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B',
  'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L', 'M',
  'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
  'i', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't',
  'u', 'v', 'w', 'x', 'y', 'z'
]

# bin to Base58 Char encoding array
const Base58*: array[58, char] = [
  '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
  'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L',
  'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
  'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
  'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r',
  's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
]

# bin to Base62 Char encoding array
const Base62*: array[62, char] = [
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
  'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
  'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
  'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
  'y', 'z'
]

# bin to Base64 Char encoding array
const Base64*: array[64, char] = [
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
  'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
  'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
  'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
  'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', '+', '/'
]

# bin to Base85 Char encoding array
const Base85*: array[85, char] = [
  '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*',
  '+', ',', '-', '.', '/', '0', '1', '2', '3', '4',
  '5', '6', '7', '8', '9', ':', ';', '<', '=', '>',
  '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
  'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\',
  ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
  'q', 'r', 's', 't', 'u'
]

# bin to Base91 Char encoding array
const Base91*: array[91, char] = [
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
  'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
  'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
  'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
  'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', '!', '#', '$', '%', '&', '(', ')', '*',
  '+', ',', '.', '/', ':', ';', '<', '=', '>', '?',
  '@', '[', ']', '^', '_', '`', '{', '|', '}', '~',
  '"'
]

# bin to Base92 Char encoding array
const Base92*: array[92, char] = [
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
  'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
  'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
  'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
  'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', '!', '#', '$', '%', '&', '(', ')', '*',
  '+', ',', '-', '.', '/', ':', ';', '<', '=', '>',
  '?', '@', '[', ']', '^', '_', '`', '{', '|', '}',
  '~', '"'
]

# --- BaseN Char To bin table ---

when not defined(noTable):
  const HexMap: array[256, uint8] = block:
    var res: array[256, uint8]
    for i in 0..255: res[i] = 255'u8
    for i, ch in Hex: res[uint8(ch)] = uint8(i)
    res
  const OctMap: array[256, uint8] = block:
    var res: array[256, uint8]
    for i in 0..255: res[i] = 255'u8
    for i, ch in Oct: res[uint8(ch)] = uint8(i)
    res
  const Base32Map: array[256, uint8] = block:
    var res: array[256, uint8]
    for i in 0..255: res[i] = 255'u8
    for i, ch in Base32: res[uint8(ch)] = uint8(i)
    res
  const Base36Map: array[256, uint8] = block:
    var res: array[256, uint8]
    for i in 0..255: res[i] = 255'u8
    for i, ch in Base36: res[uint8(ch)] = uint8(i)
    res
  const Base45Map: array[256, uint8] = block:
    var res: array[256, uint8]
    for i in 0..255: res[i] = 255'u8
    for i, ch in Base45: res[uint8(ch)] = uint8(i)
    res
  const Base56Map: array[256, uint8] = block:
    var res: array[256, uint8]
    for i in 0..255: res[i] = 255'u8
    for i, ch in Base56: res[uint8(ch)] = uint8(i)
    res
  const Base58Map: array[256, uint8] = block:
    var res: array[256, uint8]
    for i in 0..255: res[i] = 255'u8
    for i, ch in Base58: res[uint8(ch)] = uint8(i)
    res
  const Base62Map: array[256, uint8] = block:
    var res: array[256, uint8]
    for i in 0..255: res[i] = 255'u8
    for i, ch in Base62: res[uint8(ch)] = uint8(i)
    res
  const Base64Map: array[256, uint8] = block:
    var res: array[256, uint8]
    for i in 0..255: res[i] = 255'u8
    for i, ch in Base64: res[uint8(ch)] = uint8(i)
    res
  const Base85Map: array[256, uint8] = block:
    var res: array[256, uint8]
    for i in 0..255: res[i] = 255'u8
    for i, ch in Base85: res[uint8(ch)] = uint8(i)
    res
  const Base91Map: array[256, uint8] = block:
    var res: array[256, uint8]
    for i in 0..255: res[i] = 255'u8
    for i, ch in Base91: res[uint8(ch)] = uint8(i)
    res
  const Base92Map: array[256, uint8] = block:
    var res: array[256, uint8]
    for i in 0..255: res[i] = 255'u8
    for i, ch in Base92: res[uint8(ch)] = uint8(i)
    res

template ctInOpenRange(u, minVal, maxVal: uint8): uint8 =
  let au = uint32(u)
  let k1 = (au - uint32(minVal)) shr 31
  let k2 = (uint32(maxVal) - au) shr 31
  uint8(((k1 or k2) xor 1'u32) * 0xFF'u32)

template ctEq(u, val: uint8): uint8 =
  let diff = uint32(u) xor uint32(val)
  uint8((((diff or (0'u32 - diff)) shr 31) xor 1'u32) * 0xFF'u32)

# mapping logic
template getHexVal(c: char): uint8 {.autoSizeOpt.} =
  when defined(noTable):
    let u = uint8(c)
    let m0 = ctInOpenRange(u, 48'u8, 57'u8)  # '0'-'9'
    let m1 = ctInOpenRange(u, 65'u8, 70'u8)  # 'A'-'F'
    let m2 = ctInOpenRange(u, 97'u8, 102'u8) # 'a'-'f'
    let validMask = m0 or m1 or m2
    let val = (m0 and (u - 48'u8)) or (m1 and (u - 55'u8)) or (m2 and (u - 87'u8))
    val or (not validMask and 0xFF'u8)
  else:
    HexMap[uint8(c)]

template getOctVal(c: char): uint8 {.autoSizeOpt.} =
  when defined(noTable):
    let u = uint8(c)
    let m0 = ctInOpenRange(u, 48'u8, 55'u8)  # '0'-'7'
    let val = m0 and (u - 48'u8)
    val or (not m0)
  else:
    OctMap[uint8(c)]

template getBase32Val(c: char): uint8 {.autoSizeOpt.} =
  when defined(noTable):
    let u = uint8(c)
    let m0 = ctInOpenRange(u, 65'u8, 90'u8)  # 'A'-'Z'
    let m1 = ctInOpenRange(u, 50'u8, 55'u8)  # '2'-'7'
    let validMask = m0 or m1
    let val = (m0 and (u - 65'u8)) or (m1 and (u - 24'u8))
    val or (not validMask and 0xFF'u8)
  else:
    Base32Map[uint8(c)]

template getBase36Val(c: char): uint8 {.autoSizeOpt.} =
  when defined(noTable):
    let u = uint8(c)
    let m0 = ctInOpenRange(u, 48'u8, 57'u8)  # '0'-'9'
    let m1 = ctInOpenRange(u, 65'u8, 90'u8)  # 'A'-'Z'
    let m2 = ctInOpenRange(u, 97'u8, 122'u8) # 'a'-'z'
    let validMask = m0 or m1 or m2
    let val = (m0 and (u - 48'u8)) or (m1 and (u - 55'u8)) or (m2 and (u - 87'u8))
    val or (not validMask and 0xFF'u8)
  else:
    Base36Map[uint8(c)]

template getBase45Val(c: char): uint8 {.autoSizeOpt.} =
  when defined(noTable):
    let u = uint8(c)
    let m0 = ctInOpenRange(u, 48'u8, 57'u8)  # '0'-'9'
    let m1 = ctInOpenRange(u, 65'u8, 90'u8)  # 'A'-'Z'
    let s0 = ctEq(u, 32'u8)  # ' ' -> 36
    let s1 = ctEq(u, 36'u8)  # '$' -> 37
    let s2 = ctEq(u, 37'u8)  # '%' -> 38
    let s3 = ctEq(u, 42'u8)  # '*' -> 39
    let s4 = ctEq(u, 43'u8)  # '+' -> 40
    let s5 = ctEq(u, 45'u8)  # '-' -> 41
    let s6 = ctEq(u, 46'u8)  # '.' -> 42
    let s7 = ctEq(u, 47'u8)  # '/' -> 43
    let s8 = ctEq(u, 58'u8)  # ':' -> 44
    let validMask = m0 or m1 or s0 or s1 or s2 or s3 or s4 or s5 or s6 or s7 or s8
    let val = (m0 and (u - 48'u8)) or (m1 and (u - 55'u8)) or
              (s0 and 36'u8) or (s1 and 37'u8) or (s2 and 38'u8) or (s3 and 39'u8) or
              (s4 and 40'u8) or (s5 and 41'u8) or (s6 and 42'u8) or (s7 and 43'u8) or
              (s8 and 44'u8)
    val or (not validMask and 0xFF'u8)
  else:
    Base45Map[uint8(c)]

template getBase56Val(c: char): uint8 {.autoSizeOpt.} =
  when defined(noTable):
    let u = uint8(c)
    let m0 = ctInOpenRange(u, 50'u8, 57'u8)   # '2'-'9'
    let m1 = ctInOpenRange(u, 65'u8, 72'u8)   # 'A'-'H'
    let m2 = ctInOpenRange(u, 74'u8, 78'u8)   # 'J'-'N'
    let m3 = ctInOpenRange(u, 80'u8, 90'u8)   # 'P'-'Z'
    let m4 = ctInOpenRange(u, 97'u8, 107'u8)  # 'a'-'k'
    let m5 = ctInOpenRange(u, 109'u8, 110'u8) # 'm'-'n'
    let m6 = ctInOpenRange(u, 112'u8, 122'u8) # 'p'-'z'
    let validMask = m0 or m1 or m2 or m3 or m4 or m5 or m6
    let val = (m0 and (u - 50'u8)) or (m1 and (u - 57'u8)) or (m2 and (u - 58'u8)) or
              (m3 and (u - 59'u8)) or (m4 and (u - 65'u8)) or (m5 and (u - 66'u8)) or
              (m6 and (u - 67'u8))
    val or (not validMask and 0xFF'u8)
  else:
    Base56Map[uint8(c)]

template getBase58Val(c: char): uint8 {.autoSizeOpt.} =
  when defined(noTable):
    let u = uint8(c)
    let m0 = ctInOpenRange(u, 49'u8, 57'u8)   # '1'-'9'
    let m1 = ctInOpenRange(u, 65'u8, 72'u8)   # 'A'-'H'
    let m2 = ctInOpenRange(u, 74'u8, 78'u8)   # 'J'-'N'
    let m3 = ctInOpenRange(u, 80'u8, 90'u8)   # 'P'-'Z'
    let m4 = ctInOpenRange(u, 97'u8, 107'u8)  # 'a'-'k'
    let m5 = ctInOpenRange(u, 109'u8, 111'u8) # 'm'-'o'
    let m6 = ctInOpenRange(u, 112'u8, 122'u8) # 'p'-'z'
    let validMask = m0 or m1 or m2 or m3 or m4 or m5 or m6
    let val = (m0 and (u - 49'u8)) or (m1 and (u - 56'u8)) or (m2 and (u - 57'u8)) or
              (m3 and (u - 58'u8)) or (m4 and (u - 64'u8)) or (m5 and (u - 65'u8)) or
              (m6 and (u - 66'u8))
    val or (not validMask and 0xFF'u8)
  else:
    Base58Map[uint8(c)]

template getBase62Val(c: char): uint8 {.autoSizeOpt.} =
  when defined(noTable):
    let u = uint8(c)
    let m0 = ctInOpenRange(u, 48'u8, 57'u8)  # '0'-'9'
    let m1 = ctInOpenRange(u, 65'u8, 90'u8)  # 'A'-'Z'
    let m2 = ctInOpenRange(u, 97'u8, 122'u8) # 'a'-'z'
    let validMask = m0 or m1 or m2
    let val = (m0 and (u - 48'u8)) or (m1 and (u - 55'u8)) or (m2 and (u - 61'u8))
    val or (not validMask and 0xFF'u8)
  else:
    Base62Map[uint8(c)]

template getBase64Val*(c: char): uint8 {.autoSizeOpt.} =
  when defined(noTable):
    let u = uint8(c)
    let m0 = ctInOpenRange(u, 65'u8, 90'u8)
    let m1 = ctInOpenRange(u, 97'u8, 122'u8)
    let m2 = ctInOpenRange(u, 48'u8, 57'u8)
    let s0 = ctEq(u, 43'u8)
    let s1 = ctEq(u, 47'u8)
    let pad = ctEq(u, 61'u8)

    let validMask = m0 or m1 or m2 or s0 or s1 or pad

    let v0 = m0 and uint8((uint32(u) - 65'u32) and 0xFF'u32)
    let v1 = m1 and uint8((uint32(u) - 71'u32) and 0xFF'u32)
    let v2 = m2 and uint8((uint32(u) + 4'u32) and 0xFF'u32)
    let v3 = s0 and 62'u8
    let v4 = s1 and 63'u8

    (v0 or v1 or v2 or v3 or v4) or (not validMask and 0xFF'u8)
  else:
    Base64Map[uint8(c)]

template getBase85Val(c: char): uint8 {.autoSizeOpt.} =
  when defined(noTable):
    let u = uint8(c)
    let m0 = ctInOpenRange(u, 33'u8, 117'u8) # '!' to 'u'
    let val = m0 and (u - 33'u8)
    val or (not m0 and 0xFF'u8)
  else:
    Base85Map[uint8(c)]

template getBase91Val(c: char): uint8 {.autoSizeOpt.} =
  when defined(noTable):
    let u = uint8(c)
    let m0 = ctInOpenRange(u, 65'u8, 90'u8)   # A-Z
    let m1 = ctInOpenRange(u, 97'u8, 122'u8)  # a-z
    let m2 = ctInOpenRange(u, 48'u8, 57'u8)   # 0-9
    let s0 = ctEq(u, 33'u8) or ctInOpenRange(u, 35'u8, 38'u8) or ctInOpenRange(u, 40'u8, 44'u8) or
             ctInOpenRange(u, 46'u8, 47'u8) or ctInOpenRange(u, 58'u8, 64'u8)
    let s1 = ctInOpenRange(u, 91'u8, 91'u8) or ctInOpenRange(u, 93'u8, 96'u8) or ctInOpenRange(u, 123'u8, 126'u8)
    let s2 = ctEq(u, 34'u8)
    let validMask = m0 or m1 or m2 or s0 or s1 or s2
    let val = (m0 and (u - 65'u8)) or (m1 and (u - 71'u8)) or (m2 and (u + 4'u8)) or
              (s0 and (u - 33'u8 + 62'u8)) or
              (s1 and (u - 91'u8 + 81'u8)) or
              (s2 and 90'u8)
    val or (not validMask and 0xFF'u8)
  else:
    Base91Map[uint8(c)]

template getBase92Val*(c: char): uint8 {.autoSizeOpt.} =
  when defined(noTable):
    let u = uint8(c)

    let m0 = ctInOpenRange(u, 65'u8, 90'u8)   # 'A'..'Z' -> 0..25
    let m1 = ctInOpenRange(u, 97'u8, 122'u8)  # 'a'..'z' -> 26..51
    let m2 = ctInOpenRange(u, 48'u8, 57'u8)   # '0'..'9' -> 52..61

    let s00 = ctEq(u, 33'u8)   # '!' -> 62
    let s01 = ctEq(u, 35'u8)   # '#' -> 63
    let s02 = ctEq(u, 36'u8)   # '$' -> 64
    let s03 = ctEq(u, 37'u8)   # '%' -> 65
    let s04 = ctEq(u, 38'u8)   # '&' -> 66
    let s05 = ctEq(u, 40'u8)   # '(' -> 67
    let s06 = ctEq(u, 41'u8)   # ')' -> 68
    let s07 = ctEq(u, 42'u8)   # '*' -> 69
    let s08 = ctEq(u, 43'u8)   # '+' -> 70
    let s09 = ctEq(u, 44'u8)   # ',' -> 71
    let s10 = ctEq(u, 45'u8)   # '-' -> 72
    let s11 = ctEq(u, 46'u8)   # '.' -> 73
    let s12 = ctEq(u, 47'u8)   # '/' -> 74
    let s13 = ctEq(u, 58'u8)   # ':' -> 75
    let s14 = ctEq(u, 59'u8)   # ';' -> 76
    let s15 = ctEq(u, 60'u8)   # '<' -> 77
    let s16 = ctEq(u, 61'u8)   # '=' -> 78
    let s17 = ctEq(u, 62'u8)   # '>' -> 79
    let s18 = ctEq(u, 63'u8)   # '?' -> 80
    let s19 = ctEq(u, 64'u8)   # '@' -> 81
    let s20 = ctEq(u, 91'u8)   # '[' -> 82
    let s21 = ctEq(u, 93'u8)   # ']' -> 83
    let s22 = ctEq(u, 94'u8)   # '^' -> 84
    let s23 = ctEq(u, 95'u8)   # '_' -> 85
    let s24 = ctEq(u, 96'u8)   # '`' -> 86
    let s25 = ctEq(u, 123'u8)  # '{' -> 87
    let s26 = ctEq(u, 124'u8)  # '|' -> 88
    let s27 = ctEq(u, 125'u8)  # '}' -> 89
    let s28 = ctEq(u, 126'u8)  # '~' -> 90
    let s29 = ctEq(u, 34'u8)   # '"' -> 91

    let validMask = m0 or m1 or m2 or
                    s00 or s01 or s02 or s03 or s04 or s05 or s06 or s07 or s08 or s09 or
                    s10 or s11 or s12 or s13 or s14 or s15 or s16 or s17 or s18 or s19 or
                    s20 or s21 or s22 or s23 or s24 or s25 or s26 or s27 or s28 or s29

    let val = (m0 and (u - 65'u8)) or
              (m1 and (u - 71'u8)) or
              (m2 and (u + 4'u8)) or
              (s00 and 62'u8) or (s01 and 63'u8) or (s02 and 64'u8) or (s03 and 65'u8) or
              (s04 and 66'u8) or (s05 and 67'u8) or (s06 and 68'u8) or (s07 and 69'u8) or
              (s08 and 70'u8) or (s09 and 71'u8) or (s10 and 72'u8) or (s11 and 73'u8) or
              (s12 and 74'u8) or (s13 and 75'u8) or (s14 and 76'u8) or (s15 and 77'u8) or
              (s16 and 78'u8) or (s17 and 79'u8) or (s18 and 80'u8) or (s19 and 81'u8) or
              (s20 and 82'u8) or (s21 and 83'u8) or (s22 and 84'u8) or (s23 and 85'u8) or
              (s24 and 86'u8) or (s25 and 87'u8) or (s26 and 88'u8) or (s27 and 89'u8) or
              (s28 and 90'u8) or (s29 and 91'u8)

    val or (not validMask and 0xFF'u8)
  else:
    Base92Map[uint8(c)]

# charToBin logic
proc charToBin*(input: openArray[char]): seq[uint8] {.autoTemplateOpt.} =
  var output: seq[uint8] = newSeq[uint8](input.len)
  var i: int = 0
  for c in input:
    output[i] = c.uint8
    i += 1

  output

# hexToBin logic
proc hexToBin*(input: openArray[char]): Result[seq[uint8], DataformatError] {.autoTemplateOpt.} =
  # define output first
  var output: Result[seq[uint8], DataformatError]

  # check input's char is correct
  var isValid: bool = true
  for c in input:
    if getHexVal(c) == 255'u8:
      output = Result[seq[uint8], DataformatError](kind: Failure, error: WrongCharacters)
      isValid = false
      break

  if isValid:
    # calculate output length
    let outLen: int = (input.len + 1) div 2

    # initialize output
    output = Result[seq[uint8], DataformatError](kind: Success, value: newSeq[uint8](outLen))

    # logic of hex to bin decoding
    let fullPairs = input.len div 2
    for i in 0 ..< fullPairs:
      var hi: uint8 = getHexVal(input[2 * i])
      var lo: uint8 = getHexVal(input[2 * i + 1])
      output.value[i] = (hi shl 4) or lo

    # remain decoding
    if input.len mod 2 == 1:
      var hi: uint8 = getHexVal(input[^1])
      output.value[^1] = (hi shl 4)

  # returning
  output

# binToHex logic
proc binToHex*(input: openArray[uint8]): string {.autoTemplateOpt.} =
  # define and initialize output first
  # pre-initializing length is because of performance
  # add makes seq to resize and copy
  var output: string = newString(input.len * 2)

  # logic of bin to hex encoding
  var i: int = 0
  for bytes in input:
    let hi = (bytes shr 4) and 0xF
    let lo = bytes and 0xF
    output[i] = (char(hi + (if hi < 10: ord('0') else: ord('A') - 10)))
    output[i + 1] = (char(lo + (if lo < 10: ord('0') else: ord('A') - 10)))
    i += 2

  # returning
  output

# general baseNToBin translating logic for bits-baseN
template toBinGeneric(input: openArray[char], bitsPerChar: static int, valGetter: untyped): Result[seq[uint8], DataformatError] =
  # define output first
  var output: Result[seq[uint8], DataformatError]

  # check input's char is correct
  var isValid = true
  for c in input:
    if valGetter(c) == 255'u8:
      isValid = false
      break

  if not isValid:
    # return Failure and error
    output = Result[seq[uint8], DataformatError](kind: Failure, error: WrongCharacters)
  else:
    # calculate output length
    let totalBits: int = input.len * bitsPerChar

    # initialize output
    # pre-initializing length is because of performance
    # add makes seq to resize and copy
    let outLen: int = (totalBits + 7) div 8
    output = Result[seq[uint8], DataformatError](kind: Success, value: newSeq[uint8](outLen))

    # set temporary variables
    var buffer: uint32 = 0
    var bits: int = 0
    var outIndex: int = 0

    # logic of baseN to bin decoding
    for c in input:
      var val: uint32 = valGetter(c).uint32
      buffer = (buffer shl bitsPerChar) or val
      bits += bitsPerChar

      if bits >= 8:
        let shift: int = bits - 8
        output.value[outIndex] = uint8((buffer shr shift) and 0xFF'u32)
        outIndex.inc
        bits = shift
        buffer = buffer and ((1'u32 shl bits) - 1)

    # remain decoding
    if bits > 0:
      output.value[outIndex] = uint8((buffer shl (8 - bits)) and 0xFF'u32)

  # returning
  output

# general binToBaseN translating logic for bits-baseN
template fromBinGeneric(input: openArray[uint8], bitsPerChar: static int, charTable: untyped): string =
  # calculating output length
  let totalInputBits = input.len * 8
  let outLen = (totalInputBits + bitsPerChar - 1) div bitsPerChar

  # initializing output
  var output: string = newString(outLen)

  # set temporary variable and runtime constant
  var buffer: uint32 = 0
  var bits: int = 0
  let mask: int = int(1'u32 shl bitsPerChar) - 1
  var outIndex: int = 0

  # logic of bin to baseN encoding
  for b in input:
    buffer = (buffer shl 8) or b.uint32
    bits += 8
    while bits >= bitsPerChar:
      var index: uint32 = (buffer shr (bits - bitsPerChar)) and mask.uint32
      output[outIndex] = charTable[index]
      bits -= bitsPerChar
      outIndex.inc
    buffer = buffer and ((1'u32 shl bits) - 1)

  # remain encoding
  if bits > 0:
    if outIndex < outLen:
      var index: uint32 = (buffer shl (bitsPerChar - bits)) and mask.uint32
      output[outIndex] = charTable[index]
    else:
      var index: uint32 = (buffer shl (bitsPerChar - bits)) and mask.uint32
      output.add(charTable[index])

  if outIndex < outLen:
    output.setLen(outIndex)

  # returning
  output

# general baseNtoBin deocding logic for non-bits baseN
template toBinBigIntGeneric(input: openArray[char], baseValue: static int, valGetter: untyped): Result[seq[uint8], DataformatError] =
  var output: Result[seq[uint8], DataformatError]
  var isValid = true

  var zeroCount = 0
  for c in input:
    let v = valGetter(c) and 0xFF'u8
    if v == 255'u8:
      isValid = false
      break
    if v == 0'u8:
      zeroCount.inc
    else:
      break

  for c in input:
    if (valGetter(c) and 0xFF'u8) == 255'u8:
      isValid = false
      break

  if not isValid:
    output = Result[seq[uint8], DataformatError](kind: Failure, error: WrongCharacters)
  else:
    var temp = initBigInt(0'u32)
    let constant = initBigInt(baseValue.uint32)

    for c in input:
      let v = valGetter(c) and 0xFF'u8
      temp = temp * constant + initBigInt(v.uint32)

    if temp.isZero:
      output = Result[seq[uint8], DataformatError](kind: Success, value: newSeq[uint8](zeroCount))
    else:
      let logRatio = ln(baseValue.float) / ln(256.0)
      let maxLen = ceil(input.len.float * logRatio).int + zeroCount + 2

      var buffer = newSeq[uint8](maxLen)
      var outIndex = maxLen - 1

      let byteMax = initBigInt(256'u32)
      var zero = initBigInt(0'u32)

      while temp > zero:
        let (q, r) = divMod(temp, byteMax)
        buffer[outIndex] = uint8(r.value[0] and 0xFF'u32)
        outIndex.dec
        temp = q

      for i in 0 ..< zeroCount:
        buffer[outIndex] = 0'u8
        outIndex.dec

      let startPos = outIndex + 1
      let actualLen = maxLen - startPos

      var finalBytes = newSeq[uint8](actualLen)
      for i in 0 ..< actualLen:
        finalBytes[i] = buffer[startPos + i]

      output = Result[seq[uint8], DataformatError](kind: Success, value: finalBytes)

  output

# general binToBaseN translating logic for non-bits baseN
template fromBinBigIntGeneric(input: openArray[uint8], baseValue: static int, charTable: untyped): string =
  var zero: BigInt = initBigInt(0'u32)
  var temp: BigInt = zero
  let constant: BigInt = initBigInt(baseValue.uint32)
  let byteMax: BigInt = initBigInt(256'u32)

  var zeroCount = 0
  for b in input:
    if b == 0'u8: zeroCount.inc
    else: break

  for b in input:
    temp = temp * byteMax + initBigInt(b.uint32)

  if temp == zero:
    var output = newString(zeroCount)
    for i in 0 ..< zeroCount:
      output[i] = charTable[0]
    output
  else:
    let logRatio = ln(256.0) / ln(baseValue.float)
    let maxLen = ceil(input.len.float * logRatio).int + zeroCount + 2

    var buffer = newString(maxLen)
    var outIndex = maxLen - 1

    while temp > zero:
      let (q, r) = divmod(temp, constant)
      buffer[outIndex] = charTable[toInt(r)]
      outIndex.dec
      temp = q

    for i in 0 ..< zeroCount:
      buffer[outIndex] = charTable[0]
      outIndex.dec

    let startPosition = outIndex + 1
    let actualLen = maxLen - startPosition

    var finalString: string = newString(actualLen)
    # copyMem(addr finalString[0], addr buffer[startPosition], actualLen)
    fastCopy(finalString, 0, buffer, startPosition, actualLen)

    finalString

# Octal (3-bit)
proc octToBin*(input: openArray[char]): Result[seq[uint8], DataformatError] {.autoTemplateOpt.} =
  toBinGeneric(input, 3, getOctVal)
proc binToOct*(input: openArray[uint8]): string {.autoTemplateOpt.} =
  fromBinGeneric(input, 3, Oct)

# Base32 (5-bit)
proc base32ToBin*(input: openArray[char]): Result[seq[uint8], DataformatError] {.autoTemplateOpt.} =
  toBinGeneric(input, 5, getBase32Val)
proc binToBase32*(input: openArray[uint8]): string {.autoTemplateOpt.} =
  fromBinGeneric(input, 5, Base32)

# Base64 (6-bit)
proc base64ToBin*(input: openArray[char]): Result[seq[uint8], DataformatError] {.autoTemplateOpt.} =
  toBinGeneric(input, 6, getBase64Val)
proc binToBase64*(input: openArray[uint8]): string {.autoTemplateOpt.} =
  fromBinGeneric(input, 6, Base64)

# base36
proc base36ToBin*(input: openArray[char]): Result[seq[uint8], DataformatError] {.autoTemplateOpt.} =
  toBinBigIntGeneric(input, 36, getBase36Val)
proc binToBase36*(input: openArray[uint8]): string {.autoTemplateOpt.} =
  fromBinBigIntGeneric(input, 36, Base36)

# base45
proc base45ToBin*(input: openArray[char]): Result[seq[uint8], DataformatError] {.autoTemplateOpt.} =
  toBinBigIntGeneric(input, 45, getBase45Val)
proc binToBase45*(input: openArray[uint8]): string {.autoTemplateOpt.} =
  fromBinBigIntGeneric(input, 45, Base45)

# base56
proc base56ToBin*(input: openArray[char]): Result[seq[uint8], DataformatError] {.autoTemplateOpt.} =
  toBinBigIntGeneric(input, 56, getBase56Val)
proc binToBase56*(input: openArray[uint8]): string {.autoTemplateOpt.} =
  fromBinBigIntGeneric(input, 56, Base56)

# base58
proc base58ToBin*(input: openArray[char]): Result[seq[uint8], DataformatError] {.autoTemplateOpt.} =
  toBinBigIntGeneric(input, 58, getBase58Val)
proc binToBase58*(input: openArray[uint8]): string {.autoTemplateOpt.} =
  fromBinBigIntGeneric(input, 58, Base58)

# base62
proc base62ToBin*(input: openArray[char]): Result[seq[uint8], DataformatError] {.autoTemplateOpt.} =
  toBinBigIntGeneric(input, 62, getBase62Val)
proc binToBase62*(input: openArray[uint8]): string {.autoTemplateOpt.} =
  fromBinBigIntGeneric(input, 62, Base62)

# base85
proc base85ToBin*(input: openArray[char]): Result[seq[uint8], DataformatError] {.autoTemplateOpt.} =
  toBinBigIntGeneric(input, 85, getBase85Val)
proc binToBase85*(input: openArray[uint8]): string {.autoTemplateOpt.} =
  fromBinBigIntGeneric(input, 85, Base85)

# base91
proc base91ToBin*(input: openArray[char]): Result[seq[uint8], DataformatError] {.autoTemplateOpt.} =
  toBinBigIntGeneric(input, 91, getBase91Val)
proc binToBase91*(input: openArray[uint8]): string {.autoTemplateOpt.} =
  fromBinBigIntGeneric(input, 91, Base91)

# base92
proc base92ToBin*(input: openArray[char]): Result[seq[uint8], DataformatError] {.autoTemplateOpt.} =
  toBinBigIntGeneric(input, 92, getBase92Val)
proc binToBase92*(input: openArray[uint8]): string {.autoTemplateOpt.} =
  fromBinBigIntGeneric(input, 92, Base92)
