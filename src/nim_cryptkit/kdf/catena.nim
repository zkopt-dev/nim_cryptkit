import helper
import ../utils/vectorop
import ../utils/bitutils
import ../utils/endian
import ../utils/errorutils
import ../utils/digits
import ../utils/slicearray
import ../utils/optmacro
import ../utils/envconst
import ../utils/biguintBE
import helper

template h(parts: varargs[seq[uint8]]): seq[uint8] =
  var x: seq[uint8]
  for p in parts:
    x.append(p)
  let d: array[64, uint8] = blake2b_512One(x)
  @d

template reverseBits(x: uint64; n: int): int =
  var y = x
  y = ((y and 0x5555555555555555'u64) shl 1) or ((y shr 1) and 0x5555555555555555'u64)
  y = ((y and 0x3333333333333333'u64) shl 2) or ((y shr 2) and 0x3333333333333333'u64)
  y = ((y and 0x0f0f0f0f0f0f0f0f'u64) shl 4) or ((y shr 4) and 0x0f0f0f0f0f0f0f0f'u64)
  var z: uint64
  for i in static(0 ..< 8):
    z = z or (((y shr (8 * i)) and 0xff) shl (8 * (7 - i)))
  int(z shr (64 - n))

template flap(x, salt: openArray[uint8], garlic, lambda: int): seq[uint8] =
  let count: int = 1 shl garlic
  let vm1: seq[uint8] = h(@[uint8(0)], @x)
  let vm2: seq[uint8] = h(@[uint8(1)], @x)
  var v = newSeq[seq[uint8]](count)
  v[0] = h(vm1, vm2)
  if count > 1:
    v[1] = h(v[0], vm1)

  for i in 2 ..< count:
    v[i] = h(v[i - 1], v[i - 2])

  let hs: seq[uint8] = h(@salt)
  let hhs: seq[uint8] = h(hs)

  var state: array[16, uint64]
  for i in static(0 ..< 8):
    for j in static(0 ..< 8):
      state[i] = state[i] or (uint64(hs[i * 8 + j]) shl (8 * j))
      state[i + 8] = state[i + 8] or (uint64(hhs[i * 8 + j]) shl (8 * j))

  var position: int = 0

  template nextRand(): uint64 =
    var output: uint64
    var s0 = state[position]
    position = (position + 1) and 15
    var s1 = state[position]
    s1 = s1 xor (s1 shl 31)
    s1 = s1 xor (s1 shr 11)
    s0 = s0 xor (s0 shr 30)
    state[position] = s0 xor s1
    output = state[position] * 1181783497276652981'u64
    output

  let q: int = 1 shl ((3 * garlic + 3) div 4)
  for _ in 0 ..< q:
    let a: int = int(nextRand() shr (64 - garlic))
    let b: int = int(nextRand() shr (64 - garlic))
    v[a] = h(v[a], v[b])

  var k: int = 0
  while k < lambda:
    v[0] = h(@[byte(0)], h(v[^1], v[0]))
    var previous = v[0]

    for i in 1 ..< count:
      let p: int = reverseBits(uint64(i), garlic)
      v[p] = h(previous, v[p]); previous = v[p]
    k.inc
    if k >= lambda:
      break

    v[0] = h(@[uint8(0)], h(v[^1], v[0]))
    for i in 1 ..< count:
      v[i] = h(v[i-1], v[i])
    k.inc

  v[^1]

proc catena*(password, salt: openArray[byte]; garlic: int, keyLen: int = 64, minGarlic: int = -1; lambda: int = 2; associatedData: openArray[uint8] = []): seq[uint8] =
  let low = if minGarlic < 0: garlic else: minGarlic
  if low < 1 or low > garlic or garlic > 30 or lambda < 1 or keyLen < 1 or keyLen > 64 or salt.len > 255:
    raise newException(KdfError, "invalid Catena parameters")
  let version: seq[uint8] = h(@[byte('D'), byte('r'), byte('a'), byte('g'), byte('o'), byte('n'), byte('f'),
      byte('l'), byte('y'), byte('-'), byte('F'), byte('u'), byte('l'), byte('l')])
  let ad: seq[uint8] = h(@associatedData)
  var x: seq[uint8] = h(version, @[byte(0), byte(lambda), byte(keyLen), byte(salt.len)], ad, @password, @salt)
  x = flap(x, salt, (low+1) div 2, lambda)
  for g in low .. garlic:
    x = flap(x, salt, g, lambda)
    x = h(@[byte(g)], x)
    for i in keyLen ..< 64:
      x[i] = 0
  var output: seq[uint8] = x[0..<keyLen]
  output
