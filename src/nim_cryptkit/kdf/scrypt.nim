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
import pbkdf2
import ../hash/sha2

template salsa208(x: var array[16, uint32]) =
  var z: array[16, uint32] = x
  for _ in static(0 ..< 4):
    z[4] = z[4] xor rotateLeftBits(z[0] + z[12], 7)
    z[8] = z[8] xor rotateLeftBits(z[4] + z[0], 9)
    z[12] = z[12] xor rotateLeftBits(z[8] + z[4], 13)
    z[0] = z[0] xor rotateLeftBits(z[12] + z[8], 18)
    z[9] = z[9] xor rotateLeftBits(z[5] + z[1], 7)
    z[13] = z[13] xor rotateLeftBits(z[9] + z[5], 9)
    z[1] = z[1] xor rotateLeftBits(z[13] + z[9], 13)
    z[5] = z[5] xor rotateLeftBits(z[1] + z[13], 18)
    z[14] = z[14] xor rotateLeftBits(z[10] + z[6], 7)
    z[2] = z[2] xor rotateLeftBits(z[14] + z[10], 9)
    z[6] = z[6] xor rotateLeftBits(z[2] + z[14], 13)
    z[10] = z[10] xor rotateLeftBits(z[6] + z[2], 18)
    z[3] = z[3] xor rotateLeftBits(z[15] + z[11], 7)
    z[7] = z[7] xor rotateLeftBits(z[3] + z[15], 9)
    z[11] = z[11] xor rotateLeftBits(z[7] + z[3], 13)
    z[15] = z[15] xor rotateLeftBits(z[11] + z[7], 18)
    z[1] = z[1] xor rotateLeftBits(z[0] + z[3], 7)
    z[2] = z[2] xor rotateLeftBits(z[1] + z[0], 9)
    z[3] = z[3] xor rotateLeftBits(z[2] + z[1], 13)
    z[0] = z[0] xor rotateLeftBits(z[3] + z[2], 18)
    z[6] = z[6] xor rotateLeftBits(z[5] + z[4], 7)
    z[7] = z[7] xor rotateLeftBits(z[6] + z[5], 9)
    z[4] = z[4] xor rotateLeftBits(z[7] + z[6], 13)
    z[5] = z[5] xor rotateLeftBits(z[4] + z[7], 18)
    z[11] = z[11] xor rotateLeftBits(z[10] + z[9], 7)
    z[8] = z[8] xor rotateLeftBits(z[11] + z[10], 9)
    z[9] = z[9] xor rotateLeftBits(z[8] + z[11], 13)
    z[10] = z[10] xor rotateLeftBits(z[9] + z[8], 18)
    z[12] = z[12] xor rotateLeftBits(z[15] + z[14], 7)
    z[13] = z[13] xor rotateLeftBits(z[12] + z[15], 9)
    z[14] = z[14] xor rotateLeftBits(z[13] + z[12], 13)
    z[15] = z[15] xor rotateLeftBits(z[14] + z[13], 18)
  for i in static(0 ..< 16):
    x[i] = x[i] + z[i]

template blockMix(input: var seq[uint8], r: int): void =
  var x: array[64, uint8]

  let last: int = (2 * r - 1) * 64
  copyMem(addr x[0], addr input[last], 64)

  var y: seq[uint8] = newSeq[uint8](input.len)
  var words: array[16, uint32]

  for i in 0 ..< (2 * r):
    for j in static(0 ..< 64):
      x[j] = x[j] xor input[i * 64 + j]
    decodeLE(x, words)
    salsa208(words)
    encodeLE(words, x)
    let dest: int = if (i and 1) == 0: (i div 2) * 64 else: (r + i div 2) * 64
    copyMem(addr y[dest], addr x[0], 64)
  input = y

template integerify(input: openArray[uint8], r: int): uint64 =
  let offset: int = (2 * r - 1) * 64
  var a, b: uint32
  fromBytesLE(input.toSliceArray(offset, offset + 3, 4), a)
  fromBytesLE(input.toSliceArray(offset + 4, offset + 7, 4), b)
  uint64(a) or (uint64(b) shl 32)

template romix(input: var seq[uint8], n, r: int) =
  let inputLen: int = input.len
  var v: seq[uint8] = newSeq[uint8](n * inputLen)
  for i in 0 ..< n:
    copyMem(addr v[i * inputLen], addr input[0], inputLen)
    blockMix(input, r)

  for _ in 0 ..< n:
    let j: int = int(integerify(input, r) and uint64(n - 1))
    for k in 0 ..< inputLen:
      input[k] = input[k] xor v[j * inputLen + k]
    blockMix(input, r)

proc scrypt*(password, salt: openArray[uint8], n, r, p, keyLen: int): seq[uint8] =
  checkedPositive(r, "r")
  checkedPositive(p, "p")
  checkedPositive(keyLen, "keyLen")
  if n <= 1 or (n and (n - 1)) != 0:
    raise newException(KdfError, "n must be a power of two greater than one")
  if r > high(int) div (128 * p) or r > high(int) div (128 * n):
    raise newException(KdfError, "scrypt parameters overflow address space")

  var buffer: seq[uint8] = pbkdf2SHA256(password, salt, 1, 128 * r * p)
  let blockLen: int = 128 * r
  for i in 0 ..< p:
    var laneBuffer: seq[uint8] = buffer[i * blockLen ..< (i + 1) * blockLen]
    romix(laneBuffer, n, r)
    for j in 0 ..< blockLen:
      buffer[i * blockLen + j] = laneBuffer[j]
  pbkdf2SHA256(password, buffer, 1, keyLen)
