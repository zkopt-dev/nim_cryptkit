import std/[bitops]
import ../hash/[sha2, blake2]
import ../mac/hmac
import ../utils/endian
import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils
import std/[monotimes, times]
import std/bitops
import strutils

type KdfError* = object of ValueError

proc checkedPositive*(value: int; name: string): void =
  if value <= 0:
    raise newException(KdfError, name & " must be positive")

template sha256One*(input: openArray[uint8]): array[32, uint8] =
  var ctx: SHA2_256Ctx
  sha2_256Init(ctx)
  sha2_256Input(ctx, input)
  sha2_256Final(ctx)

template sha512One*(input: openArray[uint8]): array[64, uint8] =
  var ctx: SHA2_512Ctx
  sha2_512Init(ctx)
  sha2_512Input(ctx, input)
  sha2_512Final(ctx)

template blake2b_512One*(input: openArray[uint8]): array[64, uint8] =
  var ctx: Blake2b_512Ctx
  blake2b_512Init(ctx)
  blake2b_512Input(ctx, input)
  blake2b_512Final(ctx)

template blake2b_256One*(input: openArray[uint8]): array[32, uint8] =
  var ctx: Blake2b_256Ctx
  blake2b_256Init(ctx)
  blake2b_256Input(ctx, input)
  blake2b_256Final(ctx)

proc blake2bVariable*(input: openArray[uint8], outputLen: int): seq[uint8] =
  const
    IV: array[8, uint64] = [
      0x6a09e667f3bcc908'u64, 0xbb67ae8584caa73b'u64,
      0x3c6ef372fe94f82b'u64, 0xa54ff53a5f1d36f1'u64,
      0x510e527fade682d1'u64, 0x9b05688c2b3e6c1f'u64,
      0x1f83d9abfb41bd6b'u64, 0x5be0cd19137e2179'u64]
    SIGMA: array[12, array[16, int]] = [
      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
      [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
      [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
      [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
      [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
      [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
      [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
      [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
      [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
      [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
      [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
      [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]]
  if outputLen < 1 or outputLen > 64:
    raise newException(KdfError, "BLAKE2b output length must be in 1..64")

  var state: array[8, uint64] = IV

  state[0] = state[0] xor (0x01010000'u64 xor uint64(outputLen))

  template transform(chunk: slicearray[128, uint8], count: uint64; final: static bool): void =
    var message: array[16, uint64]
    decodeLE(chunk, message.toSliceArray(0, 15))
    var vector: array[16, uint64]
    copyMem(addr vector[0], addr state[0], 64)
    copyMem(addr vector[8], addr IV[0], 64)

    vector[12] = vector[12] xor count

    when final: vector[14] = not vector[14]

    template mix(a, b, c, d: static int; x, y: uint64): void =
      vector[a] = vector[a] + vector[b] + x
      vector[d] = rotateRightBits(vector[d] xor vector[a], 32)
      vector[c] = vector[c] + vector[d]
      vector[b] = rotateRightBits(vector[b] xor vector[c], 24)
      vector[a] = vector[a] + vector[b] + y
      vector[d] = rotateRightBits(vector[d] xor vector[a], 16)
      vector[c] = vector[c] + vector[d]
      vector[b] = rotateRightBits(vector[b] xor vector[c], 63)

    unroll(i, 0, 11):
      mix(0, 4, 8, 12, message[SIGMA[i][0]], message[SIGMA[i][1]]);
      mix(1, 5, 9, 13, message[SIGMA[i][2]], message[SIGMA[i][3]])
      mix(2, 6, 10, 14, message[SIGMA[i][4]], message[SIGMA[i][5]])
      mix(3, 7, 11, 15, message[SIGMA[i][6]], message[SIGMA[i][7]])
      mix(0, 5, 10, 15, message[SIGMA[i][8]], message[SIGMA[i][9]])
      mix(1, 6, 11, 12, message[SIGMA[i][10]], message[SIGMA[i][11]])
      mix(2, 7, 8, 13, message[SIGMA[i][12]], message[SIGMA[i][13]])
      mix(3, 4, 9, 14, message[SIGMA[i][14]], message[SIGMA[i][15]])

    unroll(i, 0, 7):
      state[i] = state[i] xor vector[i] xor vector[i+8]

  let inputLen: int = input.len
  var position: int = 0

  if inputLen > 0:
    while position + 128 <= inputLen:
      transform(input.toSliceArray(position, position + 127, 128), uint64(position + 128), false)
      position += 128

  var last: array[128, uint8]
  let remain: int = inputLen - position
  copyMem(addr last[0], addr input[0], remain)
  transform(last.toSliceArray(0, 127), uint64(inputLen), true)

  var output: seq[uint8] = newSeq[uint8](outputLen)
  for i in 0 ..< outputLen: output[i] = uint8(state[i div 8] shr (8 * (i mod 8)))

  output

template sha256HMAC*(key, message: openArray[uint8]): array[32, uint8] =
  hmacOne[SHA2_256Ctx, 64, 32](sha2_256Init, sha2_256Input, sha2_256Final, key, message)

template sha512HMAC*(key, message: openArray[uint8]): array[64, uint8] =
  hmacOne[SHA2_512Ctx, 128, 64](sha2_512Init, sha2_512Input, sha2_512Final, key, message)

template append*(dst: var seq[byte]; part: openArray[byte]): void =
  let start = dst.len
  dst.setLen(start + part.len)
  for i, b in part:
    dst[start + i] = b

template blake2bLong*(input: openArray[uint8]; outputLen: int): seq[uint8] =
  var output: seq[uint8] = newSeq[uint8](outputLen)
  if outputLen == 0:
    return output

  var length: array[4, uint8]
  toBytesLE(uint32(outputLen), length)

  var firstInput: seq[uint8]
  append(firstInput, length)
  append(firstInput, input)

  if outputLen <= 64:
    output = blake2bVariable(firstInput, outputLen)
  else:
    var v: array[64, uint8] = blake2b_512One(firstInput)
    copyMem(addr output[0], addr v[0], 32)

    var offset: int = 32
    while offset + 32 <= outputLen:
      var chainInput: seq[uint8]
      append(chainInput, length)
      append(chainInput, v)

      v = blake2b_512One(chainInput)
      let copyLen = if offset + 32 <= outputLen: 32 else: outputLen - offset
      copyMem(addr output[offset], addr v[0], copyLen)
      offset += 32

  output

template `==`*(a, b: openArray[uint8]): bool =
  if a.len != b.len: return false
  var different = 0'u8
  for i in 0..<a.len: different = different or (a[i] xor b[i])
  different == 0
