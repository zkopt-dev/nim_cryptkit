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
import ../hash/sha2
import bitops

## THIS CIPHER IS NOT WORKING, DON'T USE

type
  Argon2Variant* = enum
    Argon2d = 0,
    Argon2i = 1,
    Argon2id = 2
  ArgonBlock = array[128, uint64]

template toBytesLE(input: uint32): array[4, uint8] =
  var output: array[4, uint8]
  unroll(i, 0, 3):
    output[i] = uint8((input shr (i * 8)) and 0xFF'u32)
  output

template blamka(a, b: uint64): uint64 =
  a + b + 2'u64 * uint64(uint32(a)) * uint64(uint32(b))

template g(a, b, c, d: var uint64): void =
  a = blamka(a, b); d = rotateRightBits(d xor a, 32)
  c = blamka(c, d); b = rotateRightBits(b xor c, 24)
  a = blamka(a, b); d = rotateRightBits(d xor a, 16)
  c = blamka(c, d); b = rotateRightBits(b xor c, 63)

template permute(v: var array[128, uint64]; x: array[16, int]): void =
  g(v[x[0]], v[x[4]], v[x[8]], v[x[12]])
  g(v[x[1]], v[x[5]], v[x[9]], v[x[13]])
  g(v[x[2]], v[x[6]], v[x[10]], v[x[14]])
  g(v[x[3]], v[x[7]], v[x[11]], v[x[15]])
  g(v[x[0]], v[x[5]], v[x[10]], v[x[15]])
  g(v[x[1]], v[x[6]], v[x[11]], v[x[12]])
  g(v[x[2]], v[x[7]], v[x[8]], v[x[13]])
  g(v[x[3]], v[x[4]], v[x[9]], v[x[14]])

template compress(a, b: array[128, uint64]): array[128, uint64] =
  var output: array[128, uint64]
  var r: array[128, uint64] = a xor b
  output = r
  for row in static(0 ..< 8):
    var ix: array[16, int]
    for j in static(0 ..< 16):
      ix[j] = row * 16 + j
    permute(output, ix)

  for column in static(0 ..< 8):
    var ix: array[16, int]
    for j in static(0 ..< 8):
      ix[j * 2 + 0] = column * 2 + j * 16
      ix[j * 2 + 1] = column * 2 + j * 16 + 1
    permute(output, ix)
  output = output xor r

  output

proc initHash*(password, salt, secret, data: openArray[uint8], time, memory, lanes, keyLen: int, variant: Argon2Variant): array[64, uint8] =
  var x: seq[uint8]

  for n in [lanes, keyLen, memory, time, 0x13, int(variant)]:
    x.append(toBytesLE(uint32(n)))

  for part in [@password, @salt, @secret, @data]:
    x.append(toBytesLE(uint32(part.len)))
    x.append(part)
  blake2b_512One(x)

template argon2*(password, salt: openArray[uint8], timeCost, memoryKiB, parallelism, keyLen: int, variant: Argon2Variant = Argon2id, secret: openArray[uint8] = [], associatedData: openArray[uint8] = []): seq[uint8] =
  if timeCost < 1 or parallelism < 1: raise newException(KdfError, "Argon2 time and parallelism must be positive")
  if salt.len < 8: raise newException(KdfError, "Argon2 salt must be at least 8 bytes")
  if keyLen < 4: raise newException(KdfError, "Argon2 tag must be at least 4 bytes")
  if parallelism > 0xffffff or memoryKiB < 8*parallelism:
    raise newException(KdfError, "Argon2 memory must provide at least 8 KiB per lane")
  if uint64(timeCost) > uint64(high(uint32)) or
     uint64(memoryKiB) > uint64(high(uint32)) or
     uint64(keyLen) > uint64(high(uint32)) or
     uint64(password.len) > uint64(high(uint32)) or
     uint64(salt.len) > uint64(high(uint32)) or
     uint64(secret.len) > uint64(high(uint32)) or
     uint64(associatedData.len) > uint64(high(uint32)):
    raise newException(KdfError, "Argon2 parameter exceeds the version 1.3 limit")

  var blocks: int = memoryKiB div (4 * parallelism) * (4 * parallelism)
  blocks = max(blocks, 8*parallelism)
  let laneLen: int = blocks div parallelism
  let segmentLen: int = laneLen div 4
  let h0: array[64, uint8] = initHash(password, salt, secret, associatedData, timeCost, memoryKiB, parallelism, keyLen, variant)
  var mem = newSeq[array[128, uint64]](blocks)
  for lane in 0 ..< parallelism:
    for first in 0 ..< 2:
      var input: seq[uint8] = @h0
      input.append(toBytesLE(uint32(first)))
      input.append(toBytesLE(uint32(lane)))
      let long: seq[uint8] = blake2bLong(input, 1024)
      decodeLE(long, mem[lane * laneLen + first], 128)
  for pass in 0 ..< timeCost:
    for slice in 0 ..< 4:
      for lane in 0 ..< parallelism:
        let independent = variant == Argon2i or (variant == Argon2id and pass == 0 and slice < 2)
        var address, inputBlock, zero: array[128, uint64]

        if independent:
          inputBlock[0] = uint64(pass)
          inputBlock[1] = uint64(lane)
          inputBlock[2] = uint64(slice)
          inputBlock[3] = uint64(blocks)
          inputBlock[4] = uint64(timeCost)
          inputBlock[5] = uint64(ord(variant))

        let first: int = if pass == 0 and slice == 0: 2 else: 0

        if independent and first == 2:
          inc inputBlock[6]
          address = compress(zero, inputBlock);
          address = compress(zero, address)

        var cur: int = lane * laneLen + slice * segmentLen + first
        var prev: int = if slice == 0 and first == 0: cur + laneLen - 1 else: cur - 1

        for bi in first ..< segmentLen:
          var random: uint64
          if independent:
            if bi mod 128 == 0:
              inputBlock[6].inc
              address = compress(zero, inputBlock)
              address = compress(zero, address)
            random = address[bi mod 128]
          else: random = mem[prev][0]
          let refLane: int = if pass == 0 and slice == 0: lane else: int(uint64(random shr 32) mod uint64(parallelism))
          var area: int
          if pass == 0:
            if slice == 0: area = bi-1
            elif refLane == lane: area = slice*segmentLen+bi-1
            else: area = slice*segmentLen-(if bi == 0: 1 else: 0)
          else:
            area = laneLen - segmentLen + (if refLane == lane: bi - 1 else: -(if bi == 0: 1 else: 0))
          var map = random and 0xffffffff'u64; map = (map*map) shr 32
          let relative = area - 1-int((uint64(area) * map) shr 32)
          let start = if pass != 0 and slice != 3: (slice+1) * segmentLen else: 0
          let refIndex = refLane*laneLen+(start+relative) mod laneLen
          let mixed = compress(mem[prev], mem[refIndex])
          if pass == 0: mem[cur] = mixed
          else:
            mem[cur] = mem[cur] xor mixed
          prev = cur
          cur.inc

  var finalBlock: array[128, uint64] = mem[laneLen - 1]
  for lane in 1 ..< parallelism:
    finalBlock = finalBlock xor mem[lane * laneLen + laneLen - 1]
  var bytes: array[1024, uint8]
  encodeLE(finalBLock, bytes)
  blake2bLong(bytes, keyLen)

proc argon2d*(password, salt: openArray[uint8], timeCost, memoryKiB, parallelism, keyLen: int): seq[uint8] =
  argon2(password, salt, timeCost, memoryKiB, parallelism, keyLen, Argon2d)
proc argon2i*(password, salt: openArray[byte], timeCost, memoryKiB, parallelism, keyLen: int): seq[uint8] =
  argon2(password, salt, timeCost, memoryKiB, parallelism, keyLen, Argon2i)
proc argon2id*(password, salt: openArray[uint8], timeCost, memoryKiB, parallelism, keyLen: int): seq[uint8] =
  argon2(password, salt, timeCost, memoryKiB, parallelism, keyLen, Argon2id)
