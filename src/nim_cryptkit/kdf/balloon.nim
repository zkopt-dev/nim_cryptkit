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

proc balloon*(password, salt: openArray[uint8]; spaceCost, timeCost, delta, keyLen: int): seq[uint8] =
  var counter = 0'u64
  proc digest(parts: varargs[seq[uint8]]): seq[uint8] =
    var input: seq[byte]
    var count: array[8, uint8]
    toBytesLE(counter, count)
    input.append(count)
    counter.inc
    for part in parts:
      input.append(part)
    let hash = sha2_256One(input)
    @hash
  var buffer = newSeq[seq[uint8]](spaceCost)
  buffer[0] = digest(@password, @salt)
  for i in 1 ..< spaceCost:
    buffer[i] = digest(buffer[i - 1])
  for t in 0 ..< timeCost:
    for m in 0 ..< spaceCost:
      buffer[m] = digest(buffer[m], buffer[(m + spaceCost - 1) mod spaceCost])
      for d in 0 .. delta:
        var indexInput: seq[uint8]
        var count: array[8, uint8]
        toBytesLE(counter, count)
        indexInput.append(count)
        counter.inc
        indexInput.append(salt)
        let t64: uint64 = uint64(t)
        let m64: uint64 = uint64(m)
        let d64: uint64 = uint64(d)
        var tArr: array[8, uint8]
        toBytesLE(t64, tArr)
        var mArr: array[8, uint8]
        toBytesLE(m64, mArr)
        var dArr: array[8, uint8]
        toBytesLE(d64, dArr)
        indexInput.append(tArr)
        indexInput.append(mArr)
        indexInput.append(dArr)
        let indexHash: array[32, uint8] = sha2_256One(indexInput)
        let other = int(fromBytesLE[uint32, 4](indexHash.toSliceArray(0, 3))) mod spaceCost
        buffer[m] = digest(buffer[m], buffer[other])

  blake2bLong(buffer[^1], keyLen)
