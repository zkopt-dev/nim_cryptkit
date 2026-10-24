import ../utils/vectorop
import ../utils/bitutils
import ../utils/endian
import ../utils/errorutils
import ../utils/digits
import ../utils/slicearray
import ../utils/optmacro
import ../utils/envconst
import std/[monotimes, times]
import std/bitops
import ../hash/sha2
import ../mac/hmac
import helper

template pbkdf2*[H; B, O: static int](init, input, final: untyped, password, salt: openArray[uint8], iterations, keyLen: int): seq[uint8] =
  let outputLen: int = min(keyLen, int(high(uint32)))

  var output: seq[uint8] = newSeq[uint8](outputLen)

  let count: int = (outputLen + O - 1) div O

  for i in 1 .. count:
    var message: seq[uint8] = @salt
    var index: array[4, uint8]
    toBytesBE(uint32(i), index)
    message.append(index)
    var u: array[O, uint8] = hmacOne[H, B, O](init, input, final, password, message)
    var temp: array[O, uint8] = u

    for _ in 2 .. iterations:
      u = hmacOne[H, B, O](init, input, final, password, u)
      unroll(j, 0, O - 1):
        temp[j] = temp[j] xor u[j]

    let offset: int = (i - 1) * O
    let left: int = keyLen - offset
    copyMem(addr output[offset], addr temp[0], min(O, left))

  output

proc pbkdf2SHA256*(password, salt: openArray[uint8], iterations, keyLen: int): seq[uint8] =
  pbkdf2[SHA2_256Ctx, 64, 32](sha2_256Init, sha2_256Input, sha2_256Final, password, salt, iterations, keyLen)

proc pbkdf2SHA512*(password, salt: openArray[uint8], iterations, keyLen: int): seq[uint8] =
  pbkdf2[SHA2_512Ctx, 128, 64](sha2_512Init, sha2_512Input, sha2_512Final, password, salt, iterations, keyLen)
