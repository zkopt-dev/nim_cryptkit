import "../block/blowfish"
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

template eksStreamWord(input: openArray[uint8], offset: var int): uint32 =
  var output: uint32
  if input.len > 0:
    for _ in static(0..<4):
      output = (output shl 8) or uint32(input[offset])
      offset = (offset + 1) mod input.len

  output

template eksExpand(ctx: var BlowfishCtx, salt, key: openArray[uint8]): void =
  var keyOffset: int = 0
  var saltOffset: int = 0


  for i in static(0 ..< 18):
    ctx.p[i] = ctx.p[i] xor eksStreamWord(key, keyOffset)

  var cipherBlock: array[8, uint8]

  for i in countup(0, 17, 2):
    let left: uint32 = ((uint32(cipherBlock[0]) shl 24) or
                        (uint32(cipherBlock[1]) shl 16) or
                        (uint32(cipherBlock[2]) shl  8) or
                         uint32(cipherBlock[3])) xor
                        eksStreamWord(salt, saltOffset)
    let right: uint32 = ((uint32(cipherBlock[4]) shl 24) or
                         (uint32(cipherBlock[5]) shl 16) or
                         (uint32(cipherBlock[6]) shl  8) or
                          uint32(cipherBlock[7])) xor
                          eksStreamWord(salt, saltOffset)

    toBytesBE(left, cipherBlock.toSliceArray(0, 3))
    toBytesBE(right, cipherBlock.toSliceArray(4, 7))

    blowfishEncrypt(ctx, cipherBlock.toSliceArray(0, 7), cipherBlock.toSliceArray(0, 7))

    ctx.p[i] = (uint32(cipherBlock[0]) shl 24) or
               (uint32(cipherBlock[1]) shl 16) or
               (uint32(cipherBlock[2]) shl  8) or
                uint32(cipherBlock[3])
    ctx.p[i + 1] = (uint32(cipherBlock[4]) shl 24) or
                   (uint32(cipherBlock[5]) shl 16) or
                   (uint32(cipherBlock[6]) shl  8) or
                    uint32(cipherBlock[7])

  for box in 0 ..< 4:
    for i in countup(0, 254, 2):
      let left: uint32 = ((uint32(cipherBlock[0]) shl 24) or
                          (uint32(cipherBlock[1]) shl 16) or
                          (uint32(cipherBlock[2]) shl  8) or
                           uint32(cipherBlock[3])) xor
                           eksStreamWord(salt, saltOffset)
      let right: uint32 = ((uint32(cipherBlock[4]) shl 24) or
                           (uint32(cipherBlock[5]) shl 16) or
                           (uint32(cipherBlock[6]) shl  8) or
                            uint32(cipherBlock[7])) xor
                            eksStreamWord(salt, saltOffset)

      toBytesBE(left, cipherBlock.toSliceArray(0, 3))
      toBytesBE(right, cipherBlock.toSliceArray(4, 7))

      blowfishEncrypt(ctx, cipherBlock.toSliceArray(0, 7), cipherBlock.toSliceArray(0, 7))

      ctx.s[box][i] = (uint32(cipherBlock[0]) shl 24) or
                      (uint32(cipherBlock[1]) shl 16) or
                      (uint32(cipherBlock[2]) shl  8) or
                       uint32(cipherBlock[3])
      ctx.s[box][i + 1] = (uint32(cipherBlock[4]) shl 24) or
                          (uint32(cipherBlock[5]) shl 16) or
                          (uint32(cipherBlock[6]) shl  8) or
                           uint32(cipherBlock[7])

template eksBlowfishInit*(ctx: var BlowfishCtx, salt, key: openArray[uint8], cost: int): void =
  ctx.p = ORIG_P
  ctx.s = ORIG_S
  eksExpand(ctx, salt, key)
  var zero: array[1, uint8]
  for _ in 0 ..< (1 shl cost):
    eksExpand(ctx, zero, key)
    eksExpand(ctx, zero, salt)

const bcryptAlphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
const bcryptMagic = [byte('O'), byte('r'), byte('p'), byte('h'), byte('e'), byte('a'),
  byte('n'), byte('B'), byte('e'), byte('h'), byte('o'), byte('l'), byte('d'), byte('e'),
  byte('r'), byte('S'), byte('c'), byte('r'), byte('y'), byte('D'), byte('o'), byte('u'),
  byte('b'), byte('t')]

proc bcryptBase64Encode*(data: openArray[uint8]): string =
  var output: string
  var i = 0
  while i < data.len:
    let c1 = data[i]; inc i
    output.add(bcryptAlphabet[int(c1 shr 2)])
    var c = (c1 and 0x03'u8) shl 4
    if i >= data.len:
      output.add(bcryptAlphabet[int(c)])
      break
    let c2 = data[i]; inc i
    c = c or (c2 shr 4)
    output.add(bcryptAlphabet[int(c)])
    c = (c2 and 0x0f'u8) shl 2
    if i >= data.len:
      output.add(bcryptAlphabet[int(c)])
      break
    let c3 = data[i]; inc i
    c = c or (c3 shr 6)
    output.add(bcryptAlphabet[int(c)])
    output.add(bcryptAlphabet[int(c3 and 0x3f'u8)])

  output

proc bcryptBase64Decode*(text: string): seq[uint8] =
  proc decodeChar(c: char): int =
    for i, candidate in bcryptAlphabet:
      if c == candidate: return i
    -1
  var output: seq[uint8]
  var i = 0
  while i < text.len:
    let c1 = decodeChar(text[i]); inc i
    if c1 < 0 or i >= text.len: raise newException(KdfError, "invalid bcrypt base64")
    let c2 = decodeChar(text[i]); inc i
    if c2 < 0: raise newException(KdfError, "invalid bcrypt base64")
    output.add(byte((c1 shl 2) or (c2 shr 4)))
    if i >= text.len: break
    let c3 = decodeChar(text[i]); inc i
    if c3 < 0: raise newException(KdfError, "invalid bcrypt base64")
    output.add(byte((c2 shl 4) or (c3 shr 2)))
    if i >= text.len: break
    let c4 = decodeChar(text[i]); inc i
    if c4 < 0: raise newException(KdfError, "invalid bcrypt base64")
    output.add(byte((c3 shl 6) or c4))

  output

proc bcryptRaw*(password, salt: openArray[uint8], cost: int): array[23, uint8] =
  ## Derive the 23-byte bcrypt checksum.  `salt` must be exactly 16 bytes.
  if salt.len != 16: raise newException(KdfError, "bcrypt salt must be 16 bytes")
  if password.len > 72: raise newException(KdfError, "bcrypt password is limited to 72 bytes")
  var output: array[23, uint8]
  var key: seq[byte] = @password
  key.add(0) # $2b$ NUL-terminates the password before EksBlowfish.
  var ctx: BlowfishCtx
  eksBlowfishInit(ctx, salt, key, cost)
  var encrypted = bcryptMagic
  var blockIn, blockOut: array[8, uint8]

  for _ in 0..<64:
    for blockIndex in 0..<3:
      copyMem(addr blockIn[0], addr encrypted[blockIndex * 8], 8)
      blowfishEncrypt(ctx, blockIn, blockOut)
      copyMem(addr encrypted[blockIndex * 8], addr blockOut[0], 8)

  copyMem(addr output[0], addr encrypted[0], 23)
  output

proc bcrypt*(password, salt: openArray[uint8], cost: int): string =
  ## Return a portable `$2b$cc$...` bcrypt record.
  let raw = bcryptRaw(password, salt, cost)
  "$2b$" & (if cost < 10: "0" else: "") & $cost & "$" &
    bcryptBase64Encode(salt) & bcryptBase64Encode(raw)
