import ../utils/optmacro
import ../utils/bitutils
import ../utils/errorutils
import ../utils/digits
import ../utils/slicearray
import ../utils/endian
import ../utils/envconst
import ../utils/biguintBE
import std/[monotimes, times]
import std/bitops
import strutils

# declare ChaCha20 context
type
  ChaCha20Ctx* = object
    keyStream*: array[16, uint32]
    counter*: uint32

# chacha20 round : 16 bytes, a, b, c, d int
# add, xor, rotate
template chacha20Round(x: var array[16, uint32], a, b, c, d: int): void =
  x[a] += x[b]; x[d] = rotateLeftBits(x[d] xor x[a], 16)
  x[c] += x[d]; x[b] = rotateLeftBits(x[b] xor x[c], 12)
  x[a] += x[b]; x[d] = rotateLeftBits(x[d] xor x[a], 8)
  x[c] += x[d]; x[b] = rotateLeftBits(x[b] xor x[c], 7) 

# chacha20 block
template chacha20Block(input: array[16, uint32], output: var array[16, uint32], roundNumber: static int): void =
  # copy input to x
  copyMem(addr output[0], addr input[0], 64)

  # chacha20 rounds : 20 rounds(10 loops)
  for i in static(0 ..< (roundNumber div 2)):
    chacha20Round(output, 0, 4, 8, 12)
    chacha20Round(output, 1, 5, 9, 13)
    chacha20Round(output, 2, 6, 10, 14)
    chacha20Round(output, 3, 7, 11, 15)
    chacha20Round(output, 0, 5, 10, 15)
    chacha20Round(output, 1, 6, 11, 12)
    chacha20Round(output, 2, 7, 8, 13)
    chacha20Round(output, 3, 4, 9, 14)

  # add and assign input to x
  for i in static(0 ..< 16):
    output[i] += input[i]

# chacha20 init core
template chacha20InitC(ctx: var ChaCha20Ctx, key: array[32, uint8], nonce: array[12, uint8], count: uint32): void =
  # magic constant : extend 32-bytes k
  ctx.keyStream[0] = 0x61707865'u32
  ctx.keyStream[1] = 0x3320646e'u32
  ctx.keyStream[2] = 0x79622d32'u32
  ctx.keyStream[3] = 0x6b206574'u32

  # decode key and nonce to keyStream
  when cpuEndian == littleEndian:
    copyMem(addr ctx.keyStream[4], addr key, 32)
    copyMem(addr ctx.keyStream[13], addr nonce, 12)
  else:
    decodeLE(key, ctx.keyStream.toOpenArray(4, 11), 8)
    decodeLE(nonce, ctx.keyStream.toOpenArray(13, 15), 3)

  # set counter
  ctx.keyStream[12] = count

# chacha20 xor core
template chacha20XorC(ctx: var ChaCha20Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
  let totalLength: int = min(input.len, output.len)
  let completeBlocks: int = totalLength div 64
  let left: int = totalLength - (completeBlocks * 64)

  var chunk: array[16, uint32]
  var inBuffer, outBuffer: array[16, uint32]

  for i in 0 ..< completeBlocks:
    chacha20Block(ctx.keyStream, chunk, 20)

    when LE:
      copyMem(addr inBuffer[0], addr input[i], 64)
    else:
      decodeLE(input.toSliceArray(i * 64, i * 64 + 63, 64), inBuffer.toSliceArray(0, 15))

    ctx.keyStream[12] += 1

    for j in static(0 ..< 16):
      outBuffer[j] = inBuffer[j] xor chunk[j]

    when LE:
      copyMem(addr output[i], addr outBuffer[0], 64)
    else:
      encodeLE(outBuffer.toSliceArray(0, 15), output.toSliceArray(i * 64, i * 64 + 63, 64))

  if left > 0:
    chacha20Block(ctx.keyStream, chunk, 20)

    var buffer: array[64, uint8]

    when LE:
      copyMem(addr buffer[0], addr chunk[0], 64)
    else:
      encodeLE(chunk, buffer)

    ctx.keyStream[12] += 1

    for i in 0 ..< left:
      output[completeBlocks * 64 + i] = buffer[i] xor input[completeBlocks * 64 + i]

# export wrappers
when defined(templateOpt):
  template chacha20Init*(ctx: var ChaCha20Ctx, key: array[32, uint8], nonce: array[12, uint8], count: uint32): void =
    chacha20InitC(ctx, key, nonce, count)
  template chacha20Init*(ctx: ptr ChaCha20Ctx, key: ptr array[32, uint8], nonce: ptr array[12, uint8], count: uint32): void =
    chacha20InitC(ctx[], key[], nonce[], count)

  template chacha20Xor*(ctx: var ChaCha20Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    chacha20XorC(ctx, input, output)
  template chacha20Xor*(ctx: ptr ChaCha20Ctx, input, output: ptr UncheckedArray[uint8], length: int): void =
    chacha20XorC(ctx[], input.toOpenArray(0, length - 1), output.toOpenArray(0, length - 1))
else:
  proc chacha20Init*(ctx: var ChaCha20Ctx, key: array[32, uint8], nonce: array[12, uint8], count: uint32): void =
    chacha20InitC(ctx, key, nonce, count)
  proc chacha20Init*(ctx: ptr ChaCha20Ctx, key: ptr array[32, uint8], nonce: ptr array[12, uint8], count: uint32): void {.exportc: "chacha20Init".} =
    chacha20InitC(ctx[], key[], nonce[], count)

  proc chacha20Xor*(ctx: var ChaCha20Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    chacha20XorC(ctx, input, output)
  proc chacha20Xor*(ctx: ptr ChaCha20Ctx, input, output: ptr UncheckedArray[uint8], length: int): void {.exportc: "chacha20Xor".} =
    chacha20XorC(ctx[], input.toOpenArray(0, length - 1), output.toOpenArray(0, length - 1))

