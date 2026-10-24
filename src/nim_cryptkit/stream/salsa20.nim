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

# declare SalSa20 context
type
  SalSa20Ctx* = object
    keyStream*: array[16, uint32]
    counter*: uint32

# salsa20 rounds : add, xor, rotate
template salsa20Round(y0, y1, y2, y3: var uint32): void =
  y1 = y1 xor rotateLeftBits(y0 + y3, 7)
  y2 = y2 xor rotateLeftBits(y1 + y0, 9)
  y3 = y3 xor rotateLeftBits(y2 + y1, 13)
  y0 = y0 xor rotateLeftBits(y3 + y2, 18)

# salsa20 row round
template salsa20RowRound(y: var array[16, uint32]): void =
  salsa20Round(y[ 0], y[ 1], y[ 2], y[ 3])
  salsa20Round(y[ 5], y[ 6], y[ 7], y[ 4])
  salsa20Round(y[10], y[11], y[ 8], y[ 9])
  salsa20Round(y[15], y[12], y[13], y[14])

# salsa20 column round
template salsa20ColumnRound(x: var array[16, uint32]): void =
  salsa20Round(x[ 0], x[ 4], x[ 8], x[12])
  salsa20Round(x[ 5], x[ 9], x[13], x[ 1])
  salsa20Round(x[10], x[14], x[ 2], x[ 6])
  salsa20Round(x[15], x[ 3], x[ 7], x[11])

# salsa20 double round
template salsa20DoubleRound(x: var array[16, uint32]): void =
  salsa20ColumnRound(x)
  salsa20RowRound(x)
  
# salsa20 blcok : extend keystream
template salsa20Block(state: var array[16, uint32]): void =
  # declare and initialise temporary array
  var x: array[16, uint32] = state
  var z: array[16, uint32] = state

  # perform 10 double rounds
  for i in static(0 ..< 10):
    salsa20DoubleRound(z)

  # add x to z
  for i in static(0 ..< 16):
    z[i] += x[i]
  
  # copy z to state
  state = z

# salsa20 128 init core
template salsa20_128InitC(ctx: var SalSa20Ctx, key: array[16, uint8], nonce: array[8, uint8], count: uint64): void =
  # magic constant : extend 16-bytes k
  ctx.keyStream[0] = 0x61707865'u32
  ctx.keyStream[5] = 0x3120646e'u32
  ctx.keyStream[10] = 0x79622d36'u32
  ctx.keyStream[15] = 0x6b206574'u32

  # decode key, nonce, count to keyStream
  when cpuEndian == littleEndian: # when cpuEndian is littleEndian, copy memory
    copyMem(addr ctx.keyStream[1], addr key, 16)
    copyMem(addr ctx.keyStream[11], addr key, 16)
    
    copyMem(addr ctx.keyStream[6], addr nonce, 8)

    copyMem(addr ctx.keyStream[8], addr count, 8)
  else: # else, use Utility's decode function
    decodeLE(key, ctx.keyStream.toOpenArray(1, 4), 4)
    decodeLE(key, ctx.keyStream.toOpenArray(11, 14), 4)

    decodeLE(nonce, ctx.keyStream.toOpenArray(6, 7), 2)
    
    ctx.keyStream[8] = uint32(count and 0xFFFFFFFF'u64)
    ctx.keyStream[9] = uint32(count shr 32)

# salsa20 256 init core
template salsa20_256InitC(ctx: var SalSa20Ctx, key: array[32, uint8], nonce: array[8, uint8], count: uint64): void =
  # magic constant : extend 32-bytes k
  ctx.keyStream[0] = 0x61707865'u32
  ctx.keyStream[5] = 0x3320646e'u32
  ctx.keyStream[10] = 0x79622d32'u32
  ctx.keyStream[15] = 0x6b206574'u32

  # decode key, nonce, count to keyStream
  when cpuEndian == littleEndian: # when cpuEndian is littleEndian, copy memory
     copyMem(addr ctx.keyStream[1], addr key[0], 16)
     copyMem(addr ctx.keyStream[11], addr key[16], 16)
     copyMem(addr ctx.keyStream[6], addr nonce, 8)
     copyMem(addr ctx.keyStream[8], addr count, 8)
  else: # else, use Utility's decode function
    decodeLE(key.toOpenArray(0, 15), ctx.keyStream.toOpenArray(1, 4), 4)
    decodeLE(key.toOpenArray(16, 31), ctx.keyStream.toOpenArray(11, 14), 4)

    decodeLE(nonce, ctx.keyStream.toOpenArray(6, 7), 2)
    
    ctx.keyStream[8] = uint32(count and 0xFFFFFFFF'u64)
    ctx.keyStream[9] = uint32(count shr 32)

template salsa20XorC(ctx: var SalSa20Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
  let length: int = min(input.len, output.len)
  let totalBlocks: int = length div 64
  let left: int = length - totalBlocks * 64

  var chunk: array[16, uint32]
  var inBuffer, outBuffer: array[16, uint32]

  # Process complete 64-byte blocks
  for i in 0 ..< totalBlocks:
    chunk = ctx.keyStream
    salsa20Block(chunk)

    when LE:
      copyMem(addr inBuffer[0], addr input[i * 64], 64)
    else:
      decodeLE(input.toSliceArray(i * 64, i * 64 + 63, 64), inBuffer.toSliceArray(0, 15))

    for j in static(0 ..< 16):
      outBuffer[j] = inBuffer[j] xor chunk[j]

    when LE:
      copyMem(addr output[i * 64], addr outBuffer[0], 64)
    else:
      encodeLE(outBuffer.toSliceArray(0, 15), output.toSliceArray(i * 64, i * 64 + 63, 64))

    # Increment 64-bit counter at indices 8 and 9
    ctx.keyStream[8] += 1
    if ctx.keyStream[8] == 0:
      ctx.keyStream[9] += 1

  # Process remaining bytes (< 64)
  if left > 0:
    chunk = ctx.keyStream
    salsa20Block(chunk)

    var buffer: array[64, uint8]

    when LE:
      copyMem(addr buffer[0], addr chunk[0], 64)
    else:
      encodeLE(chunk, buffer)

    for i in 0 ..< left:
      output[totalBlocks * 64 + i] = input[totalBlocks * 64 + i] xor buffer[i]

    # Increment 64-bit counter at indices 8 and 9
    ctx.keyStream[8] += 1
    if ctx.keyStream[8] == 0:
      ctx.keyStream[9] += 1

# exprot wrappers
when defined(templateOpt):
  template salsa20_128Init*(ctx: var SalSa20Ctx, key: array[16, uint8], nonce: array[8, uint8], count: uint64): void =
    salsa20_128InitC(ctx, key, nonce, count)
  template salsa20_128Init*(ctx: ptr SalSa20Ctx, key: ptr array[16, uint8], nonce: ptr array[8, uint8], count: uint64): void {.exportc: "salsa20_128Init", cdecl.} =
    salsa20_128InitC(ctx[], key[], nonce[], count)

  template salsa20_256Init*(ctx: var SalSa20Ctx, key: array[32, uint8], nonce: array[8, uint8], count: uint64): void =
    salsa20_256InitC(ctx, key, nonce, count)
  template salsa20_256Init*(ctx: ptr SalSa20Ctx, key: ptr array[32, uint8], nonce: ptr array[8, uint8], count: uint64): void {.exportc: "salsa20_256Init", cdecl.} =
    salsa20_256InitC(ctx[], key[], nonce[], count)

  template salsa20Xor*(ctx: var SalSa20Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    salsa20XorC(ctx, input, output)
  template salsa20Xor*(ctx: ptr SalSa20Ctx, input, output: ptr UncheckedArray[uint8], length: int): void {.exportc: "salsa20Xor", cdecl.} =
    salsa20XorC(ctx[], input.toOpenArray(0, length - 1), output.toOpenArray(0, length - 1))
else:
  proc salsa20_128Init*(ctx: var SalSa20Ctx, key: array[16, uint8], nonce: array[8, uint8], count: uint64): void =
    salsa20_128InitC(ctx, key, nonce, count)
  proc salsa20_128Init*(ctx: ptr SalSa20Ctx, key: ptr array[16, uint8], nonce: ptr array[8, uint8], count: uint64): void {.exportc: "salsa20_128Init", cdecl.} =
    salsa20_128InitC(ctx[], key[], nonce[], count)

  proc salsa20_256Init*(ctx: var SalSa20Ctx, key: array[32, uint8], nonce: array[8, uint8], count: uint64): void =
    salsa20_256InitC(ctx, key, nonce, count)
  proc salsa20_256Init*(ctx: ptr SalSa20Ctx, key: ptr array[32, uint8], nonce: ptr array[8, uint8], count: uint64): void {.exportc: "salsa20_256Init", cdecl.} =
    salsa20_256InitC(ctx[], key[], nonce[], count)

  proc salsa20Xor*(ctx: var SalSa20Ctx, input: openArray[uint8], output: var openArray[uint8]): void =
    salsa20XorC(ctx, input, output)
  proc salsa20Xor*(ctx: ptr SalSa20Ctx, input, output: ptr UncheckedArray[uint8], length: int): void {.exportc: "salsa20Xor", cdecl.} =
    salsa20XorC(ctx[], input.toOpenArray(0, length - 1), output.toOpenArray(0, length - 1))

