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


type
  RabbitCtx* = object
    state*: array[8, uint32]
    counter*: array[8, uint32]
    carry*: uint32

template G(x: uint32): uint32 =
  let z: uint64 = uint64(x) * uint64(x)
  uint32(z shr 32) xor uint32(z)

template nextState(counter, state: var array[8, uint32]; carry: uint32): uint32 =
  var temp: array[8, uint32]
  copyMem(addr temp[0], addr counter[0], 32)
  counter[0] = counter[0] + 0x4D34D34D'u32 + carry
  counter[1] = counter[1] + 0xD34D34D3'u32 + uint32(counter[0] < temp[0])
  counter[2] = counter[2] + 0x34D34D34'u32 + uint32(counter[1] < temp[1])
  counter[3] = counter[3] + 0x4D34D34D'u32 + uint32(counter[2] < temp[2])
  counter[4] = counter[4] + 0xD34D34D3'u32 + uint32(counter[3] < temp[3])
  counter[5] = counter[5] + 0x34D34D34'u32 + uint32(counter[4] < temp[4])
  counter[6] = counter[6] + 0x4D34D34D'u32 + uint32(counter[5] < temp[5])
  counter[7] = counter[7] + 0xD34D34D3'u32 + uint32(counter[6] < temp[6])
  let newCarry = uint32(counter[7] < temp[7])
  var g: array[8, uint32]
  for i in static(0 ..< 8):
    g[i] = G(state[i] + counter[i])
  state[0] = g[0] + rotateLeftBits(g[7], 16) + rotateLeftBits(g[6], 16)
  state[1] = g[1] + rotateLeftBits(g[0], 8) + g[7]
  state[2] = g[2] + rotateLeftBits(g[1], 16) + rotateLeftBits(g[0], 16)
  state[3] = g[3] + rotateLeftBits(g[2], 8) + g[1]
  state[4] = g[4] + rotateLeftBits(g[3], 16) + rotateLeftBits(g[2], 16)
  state[5] = g[5] + rotateLeftBits(g[4], 8) + g[3]
  state[6] = g[6] + rotateLeftBits(g[5], 16) + rotateLeftBits(g[4], 16)
  state[7] = g[7] + rotateLeftBits(g[6], 8) + g[5]
  newCarry

template setKey(ctx: var RabbitCtx; key: slicearray[16, uint8]): void =
  var temp: array[4, uint32]
  decodeLE(key, temp.toSliceArray(0, 3))
  ctx.state[0] = temp[0]
  ctx.state[2] = temp[1]
  ctx.state[4] = temp[2]
  ctx.state[6] = temp[3]
  ctx.state[1] = (temp[3] shl 16) or (temp[2] shr 16)
  ctx.state[3] = (temp[0] shl 16) or (temp[3] shr 16)
  ctx.state[5] = (temp[1] shl 16) or (temp[0] shr 16)
  ctx.state[7] = (temp[2] shl 16) or (temp[1] shr 16)
  ctx.counter[0] = rotateLeftBits(temp[2], 16)
  ctx.counter[2] = rotateLeftBits(temp[3], 16)
  ctx.counter[4] = rotateLeftBits(temp[0], 16)
  ctx.counter[6] = rotateLeftBits(temp[1], 16)
  ctx.counter[1] = (temp[0] and 0xFFFF0000'u32) or (temp[1] and 0xFFFF'u32)
  ctx.counter[3] = (temp[1] and 0xFFFF0000'u32) or (temp[2] and 0xFFFF'u32)
  ctx.counter[5] = (temp[2] and 0xFFFF0000'u32) or (temp[3] and 0xFFFF'u32)
  ctx.counter[7] = (temp[3] and 0xFFFF0000'u32) or (temp[0] and 0xFFFF'u32)
  ctx.carry = 0
  for i in static(0 ..< 4):
    ctx.carry = nextState(ctx.counter, ctx.state, ctx.carry)
  for i in static(0 ..< 8):
    ctx.counter[i] = ctx.counter[i] xor ctx.state[(i + 4) and 7]

template syncIV(ctx: var RabbitCtx; iv: slicearray[8, uint8]): void =
  var temp: array[4, uint32]
  fromBytesLE(iv.toSliceArray(0, 3), temp[0])
  fromBytesLE(iv.toSliceArray(4, 7), temp[2])
  temp[1] = (temp[0] shr 16) or (temp[2] and 0xFFFF0000'u32)
  temp[3] = (temp[2] shl 16) or (temp[0] and 0x0000FFFF'u32)
  ctx.counter[0] = ctx.counter[0] xor temp[0]
  ctx.counter[1] = ctx.counter[1] xor temp[1]
  ctx.counter[2] = ctx.counter[2] xor temp[2]
  ctx.counter[3] = ctx.counter[3] xor temp[3]
  ctx.counter[4] = ctx.counter[4] xor temp[0]
  ctx.counter[5] = ctx.counter[5] xor temp[1]
  ctx.counter[6] = ctx.counter[6] xor temp[2]
  ctx.counter[7] = ctx.counter[7] xor temp[3]
  for i in static(0 ..< 4):
    ctx.carry = nextState(ctx.counter, ctx.state, ctx.carry)

template rabbitInitC*(ctx: var RabbitCtx, key: slicearray[16, uint8], nonce: slicearray[8, uint8]): void =
  zeroMem(addr ctx, sizeof(ctx))
  setKey(ctx, key)
  syncIV(ctx, nonce)

template rabbitXorC*(ctx: var RabbitCtx; input, output: openArray[uint8]): void =
  let length: int = min(input.len, output.len)
  let totalBlocks: int = length div 16
  let left: int = length - (totalBlocks * 16)

  var keyStream: array[4, uint32]
  var inBuffer, outBuffer: array[4, uint32]

  # Process complete 16-byte blocks
  for i in 0 ..< totalBlocks:
    ctx.carry = nextState(ctx.counter, ctx.state, ctx.carry)
    keyStream[0] = ctx.state[0] xor (ctx.state[5] shr 16) xor (ctx.state[3] shl 16)
    keyStream[1] = ctx.state[2] xor (ctx.state[7] shr 16) xor (ctx.state[5] shl 16)
    keyStream[2] = ctx.state[4] xor (ctx.state[1] shr 16) xor (ctx.state[7] shl 16)
    keyStream[3] = ctx.state[6] xor (ctx.state[3] shr 16) xor (ctx.state[1] shl 16)

    when LE:
      copyMem(addr inBuffer[0], addr input[i * 16], 16)
    else:
      decodeLE(input.toSliceArray(i * 16, i * 16 + 15, 16), inBuffer.toSliceArray(0, 3))

    for j in static(0 ..< 4):
      outBuffer[j] = inBuffer[j] xor keyStream[j]

    when LE:
      copyMem(addr output[i * 16], addr outBuffer[0], 16)
    else:
      encodeLE(outBuffer.toSliceArray(0, 3), output.toSliceArray(i * 16, i * 16 + 15, 16))

  # Process remaining bytes (< 16)
  if left > 0:
    ctx.carry = nextState(ctx.counter, ctx.state, ctx.carry)
    keyStream[0] = ctx.state[0] xor (ctx.state[5] shr 16) xor (ctx.state[3] shl 16)
    keyStream[1] = ctx.state[2] xor (ctx.state[7] shr 16) xor (ctx.state[5] shl 16)
    keyStream[2] = ctx.state[4] xor (ctx.state[1] shr 16) xor (ctx.state[7] shl 16)
    keyStream[3] = ctx.state[6] xor (ctx.state[3] shr 16) xor (ctx.state[1] shl 16)

    var buffer: array[16, uint8]

    when LE:
      copyMem(addr buffer[0], addr keyStream[0], 16)
    else:
      encodeLE(keyStream, buffer)

    for i in 0 ..< left:
      output[totalBlocks * 16 + i] = input[totalBlocks * 16 + i] xor buffer[i]

when defined(templateOpt):
  template rabbitInit*(ctx: var RabbitCtx, key: array[16, uint8], nonce: array[8, uint8]): void =
    rabbitInitC(ctx, key.toSliceArray(0, 15), nonce.toSliceArray(0, 7))
  template rabbitXor*(ctx: var RabbitCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    rabbitXorC(ctx, input, output)

  template rabbitInit*(ctx: ptr RabbitCtx, key: ptr array[16, uint8], nonce: ptr array[8, uint8]): void =
    rabbitInitC(ctx[], key[].toSliceArray(0, 15), nonce[].toSliceArray(0, 7))
  template rabbitXor*(ctx: ptr RabbitCtx, input, output: ptr UncheckedArray[uint8], length: int): void =
    rabbitXorC(ctx[], input.toOpenArray(0, length - 1), output.toOpenArray(0, length - 1))
else:
  proc rabbitInit*(ctx: var RabbitCtx, key: array[16, uint8], nonce: array[8, uint8]): void =
    rabbitInitC(ctx, key.toSliceArray(0, 15), nonce.toSliceArray(0, 7))
  proc rabbitXor*(ctx: var RabbitCtx, input: openArray[uint8], output: var openArray[uint8]): void =
    rabbitXorC(ctx, input, output)

  proc rabbitInit*(ctx: ptr RabbitCtx, key: ptr array[16, uint8], nonce: ptr array[8, uint8]): void {.exportc: "rabbitInit".} =
    rabbitInitC(ctx[], key[].toSliceArray(0, 15), nonce[].toSliceArray(0, 7))
  proc rabbitXor*(ctx: ptr RabbitCtx, input, output: ptr UncheckedArray[uint8], length: int): void {.exportc: "rabbitXor".} =
    rabbitXorC(ctx[], input.toOpenArray(0, length - 1), output.toOpenArray(0, length - 1))
