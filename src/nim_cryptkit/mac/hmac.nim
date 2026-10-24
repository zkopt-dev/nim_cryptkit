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

type
  HMACCtx*[H; blockSize, outputSize: static int] = object
    keypad*: array[blockSize, uint8]
    context*: H

template hmacInit*[H; B, O: static int](ctx: var HMACCtx[H, B, O], init, input, final: untyped, key: openArray[uint8]): void =
  init(ctx.context)
  let keyLen: int = key.len

  if keyLen > B:
    var hashCtx: H
    init(hashCtx)
    input(hashCtx, key)
    var temp: array[O, uint8] = final(hashCtx)
    copyMem(addr ctx.keypad[0], addr temp[0], O)
    let left: int = B - O
    zeroMem(addr ctx.keypad[O], left)
  elif keyLen == B:
     copyMem(addr ctx.keypad[0], addr key[0], B)
  elif keyLen > 0:
    copyMem(addr ctx.keypad[0], addr key[0], keyLen)
    let left: int = B - keyLen
    zeroMem(addr ctx.keypad[keyLen], left)

  var inkey: array[B, uint8]
  init(ctx.context)
  unroll(i, 0, B - 1):
    inkey[i] = ctx.keypad[i] xor 0x36'u8
  input(ctx.context, inkey)

template hmacInput*[H; B, O: static int](ctx: var HMACCtx[H, B, O], input: untyped, message: openArray[uint8]) =
  var check: bool = true
  let inputLen: int = message.len

  if inputLen <= 0: check = false

  if check:
    input(ctx.context, message)

template hmacFinal*[H; B, O: static int](ctx: HMACCtx[H, B, O], init, input, final: untyped): array[O, uint8] =
  var output: array[O, uint8]
  var outpad: array[B, uint8]
  unroll(i, 0, B - 1):
    outpad[i] = ctx.keypad[i] xor 0x5c'u8
  var inhash: array[O, uint8] = final(ctx.context)
  var finalCtx: H
  init(finalCtx)
  input(finalCtx, outpad)
  input(finalCtx, inhash)
  output = final(finalCtx)
  output

template hmacOne*[H; B, O: static int](init, input, final: untyped, key, message: openArray[uint8]): array[O, uint8] =
  var ctx: HMACCtx[H, B, O]
  hmacInit(ctx, init, input, final, key)
  hmacInput(ctx, input, message)
  hmacFinal(ctx, init, input, final)

