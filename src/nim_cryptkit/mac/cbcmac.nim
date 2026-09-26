import ../utils/endian
import ../utils/digits
import ../utils/bitutils
import ../utils/envconst
import ../utils/slicearray
import ../utils/optmacro
import ../utils/errorutils
import ../utils/vectorop
import std/[monotimes, times]
import std/bitops
import strutils

type ModeError* = enum WrongInputLen, PaddingError

type
  CBCMACCtx*[C; blockSize: static int] = object
    context*: C
    state*: array[blockSize, uint8]
    buffer*: array[blockSize, uint8]
    index*: int

template cbcmacInit*[C; B: static int](ctx: var CBCMACCtx[C, B], init: untyped, key: openArray[uint8]): void =
  init(ctx.context, key)
  zeroMem(addr ctx.state, B)
  ctx.index = 0

template cbcmacInput*[C; B: static int](ctx: var CBCMACCtx[C, B], encrypt: untyped, input: openArray[uint8]): void =
  var check: bool = true

  let inputLen: int = input.len

  if inputLen <= 0: check = false

  if check:
    var index: int = ctx.index
    let left: int = B - index
    var position: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      encrypt(ctx.context, ctx.state xor ctx.buffer, ctx.state)
      index = 0
      position = left

      while position + B <= inputLen:
        unroll(i, 0, B - 1):
          ctx.state[i] = ctx.state[i] xor input[position + i]
        encrypt(ctx.context, ctx.state, ctx.state)
        position += B

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

template cbcmacFinal*[C; B: static int](ctx: var CBCMACCtx[C, B], encrypt, padding: untyped): array[B, uint8] =
  var last: seq[uint8] = padding(ctx.buffer, ctx.index, B)

  for i in 0 ..< (last.len div B):
    unroll(j, 0, B - 1):
      ctx.state[j] = ctx.state[j] xor last[i * B + j]
    encrypt(ctx.context, ctx.state, ctx.state)

  ctx.state

template cbcmacOne*[C; B: static int](init, encrypt, padding: untyped, key, input: openArray[uint8]): void =
  var ctx: CBCMACCtx[C, B]
  cbcmacInit(ctx, init, key)
  cbcmacInput(ctx, encrypt, input)
  cbcmacFinal(ctx, encrypt, padding)
