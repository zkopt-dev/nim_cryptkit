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

const R64  = [0x1b'u8]
const R128 = [0x87'u8]
const R256 = [0x04'u8, 0x25'u8]
const R512 = [0x01'u8, 0x25'u8]
const R1024 = [0x08'u8, 0x00'u8, 0x43'u8]

template cmacDouble*[B: static int](value: array[B, uint8]): array[B, uint8] =
  var output: array[B, uint8]
  const rb: uint8 = when B == 16: 0x87'u8 elif B == 8: 0x1b'u8 else: 0'u8
  var carry: uint8
  for i in countdown(B - 1, 0):
    let nextCarry = value[i] shr 7
    output[i] = (value[i] shl 1) or carry
    carry = nextCarry
  output[B - 1] = output[B - 1] xor (rb and (0'u8 - carry))
  output

template cmacSubkeys*[C; B: static[int]](ctx: var C; encrypt: untyped): tuple[k1, k2: array[B, uint8]] =
  var zero, l: array[B, uint8]
  encrypt(ctx, zero, l)
  (k1: cmacDouble(l), k2: cmacDouble(cmacDouble(l)))

type
  CMACCtx*[C; blockSize: static int] = object
    context*: C
    state*: array[blockSize, uint8]
    buffer*: array[blockSize, uint8]
    key1*: array[blockSize, uint8]
    key2*: array[blockSize, uint8]
    index*: int

template cmacInit*[C; B: static[int]](ctx: var CMACCtx[C, B]; init, encrypt: untyped; key: openArray[byte]): void =
  init(ctx.context, key)
  let subkeys: tuple[k1, k2: array[B, uint8]] = cmacSubkeys[C, B](ctx.context, encrypt)
  ctx.key1 = subkeys.k1
  ctx.key2 = subkeys.k2
  ctx.index = 0
  zeroMem(addr ctx.state[0], B)
  zeroMem(addr ctx.buffer[0], B)

template cmacInput*[C; B: static[int]](ctx: var CMACCtx[C, B], encrypt: untyped, input: openArray[uint8]): void =
  var check: bool = true
  let inputLen: int = input.len

  if inputLen <= 0:
    check = false

  if check:
    var index: int = ctx.index
    let left: int = B - index
    var position: int = 0

    if inputLen > left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      encrypt(ctx.context, ctx.buffer xor ctx.state, ctx.state)
      position = left
      index = 0

      while position + B < inputLen:
        unroll(i, 0, B - 1):
          ctx.state[i] = ctx.state[i] xor input[position + i]
        encrypt(ctx.context, ctx.state, ctx.state)
        position += B

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

template cmacFinal*[C; B: static int](ctx: var CMACCtx[C, B], encrypt: untyped): array[B, uint8] =
  var output: array[B, uint8]
  if ctx.index == B:
    unroll(i, 0, B - 1):
      output[i] = ctx.buffer[i] xor ctx.key1[i] xor ctx.state[i]
  else:
    copyMem(addr output[0], addr ctx.buffer[0], ctx.index)
    output[ctx.index] = 0x80'u8
    unroll(i, 0, B - 1):
      output[i] = output[i] xor ctx.key2[i] xor ctx.state[i]
  encrypt(ctx.context, output, output)
  output

template cmacOne*[C; B: static int](init, encrypt: untyped, key, input: openArray[uint8]): array[B, uint8] =
  var ctx: CMACCtx[C, B]
  cmacInit(ctx, init, encrypt, key)
  cmacInput(ctx, encrypt, input)
  cmacFinal(ctx, encrypt)
