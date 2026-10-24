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

type
  Endian* = enum
    BigEndian, LittleEndian

  OFBCtx*[C; blockSize, keySize: static int] = object
    context*: C
    prevOutput*: array[blockSize, uint8]
    buffer*: array[blockSize, uint8]
    index*: int

template ofbInit*[C; B, K: static int](init: untyped, ctx: OFBCtx[C, B, K], key, iv: openArray[uint8]): void =
  copyMem(addr ctx.prevOutput[0], addr iv[0], B)
  init(ctx.context, key)
  zeroMem(addr ctx.buffer[0], B)
  ctx.index = 0

template ofbInput*[C; B, K: static int](encrypt: untyped, ctx: OFBCtx[C, B, K], input: openArray[uint8]): seq[uint8] =
  let inputLen: int = input.len
  var output: seq[uint8] = newSeq[uint8](((ctx.index + inputLen) div B) * B)

  var check: bool = true

  if inputLen <= 0: check = false

  if check:
    var index: int = ctx.index
    var point: int = 0
    var position: int = 0
    let left: int = B - index

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      encrypt(ctx.context, ctx.prevOutput, ctx.prevOutput)
      unroll(i, 0, B - 1):
        output[point + i]= ctx.buffer[i] xor ctx.prevOutput[i]
      point += B
      position += left
      index = 0

      while position + B <= inputLen:
        encrypt(ctx.context, ctx.prevOutput, ctx.prevOutput)
        unroll(i, 0, B - 1):
          output[point + i] = input[position + i] xor ctx.prevOutput[i]

        position += B
        point += B

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

  output

template ofbFinal*[C; B, K: static int](encrypt: untyped, ctx: var OFBCtx[C, B, K]): seq[uint8] =
  var output: seq[uint8]
  if ctx.index == 0:
    output = newSeq[uint8](0)
  else:
    output = newSeq[uint8](ctx.index)
    encrypt(ctx.context, ctx.prevOutput, ctx.prevOutput)

    for i in 0 ..< ctx.index:
      output[i] = ctx.buffer[i] xor ctx.prevOutput[i]

    ctx.index = 0

  output

