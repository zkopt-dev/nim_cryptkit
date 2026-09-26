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
  ECBCtx*[C; blockSize, keySize: static int] = object
    context*: C
    buffer*: array[blockSize, uint8]
    index*: int

template ecbEncryptInit*[C; B, K: static int](init: untyped, ctx: var ECBCtx[C, B, K], key: openArray[uint8]): void =
  zeroMem(addr ctx, sizeof(ctx))
  init(ctx.context, key)

template ecbEncryptInput*[C; B, K: static int](encrypt: untyped, ctx: var ECBCtx[C, B, K], input: openArray[uint8]): seq[uint8] =
  var check: bool = true
  let inputLen: int = input.len

  var output: seq[uint8] = newSeq[uint8](((ctx.index + inputLen) div B) * B)

  if inputLen <= 0: check = false

  if check:

    var index: int = ctx.index
    let left: int = B - index
    var position: int = 0
    var point: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      encrypt(ctx.context, ctx.buffer.toSliceArray(0, B - 1), output.toSliceArray(point, point + B - 1, B))
      position += left
      point += B
      index = 0

      while position + B <= inputLen:
        encrypt(ctx.context, input.toSliceArray(position, position + B - 1, B), output.toSliceArray(point, point + B - 1, B))
        position += B
        point += B

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

  output

template ecbEncryptFinal*[C; B, K: static int](encrypt, padding: untyped, ctx: var ECBCtx[C, B, K]): seq[uint8] =
  var pad: seq[uint8] = padding(ctx.buffer.toOpenArray(0, ctx.index - 1), B)
  var output: seq[uint8] = newSeq[uint8](pad.len)
  for i in 0 ..< (pad.len div B):
    encrypt(ctx.context, pad.toSliceArray(i * B, (i + 1) * B - 1, B), output.toSliceArray(i * B, (i + 1) * B - 1, B))
  output

template ecbDecryptInit*[C; B, K: static int](init: untyped, ctx: var ECBCtx[C, B, K], key: openArray[uint8]): void =
  zeroMem(addr ctx, sizeof(ctx))
  init(ctx.context, key)
  ctx.index = 0

template ecbDecryptInput*[C; B, K: static int](decrypt: untyped, ctx: var ECBCtx[C, B, K], input: openArray[uint8]): seq[uint8] =
  var check: bool = true
  let inputLen: int = input.len

  var output: seq[uint8] = newSeq[uint8](((ctx.index + inputLen) div B - 1) * B)

  if inputLen <= 0: check = false

  if check:

    var index: int = ctx.index
    let left: int = B - index
    var position: int = 0
    var point: int = 0

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      decrypt(ctx.context, ctx.buffer.toSliceArray(0, B - 1), output.toSliceArray(point, point + B - 1, B))
      position += left
      point += B
      index = 0

      while position + B < inputLen:
        decrypt(ctx.context, input.toSliceArray(position, position + B - 1, B), output.toSliceArray(point, point + B - 1, B))
        position += B
        point += B

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

  output

template ecbDecryptFinal*[C; B, K: static int](decrypt, unPadding: untyped, ctx: var ECBCtx[C, B, K]): Result[seq[uint8], ModeError] =
  var output: Result[seq[uint8], ModeError]
  var index: int = ctx.index

  if index == B:
    decrypt(ctx.context, ctx.buffer, ctx.buffer)

    let point: int = unPadding(ctx.buffer, B)
    var temp: seq[uint8] = newSeq[uint8](point)
    copyMem(addr temp[0], addr ctx.buffer[0], point)
    output = Result[seq[uint8], ModeError](kind: Success, value: temp)
  else:
    output = Result[seq[uint8], ModeError](kind: Failure, error: UnpackedBlock)

  output
