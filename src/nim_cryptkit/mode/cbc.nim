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
  CBCCtx*[C; blockSize, keySize: static int] = object
    context*: C
    buffer*: array[blockSize, uint8]
    prevBlock*: array[blockSize, uint8]
    index*: int
    length*: uint64

  ModeError* = enum
    UnpackedBlock

template cbcEncryptInit*[C; B, K: static int](init: untyped, ctx: CBCCtx[C, B, K], key, iv: openArray[uint8]): void =
  zeroMem(addr ctx, sizeof(ctx))
  init(ctx.context, key)
  copyMem(addr ctx.prevBlock[0], addr iv[0], min(iv.len, B))

template cbcEncryptInput*[C; B, K: static int](encrypt: untyped, ctx: CBCCtx[C, B, K], input: openArray[uint8]): seq[uint8] =
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
      ctx.buffer = ctx.buffer xor ctx.prevBlock
      encrypt(ctx.context, ctx.buffer, ctx.prevBlock)

      copyMem(addr output[0], addr ctx.prevBlock[0], B)

      position += left
      point += B
      index = 0

      var temp: array[B, uint8]
      while position + B <= inputLen:
        unroll(i, 0, B - 1):
          temp[i] = input[position + i] xor ctx.prevBlock[i]
        encrypt(ctx.context, temp, ctx.prevBlock)
        copyMem(addr output[point], addr ctx.prevBlock[0], B)
        position += B
        point += B

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

  output

template cbcEncryptFinal*[C; B, K: static int](encrypt, padding: untyped, ctx: var CBCCtx[C, B, K]): seq[uint8] =
  var pad: seq[uint8]
  if ctx.index > 0:
    pad = padding(ctx.buffer.toOpenArray(0, ctx.index - 1), B)
  else:
    pad = padding(newSeq[uint8](0), B)
  var output: seq[uint8] = newSeq[uint8](pad.len)

  for i in 0 ..< (pad.len div B):
    var temp: array[B, uint8]
    unroll(j, 0, B - 1):
      temp[j] = pad[i * B + j] xor ctx.prevBlock[j]

    encrypt(ctx.context, temp, ctx.prevBlock)
    copyMem(addr output[i * B], addr ctx.prevBlock[0], B)

  output

template cbcDecryptInit*[C; B, K: static int](init: untyped, ctx: var CBCCtx[C, B, K], key, iv: openArray[uint8]): void =
  zeroMem(addr ctx, sizeof(ctx))
  init(ctx.context, key)
  copyMem(addr ctx.prevBlock[0], addr iv[0], min(B, iv.len))

template cbcDecryptInput*[C; B, K: static int](decrypt: untyped, ctx: var CBCCtx[C, B, K], input: openArray[uint8]): seq[uint8] =
  let inputLen: int = input.len
  var output: seq[uint8]

  if inputLen <= 0:
    output = newSeq[uint8](0)
  else:
    let totalBlocks: int = (ctx.index + inputLen) div B
    let outputBlocks: int = max(0, totalBlocks - 1)
    output = newSeq[uint8](outputBlocks * B)

    var index: int = ctx.index
    var position: int = 0
    var point: int = 0

    let bytesToProcess: int = outputBlocks * B

    if index > 0:
      let needed: int = B - index
      let available: int = min(needed, inputLen)
      copyMem(addr ctx.buffer[index], addr input[0], available)
      position += available
      index += available

      if index == B and point < bytesToProcess:
        var decrypted: array[B, uint8]
        decrypt(ctx.context, ctx.buffer, decrypted)
        unroll(j, 0, B - 1):
          output[point + j] = decrypted[j] xor ctx.prevBlock[j]
        copyMem(addr ctx.prevBlock[0], addr ctx.buffer[0], B)
        point += B
        index = 0

    while point < bytesToProcess and position + B <= inputLen:
      var decrypted: array[B, uint8]
      decrypt(ctx.context, input.toSliceArray(position, position + B - 1, B),
              decrypted.toSliceArray(0, B - 1, B))
      unroll(j, 0, B - 1):
        output[point + j] = decrypted[j] xor ctx.prevBlock[j]
      copyMem(addr ctx.prevBlock[0], addr input[position], B)
      position += B
      point += B

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], unsafeAddr input[position], remain)
      index += remain

    ctx.index = index

  output

template cbcDecryptFinal*[C; B, K: static int](decrypt, unPadding: untyped, ctx: var CBCCtx[C, B, K]): Result[seq[uint8], ModeError] =
  var output: Result[seq[uint8], ModeError]

  if ctx.index != B:
    output = Result[seq[uint8], ModeError](kind: Failure, error: UnpackedBlock)
  else:
    var decrypted: array[B, uint8]
    decrypt(ctx.context, ctx.buffer.toSliceArray(0, B - 1), decrypted.toSliceArray(0, B - 1, B))

    unroll(j, 0, B - 1):
      decrypted[j] = decrypted[j] xor ctx.prevBlock[j]

    let validLen = unPadding(decrypted.toOpenArray(0, B - 1), B)
    if validLen < 0:
      output = Result[seq[uint8], ModeError](kind: Failure, error: UnpackedBlock)
    else:
      var ret: seq[uint8] = newSeq[uint8](validLen)
      if validLen > 0:
        copyMem(addr ret[0], addr decrypted[0], validLen)
      output = Result[seq[uint8], ModeError](kind: Success, value: ret)

  output
