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

  CFBCtx*[C; blockSize, keySize: static int] = object
    context*: C
    prevCipher*: array[blockSize, uint8]
    buffer*: array[blockSize, uint8]
    index*: int

template cfbEncryptInit*[C; B, K: static int](init: untyped, ctx: CFBCtx[C, B, K], key, iv: openArray[uint8]): void =
  copyMem(addr ctx.prevCipher[0], addr iv[0], B)
  init(ctx.context, key)
  zeroMem(addr ctx.buffer[0], B)
  ctx.index = 0

template cfbEncryptInput*[C; B, K: static int](encrypt: untyped, ctx: CFBCtx[C, B, K], input: openArray[uint8]): seq[uint8] =
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
      encrypt(ctx.context, ctx.prevCipher, ctx.prevCipher)
      ctx.prevCipher = ctx.buffer xor ctx.prevCipher
      copyMem(addr output[point], addr ctx.prevCipher[0], B)
      point += B
      index = 0
      position += left

      while position + B <= inputLen:
        encrypt(ctx.context, ctx.prevCipher, ctx.prevCipher)

        unroll(i, 0, B - 1):
          ctx.prevCipher[i] = input[position + i] xor ctx.prevCipher[i]
        copyMem(addr output[point], addr ctx.prevCipher[0], B)

        position += B
        point += B

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

  output

template cfbEncryptFinal*[C; B, K: static int](encrypt: untyped, ctx: var CFBCtx[C, B, K]): seq[uint8] =
  var output: seq[uint8]
  if ctx.index == 0:
    output = newSeq[uint8](0)
  else:
    output = newSeq[uint8](ctx.index)
    encrypt(ctx.context, ctx.prevCipher, ctx.prevCipher)

    for i in 0 ..< ctx.index:
      output[i] = ctx.buffer[i] xor ctx.prevCipher[i]

    ctx.index = 0
  output

template cfbDecryptInit*[C; B, K: static int](init: untyped, ctx: CFBCtx[C, B, K], key, iv: openArray[uint8]): void =
  copyMem(addr ctx.prevCipher[0], addr iv[0], B)
  init(ctx.context, key)
  zeroMem(addr ctx.buffer[0], B)
  ctx.index = 0

template cfbDecryptInput*[C; B, K: static int](encrypt: untyped, ctx: CFBCtx[C, B, K], input: openArray[uint8]): seq[uint8] =
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
      encrypt(ctx.context, ctx.prevCipher, ctx.prevCipher)
      unroll(i, 0, B - 1):
        output[point + i] = ctx.buffer[i] xor ctx.prevCipher[i]
      copyMem(addr ctx.prevCipher[0], addr ctx.buffer[0], B)
      point += B
      position += left
      index = 0

      while position + B <= inputLen:
        encrypt(ctx.context, ctx.prevCipher, ctx.prevCipher)

        unroll(i, 0, B - 1):
          output[point + i] = input[position + i] xor ctx.prevCipher[i]
        copyMem(addr ctx.prevCipher[0], addr input[position], B)

        position += B
        point += B

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

  output

template cfbDecryptFinal*[C; B, K: static int](encrypt: untyped, ctx: var CFBCtx[C, B, K]): seq[uint8] =
  var output: seq[uint8]
  if ctx.index == 0:
    output = newSeq[uint8](0)
  else:
    output = newSeq[uint8](ctx.index)
    encrypt(ctx.context, ctx.prevCipher, ctx.prevCipher)

    for i in 0 ..< ctx.index:
      output[i] = ctx.buffer[i] xor ctx.prevCipher[i]
      ctx.prevCipher[i] = ctx.buffer[i]

    ctx.index = 0

  output
