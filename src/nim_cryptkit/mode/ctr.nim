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

  CTRCtx*[C; blockSize, keySize, nonceSize, counterSize: static int] = object
    context*: C
    nonce*: array[nonceSize, uint8]
    counter*: array[counterSize, uint8]
    endian*: Endian
    buffer*: array[blockSize, uint8]
    index*: int

template counterToInt(counter: openArray[uint8], endian: Endian): uint64 =
  var v: uint64 = 0
  if endian == BigEndian:
    for i in 0 ..< counter.len:
      v = (v shl 8) or uint64(counter[i])
  else:
    for i in countdown(counter.len - 1, 0):
      v = (v shl 8) or uint64(counter[i])
  v

template intToCounter(default: int, counter: var openArray[uint8], endian: Endian) =
  var value: uint64 = default.uint64
  if endian == BigEndian:
    for i in countdown(counter.len - 1, 0):
      counter[i] = uint8(value and 0xFF)
      value = value shr 8
  else:
    for i in 0 ..< counter.len:
      counter[i] = uint8(value and 0xFF)
      value = value shr 8

template incrementCounter(counter: var openArray[uint8], endian: Endian): bool =
  if endian == BigEndian:
    var carry = true
    for i in countdown(counter.len - 1, 0):
      if carry:
        if counter[i] == 0xFF'u8:
          counter[i] = 0
        else:
          inc counter[i]
          carry = false
    not carry
  else:
    var carry = true
    for i in 0 ..< counter.len:
      if carry:
        if counter[i] == 0xFF'u8:
          counter[i] = 0
        else:
          inc counter[i]
          carry = false
    not carry

template ctrInit*[C; B, K, N, T: static int](init: untyped, ctx: CTRCtx[C, B, K, N, T], key: openArray[uint8], nonceInput: openArray[uint8], endians: Endian = BigEndian, counterSet: int = 1): void =
  copyMem(addr ctx.nonce[0], addr nonceInput[0], N)
  init(ctx.context, key)
  ctx.endian = endians
  intToCounter(counterSet, ctx.counter, ctx.endian)
  static: doAssert B == N + T, "Total size of nonce and counter must be blockSize"
  zeroMem(addr ctx.buffer, B)
  ctx.index = 0

template ctrInput*[C; B, K, N, T: static int](encrypt: untyped, ctx: CTRCtx[C, B, K, N, T], input: openArray[uint8]): seq[uint8] =
  let inputLen: int = input.len
  var output: seq[uint8] = newSeq[uint8](((ctx.index + inputLen) div B) * B)

  var check: bool = true

  if inputLen <= 0: check = false

  if check:
    template encodeBlock(buf: var array[B, uint8]): void =
      copyMem(addr buf[0], addr ctx.nonce[0], N)
      copyMem(addr buf[N], addr ctx.counter[0], T)

    var index: int = ctx.index
    var point: int = 0
    var position: int = 0
    let left: int = B - index

    if inputLen >= left:
      if left > 0:
        copyMem(addr ctx.buffer[index], addr input[0], left)
      var temp: array[B, uint8]
      encodeBlock(temp)
      encrypt(ctx.context, temp, temp)
      ctx.buffer = ctx.buffer xor temp
      copyMem(addr output[point], addr ctx.buffer[0], B)
      discard incrementCounter(ctx.counter, ctx.endian)
      point += B
      position += left
      index = 0
      var buffer: array[B, uint8]

      while position + B <= inputLen:
        encodeBlock(buffer)
        encrypt(ctx.context, buffer, buffer)

        unroll(i, 0, B - 1):
          output[point + i] = input[position + i] xor buffer[i]

        position += B
        point += B

        if position < inputLen:
          discard incrementCounter(ctx.counter, ctx.endian)

    let remain: int = inputLen - position
    if remain > 0:
      copyMem(addr ctx.buffer[index], addr input[position], remain)
      index += remain

    ctx.index = index

  output

template ctrFinal*[C; B, K, N, T: static int](encrypt: untyped, ctx: var CTRCtx[C, B, K, N, T]): seq[uint8] =
  var output: seq[uint8]
  if ctx.index == 0:
    output = newSeq[uint8](0)
  else:
    output = newSeq[uint8](ctx.index)
    var ksBlock: array[B, uint8]
    copyMem(addr ksBlock[0], addr ctx.nonce[0], N)
    copyMem(addr ksBlock[N], addr ctx.counter[0], T)
    encrypt(ctx.context, ksBlock, ksBlock)

    for i in 0 ..< ctx.index:
      output[i] = ctx.buffer[i] xor ksBlock[i]

    ctx.index = 0

  output
