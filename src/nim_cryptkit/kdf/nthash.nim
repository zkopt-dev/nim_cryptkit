import std/[unicode, strutils]
import ../hash/md4
import "../block/des"
import ../utils/vectorop
import ../utils/bitutils
import ../utils/endian
import ../utils/errorutils
import ../utils/digits
import ../utils/slicearray
import ../utils/optmacro
import ../utils/envconst
import ../utils/biguintBE
import helper

const
  lmMagic: array[8, uint8] = [
    uint8('K'), uint8('G'), uint8('S'), uint8('!'), uint8('@'), uint8('#'), uint8('$'), uint8('%')
  ]

template lmDesKey(chunk: openArray[uint8]): array[8, uint8] =
  var output: array[8, uint8]
  var source: array[7, uint8]
  for i in 0 ..< min(7, chunk.len):
    source[i] = chunk[i]
  output[0] = source[0] and 0xfe'u8
  output[1] = ((source[0] shl 7) or (source[1] shr 1)) and 0xfe'u8
  output[2] = ((source[1] shl 6) or (source[2] shr 2)) and 0xfe'u8
  output[3] = ((source[2] shl 5) or (source[3] shr 3)) and 0xfe'u8
  output[4] = ((source[3] shl 4) or (source[4] shr 4)) and 0xfe'u8
  output[5] = ((source[4] shl 3) or (source[5] shr 5)) and 0xfe'u8
  output[6] = ((source[5] shl 2) or (source[6] shr 6)) and 0xfe'u8
  output[7] = (source[6] shl 1) and 0xfe'u8
  output

proc lmHash*(password: string): array[16, uint8] =
  var output: array[16, uint8]
  var upper: string = password.toUpperAscii
  if upper.len > 14: upper.setLen(14)

  var first, second: array[8, uint8]
  var head, tail: array[7, uint8]
  for i in 0 ..< min(7, upper.len):
    head[i] = uint8(upper[i])
  for i in 7 ..< upper.len:
    tail[i - 7] = uint8(upper[i])
  var ctx: DESCtx
  desInit(ctx, lmDesKey(head))
  desEncrypt(ctx, lmMagic, first)
  desInit(ctx, lmDesKey(tail))
  desEncrypt(ctx, lmMagic, second)

  copyMem(addr output[0], addr first[0], 8)
  copyMem(addr output[8], addr second[0], 8)

  output

proc ntHash*(password: string): array[16, uint8] =
  var encoded: seq[uint8]
  for rune in password.runes:
    let code = uint32(rune)
    if code <= 0xffff'u32:
      encoded.add(uint8(code))
      encoded.add(uint8(code shr 8))
    else:
      let v = code - 0x10000'u32
      let hi = 0xd800'u32 or (v shr 10)
      let lo = 0xdc00'u32 or (v and 0x3ff'u32)
      encoded.add(uint8(hi))
      encoded.add(uint8(hi shr 8))
      encoded.add(uint8(lo))
      encoded.add(uint8(lo shr 8))
  var ctx: MD4Ctx
  md4Init(ctx)
  md4Input(ctx, encoded)
  md4Final(ctx)
