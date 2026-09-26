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


const
  Table*: array[256, uint8] = [
    0xa3'u8, 0xd7'u8, 0x09'u8, 0x83'u8, 0xf8'u8, 0x48'u8, 0xf6'u8, 0xf4'u8, 0xb3'u8, 0x21'u8, 0x15'u8, 0x78'u8, 0x99'u8, 0xb1'u8, 0xaf'u8, 0xf9'u8,
    0xe7'u8, 0x2d'u8, 0x4d'u8, 0x8a'u8, 0xce'u8, 0x4c'u8, 0xca'u8, 0x2e'u8, 0x52'u8, 0x95'u8, 0xd9'u8, 0x1e'u8, 0x4e'u8, 0x38'u8, 0x44'u8, 0x28'u8,
    0x0a'u8, 0xdf'u8, 0x02'u8, 0xa0'u8, 0x17'u8, 0xf1'u8, 0x60'u8, 0x68'u8, 0x12'u8, 0xb7'u8, 0x7a'u8, 0xc3'u8, 0xe9'u8, 0xfa'u8, 0x3d'u8, 0x53'u8,
    0x96'u8, 0x84'u8, 0x6b'u8, 0xba'u8, 0xf2'u8, 0x63'u8, 0x9a'u8, 0x19'u8, 0x7c'u8, 0xae'u8, 0xe5'u8, 0xf5'u8, 0xf7'u8, 0x16'u8, 0x6a'u8, 0xa2'u8,
    0x39'u8, 0xb6'u8, 0x7b'u8, 0x0f'u8, 0xc1'u8, 0x93'u8, 0x81'u8, 0x1b'u8, 0xee'u8, 0xb4'u8, 0x1a'u8, 0xea'u8, 0xd0'u8, 0x91'u8, 0x2f'u8, 0xb8'u8,
    0x55'u8, 0xb9'u8, 0xda'u8, 0x85'u8, 0x3f'u8, 0x41'u8, 0xbf'u8, 0xe0'u8, 0x5a'u8, 0x58'u8, 0x80'u8, 0x5f'u8, 0x66'u8, 0x0b'u8, 0xd8'u8, 0x90'u8,
    0x35'u8, 0xd5'u8, 0xc0'u8, 0xa7'u8, 0x33'u8, 0x06'u8, 0x65'u8, 0x69'u8, 0x45'u8, 0x00'u8, 0x94'u8, 0x56'u8, 0x6d'u8, 0x98'u8, 0x9b'u8, 0x76'u8,
    0x97'u8, 0xfc'u8, 0xb2'u8, 0xc2'u8, 0xb0'u8, 0xfe'u8, 0xdb'u8, 0x20'u8, 0xe1'u8, 0xeb'u8, 0xd6'u8, 0xe4'u8, 0xdd'u8, 0x47'u8, 0x4a'u8, 0x1d'u8,
    0x42'u8, 0xed'u8, 0x9e'u8, 0x6e'u8, 0x49'u8, 0x3c'u8, 0xcd'u8, 0x43'u8, 0x27'u8, 0xd2'u8, 0x07'u8, 0xd4'u8, 0xde'u8, 0xc7'u8, 0x67'u8, 0x18'u8,
    0x89'u8, 0xcb'u8, 0x30'u8, 0x1f'u8, 0x8d'u8, 0xc6'u8, 0x8f'u8, 0xaa'u8, 0xc8'u8, 0x74'u8, 0xdc'u8, 0xc9'u8, 0x5d'u8, 0x5c'u8, 0x31'u8, 0xa4'u8,
    0x70'u8, 0x88'u8, 0x61'u8, 0x2c'u8, 0x9f'u8, 0x0d'u8, 0x2b'u8, 0x87'u8, 0x50'u8, 0x82'u8, 0x54'u8, 0x64'u8, 0x26'u8, 0x7d'u8, 0x03'u8, 0x40'u8,
    0x34'u8, 0x4b'u8, 0x1c'u8, 0x73'u8, 0xd1'u8, 0xc4'u8, 0xfd'u8, 0x3b'u8, 0xcc'u8, 0xfb'u8, 0x7f'u8, 0xab'u8, 0xe6'u8, 0x3e'u8, 0x5b'u8, 0xa5'u8,
    0xad'u8, 0x04'u8, 0x23'u8, 0x9c'u8, 0x14'u8, 0x51'u8, 0x22'u8, 0xf0'u8, 0x29'u8, 0x79'u8, 0x71'u8, 0x7e'u8, 0xff'u8, 0x8c'u8, 0x0e'u8, 0xe2'u8,
    0x0c'u8, 0xef'u8, 0xbc'u8, 0x72'u8, 0x75'u8, 0x6f'u8, 0x37'u8, 0xa1'u8, 0xec'u8, 0xd3'u8, 0x8e'u8, 0x62'u8, 0x8b'u8, 0x86'u8, 0x10'u8, 0xe8'u8,
    0x08'u8, 0x77'u8, 0x11'u8, 0xbe'u8, 0x92'u8, 0x4f'u8, 0x24'u8, 0xc5'u8, 0x32'u8, 0x36'u8, 0x9d'u8, 0xcf'u8, 0xf3'u8, 0xa6'u8, 0xbb'u8, 0xac'u8,
    0x5e'u8, 0x6c'u8, 0xa9'u8, 0x13'u8, 0x57'u8, 0x25'u8, 0xb5'u8, 0xe3'u8, 0xbd'u8, 0xa8'u8, 0x3a'u8, 0x01'u8, 0x05'u8, 0x59'u8, 0x2a'u8, 0x46'u8,
  ]

type
  SkipjackCtx* = object
    gTable: array[5 * 65536, uint16]
    table: array[10 * 256, uint8]

template g0(ctx: SkipjackCtx; w: var uint16) =
  w = ctx.gTable[int(w)]

template g1(ctx: SkipjackCtx; w: var uint16) =
  w = ctx.gTable[65536 + int(w)]

template g2(ctx: SkipjackCtx; w: var uint16) =
  w = ctx.gTable[2 * 65536 + int(w)]

template g3(ctx: SkipjackCtx; w: var uint16) =
  w = ctx.gTable[3 * 65536 + int(w)]

template g4(ctx: SkipjackCtx; w: var uint16) =
  w = ctx.gTable[4 * 65536 + int(w)]

template hBox(ctx: SkipjackCtx; w: var uint16; i, j, k, l: int) =
  w = w xor uint16(ctx.table[l * 256 + int(w shr 8)])
  w = w xor (uint16(ctx.table[k * 256 + int(w and 0xFF'u16)]) shl 8)
  w = w xor uint16(ctx.table[j * 256 + int(w shr 8)])
  w = w xor (uint16(ctx.table[i * 256 + int(w and 0xFF'u16)]) shl 8)

template h0(ctx: SkipjackCtx; w: var uint16) =
  hBox(ctx, w, 0, 1, 2, 3)

template h1(ctx: SkipjackCtx; w: var uint16) =
  hBox(ctx, w, 4, 5, 6, 7)

template h2(ctx: SkipjackCtx; w: var uint16) =
  hBox(ctx, w, 8, 9, 0, 1)

template h3(ctx: SkipjackCtx; w: var uint16) =
  hBox(ctx, w, 2, 3, 4, 5)

template h4(ctx: SkipjackCtx; w: var uint16) =
  hBox(ctx, w, 6, 7, 8, 9)

template skipjackInitC*(ctx: var SkipjackCtx, key: slicearray[10, uint8]): void =
  for i in static(0 ..< 10):
    let k: uint8 = key[9 - i]
    for c in static(0 .. 255):
      ctx.table[i * 256 + c] = Table[c xor int(k)]

  const offsets = [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 0, 1],
                   [2, 3, 4, 5], [6, 7, 8, 9]]
  for box in static(0 .. 4):
    let base: int = box * 65536
    let i: int = offsets[box][0]
    let j: int = offsets[box][1]
    let k: int = offsets[box][2]
    let l: int = offsets[box][3]
    for x in 0 .. 65535:
      var w = uint16(x)
      w = w xor (uint16(ctx.table[i * 256 + int(w and 0xff'u16)]) shl 8)
      w = w xor uint16(ctx.table[j * 256 + int(w shr 8)])
      w = w xor (uint16(ctx.table[k * 256 + int(w and 0xff'u16)]) shl 8)
      w = w xor uint16(ctx.table[l * 256 + int(w shr 8)])
      ctx.gTable[base + x] = w

template skipjackEncryptC*(ctx: SkipjackCtx; input, output: slicearray[8, uint8]): void =
  var w1, w2, w3, w4: uint16
  fromBytesLE(input.toSliceArray(0, 1), w4)
  fromBytesLE(input.toSliceArray(2, 3), w3)
  fromBytesLE(input.toSliceArray(4, 5), w2)
  fromBytesLE(input.toSliceArray(6, 7), w1)

  g0(ctx, w1); w4 = w4 xor w1 xor 1
  g1(ctx, w4); w3 = w3 xor w4 xor 2
  g2(ctx, w3); w2 = w2 xor w3 xor 3
  g3(ctx, w2); w1 = w1 xor w2 xor 4
  g4(ctx, w1); w4 = w4 xor w1 xor 5
  g0(ctx, w4); w3 = w3 xor w4 xor 6
  g1(ctx, w3); w2 = w2 xor w3 xor 7
  g2(ctx, w2); w1 = w1 xor w2 xor 8

  w2 = w2 xor w1 xor 9; g3(ctx, w1)
  w1 = w1 xor w4 xor 10; g4(ctx, w4)
  w4 = w4 xor w3 xor 11; g0(ctx, w3)
  w3 = w3 xor w2 xor 12; g1(ctx, w2)
  w2 = w2 xor w1 xor 13; g2(ctx, w1)
  w1 = w1 xor w4 xor 14; g3(ctx, w4)
  w4 = w4 xor w3 xor 15; g4(ctx, w3)
  w3 = w3 xor w2 xor 16; g0(ctx, w2)

  g1(ctx, w1); w4 = w4 xor w1 xor 17
  g2(ctx, w4); w3 = w3 xor w4 xor 18
  g3(ctx, w3); w2 = w2 xor w3 xor 19
  g4(ctx, w2); w1 = w1 xor w2 xor 20
  g0(ctx, w1); w4 = w4 xor w1 xor 21
  g1(ctx, w4); w3 = w3 xor w4 xor 22
  g2(ctx, w3); w2 = w2 xor w3 xor 23
  g3(ctx, w2); w1 = w1 xor w2 xor 24

  w2 = w2 xor w1 xor 25; g4(ctx, w1)
  w1 = w1 xor w4 xor 26; g0(ctx, w4)
  w4 = w4 xor w3 xor 27; g1(ctx, w3)
  w3 = w3 xor w2 xor 28; g2(ctx, w2)
  w2 = w2 xor w1 xor 29; g3(ctx, w1)
  w1 = w1 xor w4 xor 30; g4(ctx, w4)
  w4 = w4 xor w3 xor 31; g0(ctx, w3)
  w3 = w3 xor w2 xor 32; g1(ctx, w2)

  toBytesLE(w4, output.toSliceArray(0, 1))
  toBytesLE(w3, output.toSliceArray(2, 3))
  toBytesLE(w2, output.toSliceArray(4, 5))
  toBytesLE(w1, output.toSliceArray(6, 7))

template skipjackDecryptC*(ctx: SkipjackCtx; input, output: slicearray[8, uint8]): void =
  var w1, w2, w3, w4: uint16
  fromBytesLE(input.toSliceArray(0, 1), w4)
  fromBytesLE(input.toSliceArray(2, 3), w3)
  fromBytesLE(input.toSliceArray(4, 5), w2)
  fromBytesLE(input.toSliceArray(6, 7), w1)

  h1(ctx, w2); w3 = w3 xor w2 xor 32
  h0(ctx, w3); w4 = w4 xor w3 xor 31
  h4(ctx, w4); w1 = w1 xor w4 xor 30
  h3(ctx, w1); w2 = w2 xor w1 xor 29
  h2(ctx, w2); w3 = w3 xor w2 xor 28
  h1(ctx, w3); w4 = w4 xor w3 xor 27
  h0(ctx, w4); w1 = w1 xor w4 xor 26
  h4(ctx, w1); w2 = w2 xor w1 xor 25

  w1 = w1 xor w2 xor 24; h3(ctx, w2)
  w2 = w2 xor w3 xor 23; h2(ctx, w3)
  w3 = w3 xor w4 xor 22; h1(ctx, w4)
  w4 = w4 xor w1 xor 21; h0(ctx, w1)
  w1 = w1 xor w2 xor 20; h4(ctx, w2)
  w2 = w2 xor w3 xor 19; h3(ctx, w3)
  w3 = w3 xor w4 xor 18; h2(ctx, w4)
  w4 = w4 xor w1 xor 17; h1(ctx, w1)

  h0(ctx, w2); w3 = w3 xor w2 xor 16
  h4(ctx, w3); w4 = w4 xor w3 xor 15
  h3(ctx, w4); w1 = w1 xor w4 xor 14
  h2(ctx, w1); w2 = w2 xor w1 xor 13
  h1(ctx, w2); w3 = w3 xor w2 xor 12
  h0(ctx, w3); w4 = w4 xor w3 xor 11
  h4(ctx, w4); w1 = w1 xor w4 xor 10
  h3(ctx, w1); w2 = w2 xor w1 xor 9

  w1 = w1 xor w2 xor 8; h2(ctx, w2)
  w2 = w2 xor w3 xor 7; h1(ctx, w3)
  w3 = w3 xor w4 xor 6; h0(ctx, w4)
  w4 = w4 xor w1 xor 5; h4(ctx, w1)
  w1 = w1 xor w2 xor 4; h3(ctx, w2)
  w2 = w2 xor w3 xor 3; h2(ctx, w3)
  w3 = w3 xor w4 xor 2; h1(ctx, w4)
  w4 = w4 xor w1 xor 1; h0(ctx, w1)

  toBytesLE(w4, output.toSliceArray(0, 1))
  toBytesLE(w3, output.toSliceArray(2, 3))
  toBytesLE(w2, output.toSliceArray(4, 5))
  toBytesLE(w1, output.toSliceArray(6, 7))

when defined(templateOpt):
  template skipjackInit*(ctx: var SkipjackCtx, key: array[10, uint8]): void = skipjackInitC(ctx, key.toSliceArray(0, 9))
  template skipjackInit*(ctx: var SkipjackCtx, key: openArray[uint8]): void = skipjackInitC(ctx, key.toSliceArray(0, 9))
  template skipjackInit*(ctx: var SkipjackCtx, key: slicearray[10, uint8]): void = skipjackInitC(ctx, key)
  template skipjackInit*(ctx: ptr SkipjackCtx, key: ptr array[10, uint8]): void = skipjackInitC(ctx[], key.toSliceArray(0, 9))

  template skipjackEncrypt*(ctx: SkipjackCtx, input: array[8, uint8], output: var array[8, uint8]): void = skipjackEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template skipjackEncrypt*(ctx: SkipjackCtx, input: openArray[uint8], output: var openArray[uint8]): void = skipjackEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template skipjackEncrypt*(ctx: SkipjackCtx, input, output: slicearray[8, uint8]): void = skipjackEncryptC(ctx, input, output)
  template skipjackEncrypt*(ctx: ptr SkipjackCtx, input, output: ptr array[8, uint8]): void = skipjackEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  template skipjackDecrypt*(ctx: SkipjackCtx, input: array[8, uint8], output: var array[8, uint8]): void = skipjackDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template skipjackDecrypt*(ctx: SkipjackCtx, input: openArray[uint8], output: var openArray[uint8]): void = skipjackDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  template skipjackDecrypt*(ctx: SkipjackCtx, input, output: slicearray[8, uint8]): void = skipjackDecryptC(ctx, input, output)
  template skipjackDecrypt*(ctx: ptr SkipjackCtx, input, output: ptr array[8, uint8]): void = skipjackDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))
else:
  proc skipjackInit*(ctx: var SkipjackCtx, key: array[10, uint8]): void = skipjackInitC(ctx, key.toSliceArray(0, 9))
  proc skipjackInit*(ctx: var SkipjackCtx, key: openArray[uint8]): void = skipjackInitC(ctx, key.toSliceArray(0, 9))
  proc skipjackInit*(ctx: var SkipjackCtx, key: slicearray[10, uint8]): void = skipjackInitC(ctx, key)
  proc skipjackInit*(ctx: ptr SkipjackCtx, key: ptr array[10, uint8]): void = skipjackInitC(ctx[], key.toSliceArray(0, 9))

  proc skipjackEncrypt*(ctx: SkipjackCtx, input: array[8, uint8], output: var array[8, uint8]): void = skipjackEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc skipjackEncrypt*(ctx: SkipjackCtx, input: openArray[uint8], output: var openArray[uint8]): void = skipjackEncryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc skipjackEncrypt*(ctx: SkipjackCtx, input, output: slicearray[8, uint8]): void = skipjackEncryptC(ctx, input, output)
  proc skipjackEncrypt*(ctx: ptr SkipjackCtx, input, output: ptr array[8, uint8]): void = skipjackEncryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))

  proc skipjackDecrypt*(ctx: SkipjackCtx, input: array[8, uint8], output: var array[8, uint8]): void = skipjackDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc skipjackDecrypt*(ctx: SkipjackCtx, input: openArray[uint8], output: var openArray[uint8]): void = skipjackDecryptC(ctx, input.toSliceArray(0, 7), output.toSliceArray(0, 7))
  proc skipjackDecrypt*(ctx: SkipjackCtx, input, output: slicearray[8, uint8]): void = skipjackDecryptC(ctx, input, output)
  proc skipjackDecrypt*(ctx: ptr SkipjackCtx, input, output: ptr array[8, uint8]): void = skipjackDecryptC(ctx[], input.toSliceArray(0, 7), output.toSliceArray(0, 7))
